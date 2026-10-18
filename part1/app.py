"""Run one of the three independently served Part 1 services."""
import argparse
import ipaddress
import json
import math
import re

from flask import g, request

from common.runtime import (ADMIN, ANALYST, AUDITOR, CONFIG, LEVELS, APIError,
    audit, body, call, choice, db, fetch, make_app, now, ok, positive_id,
    prefix, protected, text, internal_only)

ASSET_TYPES = ('Server', 'Workstation', 'Database', 'Application', 'Network Device', 'Cloud Resource')
ASSET_STATUS = ('Active', 'Inactive', 'Under Maintenance')
THREAT_TYPES = ('IP Address', 'Domain', 'File Hash', 'Malware Signature', 'Other Indicators')
VULN_STATUS = ('Open', 'Under Investigation', 'In Progress', 'Resolved', 'Closed')
FIELDS = {
    'assets': ('asset_name','asset_type','ip_address','operating_system','owner_id','department','location','criticality_level','status'),
    'threats': ('threat_type','threat_value','description','severity','source'),
    'vulnerabilities': ('title','description','cve_identifier','cvss_score','severity','asset_id','discovery_source','status','resolution_date')
}
REQUIRED = {
    'assets': ('asset_name','asset_type','ip_address','department','owner_id','criticality_level'),
    'threats': FIELDS['threats'],
    'vulnerabilities': ('title','description','cve_identifier','cvss_score','severity','asset_id','discovery_source')
}
UPDATES = {
    'assets': ('asset_name','owner_id','department','criticality_level','status'),
    'threats': ('description','severity','source'),
    'vulnerabilities': ('description','severity','status','cvss_score','resolution_date')
}
SEARCH = {
    'assets': ('asset_name','asset_type','ip_address','department','criticality_level'),
    'threats': ('threat_type','threat_value','severity','source'),
    'vulnerabilities': ('cve_identifier','severity','asset_id','status')
}


def validate(service, data, old=None):
    for key in data:
        if key not in ('owner_id','asset_id','cvss_score','resolution_date'):
            text(data, key)
    choice(data, 'severity', LEVELS)
    if service == 'assets':
        choice(data, 'asset_type', ASSET_TYPES)
        choice(data, 'criticality_level', LEVELS)
        choice(data, 'status', ASSET_STATUS)
        if 'ip_address' in data:
            try:
                data['ip_address'] = str(ipaddress.ip_address(data['ip_address']))
            except ValueError:
                raise APIError('Invalid IP address')
        if 'owner_id' in data:
            positive_id(data['owner_id'], 'owner_id')
            call('users', 'GET', f"/users/id/{data['owner_id']}")
    elif service == 'threats':
        choice(data, 'threat_type', THREAT_TYPES)
        kind, value = data.get('threat_type'), data.get('threat_value')
        if kind == 'IP Address':
            try:
                data['threat_value'] = str(ipaddress.ip_address(value))
            except ValueError:
                raise APIError('Invalid threat IP address')
        elif kind == 'Domain':
            value = value.lower().rstrip('.')
            if len(value) > 253 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', value):
                raise APIError('Invalid threat domain')
            data['threat_value'] = value
        elif kind == 'File Hash':
            if not re.fullmatch(r'(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})', value):
                raise APIError('File hash must be hexadecimal MD5, SHA1, or SHA256')
            data['threat_value'] = value.lower()
        if kind and db().execute('SELECT id FROM threats WHERE threat_type=? AND threat_value=?',
                                 (kind, data['threat_value'])).fetchone():
            raise APIError('Threat type and value already exist', 409)
    else:
        if 'cve_identifier' in data and not re.fullmatch(r'CVE-\d{4}-\d{4,}', data['cve_identifier']):
            raise APIError('CVE identifier must have format CVE-YYYY-NNNN')
        if 'cvss_score' in data:
            score = data['cvss_score']
            if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 10:
                raise APIError('CVSS score must be a number between 0 and 10')
        if 'asset_id' in data:
            positive_id(data['asset_id'], 'asset_id')
            call('assets', 'GET', f"/assets/{data['asset_id']}")
        choice(data, 'status', VULN_STATUS)
        if old and 'status' in data and data['status'] != old['status']:
            current = VULN_STATUS.index(old['status'])
            if current == len(VULN_STATUS)-1 or data['status'] != VULN_STATUS[current+1]:
                raise APIError('Invalid vulnerability status transition')
        if not old and data.get('status', 'Open') != 'Open':
            raise APIError('New vulnerabilities must start Open')
        status = data.get('status', old['status'] if old else 'Open')
        if 'resolution_date' in data:
            if data['resolution_date'] is not None:
                raise APIError('Resolution date is generated automatically when resolved')
            if status in ('Resolved','Closed'):
                raise APIError('Cannot clear resolution date after resolution')
        if status == 'Resolved' and (not old or old['status'] != 'Resolved'):
            data['resolution_date'] = now()


class ResourceService:
    """One service instance owns validation, persistence, and REST routes."""
    def __init__(self, service):
        self.service = service
        self.app = make_app(service)
        self.register()

    def register(self):
        service, app = self.service, self.app
        base = prefix('part1') + '/' + service
        read_roles = (ADMIN, ANALYST, AUDITOR)
        list_roles = (ADMIN, AUDITOR) if service == 'assets' else read_roles
        edit_roles = (ADMIN, ANALYST) if service == 'vulnerabilities' else (ADMIN,)

        @app.post(base)
        @protected(ADMIN)
        def create():
            data = body(REQUIRED[service], FIELDS[service])
            validate(service, data)
            if service == 'assets':
                data.setdefault('status', 'Active')
            elif service == 'threats':
                data['date_added'] = now()
            else:
                data.setdefault('status', 'Open')
                data['creation_date'] = now()
            audit(f'{service}:create requested', 'Validated create request')
            columns = ','.join(data)
            marks = ','.join('?' for _ in data)
            cursor = db().execute(f'INSERT INTO {service} ({columns}) VALUES ({marks})', tuple(data.values()))
            record_id = cursor.lastrowid
            if service == 'assets':
                self.history(record_id, 'Created')
            db().commit()
            record = fetch(service, record_id)
            if service in ('threats','vulnerabilities'):
                self.notify(record)
            return ok(record, 201)

        @app.get(base)
        @protected(*list_roles)
        def all_records():
            return ok([dict(row) for row in db().execute(f'SELECT * FROM {service} ORDER BY id')])

        @app.get(base + '/search')
        @protected(*read_roles)
        def search():
            if set(request.args) - set(SEARCH[service]):
                raise APIError('Unsupported search parameter')
            clauses, values = [], []
            for key, value in request.args.items():
                if not value.strip():
                    raise APIError('Search values cannot be empty')
                if key == 'asset_id':
                    if not value.isdigit() or int(value) < 1:
                        raise APIError('asset_id must be a positive integer')
                    clauses.append('asset_id=?')
                    positive_id(int(value), 'asset_id')
                    values.append(int(value))
                else:
                    # instr treats user input as literal text, including SQL wildcards.
                    clauses.append(f'instr(lower({key}), lower(?)) > 0')
                    values.append(value)
            if service == 'assets' and g.user['role'] == ANALYST:
                clauses.append('id IN (SELECT asset_id FROM incidents WHERE assigned_analyst_id=?)')
                values.append(g.user['id'])
            query = f'SELECT * FROM {service}'
            if clauses:
                query += ' WHERE ' + ' AND '.join(clauses)
            return ok([dict(row) for row in db().execute(query + ' ORDER BY id', values)])

        @app.get(base + '/<int:record_id>')
        @protected(*read_roles)
        def get_record(record_id):
            record = fetch(service, record_id)
            if service == 'assets':
                self.check_related(record_id)
                record['related_incident_ids'] = [r[0] for r in db().execute('SELECT id FROM incidents WHERE asset_id=?', (record_id,))]
                record['related_vulnerability_ids'] = [r[0] for r in db().execute('SELECT id FROM vulnerabilities WHERE asset_id=?', (record_id,))]
            return ok(record)

        @app.put(base + '/<int:record_id>')
        @protected(*edit_roles)
        def update(record_id):
            old = fetch(service, record_id)
            data = body(allowed=UPDATES[service])
            validate(service, data, old)
            audit(f'{service}:update requested', f'Validated update request for ID {record_id}')
            assignments = ','.join(f'{key}=?' for key in data)
            db().execute(f'UPDATE {service} SET {assignments} WHERE id=?', (*data.values(), record_id))
            if service == 'assets':
                self.history(record_id, 'Updated')
            db().commit()
            return ok(fetch(service, record_id))

        @app.delete(base + '/<int:record_id>')
        @protected(ADMIN)
        def delete(record_id):
            fetch(service, record_id)
            audit(f'{service}:delete requested', f'Validated deletion request for ID {record_id}')
            db().execute(f'DELETE FROM {service} WHERE id=?', (record_id,))
            db().commit()
            return ok({'message': 'Record deleted', 'id': record_id})

        if service == 'assets':
            @app.get(prefix('part1') + '/internal/assets/<int:record_id>')
            @internal_only
            def internal_asset(record_id):
                record = fetch('assets', record_id)
                return ok({'id': record['id'], 'status': record['status'], 'owner_id': record['owner_id']})

            @app.get(base + '/<int:record_id>/history')
            @protected(ADMIN, AUDITOR)
            def asset_history(record_id):
                fetch('assets', record_id)
                records = [dict(r) for r in db().execute('SELECT * FROM asset_history WHERE asset_id=? ORDER BY id', (record_id,))]
                for record in records:
                    record['snapshot'] = json.loads(record['snapshot'])
                return ok(records)

    def check_related(self, record_id):
        if g.user['role'] == ANALYST and not db().execute(
            'SELECT 1 FROM incidents WHERE asset_id=? AND assigned_analyst_id=?',
            (record_id, g.user['id'])).fetchone():
            audit('Unauthorized access', 'Analyst requested an unrelated asset', 'Warning')
            raise APIError('Analyst can only view assets related to assigned incidents', 403)

    def history(self, record_id, action):
        db().execute('INSERT INTO asset_history (asset_id,user_id,action,snapshot,timestamp) VALUES (?,?,?,?,?)',
            (record_id, g.user['id'], action, json.dumps(fetch('assets', record_id)), now()))

    def notify(self, record):
        service = self.service
        recipient = g.user['id']
        if service == 'vulnerabilities':
            recipient = fetch('assets', record['asset_id'])['owner_id']
        try:
            call('notifications', 'POST', '/internal/notifications', {
                'user_id': recipient, 'title': f'New {service} record',
                'message': f"{service} record {record['id']} was created",
                'notification_type': 'Threat Alert' if service == 'threats' else 'Vulnerability Alert',
                'severity': record['severity']
            }, internal=True)
        except APIError as error:
            # Do not report a failed create after its database transaction succeeded.
            record['notification_warning'] = error.message + '; record saved, alert delivery needs retry'


def create_app(service):
    if service not in FIELDS:
        raise ValueError('Unknown Part 1 service')
    return ResourceService(service).app


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('service', choices=FIELDS)
    args = parser.parse_args()
    create_app(args.service).run(host='127.0.0.1', port=CONFIG['ports'][args.service], debug=False)
