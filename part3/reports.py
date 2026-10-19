"""Reports aggregate authorized HTTP responses, never cross-service SQL."""
import os
from collections import Counter
from common import runtime as rt


class ReportService:
    def records(self, service):
        records = rt.call(service, 'GET', '/' + service)
        if not isinstance(records, list) or any(not isinstance(row, dict) for row in records):
            raise rt.APIError(f'{service} returned an unsupported list contract; report cannot be calculated', 503)
        return records

    def grouped(self, records, key):
        if any(key not in row for row in records):
            raise rt.APIError(f'Dependency response lacks {key}', 503)
        return dict(sorted(Counter(row[key] for row in records).items()))

    def recent(self, records, key):
        if any(not isinstance(row.get(key), str) for row in records):
            raise rt.APIError(f'Dependency response lacks timestamp {key}', 503)
        return sorted(records, key=lambda row: row[key], reverse=True)[:10]

    def generate(self, kind):
        if kind == 'summary':
            data = {service: self.records(service) for service in ('users', 'assets', 'incidents', 'threats', 'logs')}
            return {'users': len(data['users']), 'assets': len(data['assets']),
                'incidents': len(data['incidents']), 'threats': len(data['threats']),
                'open_incidents': sum(r['status'] == 'Open' for r in data['incidents']),
                'critical_threats': sum(r['severity'] == 'Critical' for r in data['threats']),
                'recent_activity': self.recent(data['logs'], 'timestamp')}
        records = self.records('logs' if kind == 'activity' else kind)
        result = {'total': len(records)}
        if kind in ('incidents', 'threats', 'vulnerabilities'):
            result['by_severity'] = self.grouped(records, 'severity')
        if kind in ('incidents', 'vulnerabilities'):
            result['by_status'] = self.grouped(records, 'status')
        if kind == 'assets':
            result.update(critical=sum(r['criticality_level'] == 'Critical' for r in records),
                by_type=self.grouped(records, 'asset_type'))
        if kind == 'threats':
            result.update(by_type=self.grouped(records, 'threat_type'), recent_indicators=self.recent(records, 'date_added'))
        if kind == 'vulnerabilities':
            result['critical'] = sum(r['severity'] == 'Critical' for r in records)
        if kind == 'activity':
            # Default labels are shared with the identity service.
            success = os.environ.get('PART3_LOGIN_SUCCESS_ACTION', rt.LOGIN_SUCCESS_ACTION)
            failure = os.environ.get('PART3_LOGIN_FAILURE_ACTION', rt.LOGIN_FAILURE_ACTION)
            if not success or not failure or success == failure:
                raise rt.APIError('Agree Part 2 login outcome labels and set PART3_LOGIN_SUCCESS_ACTION and PART3_LOGIN_FAILURE_ACTION', 503)
            actions = self.grouped(records, 'action')
            result.update(total_activities=len(records), login_attempts=actions.get(success, 0) + actions.get(failure, 0),
                failed_logins=actions.get(failure, 0), most_common_actions=dict(Counter(r['action'] for r in records).most_common()),
                login_action_labels={'success': success, 'failure': failure})
        return result


def register(app, prefix):
    service = ReportService()
    for kind in ('summary', 'incidents', 'assets', 'threats', 'vulnerabilities', 'activity'):
        def report(kind=kind):
            try:
                return rt.ok(service.generate(kind))
            except (KeyError, TypeError, ValueError) as error:
                raise rt.APIError('Dependency returned malformed report data', 503) from error
        app.add_url_rule(prefix + '/reports/' + kind, 'reports_' + kind,
            rt.protected(rt.ADMIN, rt.AUDITOR)(report), methods=['GET'])
