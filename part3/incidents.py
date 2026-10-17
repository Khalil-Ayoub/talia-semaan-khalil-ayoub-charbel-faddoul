"""Incident lifecycle, ownership checks, investigation notes and assignment alerts."""
from flask import g
from common import runtime as rt
from part3.support import active_user, deny, insert, requested, rows, strings

STATES = ('Open', 'Under Investigation', 'Mitigated', 'Resolved', 'Closed')


class IncidentService:
    def scoped(self, incident):
        role, uid = g.user['role'], g.user['id']
        if role == rt.ANALYST and incident['assigned_analyst_id'] != uid:
            deny('Analysts may access only assigned incidents')
        if role == rt.EMPLOYEE and incident['reporter_id'] != uid:
            deny('Employees may access only their own reported incidents')
        return incident

    def detail(self, incident_id):
        incident = self.scoped(rt.fetch('incidents', incident_id))
        incident['notes'] = rows('SELECT * FROM investigation_notes WHERE incident_id=? ORDER BY id', (incident_id,))
        return incident


def register(app, prefix):
    service, base = IncidentService(), prefix + '/incidents'

    @app.post(base)
    @rt.protected(rt.ADMIN, rt.EMPLOYEE)
    def incidents_create():
        required = ('title', 'description', 'category', 'severity', 'asset_id')
        data = rt.body(required, required + ('reporter_id',))
        strings(data, ('title', 'description', 'category', 'severity'))
        rt.choice(data, 'severity', rt.LEVELS)
        rt.positive_id(data['asset_id'], 'asset_id')
        rt.call('assets', 'GET', f"/internal/assets/{data['asset_id']}", internal=True)
        reporter = data.get('reporter_id', g.user['id'])
        rt.positive_id(reporter, 'reporter_id')
        if g.user['role'] == rt.EMPLOYEE and reporter != g.user['id']:
            deny('Reporter must be the authenticated employee')
        active_user(reporter)
        data.update(reporter_id=reporter, status='Open', creation_date=rt.now())
        requested('incidents:create', 'Create incident')
        with rt.db():
            incident_id = insert('incidents', data)
        return rt.ok(service.detail(incident_id), 201)

    @app.get(base)
    @rt.protected(rt.ADMIN, rt.AUDITOR)
    def incidents_list():
        return rt.ok(rows('SELECT * FROM incidents ORDER BY id'))

    @app.get(base + '/assigned')
    @rt.protected(rt.ANALYST)
    def incidents_assigned():
        return rt.ok(rows('SELECT * FROM incidents WHERE assigned_analyst_id=? ORDER BY id', (g.user['id'],)))

    @app.get(base + '/mine')
    @rt.protected(rt.EMPLOYEE)
    def incidents_mine():
        return rt.ok(rows('SELECT * FROM incidents WHERE reporter_id=? ORDER BY id', (g.user['id'],)))

    @app.get(base + '/<int:incident_id>')
    @rt.protected(rt.ADMIN, rt.ANALYST, rt.EMPLOYEE, rt.AUDITOR)
    def incidents_detail(incident_id):
        return rt.ok(service.detail(incident_id))

    @app.put(base + '/<int:incident_id>/assign')
    @rt.protected(rt.ADMIN)
    def incidents_assign(incident_id):
        rt.fetch('incidents', incident_id)
        data = rt.body(('assigned_analyst_id',), ('assigned_analyst_id',))
        active_user(data['assigned_analyst_id'], analyst=True)
        requested('incidents:assign', f'Assign incident {incident_id} to {data["assigned_analyst_id"]}')
        with rt.db():
            rt.db().execute('UPDATE incidents SET assigned_analyst_id=? WHERE id=?', (data['assigned_analyst_id'], incident_id))
        record = service.detail(incident_id)
        try:
            rt.call('notifications', 'POST', '/internal/notifications', {
                'user_id': data['assigned_analyst_id'], 'title': 'Incident assignment',
                'message': f'You are assigned incident {incident_id}: {record["title"]}',
                'notification_type': 'Incident Assignment', 'severity': record['severity']}, internal=True)
        except rt.APIError as error:
            record['notification_warning'] = error.message + '; assignment saved, alert delivery needs retry'
        return rt.ok(record)

    @app.put(base + '/<int:incident_id>/status')
    @rt.protected(rt.ADMIN, rt.ANALYST)
    def incidents_status(incident_id):
        old = service.scoped(rt.fetch('incidents', incident_id))
        data = rt.body(('status',), ('status',))
        rt.choice(data, 'status', STATES)
        if old['status'] == STATES[-1] or data['status'] != STATES[STATES.index(old['status']) + 1]:
            raise rt.APIError('Status must advance exactly one step: ' + ' -> '.join(STATES))
        requested('incidents:status', f'Incident {incident_id}: {old["status"]} -> {data["status"]}')
        with rt.db():
            changed = rt.db().execute('UPDATE incidents SET status=?, resolution_date=? WHERE id=? AND status=? AND assigned_analyst_id IS ?',
                (data['status'], rt.now() if data['status'] == 'Resolved' else old['resolution_date'], incident_id, old['status'], old['assigned_analyst_id']))
            if changed.rowcount != 1:
                raise rt.APIError('Incident changed concurrently; reload and retry', 409)
        return rt.ok(service.detail(incident_id))

    @app.post(base + '/<int:incident_id>/notes')
    @rt.protected(rt.ADMIN, rt.ANALYST)
    def incidents_notes(incident_id):
        service.scoped(rt.fetch('incidents', incident_id))
        data = rt.body(('note_content',), ('note_content',))
        strings(data, ('note_content',))
        requested('incidents:note', f'Add note to incident {incident_id}')
        with rt.db():
            # Recheck assignment under the write lock, without any HTTP call.
            rt.db().execute('BEGIN IMMEDIATE')
            current = rt.fetch('incidents', incident_id)
            if g.user['role'] == rt.ANALYST and current['assigned_analyst_id'] != g.user['id']:
                raise rt.APIError('Assignment changed concurrently; reload and retry', 409)
            note_id = insert('investigation_notes', dict(data, incident_id=incident_id,
                analyst_id=g.user['id'], creation_timestamp=rt.now()))
        return rt.ok(rt.fetch('investigation_notes', note_id), 201)
