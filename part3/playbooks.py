"""Ordered response steps with append-only execution snapshots."""
from flask import g
from common import runtime as rt
from part3.support import active_user, insert, requested, rows, strings

STATES = ('Pending', 'In Progress', 'Completed')


class PlaybookService:
    def detail(self, playbook_id):
        record = rt.fetch('playbooks', playbook_id)
        record['actions'] = rows('SELECT * FROM response_actions WHERE playbook_id=? ORDER BY step_number', (playbook_id,))
        for action in record['actions']:
            action['history'] = rows('SELECT * FROM action_history WHERE action_id=? ORDER BY id', (action['id'],))
        return record

    def history(self, action_id):
        action = rt.fetch('response_actions', action_id)
        insert('action_history', {'action_id': action_id, 'status': action['status'],
            'assigned_user_id': action['assigned_user_id'], 'changed_by': g.user['id'], 'timestamp': rt.now()})


def register(app, prefix):
    service, base = PlaybookService(), prefix + '/playbooks'

    @app.post(base)
    @rt.protected(rt.ADMIN)
    def playbooks_create():
        keys = ('name', 'description', 'incident_category', 'severity')
        data = rt.body(keys, keys)
        strings(data, keys)
        rt.choice(data, 'severity', rt.LEVELS)
        requested('playbooks:create', 'Create playbook')
        with rt.db():
            record_id = insert('playbooks', dict(data, created_by=g.user['id'], creation_date=rt.now()))
        return rt.ok(service.detail(record_id), 201)

    @app.get(base)
    @rt.protected(rt.ADMIN, rt.ANALYST, rt.AUDITOR)
    def playbooks_list():
        return rt.ok(rows('SELECT * FROM playbooks ORDER BY id'))

    @app.get(base + '/<int:playbook_id>')
    @rt.protected(rt.ADMIN, rt.ANALYST, rt.AUDITOR)
    def playbooks_detail(playbook_id):
        return rt.ok(service.detail(playbook_id))

    @app.post(base + '/<int:playbook_id>/actions')
    @rt.protected(rt.ADMIN, rt.ANALYST)
    def playbooks_add_action(playbook_id):
        rt.fetch('playbooks', playbook_id)
        data = rt.body(('description', 'step_number'), ('description', 'step_number', 'assigned_user_id'))
        strings(data, ('description',))
        rt.positive_id(data['step_number'], 'step_number')
        if 'assigned_user_id' in data:
            active_user(data['assigned_user_id'])
        requested('playbooks:action create', f'Add step {data["step_number"]} to playbook {playbook_id}')
        with rt.db():
            rt.db().execute('BEGIN IMMEDIATE')
            # Append-only ordering after execution begins avoids inserting an
            # unfinished prerequisite behind a step that already ran.
            last = rt.db().execute('SELECT MAX(step_number) FROM response_actions WHERE playbook_id=?', (playbook_id,)).fetchone()[0]
            if last is not None and data['step_number'] <= last:
                raise rt.APIError('New steps must have a unique number greater than all existing steps', 409)
            action_id = insert('response_actions', dict(data, playbook_id=playbook_id, status='Pending'))
            service.history(action_id)
        return rt.ok(rt.fetch('response_actions', action_id), 201)

    @app.put(prefix + '/actions/<int:action_id>/status')
    @rt.protected(rt.ADMIN, rt.ANALYST)
    def playbooks_action_status(action_id):
        initial = rt.fetch('response_actions', action_id)
        data = rt.body(allowed=('status', 'assigned_user_id'))
        rt.choice(data, 'status', STATES)
        assigned_id = data.get('assigned_user_id', initial['assigned_user_id'])
        if assigned_id is not None:
            active_user(assigned_id)
        requested('playbooks:action update', f'Update action {action_id}: {data}')
        with rt.db():
            rt.db().execute('BEGIN IMMEDIATE')
            old = rt.fetch('response_actions', action_id)
            if old != initial:
                raise rt.APIError('Action changed concurrently; reload and retry', 409)
            if old['status'] == 'Completed':
                raise rt.APIError('Completed actions are immutable', 409)
            status = data.get('status', old['status'])
            assigned = data.get('assigned_user_id', old['assigned_user_id'])
            if status == old['status'] and assigned == old['assigned_user_id']:
                raise rt.APIError('No action change supplied')
            if status != old['status'] and status != STATES[STATES.index(old['status']) + 1]:
                raise rt.APIError('Actions must advance Pending -> In Progress -> Completed')
            if status != 'Pending':
                if assigned is None:
                    raise rt.APIError('Assign an Active user before execution')
                if rt.db().execute('SELECT 1 FROM response_actions WHERE playbook_id=? AND step_number<? AND status<>?',
                        (old['playbook_id'], old['step_number'], 'Completed')).fetchone():
                    raise rt.APIError('Complete all earlier steps before executing this action', 409)
            rt.db().execute('UPDATE response_actions SET status=?,assigned_user_id=?,completion_date=? WHERE id=?',
                (status, assigned, rt.now() if status == 'Completed' else None, action_id))
            service.history(action_id)
        return rt.ok(rt.fetch('response_actions', action_id))

    @app.delete(base + '/<int:playbook_id>')
    @rt.protected(rt.ADMIN)
    def playbooks_delete(playbook_id):
        rt.fetch('playbooks', playbook_id)
        requested('playbooks:delete', f'Delete playbook {playbook_id} and cascade actions/history')
        with rt.db():
            rt.db().execute('DELETE FROM playbooks WHERE id=?', (playbook_id,))
        return rt.ok({'id': playbook_id, 'message': 'Playbook deleted'})
