"""Isolated tests: REAL SQLite and HTTP, explicitly DOUBLED teammate services.

These results are development checks, never submitted implementation evidence.
Run: python -m unittest discover -s tests -p test_part3.py -v
"""
import os
import logging
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from flask import Flask, jsonify, request
from werkzeug.serving import make_server
from common import runtime as rt
from part3.app import create_app


class Part3Tests(unittest.TestCase):
    def setUp(self):
        logging.getLogger('werkzeug').setLevel(logging.ERROR)
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name) / 'test.db')
        self.env = patch.dict(os.environ, {'PROJECT_DB': self.path, 'SERVICE_SECRET': 'isolated-test-secret',
            'PART3_LOGIN_SUCCESS_ACTION': 'Login successful', 'PART3_LOGIN_FAILURE_ACTION': 'Login failed'})
        self.env.start()
        self.clients = {s: create_app(s).test_client() for s in ('incidents', 'reports', 'playbooks')}
        self.users = {i: {'id': i, 'full_name': f'Test User {i}', 'role': role, 'account_status': 'Active'}
            for i, role in enumerate((rt.ADMIN, rt.ANALYST, rt.EMPLOYEE, rt.AUDITOR, rt.ANALYST, rt.EMPLOYEE), 1)}
        with self.connection() as conn:
            for user in self.users.values():
                conn.execute('INSERT INTO users(id,full_name,username,email,password_hash,department,role,account_status,created_date) VALUES(?,?,?,?,?,?,?,?,?)',
                    (user['id'], user['full_name'], f'u{user["id"]}', f'u{user["id"]}@example.test', 'TEST-NOT-A-LOGIN', 'Lab', user['role'], 'Active', rt.now()))
            conn.execute("INSERT INTO assets VALUES(1,'Lab server','Server','127.0.0.1',NULL,3,'Lab',NULL,'Critical','Active')")
        self.down = set()
        self.fail_notification = False
        self.calls = []
        double = Flask('EXPLICIT TEAMMATE DOUBLE')

        @double.route('/<service>/<path:path>', methods=['GET', 'POST'])
        def dependency(service, path):
            self.calls.append((service, path, request.headers.get('Authorization'), request.headers.get('X-Service-Key')))
            if service in self.down:
                return jsonify(status='error', message='Test dependency unavailable'), 503
            if path.startswith('internal/'):
                if request.headers.get('X-Service-Key') != 'isolated-test-secret':
                    return jsonify(status='error', message='Invalid test service key'), 401
            if path == 'internal/verify':
                token = request.json.get('token', '')
                if not token.isdigit() or int(token) not in self.users:
                    return jsonify(status='error', message='Invalid test token'), 401
                user = self.users[int(token)]
                if user['account_status'] != 'Active':
                    return jsonify(status='error', message='Inactive test account'), 401
                return jsonify(status='success', data=user)
            with self.connection() as conn:
                if path == 'internal/logs':
                    data = request.json
                    conn.execute('INSERT INTO logs(user_id,action,description,timestamp,severity,related_service) VALUES(?,?,?,?,?,?)',
                        (data['user_id'], data['action'], data['description'], rt.now(), data['severity'], data['related_service']))
                    return jsonify(status='success', data={'saved': True}), 201
                if path == 'internal/notifications':
                    if self.fail_notification:
                        return jsonify(status='error', message='Test notification unavailable'), 503
                    data = request.json
                    conn.execute('INSERT INTO notifications(user_id,title,message,notification_type,severity,creation_date) VALUES(?,?,?,?,?,?)',
                        (data['user_id'], data['title'], data['message'], data['notification_type'], data['severity'], rt.now()))
                    return jsonify(status='success', data={'saved': True}), 201
                if path == 'internal/assets/1':
                    return jsonify(status='success', data={'id': 1, 'owner_id': 3, 'status': 'Active'})
                if path.startswith('users/id/') or path.startswith('internal/users/'):
                    uid = int(path.rsplit('/', 1)[1])
                    if uid in self.users:
                        return jsonify(status='success', data=self.users[uid])
                if path in ('users', 'assets', 'incidents', 'threats', 'vulnerabilities', 'logs'):
                    return jsonify(status='success', data=[dict(r) for r in conn.execute('SELECT * FROM ' + path)])
            return jsonify(status='error', message='Test record not found'), 404

        self.server = make_server('127.0.0.1', 0, double, threaded=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.urls = patch.object(rt, 'url', side_effect=lambda service, path='': f'http://127.0.0.1:{self.server.server_port}/{service}{path}')
        self.urls.start()

    def tearDown(self):
        self.urls.stop()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.env.stop()
        self.temp.cleanup()

    def connection(self):
        conn = sqlite3.connect(self.path, timeout=1)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys=ON')
        # Return a context manager that also closes the connection on Windows.
        from contextlib import contextmanager
        @contextmanager
        def connection():
            try:
                with conn:
                    yield conn
            finally:
                conn.close()
        return connection()

    def req(self, service, method, path, user=1, data=None, code=200):
        headers = {'Authorization': 'Bearer ' + str(user)} if user is not None else {}
        response = self.clients[service].open('/charbel-faddoul' + path, method=method, headers=headers, json=data)
        self.assertEqual(response.status_code, code, response.get_json())
        return response.get_json().get('data')

    def incident(self, user=3, **changes):
        data = dict(title='Suspicious login', description='Unexpected access', category='Unauthorized access', severity='High', asset_id=1)
        data.update(changes)
        return self.req('incidents', 'POST', '/incidents', user, data, 201)

    def playbook(self):
        return self.req('playbooks', 'POST', '/playbooks', data=dict(name='Contain access', description='Ordered procedure', incident_category='Unauthorized access', severity='High'), code=201)

    def action(self, pid, step):
        return self.req('playbooks', 'POST', f'/playbooks/{pid}/actions', data=dict(description=f'Step {step}', step_number=step, assigned_user_id=2), code=201)

    def test_incident_lifecycle_ownership_and_notes(self):
        record = self.incident(title="Literal SQL '); DROP TABLE users;--")
        iid = record['id']
        self.assertEqual(record['reporter_id'], 3)
        self.req('incidents', 'GET', f'/incidents/{iid}', 6, code=403)
        self.req('incidents', 'GET', f'/incidents/{iid}', 2, code=403)
        self.req('incidents', 'PUT', f'/incidents/{iid}/assign', 3, {'assigned_analyst_id': 2}, 403)
        self.req('incidents', 'PUT', f'/incidents/{iid}/assign', data={'assigned_analyst_id': 3}, code=400)
        self.req('incidents', 'PUT', f'/incidents/{iid}/assign', data={'assigned_analyst_id': 2})
        self.assertEqual(len(self.req('incidents', 'GET', '/incidents/assigned', 2)), 1)
        self.assertEqual(len(self.req('incidents', 'GET', '/incidents/mine', 3)), 1)
        self.req('incidents', 'PUT', f'/incidents/{iid}/status', 2, {'status': 'Closed'}, 400)
        self.req('incidents', 'PUT', f'/incidents/{iid}/status', 3, {'status': 'Under Investigation'}, 403)
        note = self.req('incidents', 'POST', f'/incidents/{iid}/notes', 2, {'note_content': 'Checked access logs'}, 201)
        self.assertEqual(note['analyst_id'], 2)
        resolved = None
        for status in ('Under Investigation', 'Mitigated', 'Resolved', 'Closed'):
            result = self.req('incidents', 'PUT', f'/incidents/{iid}/status', 2, {'status': status})
            if status == 'Resolved':
                resolved = result['resolution_date']
            if status == 'Closed':
                self.assertEqual(result['resolution_date'], resolved)
        self.assertTrue(resolved)
        self.assertEqual(len(result['notes']), 1)
        self.req('incidents', 'PUT', f'/incidents/{iid}/status', 2, {'status': 'Open'}, 400)
        with self.connection() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM notifications').fetchone()[0], 1)
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM users').fetchone()[0], 6)
            self.assertTrue(conn.execute("SELECT COUNT(*) FROM logs WHERE action='Unauthorized access'").fetchone()[0])

    def test_validation_auth_and_dependencies(self):
        self.req('incidents', 'GET', '/incidents', None, code=401)
        self.req('incidents', 'GET', '/incidents', 'bad-token', code=401)
        self.req('incidents', 'GET', '/incidents/999', code=404)
        for changes in ({'severity': 'Urgent'}, {'asset_id': True}, {'title': []}, {'unknown': 1}):
            data = dict(title='x', description='x', category='x', severity='Low', asset_id=1)
            data.update(changes)
            self.req('incidents', 'POST', '/incidents', 3, data, 400)
        self.req('incidents', 'POST', '/incidents', 3, dict(title='x', description='x', category='x', severity='Low', asset_id=1, reporter_id=6), 403)
        self.down.add('assets')
        self.req('incidents', 'POST', '/incidents', 3, dict(title='x', description='x', category='x', severity='Low', asset_id=1), 503)
        self.down.clear()
        iid = self.incident()['id']
        self.fail_notification = True
        result = self.req('incidents', 'PUT', f'/incidents/{iid}/assign', data={'assigned_analyst_id': 2})
        self.assertIn('notification_warning', result)
        self.assertEqual(result['assigned_analyst_id'], 2)
        self.users[2]['account_status'] = 'Suspended'
        self.req('incidents', 'PUT', f'/incidents/{iid}/assign', data={'assigned_analyst_id': 2}, code=400)
        self.req('incidents', 'GET', f'/incidents/{iid}', 2, code=401)
        self.down.add('logs')
        self.req('incidents', 'POST', '/incidents', 3, dict(title='x', description='x', category='x', severity='Low', asset_id=1), 503)
        with self.connection() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM incidents').fetchone()[0], 1)

    def test_playbook_order_history_and_cascade(self):
        pid = self.playbook()['id']
        first, second = self.action(pid, 1), self.action(pid, 2)
        self.req('playbooks', 'PUT', f'/actions/{second["id"]}/status', 2, {'status': 'In Progress'}, 409)
        self.req('playbooks', 'PUT', f'/actions/{first["id"]}/status', 2, {'status': 'Completed'}, 400)
        for action in (first, second):
            for status in ('In Progress', 'Completed'):
                result = self.req('playbooks', 'PUT', f'/actions/{action["id"]}/status', 2, {'status': status})
            self.assertTrue(result['completion_date'])
        detail = self.req('playbooks', 'GET', f'/playbooks/{pid}', 4)
        self.assertEqual([a['step_number'] for a in detail['actions']], [1, 2])
        self.assertEqual([h['status'] for h in detail['actions'][0]['history']], ['Pending', 'In Progress', 'Completed'])
        self.req('playbooks', 'PUT', f'/actions/{first["id"]}/status', data={'assigned_user_id': 1}, code=409)
        self.req('playbooks', 'POST', f'/playbooks/{pid}/actions', data={'description': 'Duplicate', 'step_number': 1}, code=409)
        self.req('playbooks', 'DELETE', f'/playbooks/{pid}', 2, code=403)
        self.req('playbooks', 'DELETE', f'/playbooks/{pid}')
        self.req('playbooks', 'GET', f'/playbooks/{pid}', code=404)
        with self.connection() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM action_history').fetchone()[0], 0)
            self.assertEqual(conn.execute('PRAGMA foreign_key_check').fetchall(), [])

    def test_playbook_permissions_and_validation(self):
        pid = self.playbook()['id']
        self.req('playbooks', 'GET', '/playbooks', 3, code=403)
        self.req('playbooks', 'POST', '/playbooks', 2, {'name': 'x'}, 403)
        self.req('playbooks', 'POST', f'/playbooks/{pid}/actions', 4, {'description': 'x', 'step_number': 1}, 403)
        for step in (0, -1, True, '1'):
            self.req('playbooks', 'POST', f'/playbooks/{pid}/actions', data={'description': 'x', 'step_number': step}, code=400)
        action = self.req('playbooks', 'POST', f'/playbooks/{pid}/actions', 2, {'description': 'x', 'step_number': 1, 'assigned_user_id': 2}, 201)
        self.req('playbooks', 'PUT', f'/actions/{action["id"]}/status', 2, {'assigned_user_id': 5})
        self.req('playbooks', 'PUT', f'/actions/{action["id"]}/status', 2, {'completion_date': 'client time'}, 400)
        self.req('playbooks', 'PUT', f'/actions/{action["id"]}/status', 2, {'status': 'In Progress'})

    def test_reports_match_real_records_over_http(self):
        for severity in rt.LEVELS:
            self.incident(severity=severity)
        with self.connection() as conn:
            for i, level in enumerate(('High', 'Critical'), 1):
                conn.execute('INSERT INTO threats VALUES(?,?,?,?,?,?,?)', (i, 'Domain', f'test{i}.example', 'test', level, 'Lab', rt.now()))
                conn.execute('INSERT INTO vulnerabilities(id,title,description,cve_identifier,cvss_score,severity,asset_id,discovery_source,status,creation_date) VALUES(?,?,?,?,?,?,?,?,?,?)',
                    (i, 'Test', 'Test', f'CVE-2026-100{i}', 8.0, level, 1, 'Lab', 'Open', rt.now()))
            for action in ('Login successful', 'Login failed', 'Login failed', 'Login attempt'):
                conn.execute('INSERT INTO logs(user_id,action,description,timestamp,severity,related_service) VALUES(?,?,?,?,?,?)', (1, action, 'Isolated test activity', rt.now(), 'Information', 'users'))
        report = self.req('reports', 'GET', '/reports/incidents', 4)
        self.assertEqual(report['total'], 4)
        self.assertEqual(report['by_severity'], {s: 1 for s in rt.LEVELS})
        self.assertEqual(report['by_status'], {'Open': 4})
        self.assertEqual(self.req('reports', 'GET', '/reports/assets')['critical'], 1)
        for kind in ('threats', 'vulnerabilities'):
            report = self.req('reports', 'GET', '/reports/' + kind)
            self.assertEqual(report['total'], 2)
            self.assertEqual(report['by_severity'], {'Critical': 1, 'High': 1})
        activity = self.req('reports', 'GET', '/reports/activity')
        self.assertEqual(activity['login_attempts'], 3)
        self.assertEqual(activity['failed_logins'], 2)
        with self.connection() as conn:
            self.assertEqual(activity['total'], conn.execute('SELECT COUNT(*) FROM logs').fetchone()[0])
        summary = self.req('reports', 'GET', '/reports/summary')
        self.assertEqual((summary['users'], summary['incidents'], summary['threats']), (6, 4, 2))
        self.assertTrue(any(s == 'assets' and p == 'assets' and auth == 'Bearer 1' and key is None for s, p, auth, key in self.calls))

    def test_reports_empty_denied_and_outages(self):
        for kind in ('summary', 'incidents', 'assets', 'threats', 'vulnerabilities', 'activity'):
            for user in (2, 3):
                self.req('reports', 'GET', '/reports/' + kind, user, code=403)
            self.req('reports', 'GET', '/reports/' + kind, 4)
        self.assertEqual(self.req('reports', 'GET', '/reports/threats')['by_severity'], {})
        self.down.add('threats')
        self.req('reports', 'GET', '/reports/summary', code=503)
        self.req('reports', 'GET', '/reports/threats', code=503)
        with patch.dict(os.environ, {'PART3_LOGIN_SUCCESS_ACTION': ''}):
            self.req('reports', 'GET', '/reports/activity', code=503)

    def test_physical_foreign_keys_and_prefixed_routes(self):
        for client in self.clients.values():
            self.assertTrue(all(rule.rule.startswith('/charbel-faddoul/') for rule in client.application.url_map.iter_rules()))
        with self.connection() as conn:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("INSERT INTO incidents(title,description,category,severity,reporter_id,asset_id,creation_date) VALUES('x','x','x','Low',999,1,'test')")


if __name__ == '__main__':
    unittest.main()
