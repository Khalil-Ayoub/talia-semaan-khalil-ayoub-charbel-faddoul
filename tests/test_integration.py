"""All nine real applications, real HTTP and a temporary canonical database."""
import contextlib
import io
import logging
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import requests
from werkzeug.serving import make_server

from common import runtime as rt
from part1.app import create_app as part1
from part2.app import create_app as part2
from part2.bootstrap_admin import main as bootstrap
from part3.app import create_app as part3


class FullSystemTests(unittest.TestCase):
    def test_nine_services_over_http(self):
        logging.getLogger('werkzeug').setLevel(logging.ERROR)
        with tempfile.TemporaryDirectory() as temporary:
            settings = {'PROJECT_DB': str(Path(temporary) / 'integration.db'),
                        'SERVICE_SECRET': 'integration-only-service-secret-at-least-32-characters',
                        'BOOTSTRAP_ADMIN_PASSWORD': 'integration-only-password'}
            with patch.dict(os.environ, settings):
                self.run_system()

    def run_system(self):
        apps = {name: factory(name) for factory, names in (
            (part1, ('assets', 'threats', 'vulnerabilities')),
            (part2, ('users', 'logs', 'notifications')),
            (part3, ('incidents', 'reports', 'playbooks'))) for name in names}
        servers = {name: make_server('127.0.0.1', 0, app, threaded=True) for name, app in apps.items()}
        threads = []
        ports = rt.CONFIG['ports'].copy()
        try:
            for name, server in servers.items():
                rt.CONFIG['ports'][name] = server.server_port
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                threads.append(thread)
            arguments = ['bootstrap', '--full-name', 'Integration Admin', '--username', 'admin',
                         '--email', 'admin@example.test', '--department', 'Security']
            # Environment/argv select a temporary test configuration; no service
            # implementations, HTTP calls or authentication checks are replaced.
            with patch.object(sys, 'argv', arguments), contextlib.redirect_stdout(io.StringIO()):
                bootstrap()

            def request(service, method, path, data=None, token=None, expected=200, internal=False):
                headers = {'Authorization': 'Bearer ' + token} if token else {}
                if internal:
                    headers['X-Service-Key'] = os.environ['SERVICE_SECRET']
                response = requests.request(method, rt.url(service, path), json=data, headers=headers, timeout=10)
                self.assertEqual(response.status_code, expected, (service, path, response.text))
                result = response.json()
                self.assertEqual(result['status'], 'success' if expected < 400 else 'error')
                return result.get('data', result)

            def login(username, password='integration-only-password', expected=200):
                return request('users', 'POST', '/users/login', {'username': username, 'password': password}, expected=expected)

            admin = login('admin')['token']
            login('admin', 'incorrect-password', 401)
            accounts = {}
            for username, role in (('analyst', rt.ANALYST), ('analyst2', rt.ANALYST),
                                   ('employee', rt.EMPLOYEE), ('other', rt.EMPLOYEE), ('auditor', rt.AUDITOR)):
                account = request('users', 'POST', '/users/register', {
                    'full_name': username, 'username': username, 'email': username + '@example.test',
                    'password': 'integration-only-password', 'department': 'IT', 'role': role
                }, token=admin, expected=201)
                self.assertNotIn('password_hash', account)
                accounts[username] = (account['id'], login(username)['token'])
            employee_id, employee = accounts['employee']
            analyst_id, analyst = accounts['analyst']
            analyst2_id, analyst2 = accounts['analyst2']
            _, auditor = accounts['auditor']

            asset = request('assets', 'POST', '/assets', {
                'asset_name': 'Integration server', 'asset_type': 'Server', 'ip_address': '192.0.2.10',
                'department': 'IT', 'owner_id': employee_id, 'criticality_level': 'Critical'
            }, token=admin, expected=201)
            aid = asset['id']
            request('assets', 'GET', f'/assets/{aid}', token=employee, expected=403)
            request('assets', 'PUT', f'/assets/{aid}', {'status': 'Under Maintenance'}, token=admin)
            self.assertEqual(len(request('assets', 'GET', f'/assets/{aid}/history', token=auditor)), 2)
            request('assets', 'GET', '/assets', expected=401)
            request('assets', 'GET', '/assets', token='invalid', expected=401)
            request('assets', 'GET', '/assets/' + str(10**30), token=admin, expected=400)

            indicator = {'threat_type': 'Domain', 'threat_value': 'example.test',
                         'description': 'Integration indicator', 'severity': 'Critical', 'source': 'Local integration'}
            request('threats', 'POST', '/threats', indicator, token=admin, expected=201)
            request('threats', 'POST', '/threats', indicator, token=admin, expected=409)
            vulnerability = request('vulnerabilities', 'POST', '/vulnerabilities', {
                'title': 'Integration finding', 'description': 'Test finding', 'cve_identifier': 'CVE-2026-12345',
                'cvss_score': 9.1, 'severity': 'Critical', 'asset_id': aid, 'discovery_source': 'Local test'
            }, token=admin, expected=201)
            self.assertNotIn('notification_warning', vulnerability)
            vid = vulnerability['id']
            request('vulnerabilities', 'PUT', f'/vulnerabilities/{vid}', {'status': 'Closed'}, token=analyst, expected=400)
            for status in ('Under Investigation', 'In Progress', 'Resolved', 'Closed'):
                changed = request('vulnerabilities', 'PUT', f'/vulnerabilities/{vid}', {'status': status}, token=analyst)
            self.assertTrue(changed['resolution_date'])

            incident = request('incidents', 'POST', '/incidents', {
                'title': 'Unexpected access', 'description': 'Integration report', 'category': 'Unauthorized access',
                'severity': 'High', 'asset_id': aid
            }, token=employee, expected=201)
            iid = incident['id']
            assigned = request('incidents', 'PUT', f'/incidents/{iid}/assign', {'assigned_analyst_id': analyst_id}, token=admin)
            self.assertNotIn('notification_warning', assigned)
            request('incidents', 'GET', f'/incidents/{iid}', token=accounts['other'][1], expected=403)
            self.assertEqual(len(request('assets', 'GET', '/assets/search', token=analyst)), 1)
            request('assets', 'GET', f'/assets/{aid}', token=analyst2, expected=403)
            request('incidents', 'POST', f'/incidents/{iid}/notes', {'note_content': 'Investigation completed'}, token=analyst, expected=201)
            request('incidents', 'PUT', f'/incidents/{iid}/status', {'status': 'Closed'}, token=analyst, expected=400)
            for status in ('Under Investigation', 'Mitigated', 'Resolved', 'Closed'):
                request('incidents', 'PUT', f'/incidents/{iid}/status', {'status': status}, token=analyst)

            playbook = request('playbooks', 'POST', '/playbooks', {
                'name': 'Contain access', 'description': 'Two steps', 'incident_category': 'Unauthorized access', 'severity': 'High'
            }, token=admin, expected=201)
            pid = playbook['id']
            actions = [request('playbooks', 'POST', f'/playbooks/{pid}/actions', {
                'description': f'Step {step}', 'step_number': step, 'assigned_user_id': analyst2_id
            }, token=analyst, expected=201) for step in (1, 2)]
            request('playbooks', 'POST', f'/playbooks/{pid}/actions', {
                'description': 'Oversized step', 'step_number': 10**30
            }, token=admin, expected=400)
            request('playbooks', 'PUT', f'/actions/{actions[1]["id"]}/status', {'status': 'In Progress'}, token=analyst, expected=409)
            for action in actions:
                for status in ('In Progress', 'Completed'):
                    request('playbooks', 'PUT', f'/actions/{action["id"]}/status', {'status': status}, token=analyst)
            detail = request('playbooks', 'GET', f'/playbooks/{pid}', token=auditor)
            self.assertEqual(len(detail['actions'][0]['history']), 3)

            notifications = request('notifications', 'GET', f'/notifications/user/{employee_id}', token=employee)
            self.assertEqual(notifications[0]['notification_type'], 'Vulnerability Alert')
            nid = notifications[0]['id']
            request('notifications', 'GET', f'/notifications/{nid}', token=analyst, expected=403)
            first_read = request('notifications', 'PUT', f'/notifications/{nid}/read', token=employee)['read_date']
            self.assertEqual(request('notifications', 'PUT', f'/notifications/{nid}/read', token=employee)['read_date'], first_read)
            request('notifications', 'DELETE', f'/notifications/{nid}', token=admin)
            logs = request('logs', 'GET', '/logs', token=auditor)
            labels = {row['action'] for row in logs}
            self.assertTrue({'notification_creation_requested', 'notification_read_requested', 'notification_deletion_requested'} <= labels)
            for kind in ('summary', 'incidents', 'assets', 'threats', 'vulnerabilities', 'activity'):
                report = request('reports', 'GET', '/reports/' + kind, token=auditor)
                if kind == 'activity':
                    self.assertEqual(report['failed_logins'], 1)
                    self.assertEqual(report['login_attempts'], 7)
                    self.assertEqual(report['total'], len(logs))
            request('reports', 'GET', '/reports/summary', token=employee, expected=403)
            request('users', 'GET', f'/internal/users/{analyst2_id}', expected=403)
            request('users', 'GET', f'/internal/users/{analyst2_id}', internal=True)
            request('users', 'PUT', f'/users/{employee_id}/status', {'account_status': 'Suspended'}, token=admin)
            request('incidents', 'GET', '/incidents/mine', token=employee, expected=401)
            request('users', 'PUT', f'/users/{employee_id}/status', {'account_status': 'Active'}, token=admin)
            request('users', 'DELETE', f'/users/{employee_id}', token=admin)
            request('incidents', 'GET', '/incidents/mine', token=employee, expected=401)
            request('assets', 'DELETE', f'/assets/{aid}', token=admin, expected=409)
            with contextlib.closing(sqlite3.connect(os.environ['PROJECT_DB'])) as connection:
                self.assertEqual(connection.execute('PRAGMA foreign_key_check').fetchall(), [])
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute("UPDATE logs SET description='changed'")
                connection.rollback()
        finally:
            for server in servers.values():
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join()
            rt.CONFIG['ports'].update(ports)


if __name__ == '__main__':
    unittest.main()
