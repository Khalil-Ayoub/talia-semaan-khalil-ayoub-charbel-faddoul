"""Isolated tests: real Part 1 routes/SQLite, explicit doubles for missing teammates.

These tests are not Postman evidence and do not verify Part 2 authentication.
"""
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from common.runtime import ADMIN, ANALYST, AUDITOR, EMPLOYEE, db, now, prefix
from part1.app import create_app


class Reply:
    def __init__(self, data, code=200):
        self.status_code = code
        self.data = data
    def json(self):
        return self.data


class Part1Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {'PROJECT_DB': str(Path(self.temp.name)/'test.db'), 'SERVICE_SECRET':'test-only-secret'})
        self.env.start()
        self.apps = {name:create_app(name) for name in ('assets','threats','vulnerabilities')}
        self.clients = {name:app.test_client() for name, app in self.apps.items()}
        self.events = []
        self.notifications = []
        self.users = {
            'admin': {'id':1,'role':ADMIN}, 'analyst':{'id':2,'role':ANALYST},
            'employee':{'id':3,'role':EMPLOYEE}, 'auditor':{'id':4,'role':AUDITOR}
        }
        with self.apps['assets'].app_context():
            for username, user in self.users.items():
                db().execute('INSERT INTO users (id,full_name,username,email,password_hash,department,role,created_date) VALUES (?,?,?,?,?,?,?,?)',
                    (user['id'], username, username, username+'@example.test', 'TEST FIXTURE NOT A PASSWORD', 'IT', user['role'], now()))
            db().commit()
        self.network = patch('common.runtime.requests.request', side_effect=self.outbound)
        self.network.start()

    def tearDown(self):
        self.network.stop()
        self.env.stop()
        self.temp.cleanup()

    def outbound(self, method, url, json=None, headers=None, timeout=None):
        if '/internal/verify' in url:
            user = self.users.get(json['token'])
            return Reply({'data':user} if user else {'message':'Invalid or expired token'}, 200 if user else 401)
        if '/internal/logs' in url:
            self.events.append(json)
            return Reply({'data':{'id':len(self.events)}})
        if '/internal/notifications' in url:
            self.notifications.append(json)
            return Reply({'data':{'id':len(self.notifications)}})
        if '/users/id/' in url:
            uid = int(url.rsplit('/',1)[1])
            user = next((u for u in self.users.values() if u['id']==uid), None)
            return Reply({'data':user} if user else {'message':'User not found'}, 200 if user else 404)
        if '/assets/' in url:
            response = self.clients['assets'].open(prefix('part1')+'/assets/'+url.rsplit('/',1)[1], method=method, headers=headers)
            return Reply(response.get_json(), response.status_code)
        raise AssertionError('Unexpected HTTP dependency: '+url)

    def req(self, service, method='GET', path='', data=None, role='admin', query=None):
        headers = {'Authorization':'Bearer '+role} if role else {}
        return self.clients[service].open(prefix('part1')+'/'+service+path, method=method, json=data, headers=headers, query_string=query)

    def asset(self, **changes):
        data = dict(asset_name='Lab Server',asset_type='Server',ip_address='192.0.2.10',department='IT',owner_id=3,criticality_level='High')
        data.update(changes)
        response = self.req('assets','POST',data=data)
        self.assertEqual(response.status_code,201,response.get_json())
        return response.get_json()['data']['id']

    def threat(self, **changes):
        data = dict(threat_type='Domain',threat_value='example.test',description='Lab indicator',severity='High',source='Local test')
        data.update(changes)
        return self.req('threats','POST',data=data)

    def vuln(self, asset_id, **changes):
        data = dict(title='Lab vulnerability',description='Lab only',cve_identifier='CVE-2026-12345',cvss_score=8.1,severity='High',asset_id=asset_id,discovery_source='Local test')
        data.update(changes)
        return self.req('vulnerabilities','POST',data=data)

    def test_asset_crud_history_and_search(self):
        aid = self.asset()
        self.assertEqual(len(self.req('assets').json['data']),1)
        self.assertEqual(self.req('assets',path=f'/{aid}').json['data']['status'],'Active')
        self.assertEqual(self.req('assets','PUT',f'/{aid}',{'status':'Under Maintenance'}).status_code,200)
        history = self.req('assets',path=f'/{aid}/history').json['data']
        self.assertEqual([h['action'] for h in history],['Created','Updated'])
        self.assertEqual(history[0]['snapshot']['status'],'Active')
        self.assertEqual(len(self.req('assets',path='/search',query={'department':'IT','criticality_level':'High'}).json['data']),1)
        self.assertEqual(self.req('assets','DELETE',f'/{aid}').status_code,200)
        self.assertEqual(self.req('assets',path=f'/{aid}').status_code,404)

    def test_asset_invalid_formats_and_types(self):
        base = dict(asset_name='X',asset_type='Server',ip_address='bad',department='IT',owner_id=3,criticality_level='High')
        for key, value in [('ip_address','bad'),('owner_id',True),('asset_type','Unknown'),('criticality_level','Extreme'),('status','Broken')]:
            with self.subTest(key=key):
                data = dict(base,ip_address='192.0.2.1')
                data[key] = value
                self.assertEqual(self.req('assets','POST',data=data).status_code,400)

    def test_missing_owner_is_rejected(self):
        data = dict(asset_name='X',asset_type='Server',ip_address='192.0.2.1',department='IT',owner_id=999,criticality_level='Low')
        self.assertEqual(self.req('assets','POST',data=data).status_code,404)

    def test_roles_and_denied_audit(self):
        for service in self.clients:
            self.assertEqual(self.req(service,role='employee').status_code,403)
        self.assertEqual(self.req('assets',role='analyst').status_code,403)
        self.assertEqual(self.req('assets',role='auditor').status_code,200)
        self.assertTrue(any(e['action']=='Unauthorized access' for e in self.events))

    def test_missing_and_bad_tokens(self):
        self.assertEqual(self.req('assets',role=None).status_code,401)
        self.assertEqual(self.req('assets',role='invalid').status_code,401)

    def test_analyst_asset_scope(self):
        aid = self.asset()
        self.assertEqual(self.req('assets',path=f'/{aid}',role='analyst').status_code,403)
        self.assertEqual(self.req('assets',path='/search',role='analyst').json['data'],[])
        with self.apps['assets'].app_context():
            db().execute('INSERT INTO incidents (title,description,category,severity,reporter_id,asset_id,assigned_analyst_id,creation_date) VALUES (?,?,?,?,?,?,?,?)',
                ('Test','Test','Malware','High',3,aid,2,now()))
            db().commit()
        self.assertEqual(self.req('assets',path=f'/{aid}',role='analyst').status_code,200)
        self.assertEqual(len(self.req('assets',path='/search',role='analyst').json['data']),1)

    def test_threat_duplicate_normalization(self):
        self.assertEqual(self.threat(threat_value='EXAMPLE.TEST.').status_code,201)
        self.assertEqual(self.threat().status_code,409)
        self.assertEqual(len(self.notifications),1)

    def test_threat_indicator_validation(self):
        for kind, value in [('Domain','-bad.test'),('IP Address','999.1.1.1'),('File Hash','not-a-hash')]:
            self.assertEqual(self.threat(threat_type=kind,threat_value=value).status_code,400)
        self.assertEqual(self.threat(threat_type='File Hash',threat_value='a'*64).status_code,201)
        self.assertEqual(self.threat(threat_type='IP Address',threat_value='2001:db8::1').status_code,201)

    def test_threat_update_search_and_delete(self):
        tid = self.threat().json['data']['id']
        self.assertEqual(self.req('threats','PUT',f'/{tid}',{'severity':'Critical'}).status_code,200)
        self.assertEqual(len(self.req('threats',path='/search',query={'severity':'Critical'},role='auditor').json['data']),1)
        self.assertEqual(self.req('threats','DELETE',f'/{tid}',role='analyst').status_code,403)
        self.assertEqual(self.req('threats','DELETE',f'/{tid}').status_code,200)

    def test_vulnerability_lifecycle_and_dates(self):
        aid = self.asset()
        response = self.vuln(aid)
        self.assertEqual(response.status_code,201,response.json)
        vid = response.json['data']['id']
        self.assertEqual(self.notifications[-1]['user_id'],3)
        self.assertEqual(self.req('vulnerabilities','PUT',f'/{vid}',{'status':'Closed'},role='analyst').status_code,400)
        for status in ('Under Investigation','In Progress','Resolved','Closed'):
            response = self.req('vulnerabilities','PUT',f'/{vid}',{'status':status},role='analyst')
            self.assertEqual(response.status_code,200,response.json)
            if status in ('Resolved','Closed'):
                self.assertIsNotNone(response.json['data']['resolution_date'])
        self.assertEqual(self.req('vulnerabilities','PUT',f'/{vid}',{'resolution_date':None}).status_code,400)

    def test_vulnerability_score_cve_and_reference(self):
        aid = self.asset()
        for changes in ({'cvss_score':11},{'cvss_score':True},{'cvss_score':'8.0'},{'cve_identifier':'bad'},{'status':'Resolved'}):
            self.assertEqual(self.vuln(aid,**changes).status_code,400)
        self.assertEqual(self.vuln(999).status_code,404)

    def test_foreign_keys_prevent_asset_deletion(self):
        aid = self.asset()
        self.assertEqual(self.vuln(aid).status_code,201)
        self.assertEqual(self.req('assets','DELETE',f'/{aid}').status_code,409)
        self.assertEqual(self.req('assets',path=f'/{aid}').status_code,200)

    def test_injection_and_unknown_fields(self):
        self.asset()
        response = self.req('assets',path='/search',query={'asset_name':"' OR 1=1 --"})
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json['data'],[])
        self.assertEqual(self.req('assets','PUT','/1',{'role':ADMIN}).status_code,400)
        self.assertEqual(self.req('assets',path='/search',query={'unsupported':'x'}).status_code,400)
        self.assertEqual(self.req('assets','POST',data={}).status_code,400)

    def test_dependency_failure_does_not_write(self):
        import requests
        with patch('common.runtime.requests.request',side_effect=requests.ConnectionError('offline')):
            response = self.req('assets','POST',data={'asset_name':'Test'})
            self.assertEqual(response.status_code,503)
        self.assertEqual(self.req('assets').json['data'],[])

    def test_audit_outage_prevents_mutation(self):
        original = self.outbound
        def failing(method,url,**kwargs):
            if '/internal/logs' in url:
                return Reply({'message':'Audit unavailable'},503)
            return original(method,url,**kwargs)
        with patch('common.runtime.requests.request',side_effect=failing):
            self.assertEqual(self.threat().status_code,503)
        self.assertEqual(self.req('threats').json['data'],[])

    def test_notification_outage_is_explicit(self):
        original = self.outbound
        def failing(method,url,**kwargs):
            if '/internal/notifications' in url:
                return Reply({'message':'Notification unavailable'},503)
            return original(method,url,**kwargs)
        with patch('common.runtime.requests.request',side_effect=failing):
            response = self.threat()
        self.assertEqual(response.status_code,201)
        self.assertIn('notification_warning',response.json['data'])
        self.assertEqual(len(self.req('threats').json['data']),1)

    def test_log_database_protection(self):
        with self.apps['assets'].app_context():
            db().execute('INSERT INTO logs (user_id,action,description,timestamp,severity,related_service) VALUES (?,?,?,?,?,?)',
                (1,'Test','Test',now(),'Information','assets'))
            db().commit()
            with self.assertRaises(sqlite3.IntegrityError):
                db().execute("UPDATE logs SET description='changed'")
            db().rollback()

    def test_internal_asset_helper_requires_service_secret(self):
        aid = self.asset()
        path = prefix('part1') + f'/internal/assets/{aid}'
        client = self.clients['assets']
        self.assertEqual(client.get(path).status_code,401)
        self.assertEqual(client.get(path,headers={'X-Service-Key':'wrong'}).status_code,401)
        response = client.get(path,headers={'X-Service-Key':'test-only-secret'})
        self.assertEqual(response.status_code,200)
        self.assertEqual(set(response.json['data']),{'id','status','owner_id'})
        self.assertEqual(client.get(prefix('part1')+'/internal/assets/999',headers={'X-Service-Key':'test-only-secret'}).status_code,404)

    def test_read_only_and_analyst_write_boundaries(self):
        aid = self.asset()
        tid = self.threat().json['data']['id']
        vid = self.vuln(aid).json['data']['id']
        for service, record_id, update in [('assets',aid,{'status':'Inactive'}),('threats',tid,{'severity':'Low'}),('vulnerabilities',vid,{'severity':'Low'})]:
            self.assertEqual(self.req(service,'PUT',f'/{record_id}',update,role='auditor').status_code,403)
            self.assertEqual(self.req(service,'DELETE',f'/{record_id}',role='auditor').status_code,403)
        self.assertEqual(self.req('assets','PUT',f'/{aid}',{'status':'Inactive'},role='analyst').status_code,403)
        self.assertEqual(self.req('threats','PUT',f'/{tid}',{'severity':'Low'},role='analyst').status_code,403)
        self.assertEqual(self.req('vulnerabilities','PUT',f'/{vid}',{'severity':'Low'},role='analyst').status_code,200)


if __name__ == '__main__':
    unittest.main()
