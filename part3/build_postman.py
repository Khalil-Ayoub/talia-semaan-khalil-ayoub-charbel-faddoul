"""Rebuild owned Postman artifacts and endpoint table; no requests are executed."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INCIDENT = {'title': 'Unexpected account access', 'description': 'Investigate unexpected access on the selected lab asset',
    'category': 'Unauthorized access', 'severity': 'High', 'asset_id': '{{asset_id}}'}
PLAYBOOK = {'name': 'Account containment', 'description': 'Collect evidence then contain access',
    'incident_category': 'Unauthorized access', 'severity': 'High'}
# Method, path, service, allowed roles, body, expected status, explanation.
ENDPOINTS = [
    ('POST', '/incidents', 'incidents', 'Admin/Employee', INCIDENT, 201, 'Create Open incident; employee reporter is authenticated identity. Admin may include reporter_id.'),
    ('GET', '/incidents', 'incidents', 'Admin/Auditor', None, 200, 'List all incidents including status and assigned_analyst_id.'),
    ('GET', '/incidents/assigned', 'incidents', 'Analyst', None, 200, 'List only incidents assigned to authenticated analyst.'),
    ('GET', '/incidents/mine', 'incidents', 'Employee', None, 200, 'List only incidents reported by authenticated employee.'),
    ('GET', '/incidents/{{incident_id}}', 'incidents', 'Admin/Auditor/assigned Analyst/own Employee', None, 200, 'Incident details and notes, ordered by note ID.'),
    ('PUT', '/incidents/{{incident_id}}/assign', 'incidents', 'Admin', {'assigned_analyst_id': '{{analyst_id}}'}, 200, 'Validate Active Security Analyst, save assignment, notify after commit.'),
    ('PUT', '/incidents/{{incident_id}}/status', 'incidents', 'Admin/assigned Analyst', {'status': 'Under Investigation'}, 200, 'Advance exactly one incident lifecycle state; server resolution time.'),
    ('POST', '/incidents/{{incident_id}}/notes', 'incidents', 'Admin/assigned Analyst', {'note_content': 'Reviewed authentication evidence'}, 201, 'Persist linked note with authenticated author and server timestamp.'),
    *[('GET', '/reports/' + kind, 'reports', 'Admin/Auditor', None, 200, explanation) for kind, explanation in (
        ('summary', 'Totals users/assets/incidents/threats; open_incidents, critical_threats, latest ten recent_activity.'),
        ('incidents', 'Total, by_severity and by_status from authorized incident HTTP list.'),
        ('assets', 'Total, critical and by_type from authorized asset HTTP list.'),
        ('threats', 'Total, by_severity, by_type and latest ten recent_indicators.'),
        ('vulnerabilities', 'Total, by_severity, by_status and critical.'),
        ('activity', 'Total activities, login_attempts, failed_logins and most_common_actions; requires agreed outcome label configuration.'))],
    ('POST', '/playbooks', 'playbooks', 'Admin', PLAYBOOK, 201, 'Create categorized response procedure with authenticated created_by.'),
    ('GET', '/playbooks', 'playbooks', 'Admin/Analyst/Auditor', None, 200, 'List playbook fields without child actions.'),
    ('GET', '/playbooks/{{playbook_id}}', 'playbooks', 'Admin/Analyst/Auditor', None, 200, 'Retrieve ordered actions and per-action history snapshots.'),
    ('POST', '/playbooks/{{playbook_id}}/actions', 'playbooks', 'Admin/Analyst',
        {'description': 'Collect access evidence', 'step_number': 1, 'assigned_user_id': '{{analyst_id}}'}, 201, 'Append unique positive increasing step. Optional Active assigned_user_id; initial Pending.'),
    ('PUT', '/actions/{{action_id}}/status', 'playbooks', 'Admin/Analyst', {'status': 'In Progress'}, 200,
        'Optional status and/or assigned_user_id. Next-state only, earlier steps complete, Active assignee; completed immutable.'),
    ('DELETE', '/playbooks/{{playbook_id}}', 'playbooks', 'Admin', None, 200, 'Delete parent and cascade actions/history; use a disposable demo playbook.')]


def item(spec, name=None, token=None, data=None, code=None, save=None, path=None):
    method, endpoint, service, roles, default_body, expected, explanation = spec
    endpoint = path or endpoint
    expected = expected if code is None else code
    token = token or ('analyst_token' if endpoint.endswith('/assigned') or endpoint.startswith('/actions/') else
        'employee_token' if endpoint.endswith('/mine') or (method == 'POST' and endpoint == '/incidents') else 'admin_token')
    raw = 'http://{{host}}:{{' + service + '_port}}/{{owner_prefix}}' + endpoint
    request = {'method': method, 'url': raw,
        'auth': {'type': 'bearer', 'bearer': [{'key': 'token', 'value': '{{' + token + '}}', 'type': 'string'}]},
        'header': [], 'description': f'Charbel Faddoul. {explanation}\nRoles: {roles}. Expected HTTP {expected}. '
        'Path IDs are positive integers. No query parameters. Responses use status/data or status/message. '
        'These are prepared requests, not recorded execution evidence. Use real accounts and a disposable demo database.'}
    payload = default_body if data is None else data
    if payload is not None:
        raw_body = json.dumps(payload, indent=2)
        # Numeric variable placeholders must produce JSON numbers at send time.
        for key in ('asset_id', 'analyst_id'):
            raw_body = raw_body.replace('"{{' + key + '}}"', '{{' + key + '}}')
        request['header'] = [{'key': 'Content-Type', 'value': 'application/json'}]
        request['body'] = {'mode': 'raw', 'raw': raw_body, 'options': {'raw': {'language': 'json'}}}
    script = [f'pm.test("Expected HTTP {expected}", function () {{ pm.response.to.have.status({expected}); }});',
        'pm.test("Shared JSON envelope", function () { const b = pm.response.json(); pm.expect(b.status).to.eql(pm.response.code < 400 ? "success" : "error"); });']
    if save:
        script.append(f'if (pm.response.code === {expected}) pm.environment.set("{save}", pm.response.json().data.id);')
    return {'name': name or method + ' ' + endpoint, 'request': request, 'response': [],
        'event': [{'listen': 'test', 'script': {'type': 'text/javascript', 'exec': script}}]}


def main():
    by_path = {(s[0], s[1]): s for s in ENDPOINTS}
    get = lambda method, path: by_path[method, path]
    incident = [item(get('POST', '/incidents'), save='incident_id'),
        item(get('GET', '/incidents')), item(get('GET', '/incidents/mine')),
        item(get('PUT', '/incidents/{{incident_id}}/assign')),
        item(get('GET', '/incidents/assigned')),
        item(get('GET', '/incidents/{{incident_id}}'), token='employee_token'),
        item(get('POST', '/incidents/{{incident_id}}/notes'), token='analyst_token')]
    for status in ('Under Investigation', 'Mitigated', 'Resolved', 'Closed'):
        incident.append(item(get('PUT', '/incidents/{{incident_id}}/status'), name='Advance incident: ' + status,
            data={'status': status}, token='analyst_token'))
    reports = [item(s, token='auditor_token') for s in ENDPOINTS if s[2] == 'reports']
    playbook = [item(get('POST', '/playbooks'), save='playbook_id'), item(get('GET', '/playbooks'))]
    for step in (1, 2):
        playbook.append(item(get('POST', '/playbooks/{{playbook_id}}/actions'), name=f'Add ordered action {step}',
            data={'description': 'Collect evidence' if step == 1 else 'Contain access', 'step_number': step,
                'assigned_user_id': '{{analyst_id}}'}, save='action_id' if step == 1 else 'action2_id'))
    update = get('PUT', '/actions/{{action_id}}/status')
    playbook.append(item(update, name='Later action blocked before earlier completion', path='/actions/{{action2_id}}/status', code=409))
    for variable in ('action_id', 'action2_id'):
        for status in ('In Progress', 'Completed'):
            playbook.append(item(update, name=f'{variable}: {status}', path='/actions/{{' + variable + '}}/status', data={'status': status}))
    playbook.append(item(get('GET', '/playbooks/{{playbook_id}}')))
    errors = [item(s, name='401 invalid token: ' + s[0] + ' ' + s[1], token='invalid_token', code=401) for s in ENDPOINTS]
    errors += [item(get('POST', '/incidents'), name='400 invalid severity', data=dict(INCIDENT, severity='Urgent'), code=400),
        item(get('GET', '/incidents/{{incident_id}}'), name='404 missing incident', path='/incidents/2147483647', code=404),
        item(get('PUT', '/incidents/{{incident_id}}/assign'), name='403 employee assignment', token='employee_token', code=403),
        item(get('PUT', '/incidents/{{incident_id}}/status'), name='400 reverse lifecycle', data={'status': 'Open'}, code=400),
        item(get('POST', '/playbooks/{{playbook_id}}/actions'), name='409 duplicate action step', code=409),
        item(get('GET', '/reports/summary'), name='403 employee report', token='employee_token', code=403),
        item(get('DELETE', '/playbooks/{{playbook_id}}'), name='403 analyst deletion', token='analyst_token', code=403)]
    groups = [('1 Incidents: ordered scenario', incident), ('2 Reports: real sources required', reports),
        ('3 Playbooks: two ordered actions', playbook), ('4 Errors: use scenario records', errors),
        ('5 Cleanup: deletes demo history', [item(get('DELETE', '/playbooks/{{playbook_id}}'))])]
    collection = {'info': {'name': 'Part 3 — Charbel Faddoul',
        'schema': 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json',
        'description': 'Prepared development collection, not execution evidence. Run folders in order. Set real tokens for all four roles and numeric asset_id/analyst_id. '
        'The employee token creates the incident; analyst_id must match analyst_token. Missing-token and outage tests can be performed manually. '
        'Configure agreed Part 2 login outcome labels before activity report. Never expose secrets in screenshots. Cleanup deletes only the demo playbook.'},
        'item': [{'name': name, 'item': items} for name, items in groups]}
    environment = {'name': 'Part 3 local — Charbel Faddoul', '_postman_variable_scope': 'environment',
        'values': [{'key': k, 'value': v, 'enabled': True, 'type': 'secret' if k.endswith('_token') else 'default'} for k, v in {
            'host': '127.0.0.1', 'owner_prefix': 'charbel-faddoul', 'incidents_port': '5003', 'reports_port': '5006', 'playbooks_port': '5009',
            'admin_token': '', 'analyst_token': '', 'employee_token': '', 'auditor_token': '', 'invalid_token': 'deliberately-invalid',
            'asset_id': '', 'analyst_id': '', 'incident_id': '', 'playbook_id': '', 'action_id': '', 'action2_id': ''}.items()]}
    out = ROOT / 'postman'
    out.mkdir(exist_ok=True)
    (out / 'part3.collection.json').write_text(json.dumps(collection, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    (out / 'part3.environment.json').write_text(json.dumps(environment, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    table = ['# API reference (Charbel Faddoul)', '',
        'All paths below begin with `/charbel-faddoul`; use ports 5003 incidents, 5006 reports and 5009 playbooks. '
        'Every route requires `Authorization: Bearer TOKEN`. ID path parameters are positive integers. No endpoint defines query parameters. '
        'Bodies are nonempty JSON objects; unknown fields are rejected. Role shorthand: Admin = Security Administrator, Analyst = Security Analyst, '
        'Employee = Regular Employee/User, Auditor = Auditor.', '',
        '| Method/path | Roles | JSON body (illustrative request template) | Success | Purpose |',
        '|---|---|---|---|---|']
    for method, path, service, roles, payload, status, explanation in ENDPOINTS:
        table.append(f'| {method} `{path}` | {roles} | ' + ('`' + json.dumps(payload) + '`' if payload else 'None') + f' | {status} | {explanation} |')
    table += ['', '## Response and error contracts (Charbel Faddoul)', '',
        'All successes: `{"status":"success","data":...}`. Create/update/detail return a stored object; list returns an array. '
        'Incident details include `notes`; playbook detail includes `actions` ordered by step_number, each with `history`. '
        'Delete returns `{ "id": ID, "message": "Playbook deleted" }` under data. '
        'The collection contains prepared bodies and assertions, with no claimed captured responses. Token and record variables must come from your own system.', '',
        'Errors: `{"status":"error","message":"meaningful explanation"}`. '
        '400 missing/unknown fields, wrong types, invalid enums, invalid lifecycle, absent assignee for execution or no-op update; '
        '401 missing/invalid/expired token; 403 role/ownership/impersonation or analyst other-user lookup denied; '
        '404 absent incident/playbook/action/reference; 409 duplicate/ordering/immutable-completed/concurrent/FK conflict; '
        '503 unavailable authentication/audit/source dependency or missing activity login-label configuration. '
        'Every endpoint may return 401/403/503. Resource reads/mutations may return 404. Creation/mutation may return 400/409. '
        'A permission-denial audit outage may yield 503 before the intended 401/403 because common.protected requires audit service availability.', '',
        '## Field rules (Charbel Faddoul)', '',
        'Incident required: title, description, category, severity, asset_id. Optional reporter_id defaults to identity; employee cannot override to someone else. '
        'Assignment requires assigned_analyst_id. Note requires note_content. Text fields are trimmed, nonempty and <=4000 characters. '
        'Severity is Low/Medium/High/Critical. Status and creation/resolution times cannot be supplied at creation. '
        'Status updates require exactly status; Open -> Under Investigation -> Mitigated -> Resolved -> Closed. '
        'Timestamp generated on Resolved and retained on Closed.', '',
        'Playbook required: name, description, incident_category, severity. Action required: description, step_number; optional assigned_user_id. '
        'Step number is a unique positive integer greater than prior steps. Status update allows status and/or assigned_user_id, with at least one actual change. '
        'Assigned IDs must resolve to Active users; analysts currently can validate only themselves. '
        'Pending -> In Progress -> Completed, lower steps complete first, assigned user required to execute, Completed immutable. '
        'completion_date is server-generated and cannot be sent. Creation/status/assignment snapshots store changed_by and timestamp.', '',
        '## Report data (Charbel Faddoul)', '',
        'Summary data: users/assets/incidents/threats integer totals, open_incidents, critical_threats, recent_activity (latest 10). '
        'Other reports return total plus grouped counts described above. Activity additionally returns total_activities, login_attempts, failed_logins, '
        'most_common_actions and login_action_labels. Login attempts = exact configured success outcomes + failure outcomes; separate attempt-start records are excluded. '
        'Unset or equal outcome labels cause 503. Exact labels still require Part 2 agreement. Empty totals are 0 and empty grouped maps are {}. '
        'Dependencies are fetched with the caller bearer token; their failures remain explicit. Recent items are ordered by server timestamps, latest first.', '',
        '## Postman use (Charbel Faddoul)', '',
        'Import `postman/part3.collection.json` and `postman/part3.environment.json`. Set four real role tokens and numeric asset_id/analyst_id. '
        'Run ordered folders against disposable records; IDs are saved into the environment on successful creates. '
        'The two-action scenario demonstrates order rejection before progressing both steps. Error requests use the saved records; cleanup is last. '
        'Manually test missing token, real dependency outage, varied severities/types/statuses and real DB comparisons using EVIDENCE_CHECKLIST.md. '
        'All request examples are illustrative templates, not actual API execution evidence. Rebuild artifacts with `python -m part3.build_postman`.']
    docs = ROOT / 'docs' / 'part3'
    docs.mkdir(parents=True, exist_ok=True)
    (docs / 'API_REFERENCE.md').write_text('\n'.join(table) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
