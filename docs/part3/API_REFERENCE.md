# API reference (Charbel Faddoul)

All paths below begin with `/charbel-faddoul`; use ports 5003 incidents, 5006 reports and 5009 playbooks. Every route requires `Authorization: Bearer TOKEN`. ID path parameters are positive integers. No endpoint defines query parameters. Bodies are nonempty JSON objects; unknown fields are rejected. Role shorthand: Admin = Security Administrator, Analyst = Security Analyst, Employee = Regular Employee/User, Auditor = Auditor.

| Method/path | Roles | JSON body (illustrative request template) | Success | Purpose |
|---|---|---|---|---|
| POST `/incidents` | Admin/Employee | `{"title": "Unexpected account access", "description": "Investigate unexpected access on the selected lab asset", "category": "Unauthorized access", "severity": "High", "asset_id": "{{asset_id}}"}` | 201 | Create Open incident; employee reporter is authenticated identity. Admin may include reporter_id. |
| GET `/incidents` | Admin/Auditor | None | 200 | List all incidents including status and assigned_analyst_id. |
| GET `/incidents/assigned` | Analyst | None | 200 | List only incidents assigned to authenticated analyst. |
| GET `/incidents/mine` | Employee | None | 200 | List only incidents reported by authenticated employee. |
| GET `/incidents/{{incident_id}}` | Admin/Auditor/assigned Analyst/own Employee | None | 200 | Incident details and notes, ordered by note ID. |
| PUT `/incidents/{{incident_id}}/assign` | Admin | `{"assigned_analyst_id": "{{analyst_id}}"}` | 200 | Validate Active Security Analyst, save assignment, notify after commit. |
| PUT `/incidents/{{incident_id}}/status` | Admin/assigned Analyst | `{"status": "Under Investigation"}` | 200 | Advance exactly one incident lifecycle state; server resolution time. |
| POST `/incidents/{{incident_id}}/notes` | Admin/assigned Analyst | `{"note_content": "Reviewed authentication evidence"}` | 201 | Persist linked note with authenticated author and server timestamp. |
| GET `/reports/summary` | Admin/Auditor | None | 200 | Totals users/assets/incidents/threats; open_incidents, critical_threats, latest ten recent_activity. |
| GET `/reports/incidents` | Admin/Auditor | None | 200 | Total, by_severity and by_status from authorized incident HTTP list. |
| GET `/reports/assets` | Admin/Auditor | None | 200 | Total, critical and by_type from authorized asset HTTP list. |
| GET `/reports/threats` | Admin/Auditor | None | 200 | Total, by_severity, by_type and latest ten recent_indicators. |
| GET `/reports/vulnerabilities` | Admin/Auditor | None | 200 | Total, by_severity, by_status and critical. |
| GET `/reports/activity` | Admin/Auditor | None | 200 | Total activities, login_attempts, failed_logins and most_common_actions; requires agreed outcome label configuration. |
| POST `/playbooks` | Admin | `{"name": "Account containment", "description": "Collect evidence then contain access", "incident_category": "Unauthorized access", "severity": "High"}` | 201 | Create categorized response procedure with authenticated created_by. |
| GET `/playbooks` | Admin/Analyst/Auditor | None | 200 | List playbook fields without child actions. |
| GET `/playbooks/{{playbook_id}}` | Admin/Analyst/Auditor | None | 200 | Retrieve ordered actions and per-action history snapshots. |
| POST `/playbooks/{{playbook_id}}/actions` | Admin/Analyst | `{"description": "Collect access evidence", "step_number": 1, "assigned_user_id": "{{analyst_id}}"}` | 201 | Append unique positive increasing step. Optional Active assigned_user_id; initial Pending. |
| PUT `/actions/{{action_id}}/status` | Admin/Analyst | `{"status": "In Progress"}` | 200 | Optional status and/or assigned_user_id. Next-state only, earlier steps complete, Active assignee; completed immutable. |
| DELETE `/playbooks/{{playbook_id}}` | Admin | None | 200 | Delete parent and cascade actions/history; use a disposable demo playbook. |

## Response and error contracts (Charbel Faddoul)

All successes: `{"status":"success","data":...}`. Create/update/detail return a stored object; list returns an array. Incident details include `notes`; playbook detail includes `actions` ordered by step_number, each with `history`. Delete returns `{ "id": ID, "message": "Playbook deleted" }` under data. The collection contains prepared bodies and assertions, with no claimed captured responses. Token and record variables must come from your own system.

Errors: `{"status":"error","message":"meaningful explanation"}`. 400 missing/unknown fields, wrong types, invalid enums, invalid lifecycle, absent assignee for execution or no-op update; 401 missing/invalid/expired token; 403 role/ownership/impersonation or analyst other-user lookup denied; 404 absent incident/playbook/action/reference; 409 duplicate/ordering/immutable-completed/concurrent/FK conflict; 503 unavailable authentication/audit/source dependency or missing activity login-label configuration. Every endpoint may return 401/403/503. Resource reads/mutations may return 404. Creation/mutation may return 400/409. A permission-denial audit outage may yield 503 before the intended 401/403 because common.protected requires audit service availability.

## Field rules (Charbel Faddoul)

Incident required: title, description, category, severity, asset_id. Optional reporter_id defaults to identity; employee cannot override to someone else. Assignment requires assigned_analyst_id. Note requires note_content. Text fields are trimmed, nonempty and <=4000 characters. Severity is Low/Medium/High/Critical. Status and creation/resolution times cannot be supplied at creation. Status updates require exactly status; Open -> Under Investigation -> Mitigated -> Resolved -> Closed. Timestamp generated on Resolved and retained on Closed.

Playbook required: name, description, incident_category, severity. Action required: description, step_number; optional assigned_user_id. Step number is a unique positive integer greater than prior steps. Status update allows status and/or assigned_user_id, with at least one actual change. Assigned IDs must resolve to Active users; analysts currently can validate only themselves. Pending -> In Progress -> Completed, lower steps complete first, assigned user required to execute, Completed immutable. completion_date is server-generated and cannot be sent. Creation/status/assignment snapshots store changed_by and timestamp.

## Report data (Charbel Faddoul)

Summary data: users/assets/incidents/threats integer totals, open_incidents, critical_threats, recent_activity (latest 10). Other reports return total plus grouped counts described above. Activity additionally returns total_activities, login_attempts, failed_logins, most_common_actions and login_action_labels. Login attempts = exact configured success outcomes + failure outcomes; separate attempt-start records are excluded. Unset or equal outcome labels cause 503. Exact labels still require Part 2 agreement. Empty totals are 0 and empty grouped maps are {}. Dependencies are fetched with the caller bearer token; their failures remain explicit. Recent items are ordered by server timestamps, latest first.

## Postman use (Charbel Faddoul)

Import `postman/part3.collection.json` and `postman/part3.environment.json`. Set four real role tokens and numeric asset_id/analyst_id. Run ordered folders against disposable records; IDs are saved into the environment on successful creates. The two-action scenario demonstrates order rejection before progressing both steps. Error requests use the saved records; cleanup is last. Manually test missing token, real dependency outage, varied severities/types/statuses and real DB comparisons using EVIDENCE_CHECKLIST.md. All request examples are illustrative templates, not actual API execution evidence. Rebuild artifacts with `python -m part3.build_postman`.
