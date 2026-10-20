# Sprint 1 team integration contract

Read the supplied Word brief in full. This file fixes implementation choices; it does not replace its requirements. Each person owns three complete services. Backend only. Python 3.11+, Flask, SQLite, requests; no Docker, frontend, message broker, ORM, or cloud deployment.

## File ownership and delivery

- Part 1: `part1/`, `docs/part1/`, `postman/part1*`, `tests/test_part1.py`.
- Part 2: `part2/`, `docs/part2/`, `postman/part2*`, `tests/test_part2.py`.
- Part 3: `part3/`, `docs/part3/`, `postman/part3*`, `tests/test_part3.py`.
- Root `common/`, `team_config.json`, and this contract are canonical shared files supplied by Part 1. Do not independently redesign or rename them. Propose changes in `INTEGRATION_NOTES.md` in your own part folder. Return a ZIP with your owned folders at its root. No enclosing extra project folder, venv, credentials, caches, Git directory, or personal database. Include your SQL additions separately if needed; do not overwrite the canonical schema.
- Each student must make and push their own meaningful GitHub commits. Keep authentic screenshots with captions containing the student's full name, API title, and explanation. A test double is never submission evidence.

## Personal ZIP organization

The outer package contains exactly three personal ZIPs: `khalil ayoub.zip` (Part 1), `talia semaan.zip` (Part 2), and `charbel faddoul.zip` (Part 3). Shared common/, team_config.json, requirements.txt, README and this contract remain external alongside them. The common final report and combined evidence are external alongside the personal ZIPs. Extract all three personal ZIPs into the shared parent directory before running; preserve the internal part1/part2/part3 Python paths. All three personal ZIPs contain the completed service implementations. The instructor's naming requirement still applies to the eventual outer common submission.

## Run and naming

GitHub repository: https://github.com/Khalil-Ayoub/talia-semaan-khalil-ayoub-charbel-faddoul (public). Khalil uses Khalil-Ayoub and branch khalil; Talia uses taliasemaan and branch talia; Charbel uses Charbel-Faddoul (formerly Ta3awon) and branch charbel. Their service pull requests #1, #4 and #3 were merged into main on 19 October 2026. The original student commits and branches are preserved. Personal ZIPs organize the common submission; GitHub history records the actual account contributions.

One Flask process for each service, all on localhost. Ports: users 5001, assets 5002, incidents 5003, threats 5004, logs 5005, reports 5006, vulnerabilities 5007, notifications 5008, playbooks 5009. Entrypoints: `python -m part1.app assets`, `python -m part2.app users`, `python -m part3.app incidents`, similarly for each owned service. No debug mode.

`team_config.json` contains the three exact full names. Every route, including internal routes, starts with the owning student's full name converted to lowercase hyphen-separated words by `common.runtime.prefix()`. Example: `/khalil-ayoub/assets`. Do not hardcode someone else's name. URLs are built by `common.runtime.url()`.

Use one physical SQLite database at root `data/project.db`, or `PROJECT_DB` environment override. Shared schema is initialized by `make_app`. Every connection enforces foreign keys. Each service writes only its owned entities. Cross-service business lookups and reporting use HTTP APIs; same-database relationships remain physical foreign keys. No separate incompatible copies of `project.db` in the final ZIP.

## JSON and errors

Success: `{"status":"success","data":OBJECT_OR_ARRAY}`. Creates 201; reads/updates/deletes 200. Error: `{"status":"error","message":"meaningful explanation"}`. Use 400 invalid input, 401 missing/invalid/expired token, 403 authenticated forbidden operation, 404 missing record, 409 duplicate or relationship conflict, 503 unavailable dependency. Never expose passwords, hashes, tracebacks, or secrets in responses. Snake_case field names follow `common/schema.sql`. Datetimes are server-generated UTC ISO 8601 strings. Prevent SQL injection using bound parameters; never interpolate user-supplied SQL identifiers. Reject unknown JSON fields and invalid types.

Roles exactly: `Security Administrator`, `Security Analyst`, `Regular Employee/User`, `Auditor`. Four severity values: `Low`, `Medium`, `High`, `Critical`. Roles are checked on every protected request, with record ownership restrictions where required. Auditor is read-only, except permitted GET report generation.

## Authentication and service calls

Public clients send `Authorization: Bearer TOKEN`. Part 2 owns password hashing, login, signed expiring tokens or opaque sessions, and current user verification. Every verification must reread the current account role/status and reject inactive, suspended, or deleted accounts. No trusting role headers or client-submitted role claims.

All processes share an environment `SERVICE_SECRET` (a sufficiently long random value, never committed). Internal endpoints require `X-Service-Key` and constant-time secret comparison. Never expose service credentials to regular clients. Part 2 supplies:

1. `POST /OWNER/internal/verify`, users port. Body `{"token":"..."}`. Success data: `{"id":1,"full_name":"...","role":"Security Administrator","account_status":"Active"}`. Invalid tokens return 401, not 200. Internal access bypasses public user-management permissions but verifies the token's actual identity.
2. `GET /OWNER/users/id/<id>`, users port. Public bearer authentication, admin/auditor only. Return safe user data including id and role, or 404. This necessary helper avoids confusing numeric IDs with usernames and validates asset owners and assigned analysts.
3. `POST /OWNER/internal/logs`, logs port. Body `user_id` (nullable for unknown login/unauthenticated attempts), `action`, `description`, `severity`, `related_service`. Generate timestamp. Allow only known roles/fields/severity values as appropriate; authenticate the calling service. Do not recursively audit writes to logs. Return stored log in data.
4. `POST /OWNER/internal/notifications`, notifications port. Body `user_id`, `title`, `message`, `notification_type`, `severity`. Generate creation_date, status Unread, read_date null. Validate recipient exists. Return stored notification.

Part 1 supplies `GET /OWNER/internal/assets/<id>` on port 5002, authenticated by X-Service-Key using `common.runtime.internal_only`. Returns only id/status/owner_id or 404. Part 3 can validate an employee-reported asset through this endpoint without granting the employee public asset access. `internal_only` is available for Part 2's internal routes too.

`common.runtime.protected` calls identity verification and audits missing-token and forbidden-role attempts. Part 2 must also log invalid/expired token rejections inside identity verification, plus public authentication failures. Avoid recursion: logs/notifications internal endpoints verify the service secret locally; the identity verification endpoint must not call itself. Login and registration use their own explicit authentication logic.

Automatic logs include successful and failed login, user creation/deletion, role changes, unauthorized attempts, and data modifications. Part 1 logs validated modification requests before its transaction so the logging service does not contend with an open SQLite write transaction; descriptions explicitly say requested, not completed. Never hold an SQLite write transaction while making an HTTP call that writes another table in the same database. Commit before cross-service calls or call them before starting the write transaction.

## Additional routes and interpretations needed by the brief

- Part 2 supplies admin role/account status management through `PUT /users/<id>/role` and `PUT /users/<id>/status`; role removal means reset to Regular Employee/User because schema has one role per account. No public self-registration into admin/analyst/auditor roles. Bootstrap the initial administrator with an explicit local CLI, not an unauthenticated API.
- Users deletion is logical: set deleted_at and prevent further login, verification, listing, or retrieval. Preserve historical foreign keys and audit evidence; explain this in the report. Username stays reserved. Do not erase related security history.
- Analysts see assigned incidents only; employees see their own reported incidents and notifications only. Analyst asset searches/details are limited to assets of their assigned incidents. Asset list is admin/auditor only.
- The general role table permits auditor threat search, though Service 4's shorter table omits it: allow auditor read-only threat search. The Service 5 table explicitly permits analyst log detail/search despite broader introductory wording: permit those, not unrestricted list/delete. Document these interpretations rather than silently changing them.
- Add `GET /incidents/assigned` for analysts and `GET /incidents/mine` for employees because the overview explicitly requires these lists. Register static routes before variable routes.
- Asset history uses `asset_history`; admin/auditor can GET `/assets/<id>/history`.
- Playbook actions are ordered and history is stored in `action_history`; include history when retrieving a playbook. Completed actions should not be silently rewritten without an explicit policy. Deletion cascades child actions/history; audit the deletion separately.
- Report values must be calculated, never hardcoded; fetch users/assets/incidents/threats/logs/vulnerabilities via APIs with caller's bearer token. Auditor/admin can access required lists.
- Part 1 creates threat alerts for the creating administrator and vulnerability alerts for the affected asset owner. Part 3 creates incident assignment notifications for the assigned analyst. Record selection policies in report. No real email/SMS delivery is required. If alert delivery fails after a committed change, return the saved record with an explicit `notification_warning`; do not claim delivery.

## Integrated behavior

Users use the canonical created_date and last_login_date columns. Part 2 uses the shared URL builder with normalized leading slashes. All notification changes emit audit records outside write transactions.

GET /OWNER/internal/users/<id> on port 5001 requires X-Service-Key and returns only id, role, account_status and deleted_at for a non-deleted account. Playbooks use this endpoint to validate assignees without granting public user-management access to analysts.

The shared login action names are login_succeeded and login_failed. Activity reports use them by default; optional PART3_LOGIN_SUCCESS_ACTION and PART3_LOGIN_FAILURE_ACTION override them only for a coordinated change. Tokens are signed and expire after eight hours, with current account state checked on every protected request.

Positive IDs and step numbers must fit SQLite's signed 64-bit integer range. An out-of-range request is rejected with 400.

Run all nine processes using python run_services.py with SERVICE_SECRET set. After startup, bootstrap the first administrator using python -m part2.bootstrap_admin --full-name "Admin Name" --username admin --email admin@example.test --department Security. Use the same SERVICE_SECRET in that terminal. Password entry is interactive, or BOOTSTRAP_ADMIN_PASSWORD may supply a local value. Do not commit credentials.

Run python -m unittest discover -s tests -p "test_*.py" -v after extracting all three parts. The integration test runs all nine real applications with temporary SQLite and local HTTP; it does not replace service implementations. The isolated service suites remain useful for focused checks.
