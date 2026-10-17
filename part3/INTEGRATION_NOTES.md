# Integration notes (Charbel Faddoul)

This is a reviewed-development draft for Services 3, 6 and 9, pending student review/adaptation and instructor-policy verification. The brief prohibits copying complete AI-generated solutions. No claim of submission readiness or nine-service integration is made.

## Identity and ownership (Charbel Faddoul)

Canonical `team_config.json` already configures `owners.part3` as `Charbel Faddoul`; confirmed locally without changing the shared file. Prefix: `/charbel-faddoul`. Git author, confirmed by Charbel: `Charbel F <ctf02@mail.aub.edu>`. GitHub account verified using the authenticated API: `Ta3awon`, with push access to Khalil-Ayoub/talia-semaan-khalil-ayoub-charbel-faddoul; no pending invitation was returned. Branch: `charbel`. Only Part 3 owned files are committed and packaged.

## Setup and execution (Charbel Faddoul)

Extract owned folders alongside canonical external `common/`, `team_config.json` and `requirements.txt`. From that parent directory:

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:SERVICE_SECRET = 'set-a-long-random-local-secret-in-every-service-terminal'
# Optional: same absolute path in all nine terminals
$env:PROJECT_DB = 'C:\your-project\data\project.db'
.venv\Scripts\python.exe -m part3.app incidents
```

Use separate terminals with the same environment for `reports` and `playbooks`; ports 5003, 5006 and 5009. Production implementation has no dependency doubles or bypass authentication. Start real Part 2 users/logs/notifications and Part 1 assets/threats/vulnerabilities for integration. Part 2 must initialize an administrator and issue real bearer tokens. No credential or reusable token is included.

Activity reporting requires the **exact outcome action labels used by Part 2**, supplied as `PART3_LOGIN_SUCCESS_ACTION` and `PART3_LOGIN_FAILURE_ACTION` in the reports terminal. They are deliberately unset by default. An outcome log is counted once; separate attempt-start records are not counted. Confirm Part 2 emits exactly one outcome per login and choose labels specific to login, not general token-verification failures. Missing/equal labels return 503. Names in tests are fixture labels, not an assertion about Part 2.

## Contract proposals and constraints (Charbel Faddoul)

- No canonical files, columns, ports or shared JSON wrappers were changed. No SQL additions are required for the supplied schema.
- Part 2's existing `/users/id/<id>` is admin/auditor-only. Therefore analysts can assign action users to themselves; an analyst trying to validate another user's account receives an audited 403. This also affects status changes on an action assigned to another user because current Active status must be verified. **Remaining functional gap:** agree a service-secret-protected minimal `GET /internal/users/<id>` returning id/role/account_status/deleted_at, and update `active_user` after Part 2 implements it. Do not broaden public user management or silently invent the endpoint.
- Agree exact login success/failure labels with Part 2 and set the environment above. Until then activity reports fail explicitly; other five reports work with their required APIs.
- Incident note input uses canonical `note_content`, not `content`. Assigned incident input is `assigned_analyst_id`; all IDs are JSON positive integers. Employee reporter defaults to authenticated ID; a conflicting reporter is denied. An admin may supply another Active reporter.
- All new incidents require an existing asset. Public employee asset access is never used; validation calls Part 1's existing internal asset helper with the service secret.
- Audits use canonical pre-transaction `... requested` records. They establish a validated request, **not guaranteed completion**. A later SQL conflict can leave a requested audit without a business write. No cross-service calls occur inside SQLite write transactions. Notification failure after assignment returns the saved record and `notification_warning`; no retry worker or delivery claim.
- Incident status changes use a conditional update; notes recheck assignment under a write lock. Action changes/order checks and history are atomic under `BEGIN IMMEDIATE`. External user state may change after HTTP validation; actual FKs still protect references. Fully atomic remote authorization is outside this simple shared contract.
- Steps are positive, unique and appended with increasing numbers; gaps are permitted. All lower-numbered actions must be Completed before executing a later action. Pending -> In Progress -> Completed, no reversal/skips, and Completed records are immutable. A valid Active assigned user is required for execution. History stores creation and each status/assignment snapshot; preceding snapshots show the prior values. Admin deletion intentionally cascades actions/history and leaves a separate audit request.
- Reports consume unpaginated list arrays under canonical success/data with caller bearer token. Pagination would require coordinated changes. Aggregates are collected sequentially and are not a simultaneous database snapshot. Recent items means latest 10 timestamps. Empty groups are `{}`; unavailable/malformed dependencies cause errors, never invented zero counts.

## Verification and remaining work (Charbel Faddoul)

Run `.venv\Scripts\python.exe -m unittest discover -s tests -p test_part3.py -v`.
Seven local tests passed on 17 October 2026 using real temporary SQLite and HTTP transport with explicitly labeled teammate service doubles. Tests verify all six report paths, report counts against stored fixture records, RBAC, scope, input validation, incident lifecycle, notes, notifications/warnings, ordering, snapshots, cascading deletion and physical foreign keys. See `docs/part3/TEST_RESULTS.md`. These are isolated development checks, not submitted implementation evidence.

No real Postman/DB screenshots, nine-service run, real login verification, or final common report was produced. See the complete pending checklist in `docs/part3/EVIDENCE_CHECKLIST.md`. Review/adapt/explain the draft, resolve the two Part 2 agreements, merge with teammates, run all services, execute Postman and capture authentic evidence before submission. Each screenshot caption must contain Charbel Faddoul, API title and what it demonstrates.

ZIP contains only `part3/`, `docs/part3/`, `postman/part3*`, `tests/test_part3.py`, with no enclosing directory or shared files. Shared dependencies stay external. GitHub branch/PR are delivered separately; Git history is actual development, not fabricated team contribution evidence.
