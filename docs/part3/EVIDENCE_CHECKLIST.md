# Traceability and pending evidence (Charbel Faddoul)

Every item below is **pending authentic assembled-system evidence**. Local tests use teammate doubles and must not be presented as implementation evidence. Capture real request/body/bearer role, response and relevant database rows. Caption every screenshot: `Charbel Faddoul — <API title> — <what this execution demonstrates>`. Never include tokens or service secrets in shared screenshots.

| Brief requirement | Implementation / development check | Required real evidence |
|---|---|---|
| S3 Create | incidents_create; severity fixture loop | create multiple severities in Postman; stored rows; explain Low limited impact, Medium investigation, High important systems, Critical immediate response based on actual scenario |
| S3 Retrieve all | incidents_list; list SQL | multiple records, status/analyst fields; explain response wrapper and list |
| S3 Retrieve specific | incidents_detail; existing/missing tests | existing ID including notes; missing ID 404; explain messages |
| S3 Assign | incidents_assign; Active analyst validation | successful admin assignment, updated DB, unauthorized attempt, audit record and notification |
| S3 Status | incidents_status; complete lifecycle test | screenshots of all four next-step transitions; before/after DB and resolution time; reject Open -> Closed; explain workflow |
| S3 Notes | incidents_notes; linked author/incident test | add notes, retrieve updated incident, stored note FKs and timestamp; explain association |
| S3 overview own/assigned | incidents_mine/assigned; scoping tests | own employee list and assigned analyst list; reject other employee/analyst detail access |
| S6 Summary/incident/assets | reports.py; persisted aggregation tests | report screenshots with actual team database; totals/distributions match source rows; show HTTP collection with authorized token |
| S6 Threats | report type/severity/recent aggregation | insert varied types and severities via Part 1; execute Postman; screenshot; explain owner HTTP; compare returned values to stored records |
| S6 Vulnerabilities | report severity/status/critical aggregation | create varied severities/statuses via Part 1; execute Postman; screenshot; explain collection; compare counts to actual stored rows |
| S6 Activity | configured outcome labels; count test | agree Part 2 labels, generate different actual user activities and audit records; Postman; explain analysis; verify totals/login attempts/failures/actions against stored logs, without double-counting start/outcome events |
| S9 Create | playbooks_create | create multiple playbooks; show database; explain category/severity organization |
| S9 List | playbooks_list | execute Postman, screenshot and explain returned fields |
| S9 Detail | playbooks_detail | existing and missing IDs; ordered actions/history; explain 200/404 |
| S9 Add action | playbooks_add_action; ordering tests | multiple stored steps, explain increasing numbers and prerequisites; duplicate/invalid number response |
| S9 Action update | playbooks_action_status; two-step test | actual Pending -> In Progress -> Completed on each step; demonstrate blocked later action; timestamps and history snapshots; explain Active assignment and validation |
| S9 Delete | playbooks_delete; cascade test | authorized deletion, unauthorized prevention, explain roles and cascade with separate log |
| Database evidence | external schema; FK tests | actual created tables, PK/FK structure screenshots, sample rows; relationship explanation and diagram in DATABASE.md; no fixture evidence |
| API docs | API_REFERENCE.md and Postman collection | run every documented request; screenshots of actual execution; discuss at least three APIs using report explanations |
| Authentication/RBAC | common.protected + local scope checks | actual valid/invalid Part 2 login, insufficient/correct role on same endpoint, real verified permissions and logs |
| Validation/sanitization | required/type/enum/unknown-field checks; bound SQL | Postman invalid/empty input, invalid severity, type and transition; rejected response screenshots and explanation |
| Errors | shared APIError handlers | real 400/401/403/404/409 and dependency failure; screenshots, meaningful messages, explain consistent handling |
| GitHub | actual charbel branch and meaningful commits | capture real team history/contributions after all members push; repository link, Charbel's work; no manufactured commits |
| Common report | report fragment, DB and API docs | team combines into one final report with title/contents/page numbers/member names, architecture, all nine services and genuine screenshots |
| Communication/submission | brief and contract notes | team attends 30-minute CREATES session after interim memos and >=3 days before actual deadline, applies feedback; verify 430L naming; each student uploads common deliverable |
| Own work/AI rule | disclosure in report fragment | Charbel reviews/adapts and demonstrates understanding; verify instructor policy before submission; accurately disclose AI assistance |

## Code review and demonstration (Charbel Faddoul)

- Explain identity verification versus role checks and why reporter impersonation fails.
- Explain why employee asset validation uses service-secret HTTP and does not expose public assets.
- Trace incident status ordering, optimistic conflict handling and UTC resolution time.
- Explain parameterized SQL, FK enforcement and why no remote writes occur inside a SQLite transaction.
- Demonstrate assigned/own visibility and auditor read-only behavior.
- Demonstrate two ordered playbook steps and preserved snapshots; explain deletion cascades.
- Explain report collection through bearer HTTP, real aggregation and outage behavior.
- Resolve analyst user lookup and exact Part 2 login labels; perform real full-system tests.
- Review every drafted module and document in light of the instructor's AI policy before submission.
