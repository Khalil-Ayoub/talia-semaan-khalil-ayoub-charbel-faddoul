# Local development checks (Charbel Faddoul)

Executed 17 October 2026, Python 3.11, Flask 3.1.3, Requests 2.34.2, Windows. Command from the cloned repository:

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -p test_part3.py -v
```

Result: **7 tests passed**. Each test creates a real SQLite file with canonical schema and FK enforcement. Real HTTP transport goes to a local test-only Flask server explicitly doubling unavailable teammate services; owned endpoints run through Flask test clients. No mock authentication/data is used in production code. No claim of real Part 2 authentication or nine-service integration is made.

| Test | Checks |
|---|---|
| incident_lifecycle_ownership_and_notes | literal SQL-looking text safely persists; own/assigned scope; invalid analyst assignment; assignment notification; exact lifecycle; resolution timestamp; notes; audited denies |
| validation_auth_and_dependencies | missing/invalid token, absent record, invalid severity/types/unknown fields, impersonation, HTTP outage, committed assignment with notification warning, suspended user, audit outage prevents mutation |
| playbook_order_history_and_cascade | two steps, premature execution denied, skipped states denied, completion timestamps, ordered detail, three history snapshots, completed immutability, duplicate rejection, analyst deletion denial, cascades |
| playbook_permissions_and_validation | employee/auditor/analyst permissions, positive integer steps, analyst self-assignment, rejection of other-user lookup pending shared helper, client completion timestamp rejection |
| reports_match_real_records_over_http | persisted incident severity/status distribution, asset criticality, threat/vulnerability counts, summary totals, outcome-only login counting, total activity matches SQLite, public bearer forwarding |
| reports_empty_denied_and_outages | all six reports, both permitted roles through suite, analyst/employee denial, empty groups, outage propagation, unset login-label configuration |
| physical_foreign_keys_and_prefixed_routes | physical orphan insert rejection, no FK violations, all registered routes include Charbel Faddoul prefix |

Additional local checks: all 55 Postman request templates parsed after substituting numeric fixture IDs; every request has descriptions and status assertions. All three actual CLI entrypoints were launched as separate processes on 5003/5006/5009 using a temporary database; each returned the expected shared JSON 503 when the absent real logs dependency was required for unauthenticated access. Processes were stopped after the smoke check. This confirms startup/error behavior, not successful authenticated integration. An initial smoke probe used too short a client timeout; repeating with a timeout above the canonical dependency timeout passed.

Not verified: real teammate login/audit behavior, agreed action labels, analyst other-user lookup, real multi-process all-nine service run, Postman execution, genuine screenshot evidence, common report assembly. No performance measurements are asserted. The evidence checklist covers actual system work still required. Packaging JSON and Git checks are performed separately during delivery.
