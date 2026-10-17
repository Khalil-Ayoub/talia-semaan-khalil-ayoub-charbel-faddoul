# Part 1 API reference (Khalil Ayoub)

All paths below are prefixed with `/{full-name-slug}`. Use Authorization: Bearer TOKEN for public routes. Bodies and responses are JSON. Success wraps data as `{"status":"success","data":...}`; error wraps `{"status":"error","message":"..."}`. Create is 201, other success is 200. Errors: 400 malformed/invalid input, 401 missing/bad token, 403 forbidden role or unrelated asset, 404 missing record, 409 duplicate/reference conflict, 503 unavailable dependency, 500 unexpected internal error with no traceback returned.

## Asset Management

| Method and path | Request / parameters | Data returned | Roles |
|---|---|---|---|
| POST /assets | Required asset_name, asset_type, ip_address, department, owner_id, criticality_level. Optional operating_system, location, status | Stored asset including ID; status defaults Active | Admin |
| GET /assets | None | All assets ordered by ID | Admin, Auditor |
| GET /assets/{id} | Integer path ID | Asset plus related_incident_ids and related_vulnerability_ids | Admin, Auditor, Analyst on assigned-incident assets |
| PUT /assets/{id} | Any nonempty subset of asset_name, owner_id, department, criticality_level, status | Updated asset | Admin |
| DELETE /assets/{id} | Integer ID | Deleted ID and message; 409 if referenced by incident/vulnerability | Admin |
| GET /assets/search | Optional asset_name, asset_type, ip_address, department, criticality_level | AND-filtered case-insensitive literal substring results; no matches is [] | Admin, Auditor, Analyst restricted to assigned-incident assets |
| GET /assets/{id}/history | Integer ID | Timestamped create/update snapshots and acting user IDs | Admin, Auditor |
| GET /internal/assets/{id} | X-Service-Key instead of user token | Only id, status, owner_id; used by incident service | Trusted services |

Asset types: Server, Workstation, Database, Application, Network Device, Cloud Resource. Criticality: Low/Medium/High/Critical. Status: Active/Inactive/Under Maintenance. IP supports IPv4/IPv6. Owner must be a real user validated by identity-service HTTP lookup. Missing/empty fields, unknown JSON keys, invalid types/enums are rejected. History is retained while the asset exists; deletes cascade its local history, with separate audit deletion-request record retained.

Example create request:

```json
{"asset_name":"Lab Server","asset_type":"Server","ip_address":"192.0.2.10","department":"IT","owner_id":3,"criticality_level":"High"}
```

Illustrative shape only, not execution evidence: data includes the above fields plus `id` and `status:"Active"`.

## Threat Intelligence

| Method and path | Request / parameters | Data returned | Roles |
|---|---|---|---|
| POST /threats | threat_type, threat_value, description, severity, source | Stored indicator with ID/date_added | Admin |
| GET /threats | None | All indicators | Admin, Analyst, Auditor |
| GET /threats/{id} | Integer ID | One indicator | Admin, Analyst, Auditor |
| GET /threats/search | threat_type, threat_value, severity, source | AND-filtered substring results | Admin, Analyst, Auditor |
| PUT /threats/{id} | Nonempty subset description, severity, source | Updated indicator | Admin |
| DELETE /threats/{id} | Integer ID | Deleted ID/message | Admin |

Threat types: IP Address, Domain, File Hash, Malware Signature, Other Indicators. Validate actual IP, domain labels, or hexadecimal MD5/SHA1/SHA256. Normalize IP representation, lowercase domains/hashes, and remove trailing domain dot before checking compound uniqueness (type,value). Database uniqueness protects concurrent duplicates. Different types may share a value if formats permit. Severity uses Low/Medium/High/Critical. A creation attempts a Threat Alert notification to its creating administrator. Other roles cannot modify threats; employees cannot read them.

```json
{"threat_type":"Domain","threat_value":"example.test","description":"Training indicator","severity":"High","source":"Local exercise"}
```

## Vulnerability Management

| Method and path | Request / parameters | Data returned | Roles |
|---|---|---|---|
| POST /vulnerabilities | title, description, cve_identifier, cvss_score, severity, asset_id, discovery_source; optional status=Open | Stored vulnerability with ID/creation_date | Admin |
| GET /vulnerabilities | None | All vulnerabilities | Admin, Analyst, Auditor |
| GET /vulnerabilities/{id} | Integer ID | One vulnerability | Admin, Analyst, Auditor |
| GET /vulnerabilities/search | cve_identifier, severity, asset_id, status | AND-filtered results; asset_id exact match | Admin, Analyst, Auditor |
| PUT /vulnerabilities/{id} | Nonempty subset description, severity, status, cvss_score, resolution_date | Updated vulnerability | Admin, Analyst |
| DELETE /vulnerabilities/{id} | Integer ID | Deleted ID/message | Admin |

CVSS must be a finite JSON number in [0,10], not boolean/string. CVE format CVE-YYYY-NNNN or longer numeric suffix. Asset must exist and is checked through the asset service. New status Open; only next transition Open -> Under Investigation -> In Progress -> Resolved -> Closed. Repeating the current status is allowed. resolution_date is set automatically upon entering Resolved, preserved on Closed; clients cannot invent dates or clear a resolved date. Optional null is accepted before resolution. Severity is supplied explicitly, not automatically inferred from CVSS because the brief does not mandate a mapping. Creation attempts a Vulnerability Alert to asset owner.

```json
{"title":"Training vulnerability","description":"Lab finding","cve_identifier":"CVE-2026-12345","cvss_score":8.1,"severity":"High","asset_id":1,"discovery_source":"Local exercise"}
```

Example status update: `{"status":"Under Investigation"}`. Direct Open -> Closed returns 400.

## Dependency behavior

All protected operations verify current identity through Part 2. Missing/invalid token logging depends on audit availability. No identity or audit bypass is provided. Modification requests are validated, then logged through the audit API before a local transaction starts. Audit descriptions explicitly represent validated requests, including requests later rejected by FK conflict; they do not falsely claim completion. An audit outage blocks mutation with 503. This simple policy avoids shared-SQLite write-lock deadlocks.

If an alert service fails after a creation commits, the creation still returns 201 and saved data with `notification_warning`. That warning is not persisted; retry the internal notification using the saved ID after recovery. There is no automatic retry queue. Verify successful alert generation in the integrated normal-path evidence before submission.
