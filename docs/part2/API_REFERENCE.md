# Part 2 API Reference (Talia Semaan)

Base URL: `http://127.0.0.1:<port>/talia-semaan`. All successful responses use `{"status":"success","data":...}`. Errors use `{"status":"error","message":"..."}`. Protected public requests use `Authorization: Bearer TOKEN`; internal routes use `X-Service-Key`.

## Users and identity (port 5001)

Passwords require at least 12 characters and are hashed with Werkzeug. Public registration may create only `Regular Employee/User`. A logged-in Security Administrator may create a privileged role. Account status is `Active`, `Inactive`, or `Suspended`; only active accounts can log in or verify. User profile responses never include password hashes.

| Method and endpoint | Purpose, access, and input | Success / common errors |
| --- | --- | --- |
| `POST /users/register` | Public account registration. Required JSON: `full_name`, `username`, `email`, `password`, `department`, `role`. | `201` safe user; `400` malformed, unknown field, invalid email, or short password; `403` privileged public registration; `409` duplicate identity. |
| `POST /users/login` | Public login. JSON has exactly one of `username` or `email`, plus `password`. | `200` includes `data.token` and safe user; `400` malformed; `401` invalid credentials/inactive account; `503` audit dependency unavailable. |
| `PUT /users/{id}` | Admin or own regular user. JSON accepts only `full_name`, `email`, `department`. | `200` safe user; `400` unknown/invalid fields; `403` wrong owner/role; `404` missing/deleted; `409` duplicate email. |
| `DELETE /users/{id}` | Admin only; logical deletion preserves foreign keys and history. | `200` deleted ID; `403` forbidden; `404` missing/deleted. |
| `GET /users` | Admin and Auditor. | `200` safe active/non-deleted users; `401` unauthenticated; `403` forbidden. |
| `GET /users/{username}` | Admin/Auditor; regular user may retrieve only self. | `200` safe user; `401`, `403`, or `404`. |
| `GET /users/id/{id}` | Admin/Auditor helper for numeric cross-service IDs. | `200` safe user with ID and role; `401`, `403`, or `404`. |
| `PUT /users/{id}/role` | Admin only. JSON: `{"role":"Security Analyst"}`; role removal uses `Regular Employee/User`. | `200` safe user; `400` invalid role; `403`; `404`. |
| `PUT /users/{id}/status` | Admin only. JSON: `{"account_status":"Suspended"}`. | `200` safe user; `400` invalid status; `403`; `404`. |
| `POST /internal/verify` | Service key required. JSON: `{"token":"..."}`. | `200` `{id, full_name, role, account_status}`; `401` invalid/expired/inactive/deleted; `403` bad service key. |

The signed token contains user ID and expiry only; every check rereads current role, status, and deletion state. Tokens expire after eight hours. User deletion is logical: set `deleted_at`, exclude the account from login/list/detail/verification, and preserve its foreign-key history and reserved username/email.

## Security audit logs (port 5005)

Allowed severity values: `Information`, `Warning`, `Error`, `Critical`. Admin creates, lists, reads, searches, and deletes; Auditor reads/lists/searches/by-user; Analyst reads an individual log or searches only. Employees have no access. Logs are immutable through the API: there is no update endpoint; the shared schema must provide the requested update-blocking trigger. Empty user-log searches return `200` with `data: []`.

| Method and endpoint | Purpose, access, and input | Success / common errors |
| --- | --- | --- |
| `POST /logs` | Admin creates; JSON requires `user_id` (integer or null), `action`, `description`, `severity`, `related_service`. | `201` stored log; `400` validation; `401`/`403`; `409` relationship conflict. |
| `GET /logs` | Admin/Auditor list. | `200` array; `401`/`403`. |
| `GET /logs/{id}` | Admin/Auditor/Analyst detail. | `200` record; `401`/`403`/`404`. |
| `GET /logs/search` | Admin/Auditor/Analyst. Query filters: `user_id`, `date` (`YYYY-MM-DD`), `action`, `severity`, `related_service`. | `200` filtered array (possibly empty); `400` invalid filter; `401`/`403`. |
| `DELETE /logs/{id}` | Admin only. | `200` deleted ID; `401`/`403`/`404`. |
| `GET /logs/user/{user_id}` | Admin/Auditor only. | `200` matching array, including empty; `401`/`403`. |
| `POST /internal/logs` | Service key only; same fields as public create. Timestamp is server-generated. | `201` stored record; `400` invalid field; `403` bad service key; `409` invalid user relation. |

Identity service logs successful/failed login, user creation/deletion requests, role/status changes, and rejected authorization/authentication. Log text explicitly says “requested” when written before the transaction. Log writes are not recursively logged.

## Notifications (port 5008)

Types: `Incident Assignment`, `Security Alert`, `System Notification`, `Threat Alert`, `Vulnerability Alert`. Severity: `Low`, `Medium`, `High`, `Critical`. Status is generated as `Unread`; `read_date` is null until first read, and repeated reads preserve the first timestamp. Admin can create/manage all; Auditor can read/search; Analysts and regular users can access only their own records and mark their own notifications read. Analysts can search their own records; regular users cannot search. Creation means a stored notification, not external delivery.

| Method and endpoint | Purpose, access, and input | Success / common errors |
| --- | --- | --- |
| `POST /notifications` | Admin creates. JSON requires `user_id`, `title`, `message`, `notification_type`, `severity`; status/timestamps are server-owned. | `201` notification; `400` invalid input; `401`/`403`; `404` missing/inactive recipient. |
| `GET /notifications/user/{user_id}` | Admin/Auditor any user; Analyst/Employee self only. | `200` array, including empty; `401`/`403`. |
| `GET /notifications/{id}` | Admin/Auditor any; Analyst/Employee own. | `200`; `401`/`403`/`404`. |
| `PUT /notifications/{id}/read` | Admin or owning Analyst/Employee; no body. | `200` updated notification; `401`/`403`/`404`. |
| `GET /notifications/search` | Admin/Auditor; Analyst receives own records only. Filters: `user_id`, `notification_type`, `severity`, `status`. | `200` array; `400` invalid filter; `401`/`403`. |
| `DELETE /notifications/{id}` | Admin only. | `200` deleted ID; `401`/`403`/`404`. |
| `POST /internal/notifications` | Service key only; same client fields as create, with generated status and timestamps. | `201`; `400` invalid input; `403` bad key; `404` missing/inactive recipient. |

## Internal user validation

GET /internal/users/{id} requires X-Service-Key, returns only id/role/account_status/deleted_at for a non-deleted user, or 404. This validates assignees without granting analysts public user-management access. User timestamps use created_date/last_login_date. Notification modifications are audited outside write transactions.

## Cross-service patterns

Internal log and notification writes validate `X-Service-Key` using constant-time comparison and do not call identity verification, preventing recursion. Public user/log/notification requests verify bearer tokens through the users identity endpoint. A dependency outage returns `503`; it never grants access. All query values are SQL-bound parameters. Postman examples are for manual execution and are not execution evidence.