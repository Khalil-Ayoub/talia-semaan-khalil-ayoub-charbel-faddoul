"""Behavior tests using an isolated SQLite fixture, not submission evidence."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import tempfile
from pathlib import Path
from contextlib import closing
import unittest
from unittest.mock import patch

from werkzeug.security import generate_password_hash

from part2.app import create_app
from part2.core import ApiProblem, issue_token, utc_now

PREFIX = "/talia-semaan"
ADMIN = "Security Administrator"
ANALYST = "Security Analyst"
EMPLOYEE = "Regular Employee/User"
AUDITOR = "Auditor"


class Part2Tests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = os.path.join(self.temp_dir.name, "project.db")
        os.environ["PROJECT_DB"] = self.database
        os.environ["SERVICE_SECRET"] = "test-secret-that-is-at-least-32-bytes-long"
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.executescript((Path(__file__).resolve().parents[1] / 'common' / 'schema.sql').read_text())
            now = utc_now()
            for name, username, role in (
                ("Talia Admin", "admin", ADMIN), ("Analyst One", "analyst", ANALYST),
                ("Employee One", "employee", EMPLOYEE), ("Auditor One", "auditor", AUDITOR),
            ):
                connection.execute(
                    "INSERT INTO users (full_name, username, email, password_hash, department, role, account_status, created_date) "
                    "VALUES (?, ?, ?, ?, 'Security', ?, 'Active', ?)",
                    (name, username, f"{username}@example.test", generate_password_hash("test-password-123"), role, now),
                )
        self.ids = {"admin": 1, "analyst": 2, "employee": 3, "auditor": 4}
        self.tokens = {name: issue_token(user_id) for name, user_id in self.ids.items()}
        self.apps = {service: create_app(service).test_client() for service in ("users", "logs", "notifications")}
        self.identities = {
            token: {"id": user_id, "role": name_to_role(name), "account_status": "Active"}
            for name, token in self.tokens.items() for user_id in [self.ids[name]]
        }
        self.audit_patch = patch("part2.core.audit")
        self.user_audit_patch = patch("part2.users.audit")
        self.remote_patch = patch("part2.core.verify_remote_token", side_effect=lambda token: self.identities[token])
        self.audit_patch.start()
        self.user_audit_patch.start()
        self.remote_patch.start()

    def tearDown(self):
        self.remote_patch.stop()
        self.user_audit_patch.stop()
        self.audit_patch.stop()
        os.environ.pop("PROJECT_DB", None)
        os.environ.pop("SERVICE_SECRET", None)
        self.temp_dir.cleanup()

    def headers(self, user="admin"):
        return {"Authorization": f"Bearer {self.tokens[user]}"}

    def test_registration_hashes_password_and_login_returns_token(self):
        response = self.apps["users"].post(f"{PREFIX}/users/register", json={
            "full_name": "New Employee", "username": "new-user", "email": "new@example.test",
            "password": "a-long-test-password", "department": "Engineering", "role": EMPLOYEE,
        })
        self.assertEqual(response.status_code, 201)
        self.assertNotIn("password_hash", response.json["data"])
        with closing(sqlite3.connect(self.database)) as connection, connection:
            stored = connection.execute("SELECT password_hash FROM users WHERE username = 'new-user'").fetchone()[0]
        self.assertNotEqual(stored, "a-long-test-password")
        login = self.apps["users"].post(f"{PREFIX}/users/login", json={
            "email": "new@example.test", "password": "a-long-test-password",
        })
        self.assertEqual(login.status_code, 200)
        self.assertTrue(login.json["data"]["token"])

    def test_registration_rejects_privilege_escalation_and_short_password(self):
        fields = {"full_name": "Intruder", "username": "intruder", "email": "i@example.test",
                  "password": "a-long-test-password", "department": "Ops", "role": ADMIN}
        self.assertEqual(self.apps["users"].post(f"{PREFIX}/users/register", json=fields).status_code, 403)
        fields["role"] = EMPLOYEE
        fields["password"] = "short"
        self.assertEqual(self.apps["users"].post(f"{PREFIX}/users/register", json=fields).status_code, 400)

    def test_registration_rejects_duplicates_bad_email_and_unknown_fields(self):
        fields = {"full_name": "Existing", "username": "employee", "email": "other@example.test",
                  "password": "a-long-test-password", "department": "Ops", "role": EMPLOYEE}
        self.assertEqual(self.apps["users"].post(f"{PREFIX}/users/register", json=fields).status_code, 409)
        fields.update(username="new-user", email="not-an-email")
        self.assertEqual(self.apps["users"].post(f"{PREFIX}/users/register", json=fields).status_code, 400)
        fields.update(email="new@example.test", role=EMPLOYEE, unexpected="no")
        self.assertEqual(self.apps["users"].post(f"{PREFIX}/users/register", json=fields).status_code, 400)

    def test_missing_invalid_and_expired_tokens_are_rejected(self):
        route = f"{PREFIX}/users"
        self.assertEqual(self.apps["users"].get(route).status_code, 401)
        self.assertEqual(self.apps["users"].get(route, headers={"Authorization": "Bearer invalid"}).status_code, 401)
        payload = base64.urlsafe_b64encode(json.dumps({"sub": 1, "exp": 1}).encode()).decode().rstrip("=")
        signature = base64.urlsafe_b64encode(hmac.new(
            os.environ["SERVICE_SECRET"].encode(), payload.encode(), hashlib.sha256
        ).digest()).decode().rstrip("=")
        expired = f"{payload}.{signature}"
        self.assertEqual(self.apps["users"].get(route, headers={"Authorization": f"Bearer {expired}"}).status_code, 401)

    def test_missing_audit_dependency_returns_503_for_denied_request(self):
        with patch("part2.core.audit", side_effect=ApiProblem(503, "The audit logging service is unavailable")):
            response = self.apps["users"].get(f"{PREFIX}/users")
        self.assertEqual(response.status_code, 503)

    def test_internal_verification_requires_key_and_rereads_account_state(self):
        route = f"{PREFIX}/internal/verify"
        payload = {"token": self.tokens["admin"]}
        self.assertEqual(self.apps["users"].post(route, json=payload).status_code, 403)
        headers = {"X-Service-Key": os.environ["SERVICE_SECRET"]}
        self.assertEqual(self.apps["users"].post(route, json=payload, headers=headers).status_code, 200)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("UPDATE users SET account_status = 'Suspended' WHERE id = ?", (self.ids["admin"],))
        self.assertEqual(self.apps["users"].post(route, json=payload, headers=headers).status_code, 401)

    def test_profile_is_owner_scoped_and_role_changes_are_separate(self):
        endpoint = f"{PREFIX}/users/{self.ids['employee']}"
        self.assertEqual(self.apps["users"].put(endpoint, json={"department": "Finance"},
                                                 headers=self.headers("employee")).status_code, 200)
        self.assertEqual(self.apps["users"].put(endpoint, json={"role": ADMIN},
                                                 headers=self.headers("employee")).status_code, 400)
        self.assertEqual(self.apps["users"].put(endpoint, json={"full_name": "Changed"},
                                                 headers=self.headers("analyst")).status_code, 403)

    def test_role_and_status_are_reread_for_existing_tokens(self):
        endpoint = f"{PREFIX}/users/{self.ids['employee']}/role"
        changed = self.apps["users"].put(endpoint, json={"role": ANALYST}, headers=self.headers())
        self.assertEqual(changed.status_code, 200)
        self.identities[self.tokens["employee"]]["role"] = ANALYST
        self.assertEqual(self.apps["users"].get(f"{PREFIX}/users", headers=self.headers("employee")).status_code, 403)
        status_endpoint = f"{PREFIX}/users/{self.ids['employee']}/status"
        self.assertEqual(self.apps["users"].put(status_endpoint, json={"account_status": "Inactive"},
                             headers=self.headers()).status_code, 200)
        self.assertEqual(self.apps["users"].get(f"{PREFIX}/users/employee", headers=self.headers("employee")).status_code, 401)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("UPDATE users SET account_status = 'Suspended' WHERE id = ?", (self.ids["employee"],))
        self.assertEqual(self.apps["users"].get(f"{PREFIX}/users/employee", headers=self.headers("employee")).status_code, 401)

    def test_deleted_users_are_logically_removed_and_tokens_stop_working(self):
        endpoint = f"{PREFIX}/users/{self.ids['employee']}"
        self.assertEqual(self.apps["users"].delete(endpoint, headers=self.headers()).status_code, 200)
        self.assertEqual(self.apps["users"].get(f"{PREFIX}/users/employee", headers=self.headers("employee")).status_code, 401)
        self.assertEqual(self.apps["users"].get(f"{PREFIX}/users/employee", headers=self.headers()).status_code, 404)

    def test_logs_role_matrix_search_and_empty_user_results(self):
        internal = {"X-Service-Key": os.environ["SERVICE_SECRET"]}
        created = self.apps["logs"].post(f"{PREFIX}/internal/logs", json={
            "user_id": self.ids["admin"], "action": "test", "description": "created by test",
            "severity": "Information", "related_service": "Users",
        }, headers=internal)
        self.assertEqual(created.status_code, 201)
        log_id = created.json["data"]["id"]
        self.assertEqual(self.apps["logs"].get(f"{PREFIX}/logs", headers=self.headers("analyst")).status_code, 403)
        self.assertEqual(self.apps["logs"].get(f"{PREFIX}/logs/{log_id}", headers=self.headers("analyst")).status_code, 200)
        search = self.apps["logs"].get(f"{PREFIX}/logs/search?action=test", headers=self.headers("analyst"))
        self.assertEqual(len(search.json["data"]), 1)
        empty = self.apps["logs"].get(f"{PREFIX}/logs/user/999", headers=self.headers("auditor"))
        self.assertEqual(empty.status_code, 200)
        self.assertEqual(empty.json["data"], [])
        self.assertEqual(self.apps["logs"].put(f"{PREFIX}/logs/{log_id}", json={}, headers=self.headers()).status_code, 405)

    def test_internal_log_requires_service_key_and_valid_fields(self):
        route = f"{PREFIX}/internal/logs"
        payload = {"user_id": None, "action": "failed_login", "description": "unknown identity",
                   "severity": "Warning", "related_service": "Users"}
        self.assertEqual(self.apps["logs"].post(route, json=payload).status_code, 403)
        response = self.apps["logs"].post(route, json={**payload, "severity": "Urgent"},
                                           headers={"X-Service-Key": os.environ["SERVICE_SECRET"]})
        self.assertEqual(response.status_code, 400)

    def test_notification_ownership_search_and_read_timestamp(self):
        route = f"{PREFIX}/internal/notifications"
        payload = {"user_id": self.ids["employee"], "title": "Review", "message": "Please review.",
                   "notification_type": "System Notification", "severity": "Medium"}
        created = self.apps["notifications"].post(route, json=payload,
            headers={"X-Service-Key": os.environ["SERVICE_SECRET"]})
        self.assertEqual(created.status_code, 201)
        notification_id = created.json["data"]["id"]
        other_user = self.apps["notifications"].get(f"{PREFIX}/notifications/user/{self.ids['employee']}",
                                                       headers=self.headers("analyst"))
        self.assertEqual(other_user.status_code, 403)
        own = self.apps["notifications"].get(f"{PREFIX}/notifications/user/{self.ids['employee']}",
                                               headers=self.headers("employee"))
        self.assertEqual(len(own.json["data"]), 1)
        cross_user_search = self.apps["notifications"].get(
            f"{PREFIX}/notifications/search?user_id={self.ids['employee']}", headers=self.headers("analyst"))
        self.assertEqual(cross_user_search.status_code, 403)
        own_search = self.apps["notifications"].get(
            f"{PREFIX}/notifications/search?status=Unread", headers=self.headers("employee"))
        self.assertEqual(own_search.status_code, 403)
        read_route = f"{PREFIX}/notifications/{notification_id}/read"
        first = self.apps["notifications"].put(read_route, headers=self.headers("employee")).json["data"]["read_date"]
        second = self.apps["notifications"].put(read_route, headers=self.headers("employee")).json["data"]["read_date"]
        self.assertEqual(first, second)

    def test_notification_internal_recipient_validation_and_auditor_read_only(self):
        route = f"{PREFIX}/internal/notifications"
        payload = {"user_id": 999, "title": "Missing", "message": "No account",
                   "notification_type": "Security Alert", "severity": "High"}
        self.assertEqual(self.apps["notifications"].post(route, json=payload,
            headers={"X-Service-Key": os.environ["SERVICE_SECRET"]}).status_code, 404)
        self.assertEqual(self.apps["notifications"].put(f"{PREFIX}/notifications/1/read",
            headers=self.headers("auditor")).status_code, 403)
        self.assertEqual(self.apps["notifications"].get(
            f"{PREFIX}/notifications/user/{self.ids['analyst']}", headers=self.headers("analyst")).json["data"], [])
        self.assertEqual(self.apps["notifications"].get(
            f"{PREFIX}/notifications/999", headers=self.headers("auditor")).status_code, 404)


def name_to_role(name: str) -> str:
    return {"admin": ADMIN, "analyst": ANALYST, "employee": EMPLOYEE, "auditor": AUDITOR}[name]


if __name__ == "__main__":
    unittest.main()