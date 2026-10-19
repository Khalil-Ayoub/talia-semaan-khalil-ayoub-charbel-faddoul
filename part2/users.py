"""User identity and account management service."""

from __future__ import annotations

import sqlite3
from typing import Any

from flask import Blueprint, request
from werkzeug.security import check_password_hash, generate_password_hash

from part2.core import (
    ACCOUNT_STATUSES, EMAIL_PATTERN, ROLES, ApiProblem, audit, check_role,
    database, failure, issue_token, parse_json, principal, require_choice, require_text,
    success, token_user, utc_now,
)

ADMIN = ("Security Administrator",)
READ_USERS = ("Security Administrator", "Auditor")
PUBLIC_ROLE = "Regular Employee/User"
PROFILE_FIELDS = {"full_name", "email", "department"}


def safe_user(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    keys = ("id", "full_name", "username", "email", "department", "role", "account_status", "created_date", "last_login_date")
    return {key: row[key] for key in keys}


class UserService:
    def create(self, body: dict[str, Any], actor: dict[str, Any] | None) -> dict[str, Any]:
        full_name = require_text(body, "full_name", 120)
        username = require_text(body, "username", 80)
        email = require_text(body, "email", 254).lower()
        password = body.get("password")
        department = require_text(body, "department", 100)
        role = require_choice(body.get("role"), "role", ROLES)
        if not EMAIL_PATTERN.fullmatch(email):
            raise ApiProblem(400, "email must be a valid email address")
        if not isinstance(password, str) or len(password) < 12:
            raise ApiProblem(400, "password must contain at least 12 characters")
        if role != PUBLIC_ROLE and (actor is None or actor.get("role") != "Security Administrator"):
            audit(actor["id"] if actor else None, "authorization_rejected",
                  "Public registration attempted to create a privileged account", "Warning")
            raise ApiProblem(403, "Only an authenticated Security Administrator may create privileged accounts")
        with database() as connection:
            duplicate = connection.execute(
                "SELECT id FROM users WHERE lower(username) = lower(?) OR lower(email) = lower(?)",
                (username, email),
            ).fetchone()
        if duplicate:
            raise ApiProblem(409, "Username or email is already registered")
        audit(actor["id"] if actor else None, "user_creation_requested", f"Account creation requested for username {username}")
        try:
            with database() as connection:
                cursor = connection.execute(
                    "INSERT INTO users (full_name, username, email, password_hash, department, role, account_status, created_date) "
                    "VALUES (?, ?, ?, ?, ?, ?, 'Active', ?)",
                    (full_name, username, email, generate_password_hash(password), department, role, utc_now()),
                )
                return safe_user(connection.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone())
        except sqlite3.IntegrityError:
            raise ApiProblem(409, "Username or email is already registered") from None

    def login(self, body: dict[str, Any]) -> dict[str, Any]:
        password = body.get("password")
        identifier = body.get("username", body.get("email"))
        if not isinstance(identifier, str) or not identifier.strip() or not isinstance(password, str):
            audit(None, "login_failed", "Login attempt rejected: missing username/email or password", "Warning")
            raise ApiProblem(400, "username (or email) and password are required")
        with database() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE lower(username) = lower(?) OR lower(email) = lower(?)",
                (identifier.strip(), identifier.strip()),
            ).fetchone()
            valid = (row is not None and row["deleted_at"] is None and row["account_status"] == "Active"
                     and check_password_hash(row["password_hash"], password))
            if not valid:
                audit(row["id"] if row else None, "login_failed", "Login attempt failed for the supplied account", "Warning")
                raise ApiProblem(401, "Invalid credentials or inactive account")
            user = safe_user(row)
            token = issue_token(row["id"])
            audit(row["id"], "login_succeeded", "Successful user login")
            last_login = utc_now()
            connection.execute("UPDATE users SET last_login_date = ? WHERE id = ?", (last_login, row["id"]))
            user["last_login_date"] = last_login
            return {"token": token, "user": user}

    def get_by_username(self, username: str, actor: dict[str, Any]) -> dict[str, Any]:
        if actor["role"] not in READ_USERS and not (
            actor["role"] == PUBLIC_ROLE and actor["username"].lower() == username.lower()
        ):
            check_role(actor, READ_USERS + (PUBLIC_ROLE,))
        with database() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE lower(username) = lower(?) AND deleted_at IS NULL", (username,)
            ).fetchone()
            if row is None:
                raise ApiProblem(404, "User not found")
            if actor["role"] == PUBLIC_ROLE and row["id"] != actor["id"]:
                check_role(actor, READ_USERS)
            return safe_user(row)

    def update_profile(self, user_id: int, body: dict[str, Any], actor: dict[str, Any]) -> dict[str, Any]:
        if actor["role"] == PUBLIC_ROLE:
            if actor["id"] != user_id:
                check_role(actor, ADMIN)
        elif actor["role"] != "Security Administrator":
            check_role(actor, ADMIN)
        if not body or set(body) - PROFILE_FIELDS:
            raise ApiProblem(400, "Only full_name, email, and department may be updated here")
        values = {field: require_text(body, field, 254 if field == "email" else 120) for field in body}
        if "email" in values:
            values["email"] = values["email"].lower()
            if not EMAIL_PATTERN.fullmatch(values["email"]):
                raise ApiProblem(400, "email must be a valid email address")
        with database() as connection:
            current = connection.execute("SELECT id FROM users WHERE id = ? AND deleted_at IS NULL", (user_id,)).fetchone()
            if current is None:
                raise ApiProblem(404, "User not found")
            if "email" in values and connection.execute(
                "SELECT id FROM users WHERE lower(email) = lower(?) AND id <> ? AND deleted_at IS NULL",
                (values["email"], user_id),
            ).fetchone():
                raise ApiProblem(409, "Email is already registered")
        audit(actor["id"], "user_update_requested", f"Profile update requested for user {user_id}")
        assignments = ", ".join(f"{field} = ?" for field in values)
        try:
            with database() as connection:
                connection.execute(f"UPDATE users SET {assignments} WHERE id = ?", (*values.values(), user_id))
                return safe_user(connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone())
        except sqlite3.IntegrityError:
            raise ApiProblem(409, "The profile conflicts with an existing account") from None

    def delete(self, user_id: int, actor: dict[str, Any]) -> None:
        check_role(actor, ADMIN)
        with database() as connection:
            if not connection.execute("SELECT id FROM users WHERE id = ? AND deleted_at IS NULL", (user_id,)).fetchone():
                raise ApiProblem(404, "User not found")
        audit(actor["id"], "user_deletion_requested", f"Logical deletion requested for user {user_id}", "Warning")
        with database() as connection:
            connection.execute("UPDATE users SET deleted_at = ? WHERE id = ?", (utc_now(), user_id))

    def list_users(self) -> list[dict[str, Any]]:
        with database() as connection:
            return [safe_user(row) for row in connection.execute(
                "SELECT * FROM users WHERE deleted_at IS NULL ORDER BY id"
            ).fetchall()]

    def set_role(self, user_id: int, role: str, actor: dict[str, Any]) -> dict[str, Any]:
        check_role(actor, ADMIN)
        require_choice(role, "role", ROLES)
        return self._set_account_field(user_id, "role", role, actor)

    def set_status(self, user_id: int, status: str, actor: dict[str, Any]) -> dict[str, Any]:
        check_role(actor, ADMIN)
        require_choice(status, "account_status", ACCOUNT_STATUSES)
        return self._set_account_field(user_id, "account_status", status, actor)

    def _set_account_field(self, user_id: int, field: str, value: str, actor: dict[str, Any]) -> dict[str, Any]:
        with database() as connection:
            if not connection.execute("SELECT id FROM users WHERE id = ? AND deleted_at IS NULL", (user_id,)).fetchone():
                raise ApiProblem(404, "User not found")
        audit(actor["id"], f"user_{field}_change_requested", f"{field} change requested for user {user_id}")
        with database() as connection:
            connection.execute(f"UPDATE users SET {field} = ? WHERE id = ?", (value, user_id))
            return safe_user(connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone())


def _actor() -> dict[str, Any]:
    with database() as connection:
        return principal(connection)


def register_user_routes(blueprint: Blueprint) -> None:
    service = UserService()

    @blueprint.post("/users/register")
    def register():
        fields = {"full_name", "username", "email", "password", "department", "role"}
        body = parse_json(fields, fields)
        actor = _actor() if request.headers.get("Authorization") else None
        return success(service.create(body, actor), 201)

    @blueprint.post("/users/login")
    def login():
        try:
            body = parse_json({"username", "email", "password"}, {"password"})
            if ("username" in body) == ("email" in body):
                raise ApiProblem(400, "Provide exactly one of username or email")
        except ApiProblem:
            audit(None, "login_failed", "Login attempt rejected: invalid request", "Warning")
            raise
        return success(service.login(body))

    @blueprint.get("/users")
    def list_users():
        check_role(_actor(), READ_USERS)
        return success(service.list_users())

    @blueprint.get("/users/id/<int:user_id>")
    def get_by_id(user_id: int):
        check_role(_actor(), READ_USERS)
        with database() as connection:
            row = connection.execute("SELECT * FROM users WHERE id = ? AND deleted_at IS NULL", (user_id,)).fetchone()
            if row is None:
                raise ApiProblem(404, "User not found")
            return success(safe_user(row))

    @blueprint.put("/users/<int:user_id>/role")
    def set_role(user_id: int):
        actor = _actor()
        body = parse_json({"role"}, {"role"})
        return success(service.set_role(user_id, body["role"], actor))

    @blueprint.put("/users/<int:user_id>/status")
    def set_status(user_id: int):
        actor = _actor()
        body = parse_json({"account_status"}, {"account_status"})
        return success(service.set_status(user_id, body["account_status"], actor))

    @blueprint.put("/users/<int:user_id>")
    def update_user(user_id: int):
        actor = _actor()
        return success(service.update_profile(user_id, parse_json(PROFILE_FIELDS), actor))

    @blueprint.delete("/users/<int:user_id>")
    def delete_user(user_id: int):
        service.delete(user_id, _actor())
        return success({"deleted_id": user_id})

    @blueprint.get("/users/<username>")
    def get_by_username(username: str):
        return success(service.get_by_username(username, _actor()))

    @blueprint.post("/internal/verify")
    def verify_token():
        from part2.core import internal_request_allowed
        if not internal_request_allowed():
            return failure("Invalid service key", 403)
        body = parse_json({"token"}, {"token"})
        if not isinstance(body["token"], str) or not body["token"]:
            raise ApiProblem(400, "token must be a non-empty string")
        try:
            with database() as connection:
                user = token_user(connection, body["token"])
        except ApiProblem:
            audit(None, "token_verification_failed", "Internal token verification failed", "Warning")
            raise ApiProblem(401, "Invalid, expired, or inactive token") from None
        data = {key: user[key] for key in ("id", "full_name", "role", "account_status")}
        return success(data)

    @blueprint.get("/internal/users/<int:user_id>")
    def internal_user(user_id: int):
        from part2.core import internal_request_allowed, require_id
        if not internal_request_allowed():
            return failure("Invalid service key", 403)
        require_id(user_id, "user_id")
        with database() as connection:
            row = connection.execute(
                "SELECT id, role, account_status, deleted_at FROM users WHERE id=? AND deleted_at IS NULL",
                (user_id,),
            ).fetchone()
            if row is None:
                raise ApiProblem(404, "User not found")
            return success(dict(row))
