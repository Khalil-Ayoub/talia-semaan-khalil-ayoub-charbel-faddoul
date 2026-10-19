"""Append-only audit logging service."""

from __future__ import annotations

import sqlite3
from datetime import date

from flask import Blueprint, request

from part2.core import (
    LOG_SEVERITIES, ApiProblem, database, internal_request_allowed, parse_json,
    principal, require_choice, require_text, success, utc_now, require_id,
)

ADMIN_AUDITOR = ("Security Administrator", "Auditor")
SEARCH_ROLES = ADMIN_AUDITOR + ("Security Analyst",)
FILTERS = {"user_id", "date", "action", "severity", "related_service"}


class LogService:
    def insert(self, body: dict, internal: bool = False) -> dict:
        user_id = body.get("user_id")
        if user_id is not None and (not isinstance(user_id, int) or isinstance(user_id, bool) or user_id <= 0):
            raise ApiProblem(400, "user_id must be a positive integer or null")
        if user_id is not None:
            require_id(user_id, "user_id")
        action = require_text(body, "action", 100)
        description = require_text(body, "description", 2000)
        severity = require_choice(body.get("severity"), "severity", LOG_SEVERITIES)
        related_service = require_text(body, "related_service", 80)
        timestamp = utc_now()
        try:
            with database() as connection:
                cursor = connection.execute(
                    "INSERT INTO logs (user_id, action, description, timestamp, severity, related_service) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (user_id, action, description, timestamp, severity, related_service),
                )
                row = connection.execute("SELECT * FROM logs WHERE id = ?", (cursor.lastrowid,)).fetchone()
                return dict(row)
        except sqlite3.IntegrityError:
            raise ApiProblem(409, "The log references an invalid user or violates a database constraint") from None

    def list(self) -> list[dict]:
        with database() as connection:
            return [dict(row) for row in connection.execute("SELECT * FROM logs ORDER BY timestamp DESC, id DESC").fetchall()]

    def get(self, log_id: int) -> dict:
        with database() as connection:
            row = connection.execute("SELECT * FROM logs WHERE id = ?", (log_id,)).fetchone()
            if row is None:
                raise ApiProblem(404, "Log not found")
            return dict(row)

    def search(self, filters: dict[str, str]) -> list[dict]:
        unknown = set(filters) - FILTERS
        if unknown:
            raise ApiProblem(400, f"Unknown search filter: {sorted(unknown)[0]}")
        clauses = []
        parameters: list[object] = []
        for key, value in filters.items():
            if key == "user_id":
                try:
                    parsed = int(value)
                except ValueError:
                    raise ApiProblem(400, "user_id must be an integer") from None
                if parsed <= 0:
                    raise ApiProblem(400, "user_id must be a positive integer")
                require_id(parsed, "user_id")
                clauses.append("user_id = ?")
                parameters.append(parsed)
            elif key == "severity":
                clauses.append("severity = ?")
                parameters.append(require_choice(value, "severity", LOG_SEVERITIES))
            elif key == "date":
                try:
                    date.fromisoformat(value)
                except ValueError:
                    raise ApiProblem(400, "date must use YYYY-MM-DD")
                clauses.append("substr(timestamp, 1, 10) = ?")
                parameters.append(value)
            else:
                if not value.strip():
                    raise ApiProblem(400, f"{key} cannot be empty")
                clauses.append(f"{key} LIKE ?")
                parameters.append(f"%{value.strip()}%")
        query = "SELECT * FROM logs"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY timestamp DESC, id DESC"
        with database() as connection:
            return [dict(row) for row in connection.execute(query, parameters).fetchall()]

    def by_user(self, user_id: int) -> list[dict]:
        with database() as connection:
            return [dict(row) for row in connection.execute(
                "SELECT * FROM logs WHERE user_id = ? ORDER BY timestamp DESC, id DESC", (user_id,)
            ).fetchall()]

    def delete(self, log_id: int) -> None:
        with database() as connection:
            cursor = connection.execute("DELETE FROM logs WHERE id = ?", (log_id,))
            if cursor.rowcount == 0:
                raise ApiProblem(404, "Log not found")


def _actor() -> dict:
    return principal(None, remote=True)


def register_log_routes(blueprint: Blueprint) -> None:
    service = LogService()

    @blueprint.post("/internal/logs")
    def internal_create():
        if not internal_request_allowed():
            return {"status": "error", "message": "Invalid service key"}, 403
        body = parse_json({"user_id", "action", "description", "severity", "related_service"},
                          {"user_id", "action", "description", "severity", "related_service"})
        return success(service.insert(body, internal=True), 201)

    @blueprint.post("/logs")
    def create_log():
        actor = _actor()
        if actor["role"] != "Security Administrator":
            from part2.core import check_role
            check_role(actor, ("Security Administrator",))
        body = parse_json({"user_id", "action", "description", "severity", "related_service"},
                          {"user_id", "action", "description", "severity", "related_service"})
        return success(service.insert(body), 201)

    @blueprint.get("/logs")
    def list_logs():
        from part2.core import check_role
        check_role(_actor(), ADMIN_AUDITOR)
        return success(service.list())

    @blueprint.get("/logs/search")
    def search_logs():
        from part2.core import check_role
        check_role(_actor(), SEARCH_ROLES)
        return success(service.search(request.args.to_dict()))

    @blueprint.get("/logs/user/<int:user_id>")
    def user_logs(user_id: int):
        from part2.core import check_role
        check_role(_actor(), ADMIN_AUDITOR)
        return success(service.by_user(user_id))

    @blueprint.get("/logs/<int:log_id>")
    def get_log(log_id: int):
        from part2.core import check_role
        check_role(_actor(), SEARCH_ROLES)
        return success(service.get(log_id))

    @blueprint.delete("/logs/<int:log_id>")
    def delete_log(log_id: int):
        from part2.core import check_role
        check_role(_actor(), ("Security Administrator",))
        service.delete(log_id)
        return success({"deleted_id": log_id})