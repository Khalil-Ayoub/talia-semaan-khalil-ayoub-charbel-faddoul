"""User notification storage and read-state management."""

from __future__ import annotations

import sqlite3

from flask import Blueprint, request
from part2 import core

from part2.core import (
    NOTIFICATION_STATUSES, NOTIFICATION_TYPES, SEVERITIES, ApiProblem,
    database, internal_request_allowed, parse_json, principal, require_choice,
    require_text, success, utc_now, require_id,
)

ADMIN = ("Security Administrator",)
READ_ANY = ("Security Administrator", "Auditor")
RECIPIENT_ROLES = ("Security Analyst", "Regular Employee/User")
SEARCH_ROLES = ("Security Administrator", "Security Analyst", "Auditor")
FILTER_FIELDS = {"user_id", "notification_type", "severity", "status"}


class NotificationService:
    def create(self, body: dict, actor_id: int | None = None) -> dict:
        user_id = body.get("user_id")
        require_id(user_id, "user_id")
        title = require_text(body, "title", 200)
        message = require_text(body, "message", 4000)
        notification_type = require_choice(body.get("notification_type"), "notification_type", NOTIFICATION_TYPES)
        severity = require_choice(body.get("severity"), "severity", SEVERITIES)
        created = utc_now()
        try:
            with database() as connection:
                recipient = connection.execute(
                    "SELECT id FROM users WHERE id = ? AND deleted_at IS NULL AND account_status = 'Active'",
                    (user_id,),
                ).fetchone()
                if recipient is None:
                    raise ApiProblem(404, "Notification recipient not found or inactive")
            core.audit(actor_id, "notification_creation_requested", f"Notification creation for user {user_id} requested", related_service="notifications")
            with database() as connection:
                cursor = connection.execute(
                    "INSERT INTO notifications (user_id, title, message, notification_type, severity, status, creation_date, read_date) "
                    "VALUES (?, ?, ?, ?, ?, 'Unread', ?, NULL)",
                    (user_id, title, message, notification_type, severity, created),
                )
                return dict(connection.execute("SELECT * FROM notifications WHERE id = ?", (cursor.lastrowid,)).fetchone())
        except sqlite3.IntegrityError:
            raise ApiProblem(409, "Notification could not be stored due to a relationship conflict") from None

    def list_for_user(self, user_id: int) -> list[dict]:
        with database() as connection:
            return [dict(row) for row in connection.execute(
                "SELECT * FROM notifications WHERE user_id = ? ORDER BY creation_date DESC, id DESC", (user_id,)
            ).fetchall()]

    def get(self, notification_id: int) -> dict:
        with database() as connection:
            row = connection.execute("SELECT * FROM notifications WHERE id = ?", (notification_id,)).fetchone()
            if row is None:
                raise ApiProblem(404, "Notification not found")
            return dict(row)

    def mark_read(self, notification_id: int, actor_id: int | None = None) -> dict:
        require_id(notification_id)
        current = self.get(notification_id)
        if current["status"] != "Read":
            core.audit(actor_id, "notification_read_requested", f"Mark notification {notification_id} as read requested", related_service="notifications")
        with database() as connection:
            row = connection.execute("SELECT * FROM notifications WHERE id = ?", (notification_id,)).fetchone()
            if row is None:
                raise ApiProblem(404, "Notification not found")
            if row["status"] != "Read":
                connection.execute(
                    "UPDATE notifications SET status = 'Read', read_date = ? WHERE id = ? AND status <> 'Read'",
                    (utc_now(), notification_id),
                )
            return dict(connection.execute("SELECT * FROM notifications WHERE id = ?", (notification_id,)).fetchone())

    def search(self, filters: dict[str, str], user: dict) -> list[dict]:
        unknown = set(filters) - FILTER_FIELDS
        if unknown:
            raise ApiProblem(400, f"Unknown search filter: {sorted(unknown)[0]}")
        role = user["role"]
        if role not in SEARCH_ROLES:
            from part2.core import check_role
            check_role(user, SEARCH_ROLES)
        clauses = []
        parameters: list[object] = []
        if role == "Security Analyst":
            clauses.append("user_id = ?")
            parameters.append(user["id"])
            if "user_id" in filters and filters["user_id"] != str(user["id"]):
                from part2.core import check_role
                check_role(user, ADMIN)
        for key, value in filters.items():
            if key == "user_id":
                try:
                    user_id = int(value)
                except ValueError:
                    raise ApiProblem(400, "user_id must be an integer") from None
                if user_id <= 0:
                    raise ApiProblem(400, "user_id must be a positive integer")
                require_id(user_id, "user_id")
                clauses.append("user_id = ?")
                parameters.append(user_id)
            elif key == "notification_type":
                clauses.append("notification_type = ?")
                parameters.append(require_choice(value, key, NOTIFICATION_TYPES))
            elif key == "severity":
                clauses.append("severity = ?")
                parameters.append(require_choice(value, key, SEVERITIES))
            else:
                clauses.append("status = ?")
                parameters.append(require_choice(value, key, NOTIFICATION_STATUSES))
        sql = "SELECT * FROM notifications"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY creation_date DESC, id DESC"
        with database() as connection:
            return [dict(row) for row in connection.execute(sql, parameters).fetchall()]

    def delete(self, notification_id: int, actor_id: int | None = None) -> None:
        notification = self.get(notification_id)
        core.audit(actor_id, "notification_deletion_requested", f"Notification {notification_id} deletion requested", related_service="notifications")
        with database() as connection:
            cursor = connection.execute("DELETE FROM notifications WHERE id = ?", (notification_id,))
            if cursor.rowcount == 0:
                raise ApiProblem(404, "Notification not found")


def _actor() -> dict:
    return principal(None, remote=True)


def _can_view(user: dict, recipient_id: int) -> bool:
    return user["role"] in READ_ANY or (
        user["role"] in RECIPIENT_ROLES and user["id"] == recipient_id
    )


def register_notification_routes(blueprint: Blueprint) -> None:
    service = NotificationService()

    @blueprint.post("/internal/notifications")
    def internal_create():
        if not internal_request_allowed():
            return {"status": "error", "message": "Invalid service key"}, 403
        fields = {"user_id", "title", "message", "notification_type", "severity"}
        return success(service.create(parse_json(fields, fields)), 201)

    @blueprint.post("/notifications")
    def create_notification():
        from part2.core import check_role
        actor = _actor()
        check_role(actor, ADMIN)
        fields = {"user_id", "title", "message", "notification_type", "severity"}
        return success(service.create(parse_json(fields, fields), actor["id"]), 201)

    @blueprint.get("/notifications/user/<int:user_id>")
    def list_notifications(user_id: int):
        from part2.core import check_role
        actor = _actor()
        if not _can_view(actor, user_id):
            check_role(actor, READ_ANY)
        return success(service.list_for_user(user_id))

    @blueprint.get("/notifications/search")
    def search_notifications():
        return success(service.search(request.args.to_dict(), _actor()))

    @blueprint.get("/notifications/<int:notification_id>")
    def get_notification(notification_id: int):
        from part2.core import check_role
        actor = _actor()
        notification = service.get(notification_id)
        if not _can_view(actor, notification["user_id"]):
            check_role(actor, READ_ANY)
        return success(notification)

    @blueprint.put("/notifications/<int:notification_id>/read")
    def mark_read(notification_id: int):
        from part2.core import check_role
        actor = _actor()
        if actor["role"] not in ADMIN + RECIPIENT_ROLES:
            check_role(actor, ADMIN + RECIPIENT_ROLES)
        notification = service.get(notification_id)
        if actor["role"] != "Security Administrator" and notification["user_id"] != actor["id"]:
            check_role(actor, ADMIN)
        return success(service.mark_read(notification_id, actor["id"]))

    @blueprint.delete("/notifications/<int:notification_id>")
    def delete_notification(notification_id: int):
        from part2.core import check_role
        actor = _actor()
        check_role(actor, ADMIN)
        service.delete(notification_id, actor["id"])
        return success({"deleted_id": notification_id})
