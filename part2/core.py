"""Shared validation, persistence, authentication, and service-call helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests
from flask import jsonify, request

ROLES = ("Security Administrator", "Security Analyst", "Regular Employee/User", "Auditor")
ACCOUNT_STATUSES = ("Active", "Inactive", "Suspended")
SEVERITIES = ("Low", "Medium", "High", "Critical")
LOG_SEVERITIES = ("Information", "Warning", "Error", "Critical")
NOTIFICATION_TYPES = (
    "Incident Assignment", "Security Alert", "System Notification",
    "Threat Alert", "Vulnerability Alert",
)
NOTIFICATION_STATUSES = ("Unread", "Read")
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class ApiProblem(Exception):
    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code


def success(data: Any, status_code: int = 200):
    return jsonify({"status": "success", "data": data}), status_code


def failure(message: str, status_code: int):
    return jsonify({"status": "error", "message": message}), status_code


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_json(allowed: set[str], required: set[str] | None = None) -> dict[str, Any]:
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ApiProblem(400, "A JSON object is required")
    unknown = set(body) - allowed
    missing = (required or set()) - set(body)
    if unknown:
        raise ApiProblem(400, f"Unknown field: {sorted(unknown)[0]}")
    if missing:
        raise ApiProblem(400, f"Missing required field: {sorted(missing)[0]}")
    return body


def require_text(body: dict[str, Any], name: str, maximum: int = 255) -> str:
    value = body.get(name)
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > maximum:
        raise ApiProblem(400, f"{name} must be a non-empty string of at most {maximum} characters")
    return value.strip()


def require_choice(value: Any, name: str, choices: tuple[str, ...]) -> str:
    if not isinstance(value, str) or value not in choices:
        raise ApiProblem(400, f"{name} must be one of: {', '.join(choices)}")
    return value


def get_db() -> sqlite3.Connection:
    database = Path(os.environ.get("PROJECT_DB", Path.cwd() / "data" / "project.db"))
    if not database.exists():
        raise ApiProblem(503, "The shared project database is not initialized")
    connection = sqlite3.connect(database, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def database():
    connection = get_db()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def service_secret() -> str:
    secret = os.environ.get("SERVICE_SECRET", "")
    if len(secret) < 32:
        raise ApiProblem(503, "SERVICE_SECRET must be configured with at least 32 characters")
    return secret


def internal_request_allowed() -> bool:
    supplied = request.headers.get("X-Service-Key", "")
    try:
        expected = service_secret()
    except ApiProblem:
        return False
    return hmac.compare_digest(supplied, expected)


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def issue_token(user_id: int) -> str:
    secret = service_secret().encode("utf-8")
    claims = {"sub": user_id, "exp": int((datetime.now(timezone.utc) + timedelta(hours=8)).timestamp())}
    payload = _encode(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    signature = _encode(hmac.new(secret, payload.encode("ascii"), hashlib.sha256).digest())
    return f"{payload}.{signature}"


def token_user(connection: sqlite3.Connection, token: str) -> dict[str, Any]:
    try:
        payload, signature = token.split(".", 1)
        expected = _encode(hmac.new(service_secret().encode("utf-8"), payload.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise ValueError
        claims = json.loads(_decode(payload))
        if not isinstance(claims.get("sub"), int) or claims["exp"] <= int(datetime.now(timezone.utc).timestamp()):
            raise ValueError
        row = connection.execute(
            "SELECT id, full_name, username, email, department, role, account_status, deleted_at "
            "FROM users WHERE id = ?",
            (claims["sub"],),
        ).fetchone()
        if row is None or row["deleted_at"] is not None or row["account_status"] != "Active":
            raise ValueError
        return dict(row)
    except (ApiProblem, ValueError, TypeError, KeyError, OverflowError, json.JSONDecodeError, sqlite3.Error):
        raise ApiProblem(401, "Missing, invalid, or expired bearer token") from None


def bearer_token() -> str:
    header = request.headers.get("Authorization", "")
    scheme, separator, token = header.partition(" ")
    if not separator or scheme.lower() != "bearer" or not token.strip():
        raise ApiProblem(401, "A bearer token is required")
    return token.strip()


def service_url(service: str, endpoint: str) -> str:
    try:
        from common.runtime import url
        return url(service, '/' + endpoint.lstrip('/'))
    except (ImportError, TypeError, AttributeError):
        try:
            config = json.loads(Path("team_config.json").read_text(encoding="utf-8"))
            owner = config["owners"]["part2"]
            slug = "-".join(owner.lower().split())
            port = config["ports"][service]
            return f"http://127.0.0.1:{port}/{slug}/{endpoint.lstrip('/')}"
        except (OSError, KeyError, json.JSONDecodeError):
            raise ApiProblem(503, "Service routing configuration is unavailable") from None


def verify_remote_token(token: str) -> dict[str, Any]:
    try:
        response = requests.post(
            service_url("users", "internal/verify"),
            json={"token": token},
            headers={"X-Service-Key": service_secret()},
            timeout=3,
        )
    except (requests.RequestException, ApiProblem):
        raise ApiProblem(503, "The identity service is unavailable") from None
    if response.status_code == 401:
        raise ApiProblem(401, "Missing, invalid, or expired bearer token")
    if response.status_code != 200:
        raise ApiProblem(503, "The identity service could not verify this request")
    try:
        data = response.json()["data"]
        if not isinstance(data, dict) or data.get("account_status") != "Active":
            raise ValueError
        return data
    except (ValueError, KeyError, TypeError):
        raise ApiProblem(503, "The identity service returned an invalid response") from None


def audit(user_id: int | None, action: str, description: str, severity: str = "Information", related_service: str = "users") -> None:
    try:
        response = requests.post(
            service_url("logs", "internal/logs"),
            json={"user_id": user_id, "action": action, "description": description,
                  "severity": severity, "related_service": related_service},
            headers={"X-Service-Key": service_secret()}, timeout=3,
        )
    except (requests.RequestException, ApiProblem):
        raise ApiProblem(503, "The audit logging service is unavailable") from None
    if response.status_code not in (200, 201):
        raise ApiProblem(503, "The audit logging service rejected the record")


def create_notification(user_id: int, title: str, message: str, kind: str, severity: str) -> dict[str, Any] | None:
    try:
        response = requests.post(
            service_url("notifications", "internal/notifications"),
            json={"user_id": user_id, "title": title, "message": message,
                  "notification_type": kind, "severity": severity},
            headers={"X-Service-Key": service_secret()}, timeout=3,
        )
    except (requests.RequestException, ApiProblem):
        return None
    if response.status_code not in (200, 201):
        return None
    try:
        return response.json()["data"]
    except (ValueError, KeyError, TypeError):
        return None


def require_role(user: dict[str, Any], allowed: tuple[str, ...]) -> None:
    if user.get("role") not in allowed:
        raise ApiProblem(403, "User does not have permission to perform this operation")


def principal(connection: sqlite3.Connection, remote: bool = False) -> dict[str, Any]:
    try:
        token = bearer_token()
        return verify_remote_token(token) if remote else token_user(connection, token)
    except ApiProblem as error:
        audit(None, "authentication_rejected", "Protected request rejected: authentication failed", "Warning")
        raise error


def check_role(user: dict[str, Any], allowed: tuple[str, ...]) -> None:
    try:
        require_role(user, allowed)
    except ApiProblem:
        audit(user.get("id"), "authorization_rejected", "Protected request rejected: insufficient role", "Warning")
        raise


def handle_problem(error: ApiProblem):
    return failure(str(error), error.status_code)

def require_id(value: Any, name: str = "id") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2**63-1:
        raise ApiProblem(400, f"{name} must be an integer between 1 and {2**63-1}")
    return value
