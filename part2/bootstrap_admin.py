"""Create the first administrator from an explicit local CLI invocation."""

from __future__ import annotations

import getpass
import os
import re
import sqlite3
from argparse import ArgumentParser

from werkzeug.security import generate_password_hash

from part2.core import EMAIL_PATTERN, ApiProblem, audit, database, utc_now


def main() -> None:
    parser = ArgumentParser(description="Bootstrap the initial Security Administrator")
    parser.add_argument("--full-name", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--department", required=True)
    args = parser.parse_args()
    email = args.email.strip().lower()
    if not EMAIL_PATTERN.fullmatch(email):
        parser.error("--email must be a valid email address")
    password = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD") or getpass.getpass("Initial administrator password: ")
    if len(password) < 12:
        parser.error("the bootstrap password must contain at least 12 characters")
    with database() as connection:
        exists = connection.execute(
            "SELECT id FROM users WHERE role = 'Security Administrator' AND deleted_at IS NULL"
        ).fetchone()
        duplicate = connection.execute(
            "SELECT id FROM users WHERE lower(username) = lower(?) OR lower(email) = lower(?)",
            (args.username, email),
        ).fetchone()
    if exists:
        parser.error("an active administrator already exists")
    if duplicate:
        parser.error("username or email is already registered")
    try:
        audit(None, "bootstrap_admin_requested", "Initial administrator account creation requested")
        with database() as connection:
            connection.execute(
                "INSERT INTO users (full_name, username, email, password_hash, department, role, account_status, created_date) "
                "VALUES (?, ?, ?, ?, ?, 'Security Administrator', 'Active', ?)",
                (args.full_name.strip(), args.username.strip(), email,
                 generate_password_hash(password), args.department.strip(), utc_now()),
            )
    except sqlite3.IntegrityError:
        parser.error("username or email is already registered")
    except ApiProblem as error:
        parser.error(str(error))
    print("Initial Security Administrator created.")


if __name__ == "__main__":
    main()