# Security Incident Detection and Response Management Backend

Python, Flask and SQLite backend for reporting, investigating and responding to security incidents. Services communicate through HTTP APIs and enforce role-based permissions.

## Responsibilities

| Member | Services | Branch |
|---|---|---|
| Khalil Ayoub | Assets, Threat Intelligence, Vulnerabilities | khalil |
| Talia Semaan | Users and Identity, Audit Logging, Notifications | talia |
| Charbel Faddoul | Incidents, Security Reports, Playbooks | charbel |

Shared runtime, database schema and API conventions are in common/ and TEAM_CONTRACT.md. Each member develops assigned services on their branch and submits a pull request to main. Implementations are being integrated; shared starter files alone are not a complete running system.

## Setup

Use Python 3.11 or later. Create an environment with `python -m venv .venv`, then install dependencies with `.venv/Scripts/python.exe -m pip install -r requirements.txt`. Some Python distributions use `.venv/bin/python.exe` instead.

Configure the same SERVICE_SECRET environment variable in every service terminal. Generate a local random value with `python -c "import secrets; print(secrets.token_hex(32))"`. Never commit secrets. Identity authentication configuration is documented by the Users service.

All processes share data/project.db. If PROJECT_DB is set, use the same absolute path in every process. The runtime initializes the schema with foreign keys enabled.

## Running services

Run each available service in a separate terminal from the repository root, for example `python -m part1.app assets` using the environment's Python interpreter.

| Module | Service arguments | Ports |
|---|---|---|
| part1.app | assets, threats, vulnerabilities | 5002, 5004, 5007 |
| part2.app | users, logs, notifications | 5001, 5005, 5008 |
| part3.app | incidents, reports, playbooks | 5003, 5006, 5009 |

Start the identity, logging and notification dependencies before exercising protected operations. Bootstrap the initial administrator using the Users service's documented CLI and obtain a bearer token through login.

API routes start with the owner's full name from team_config.json, for example /khalil-ayoub/assets. Protected public routes require Authorization: Bearer TOKEN. Internal routes require X-Service-Key.

## Testing

As implementations are added, run their tests, for example `python -m unittest tests.test_part1 -v`. Isolated tests may substitute external service dependencies; run integration checks against all real services separately. Postman collections and API documentation are stored in each member's owned paths listed in TEAM_CONTRACT.md.
