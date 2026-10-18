# Security Incident Detection and Response Management Backend

Python, Flask and SQLite backend for reporting, investigating and responding to security incidents. Services communicate through HTTP APIs and enforce role-based permissions.

## Responsibilities

| Member | Services | Branch |
|---|---|---|
| Khalil Ayoub | Assets, Threat Intelligence, Vulnerabilities | khalil |
| Talia Semaan | Users and Identity, Audit Logging, Notifications | talia |
| Charbel Faddoul | Incidents, Security Reports, Playbooks | charbel |

Shared runtime, database schema and API conventions are in common/ and TEAM_CONTRACT.md. Each member develops assigned services on their branch and submits a pull request to main. Extract all three personal parts alongside the shared files before running the complete system.

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

## Complete system startup

1. Install requirements in your virtual environment.
2. Set SERVICE_SECRET to a local random value of at least 32 characters.
3. Run `python run_services.py` to start all nine processes.
4. In another terminal with the same secret, run `python -m part2.bootstrap_admin --full-name "Admin Name" --username admin --email admin@example.test --department Security` and enter a local password of at least 12 characters.
5. Log in through Postman and use the returned bearer token. Create accounts with each required role before exercising permission scenarios.

The launcher stops all services together on Ctrl+C. Login action labels are coordinated by default; activity reports need no extra environment settings.

Run all tests with `python -m unittest discover -s tests -p "test_*.py" -v`. The full-system test uses all nine actual applications, real HTTP, real password verification and temporary SQLite. These automated checks do not replace the final Postman and database screenshots.
