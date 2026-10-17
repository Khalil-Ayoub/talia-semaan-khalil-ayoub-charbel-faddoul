# Security Incident Detection and Response Management Backend

Part 1 owns Asset Management (2), Threat Intelligence (4), and Vulnerability Management (7). Part 2 and Part 3 are implemented by the other team members. Read `TEAM_CONTRACT.md` before sending work to another Codex session.

## Send to colleagues

The organized package is `deliveries/final-package/`:

- `khalil ayoub.zip`: Part 1 code, tests, Postman files and report notes.
- `talia semaan.zip`: Part 2; currently a clearly marked pending-delivery handoff.
- `charbel faddoul.zip`: Part 3; currently a clearly marked pending-delivery handoff.
- External `common/`, configuration, requirements, prompts and integration instructions shared by all three.

Send each colleague their named ZIP, the external shared files, and the original Word brief. Talia pastes `prompts/COLLEAGUE_1.md`; Charbel pastes `prompts/COLLEAGUE_2.md`. They return completed ZIPs with the same personal filenames. Extract all three into the shared parent folder before running. The common final report, database scripts and GitHub evidence stay external when completed. Do not overwrite canonical shared files with colleagues' stale copies.

## Setup

1. Install Python 3.11 or later. From the project root: `python -m venv .venv`.
2. Standard Windows Python: `.venv\Scripts\python.exe -m pip install -r requirements.txt`. This computer's MinGW Python instead uses `.venv\bin\python.exe`; that environment is already prepared.
3. Set all exact full names in `team_config.json`. Routes use the complete name as lowercase hyphenated words, for example `/first-last/assets`. Configured names are Khalil Ayoub, Talia Semaan, and Charbel Faddoul.
4. Set the same `SERVICE_SECRET` environment variable in every server terminal. Generate a local secret with `python -c "import secrets; print(secrets.token_hex(32))"`. Do not put it in Git or a shared ZIP. Part 2 also documents its token-signing secret.
5. After Part 2 arrives, start its logs, users, and notifications services and bootstrap a real administrator using its CLI. Login through Postman, obtain a token, and create the required test accounts.
6. Start three terminals for Part 1:

```powershell
$env:SERVICE_SECRET = 'YOUR LOCAL SECRET'
.\.venv\bin\python.exe -m part1.app assets
```

Repeat with `threats` and `vulnerabilities`. Use Scripts instead of bin on standard Windows Python. Ports are 5002, 5004, 5007. Data is saved to `data/project.db`; every process must use the same absolute `PROJECT_DB` override if one is set. The app initializes tables; do not manually pre-create an incompatible schema.

7. Import `postman/part1.collection.json` and `postman/part1.environment.json`. Set owner_prefix to your actual lowercase name slug, owner_id to a real account ID, and token variables using real logins. Run Create Asset before Create Vulnerability. Save response IDs to collection variables automatically or enter them in the environment. Do not run destructive requests against records you want to preserve for later screenshots.

## Verification and status

Run `.venv\bin\python.exe -m unittest tests.test_part1 -v` (Scripts on standard Python). Tests use real Part 1 handlers and a temporary SQLite database, with explicit doubles for absent teammate HTTP services. They verify validation, role checks, scoping, lifecycle, FK conflicts, audit dependencies and alert failures. They do not verify the future authentication implementation or constitute Postman execution evidence.

Part 1 is an implementation draft pending integration. The other six services, real Postman screenshots, GitHub contribution evidence, and common final Word report are not supplied yet. `docs/part1/EVIDENCE_CHECKLIST.md` tracks required actual evidence. No mocked responses or generated screenshots should be submitted as running-system evidence.

The assignment prohibits copying complete AI-generated solutions. Review/adapt this draft, understand and demonstrate it, disclose assistance, and verify your instructor's allowed scope before submission. Report notes and review questions are included for that purpose.

## Team GitHub repository

https://github.com/Khalil-Ayoub/talia-semaan-khalil-ayoub-charbel-faddoul

This is the private common repository. Accept your collaborator invitation, clone it, and use your own GitHub account to push branch talia or charbel. Do not create another repository. Shared starter files live on main; personal code remains owned by the assigned student.
