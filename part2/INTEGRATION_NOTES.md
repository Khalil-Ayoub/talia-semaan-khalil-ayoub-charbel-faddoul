# Part 2 integration notes

Owner: Talia Semaan. Run users/logs/notifications with python -m part2.app SERVICE from the shared root, or start the full system with python run_services.py. Ports are 5001, 5005 and 5008. All processes use the same SERVICE_SECRET (at least 32 characters) and shared PROJECT_DB if configured.

The existing implementation was adjusted to canonical created_date/last_login_date columns and leading-slash URL conventions. Notification creation/read/deletion now produce audit events. Signed tokens still reread current role/status/deletion and expire after eight hours. The new service-key-only GET /internal/users/<id> supplies minimal user state for playbook assignment validation. Login action names are login_succeeded and login_failed.

Tests now use common/schema.sql and close SQLite connections on Windows. Run python -m unittest discover -s tests -p test_part2.py -v. For all-nine-service verification run tests/test_integration.py after extracting every part. No secrets or personal database are included.
