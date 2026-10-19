# Part 3 integration notes

Owner: Charbel Faddoul. Existing incidents, reports and playbooks implementations are retained. Ports are 5003, 5006 and 5009. Run python -m part3.app SERVICE or use the common python run_services.py launcher after extracting all three parts.

Assignee validation now calls Talia's service-key-protected GET /internal/users/<id>. Analysts may validate and assign other Active users and update action status without public user-management access. Activity reports default to shared login_succeeded/login_failed action labels, so no additional report environment configuration is required. Shared integer validation rejects values outside SQLite range before storage.

The incident lifecycle, ordered actions, completion timestamps, history and role restrictions are unchanged. Run python -m unittest discover -s tests -p test_part3.py -v. Full-system tests use all nine actual applications; real Postman/database screenshots remain separate evidence.
