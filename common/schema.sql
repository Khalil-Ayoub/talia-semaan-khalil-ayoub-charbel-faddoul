PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, full_name TEXT NOT NULL, username TEXT NOT NULL UNIQUE,
 email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, department TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('Security Administrator','Security Analyst','Regular Employee/User','Auditor')),
 account_status TEXT NOT NULL DEFAULT 'Active' CHECK(account_status IN ('Active','Inactive','Suspended')),
 created_date TEXT NOT NULL, last_login_date TEXT, deleted_at TEXT
);
CREATE TABLE IF NOT EXISTS assets (
 id INTEGER PRIMARY KEY, asset_name TEXT NOT NULL, asset_type TEXT NOT NULL, ip_address TEXT NOT NULL,
 operating_system TEXT, owner_id INTEGER NOT NULL REFERENCES users(id), department TEXT NOT NULL,
 location TEXT, criticality_level TEXT NOT NULL CHECK(criticality_level IN ('Low','Medium','High','Critical')),
 status TEXT NOT NULL CHECK(status IN ('Active','Inactive','Under Maintenance'))
);
CREATE TABLE IF NOT EXISTS asset_history (
 id INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL REFERENCES users(id), action TEXT NOT NULL,
 snapshot TEXT NOT NULL, timestamp TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incidents (
 id INTEGER PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL, category TEXT NOT NULL,
 severity TEXT NOT NULL, reporter_id INTEGER NOT NULL REFERENCES users(id), asset_id INTEGER REFERENCES assets(id),
 assigned_analyst_id INTEGER REFERENCES users(id), status TEXT NOT NULL DEFAULT 'Open',
 creation_date TEXT NOT NULL, resolution_date TEXT
);
CREATE TABLE IF NOT EXISTS investigation_notes (
 id INTEGER PRIMARY KEY, incident_id INTEGER NOT NULL REFERENCES incidents(id),
 analyst_id INTEGER NOT NULL REFERENCES users(id), note_content TEXT NOT NULL, creation_timestamp TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS threats (
 id INTEGER PRIMARY KEY, threat_type TEXT NOT NULL, threat_value TEXT NOT NULL, description TEXT NOT NULL,
 severity TEXT NOT NULL CHECK(severity IN ('Low','Medium','High','Critical')), source TEXT NOT NULL,
 date_added TEXT NOT NULL, UNIQUE(threat_type, threat_value)
);
CREATE TABLE IF NOT EXISTS logs (
 id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), action TEXT NOT NULL,
 description TEXT NOT NULL, timestamp TEXT NOT NULL, severity TEXT NOT NULL, related_service TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS logs_no_update BEFORE UPDATE ON logs
BEGIN SELECT RAISE(ABORT, 'Audit logs cannot be modified'); END;
CREATE TABLE IF NOT EXISTS vulnerabilities (
 id INTEGER PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL, cve_identifier TEXT NOT NULL,
 cvss_score REAL NOT NULL CHECK(cvss_score BETWEEN 0 AND 10), severity TEXT NOT NULL,
 asset_id INTEGER NOT NULL REFERENCES assets(id), discovery_source TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'Open', creation_date TEXT NOT NULL, resolution_date TEXT
);
CREATE TABLE IF NOT EXISTS notifications (
 id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), title TEXT NOT NULL,
 message TEXT NOT NULL, notification_type TEXT NOT NULL, severity TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'Unread', creation_date TEXT NOT NULL, read_date TEXT
);
CREATE TABLE IF NOT EXISTS playbooks (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL, incident_category TEXT NOT NULL,
 severity TEXT NOT NULL, created_by INTEGER NOT NULL REFERENCES users(id), creation_date TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS response_actions (
 id INTEGER PRIMARY KEY, playbook_id INTEGER NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
 description TEXT NOT NULL, step_number INTEGER NOT NULL CHECK(step_number > 0),
 status TEXT NOT NULL DEFAULT 'Pending', assigned_user_id INTEGER REFERENCES users(id),
 completion_date TEXT, UNIQUE(playbook_id,step_number)
);
CREATE TABLE IF NOT EXISTS action_history (
 id INTEGER PRIMARY KEY, action_id INTEGER NOT NULL REFERENCES response_actions(id) ON DELETE CASCADE,
 status TEXT NOT NULL, assigned_user_id INTEGER REFERENCES users(id), changed_by INTEGER NOT NULL REFERENCES users(id),
 timestamp TEXT NOT NULL
);
