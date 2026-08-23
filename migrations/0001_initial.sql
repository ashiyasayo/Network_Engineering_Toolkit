CREATE TABLE schema_migration (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL,
    checksum TEXT NOT NULL
);

CREATE TABLE network_profile (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    active_revision INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE network_profile_revision (
    profile_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    configuration_json TEXT NOT NULL,
    checksum TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (profile_id, revision),
    FOREIGN KEY (profile_id) REFERENCES network_profile(id)
);
CREATE TABLE hosts_profile (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE hosts_entry (id TEXT PRIMARY KEY, profile_id TEXT NOT NULL, enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)), address TEXT NOT NULL, hostname TEXT NOT NULL, comment TEXT, sort_order INTEGER NOT NULL, FOREIGN KEY (profile_id) REFERENCES hosts_profile(id));
CREATE TABLE node (id TEXT PRIMARY KEY, name TEXT NOT NULL, first_seen_at TEXT NOT NULL, last_seen_at TEXT, last_address TEXT);
CREATE TABLE node_trust (node_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, trust_status TEXT NOT NULL, trusted_at TEXT, revoked_at TEXT, FOREIGN KEY (node_id) REFERENCES node(id));
CREATE TABLE operation (operation_id TEXT PRIMARY KEY, action TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL, completed_at TEXT, error_code TEXT);
CREATE TABLE safe_apply (operation_id TEXT PRIMARY KEY, target_interface TEXT NOT NULL, snapshot_id TEXT NOT NULL, state TEXT NOT NULL, deadline TEXT NOT NULL, FOREIGN KEY (operation_id) REFERENCES operation(operation_id));
CREATE TABLE speed_session (session_id TEXT PRIMARY KEY, remote_node TEXT, protocol TEXT NOT NULL, backend TEXT NOT NULL, direction TEXT NOT NULL, started_at TEXT NOT NULL, completed_at TEXT, result_state TEXT NOT NULL, configuration_json TEXT NOT NULL, result_json TEXT);
CREATE TABLE packet_session (session_id TEXT PRIMARY KEY, interface TEXT NOT NULL, backend TEXT NOT NULL, capture_mode TEXT NOT NULL, analysis_mode TEXT NOT NULL, started_at TEXT NOT NULL, completed_at TEXT, final_drop_counters_json TEXT, confidence TEXT);
CREATE TABLE hardware_profile (id TEXT PRIMARY KEY, profile_json TEXT NOT NULL, profile_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL);
CREATE TABLE benchmark_result (id TEXT PRIMARY KEY, hardware_profile_id TEXT NOT NULL, software_build TEXT NOT NULL, configuration_json TEXT NOT NULL, result_json TEXT NOT NULL, certification_state TEXT NOT NULL, checksum TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY (hardware_profile_id) REFERENCES hardware_profile(id));
CREATE TABLE hardware_certification (id TEXT PRIMARY KEY, hardware_profile_id TEXT NOT NULL, software_profile TEXT NOT NULL, result TEXT NOT NULL, benchmark_result_id TEXT NOT NULL, certified_at TEXT NOT NULL, FOREIGN KEY (hardware_profile_id) REFERENCES hardware_profile(id), FOREIGN KEY (benchmark_result_id) REFERENCES benchmark_result(id));
CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT, action TEXT NOT NULL, target TEXT, old_state_hash TEXT, new_state_hash TEXT, caller TEXT NOT NULL, result TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE application_setting (key TEXT PRIMARY KEY, value_json TEXT NOT NULL, updated_at TEXT NOT NULL);

INSERT INTO schema_migration(version, applied_at, checksum)
VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), '0001_initial_v1');
