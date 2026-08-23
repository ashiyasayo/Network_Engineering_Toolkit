BEGIN IMMEDIATE;

ALTER TABLE packet_session
    ADD COLUMN result_state TEXT NOT NULL DEFAULT 'running'
    CHECK(result_state IN ('running', 'completed', 'failed', 'canceled'));

INSERT INTO schema_migration(version, applied_at, checksum)
VALUES (3, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), '0003_packet_session_state_v1');

COMMIT;
