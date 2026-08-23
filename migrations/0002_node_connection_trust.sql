BEGIN IMMEDIATE;

ALTER TABLE node_trust ADD COLUMN certificate_der BLOB;
ALTER TABLE node_trust ADD COLUMN server_name TEXT;
ALTER TABLE node_trust ADD COLUMN control_address TEXT;

INSERT INTO schema_migration(version, applied_at, checksum)
VALUES (2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), '0002_node_connection_trust_v1');

COMMIT;
