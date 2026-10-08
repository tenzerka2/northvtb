CREATE UNIQUE INDEX agent_credential_unique ON north.agents(credential_ref);
ALTER TABLE north.payments ADD COLUMN next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp();
ALTER TABLE north.payments ADD COLUMN attempts integer NOT NULL DEFAULT 0 CHECK(attempts>=0);
ALTER TABLE north.refunds ADD COLUMN next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp();
ALTER TABLE north.refunds ADD COLUMN attempts integer NOT NULL DEFAULT 0 CHECK(attempts>=0);
CREATE INDEX payments_due ON north.payments(next_attempt_at) WHERE state IN ('PENDING','SUBMITTED','UNKNOWN');
CREATE TABLE north.event_inbox (
 event_id north.identifier PRIMARY KEY REFERENCES north.audit_events(event_id),
 payload bytea NOT NULL,
 payload_hash north.digest NOT NULL,
 delivered_at timestamptz NOT NULL
);
GRANT SELECT,INSERT ON north.event_inbox TO north_app;
