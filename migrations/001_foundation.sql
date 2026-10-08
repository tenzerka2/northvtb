-- Applied by migrations/apply.sql inside a locked transaction.
CREATE SCHEMA north;
CREATE DOMAIN north.identifier AS text CHECK (VALUE ~ '^[A-Za-z0-9_.-]{1,128}$');
CREATE DOMAIN north.digest AS bytea CHECK (octet_length(VALUE) = 32);

CREATE TABLE north.agents (
 id north.identifier PRIMARY KEY,
 owner_subject text NOT NULL CHECK (length(owner_subject) BETWEEN 1 AND 512),
 provider_id north.identifier NOT NULL,
 credential_ref text NOT NULL CHECK (length(credential_ref) BETWEEN 1 AND 512),
 version bigint NOT NULL CHECK (version > 0),
 status text NOT NULL CHECK (status IN ('ACTIVE','REVOKED')),
 risk_class smallint NOT NULL CHECK (risk_class BETWEEN 0 AND 100),
 created_at timestamptz NOT NULL,
 revoked_at timestamptz,
 CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL))
);
CREATE TABLE north.mandates (
 id north.identifier PRIMARY KEY,
 owner_subject text NOT NULL,
 agent_id north.identifier NOT NULL REFERENCES north.agents(id),
 version bigint NOT NULL CHECK (version > 0),
 predecessor_id north.identifier UNIQUE REFERENCES north.mandates(id),
 state text NOT NULL CHECK (state IN ('DRAFT','ACTIVE','REVOKED','EXPIRED','CONSUMED')),
 canonical_terms bytea NOT NULL CHECK (octet_length(canonical_terms) BETWEEN 1 AND 65536),
 terms_digest north.digest NOT NULL,
 key_id north.identifier,
 signature bytea,
 max_amount bigint NOT NULL CHECK (max_amount > 0),
 currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
 max_uses bigint NOT NULL CHECK (max_uses BETWEEN 1 AND 1000000),
 reserved_uses bigint NOT NULL DEFAULT 0 CHECK (reserved_uses >= 0),
 consumed_uses bigint NOT NULL DEFAULT 0 CHECK (consumed_uses >= 0),
 created_at timestamptz NOT NULL,
 approved_at timestamptz,
 expires_at timestamptz NOT NULL,
 CHECK (expires_at > created_at),
 CHECK (consumed_uses <= max_uses AND reserved_uses <= max_uses - consumed_uses),
 CHECK (state <> 'ACTIVE' OR (approved_at IS NOT NULL AND key_id IS NOT NULL AND signature IS NOT NULL)),
 CHECK (signature IS NULL OR octet_length(signature) BETWEEN 1 AND 8192),
 CHECK (state <> 'CONSUMED' OR (consumed_uses = max_uses AND reserved_uses = 0)),
 CHECK (state <> 'DRAFT' OR (approved_at IS NULL AND reserved_uses = 0 AND consumed_uses = 0))
);
CREATE TABLE north.grants (
 id north.identifier PRIMARY KEY,
 mandate_id north.identifier NOT NULL REFERENCES north.mandates(id),
 agent_id north.identifier NOT NULL REFERENCES north.agents(id),
 merchant_id north.identifier NOT NULL,
 transaction_hash north.digest NOT NULL,
 canonical_transaction bytea NOT NULL CHECK (octet_length(canonical_transaction) BETWEEN 1 AND 65536),
 amount bigint NOT NULL CHECK (amount > 0),
 currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
 nonce bytea NOT NULL UNIQUE CHECK (octet_length(nonce) = 32),
 max_uses smallint NOT NULL DEFAULT 1 CHECK (max_uses = 1),
 issued_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL CHECK (expires_at > issued_at),
 key_id north.identifier NOT NULL,
 signature bytea NOT NULL CHECK (octet_length(signature) BETWEEN 1 AND 8192),
 state text NOT NULL CHECK (state IN ('ISSUED','CONSUMED','EXPIRED','REVOKED')),
 consumed_at timestamptz,
 CHECK ((state = 'CONSUMED') = (consumed_at IS NOT NULL))
);
CREATE INDEX grants_expiry ON north.grants(expires_at) WHERE state='ISSUED';
CREATE INDEX grants_mandate ON north.grants(mandate_id);
CREATE TABLE north.payments (
 id north.identifier PRIMARY KEY,
 grant_id north.identifier NOT NULL UNIQUE REFERENCES north.grants(id),
 provider_id north.identifier NOT NULL,
 provider_payment_id text,
 state text NOT NULL CHECK (state IN ('PENDING','SUBMITTED','UNKNOWN','SUCCEEDED','FAILED','CANCELLED')),
 amount bigint NOT NULL CHECK (amount > 0),
 currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
 created_at timestamptz NOT NULL,
 updated_at timestamptz NOT NULL,
 UNIQUE (provider_id,provider_payment_id)
);
CREATE TABLE north.idempotency (
 principal text NOT NULL CHECK (length(principal) BETWEEN 1 AND 512),
 operation north.identifier NOT NULL,
 key text NOT NULL CHECK (key ~ '^[!-~]{1,128}$'),
 request_hash north.digest NOT NULL,
 response_status smallint NOT NULL CHECK (response_status BETWEEN 200 AND 499),
 response_body bytea NOT NULL CHECK (octet_length(response_body) <= 1048576),
 created_at timestamptz NOT NULL,
 PRIMARY KEY (principal,operation,key)
);
CREATE TABLE north.provider_callbacks (
 provider_id north.identifier NOT NULL,
 event_id north.identifier NOT NULL,
 payment_id north.identifier NOT NULL REFERENCES north.payments(id),
 payload_hash north.digest NOT NULL,
 received_at timestamptz NOT NULL,
 PRIMARY KEY (provider_id,event_id)
);
CREATE TABLE north.audit_head (
 singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
 sequence bigint NOT NULL CHECK (sequence >= 0),
 hash north.digest NOT NULL
);
INSERT INTO north.audit_head VALUES (true,0,decode(repeat('00',32),'hex'));
CREATE TABLE north.audit_events (
 sequence bigint PRIMARY KEY CHECK (sequence > 0),
 event_id north.identifier NOT NULL UNIQUE,
 occurred_at timestamptz NOT NULL,
 actor text NOT NULL,
 event_type text NOT NULL,
 subject text NOT NULL,
 canonical_event bytea NOT NULL CHECK (octet_length(canonical_event) BETWEEN 1 AND 65536),
 previous_hash north.digest NOT NULL,
 hash north.digest NOT NULL UNIQUE
);
CREATE TABLE north.outbox (
 event_id north.identifier PRIMARY KEY REFERENCES north.audit_events(event_id),
 created_at timestamptz NOT NULL,
 attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
 available_at timestamptz NOT NULL,
 lease_until timestamptz,
 delivered_at timestamptz
);
CREATE INDEX outbox_pending ON north.outbox(available_at) WHERE delivered_at IS NULL;

CREATE FUNCTION north.guard_mandate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.id,NEW.owner_subject,NEW.agent_id,NEW.version,NEW.predecessor_id,NEW.created_at)
    IS DISTINCT FROM ROW(OLD.id,OLD.owner_subject,OLD.agent_id,OLD.version,OLD.predecessor_id,OLD.created_at) THEN
  RAISE EXCEPTION 'mandate identity is immutable' USING ERRCODE='23514';
 END IF;
 IF OLD.state <> 'DRAFT' AND ROW(NEW.canonical_terms,NEW.terms_digest,NEW.key_id,NEW.signature,NEW.max_amount,NEW.currency,NEW.max_uses,NEW.approved_at,NEW.expires_at)
    IS DISTINCT FROM ROW(OLD.canonical_terms,OLD.terms_digest,OLD.key_id,OLD.signature,OLD.max_amount,OLD.currency,OLD.max_uses,OLD.approved_at,OLD.expires_at) THEN
  RAISE EXCEPTION 'approved mandate terms are immutable' USING ERRCODE='23514';
 END IF;
 IF NEW.state <> OLD.state AND NOT (
  (OLD.state='DRAFT' AND NEW.state IN ('ACTIVE','REVOKED')) OR
  (OLD.state='ACTIVE' AND NEW.state IN ('REVOKED','EXPIRED','CONSUMED'))
 ) THEN RAISE EXCEPTION 'invalid mandate transition' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER immutable_mandate BEFORE UPDATE ON north.mandates FOR EACH ROW EXECUTE FUNCTION north.guard_mandate();

CREATE FUNCTION north.guard_agent() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.id,NEW.owner_subject,NEW.provider_id,NEW.credential_ref,NEW.version,NEW.created_at)
    IS DISTINCT FROM ROW(OLD.id,OLD.owner_subject,OLD.provider_id,OLD.credential_ref,OLD.version,OLD.created_at)
    OR (OLD.status='REVOKED' AND NEW IS DISTINCT FROM OLD) THEN
  RAISE EXCEPTION 'immutable agent identity or revoked agent' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER immutable_agent BEFORE UPDATE ON north.agents FOR EACH ROW EXECUTE FUNCTION north.guard_agent();

CREATE FUNCTION north.guard_grant() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.id,NEW.mandate_id,NEW.agent_id,NEW.merchant_id,NEW.transaction_hash,NEW.canonical_transaction,NEW.amount,NEW.currency,NEW.nonce,NEW.max_uses,NEW.issued_at,NEW.expires_at,NEW.key_id,NEW.signature)
    IS DISTINCT FROM ROW(OLD.id,OLD.mandate_id,OLD.agent_id,OLD.merchant_id,OLD.transaction_hash,OLD.canonical_transaction,OLD.amount,OLD.currency,OLD.nonce,OLD.max_uses,OLD.issued_at,OLD.expires_at,OLD.key_id,OLD.signature)
    OR (OLD.state <> 'ISSUED' AND NEW IS DISTINCT FROM OLD)
    OR (NEW.state <> OLD.state AND NOT (OLD.state='ISSUED' AND NEW.state IN ('CONSUMED','EXPIRED','REVOKED'))) THEN
  RAISE EXCEPTION 'immutable grant or invalid transition' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER immutable_grant BEFORE UPDATE ON north.grants FOR EACH ROW EXECUTE FUNCTION north.guard_grant();

CREATE FUNCTION north.guard_payment() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.id,NEW.grant_id,NEW.provider_id,NEW.amount,NEW.currency,NEW.created_at)
    IS DISTINCT FROM ROW(OLD.id,OLD.grant_id,OLD.provider_id,OLD.amount,OLD.currency,OLD.created_at)
    OR (OLD.provider_payment_id IS NOT NULL AND NEW.provider_payment_id IS DISTINCT FROM OLD.provider_payment_id)
    OR (NEW.state <> OLD.state AND NOT (
     (OLD.state='PENDING' AND NEW.state IN ('SUBMITTED','CANCELLED')) OR
     (OLD.state='SUBMITTED' AND NEW.state IN ('UNKNOWN','SUCCEEDED','FAILED')) OR
     (OLD.state='UNKNOWN' AND NEW.state IN ('SUCCEEDED','FAILED')))) THEN
  RAISE EXCEPTION 'immutable payment or invalid transition' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER immutable_payment BEFORE UPDATE ON north.payments FOR EACH ROW EXECUTE FUNCTION north.guard_payment();

CREATE FUNCTION north.reject_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'audit history is append only' USING ERRCODE='42501'; END $$;
CREATE TRIGGER append_only_audit BEFORE UPDATE OR DELETE OR TRUNCATE ON north.audit_events FOR EACH STATEMENT EXECUTE FUNCTION north.reject_audit_mutation();

-- A provisioned LOGIN role should inherit north_app. Never use migration owner in the app.
DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='north_app') THEN CREATE ROLE north_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION; END IF; END $$;
REVOKE ALL ON SCHEMA north FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA north FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA north FROM PUBLIC;
GRANT USAGE ON SCHEMA north TO north_app;
GRANT SELECT,INSERT,UPDATE ON north.agents,north.mandates,north.grants,north.payments,north.outbox TO north_app;
GRANT SELECT,INSERT ON north.idempotency,north.provider_callbacks,north.audit_events TO north_app;
GRANT SELECT,UPDATE ON north.audit_head TO north_app;
