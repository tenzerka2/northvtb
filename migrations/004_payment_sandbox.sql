CREATE TABLE north.refunds (
 id north.identifier PRIMARY KEY,
 payment_id north.identifier NOT NULL UNIQUE REFERENCES north.payments(id),
 state text NOT NULL CHECK (state IN ('PENDING','UNKNOWN','SUCCEEDED')),
 created_at timestamptz NOT NULL,
 updated_at timestamptz NOT NULL
);
GRANT SELECT,INSERT,UPDATE ON north.refunds TO north_app;
CREATE SCHEMA sandbox;
CREATE TABLE sandbox.payments (
 id text PRIMARY KEY,
 request_hash text NOT NULL,
 merchant text NOT NULL,
 currency text NOT NULL,
 amount bigint NOT NULL CHECK (amount>0),
 state text NOT NULL CHECK (state IN ('AUTHORIZED','CAPTURED','DECLINED','REFUNDED')),
 captures smallint NOT NULL DEFAULT 0 CHECK (captures BETWEEN 0 AND 1)
);
CREATE TABLE sandbox.refunds (id text PRIMARY KEY,payment_id text NOT NULL UNIQUE REFERENCES sandbox.payments(id));
DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='north_provider') THEN CREATE ROLE north_provider NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION; END IF; END $$;
REVOKE ALL ON SCHEMA sandbox FROM PUBLIC;
GRANT USAGE ON SCHEMA sandbox TO north_provider;
GRANT SELECT,INSERT,UPDATE ON sandbox.payments,sandbox.refunds TO north_provider;
