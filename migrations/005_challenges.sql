CREATE TABLE north.challenges (
 id north.identifier PRIMARY KEY,
 agent_id north.identifier NOT NULL REFERENCES north.agents(id),
 mandate_id north.identifier NOT NULL REFERENCES north.mandates(id),
 transaction_hash north.digest NOT NULL,
 expires_at timestamptz NOT NULL,
 approved_at timestamptz,
 grant_id north.identifier UNIQUE REFERENCES north.grants(id)
);
ALTER TABLE north.grants ADD COLUMN risk_approval_id north.identifier REFERENCES north.challenges(id);
GRANT SELECT,INSERT,UPDATE ON north.challenges TO north_app;
CREATE FUNCTION north.guard_grant_risk() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN IF NEW.risk_approval_id IS DISTINCT FROM OLD.risk_approval_id THEN RAISE EXCEPTION 'immutable risk approval' USING ERRCODE='23514'; END IF; RETURN NEW; END $$;
REVOKE ALL ON FUNCTION north.guard_grant_risk() FROM PUBLIC;
CREATE TRIGGER immutable_grant_risk BEFORE UPDATE ON north.grants FOR EACH ROW EXECUTE FUNCTION north.guard_grant_risk();
