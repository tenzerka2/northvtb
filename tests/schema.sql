\set ON_ERROR_STOP on
BEGIN;
SET LOCAL ROLE north_app;
INSERT INTO north.agents VALUES ('a','issuer|owner','p','vault:agent-a',1,'ACTIVE',0,now(),NULL);
INSERT INTO north.mandates(id,owner_subject,agent_id,version,state,canonical_terms,terms_digest,max_amount,currency,max_uses,created_at,expires_at)
VALUES ('m','issuer|owner','a',1,'DRAFT',decode('01','hex'),decode(repeat('00',32),'hex'),8500000,'RUB',1,now(),now()+interval '1 hour');
UPDATE north.mandates SET state='ACTIVE',approved_at=now(),key_id='test-key',signature=decode('01','hex') WHERE id='m';
DO $$ BEGIN
 BEGIN UPDATE north.mandates SET max_amount=9900000 WHERE id='m'; RAISE EXCEPTION 'mutation accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
 BEGIN UPDATE north.mandates SET agent_id='b' WHERE id='m'; RAISE EXCEPTION 'identity mutation accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
 BEGIN UPDATE north.mandates SET reserved_uses=2 WHERE id='m'; RAISE EXCEPTION 'overspend accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
INSERT INTO north.grants(id,mandate_id,agent_id,merchant_id,transaction_hash,canonical_transaction,amount,currency,nonce,issued_at,expires_at,key_id,signature,state)
VALUES ('g','m','a','seller',decode(repeat('00',32),'hex'),decode('01','hex'),8299000,'RUB',decode(repeat('01',32),'hex'),now(),now()+interval '1 minute','key',decode('01','hex'),'ISSUED');
UPDATE north.grants SET state='CONSUMED',consumed_at=now() WHERE id='g';
INSERT INTO north.payments(id,grant_id,provider_id,state,amount,currency,created_at,updated_at) VALUES ('pay','g','sandbox','PENDING',8299000,'RUB',now(),now());
DO $$ BEGIN
 BEGIN UPDATE north.grants SET state='ISSUED',consumed_at=NULL WHERE id='g'; RAISE EXCEPTION 'grant replay accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
 BEGIN UPDATE north.grants SET amount=9299000 WHERE id='g'; RAISE EXCEPTION 'grant tamper accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
 BEGIN INSERT INTO north.payments(id,grant_id,provider_id,state,amount,currency,created_at,updated_at) VALUES ('pay2','g','sandbox','PENDING',8299000,'RUB',now(),now()); RAISE EXCEPTION 'double execution command accepted'; EXCEPTION WHEN unique_violation THEN NULL; END;
END $$;
UPDATE north.payments SET state='SUBMITTED' WHERE id='pay';
UPDATE north.payments SET state='UNKNOWN' WHERE id='pay';
DO $$ BEGIN
 BEGIN UPDATE north.payments SET state='PENDING' WHERE id='pay'; RAISE EXCEPTION 'unknown payment reset accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
UPDATE north.payments SET state='SUCCEEDED' WHERE id='pay';
UPDATE north.mandates SET state='REVOKED' WHERE id='m';
UPDATE north.agents SET status='REVOKED',revoked_at=now() WHERE id='a';
DO $$ BEGIN
 BEGIN UPDATE north.mandates SET state='ACTIVE' WHERE id='m'; RAISE EXCEPTION 'revoked mandate revived'; EXCEPTION WHEN check_violation THEN NULL; END;
 BEGIN UPDATE north.agents SET status='ACTIVE',revoked_at=NULL WHERE id='a'; RAISE EXCEPTION 'revoked agent revived'; EXCEPTION WHEN check_violation THEN NULL; END;
 BEGIN UPDATE north.payments SET state='SUBMITTED' WHERE id='pay'; RAISE EXCEPTION 'final payment regressed'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
INSERT INTO north.audit_events VALUES (1,'evt',now(),'owner','test','m',decode('01','hex'),decode(repeat('00',32),'hex'),decode(repeat('01',32),'hex'));
DO $$ BEGIN
 BEGIN UPDATE north.audit_events SET actor='attacker'; RAISE EXCEPTION 'audit update allowed'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN DELETE FROM north.audit_events; RAISE EXCEPTION 'audit deletion allowed'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN TRUNCATE north.audit_events CASCADE; RAISE EXCEPTION 'audit truncate allowed'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN CREATE TABLE north.attacker (id int); RAISE EXCEPTION 'app schema DDL allowed'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
-- Defense-in-depth trigger also blocks ordinary mutations by the table owner.
DO $$ BEGIN
 BEGIN UPDATE north.audit_events SET actor='attacker'; RAISE EXCEPTION 'audit owner update allowed'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
ROLLBACK;
