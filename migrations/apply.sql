\set ON_ERROR_STOP on
BEGIN;
-- Serializes bootstrap and all later migration application on this database.
SELECT pg_advisory_xact_lock(786678428001);
CREATE TABLE IF NOT EXISTS public.north_schema_migrations (
 version integer PRIMARY KEY,
 applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
SELECT NOT EXISTS (SELECT FROM public.north_schema_migrations WHERE version=1) AS apply_v1 \gset
\if :apply_v1
\ir 001_foundation.sql
INSERT INTO public.north_schema_migrations(version) VALUES (1);
\endif
SELECT NOT EXISTS (SELECT FROM public.north_schema_migrations WHERE version=2) AS apply_v2 \gset
\if :apply_v2
\ir 002_offers.sql
INSERT INTO public.north_schema_migrations(version) VALUES (2);
\endif
SELECT NOT EXISTS (SELECT FROM public.north_schema_migrations WHERE version=3) AS apply_v3 \gset
\if :apply_v3
\ir 003_offer_lock.sql
INSERT INTO public.north_schema_migrations(version) VALUES (3);
\endif
SELECT NOT EXISTS (SELECT FROM public.north_schema_migrations WHERE version=4) AS apply_v4 \gset
\if :apply_v4
\ir 004_payment_sandbox.sql
INSERT INTO public.north_schema_migrations(version) VALUES (4);
\endif
SELECT NOT EXISTS (SELECT FROM public.north_schema_migrations WHERE version=5) AS apply_v5 \gset
\if :apply_v5
\ir 005_challenges.sql
INSERT INTO public.north_schema_migrations(version) VALUES (5);
\endif
SELECT NOT EXISTS (SELECT FROM public.north_schema_migrations WHERE version=6) AS apply_v6 \gset
\if :apply_v6
\ir 006_operations.sql
INSERT INTO public.north_schema_migrations(version) VALUES (6);
\endif
COMMIT;
