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
COMMIT;
