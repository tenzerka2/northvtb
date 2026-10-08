#!/bin/sh
set -eu
psql -X -v ON_ERROR_STOP=1 -f /migrations/apply.sql
psql -X -v ON_ERROR_STOP=1 -v app_password="$NORTH_APP_DB_PASSWORD" -v provider_password="$NORTH_PROVIDER_DB_PASSWORD" -f /scripts/provision.sql
psql -X -v ON_ERROR_STOP=1 -f /scripts/seed.sql
