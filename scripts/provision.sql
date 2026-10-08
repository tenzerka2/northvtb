\set ON_ERROR_STOP on
SELECT format('CREATE ROLE north_app_login LOGIN PASSWORD %L', :'app_password') WHERE NOT EXISTS(SELECT FROM pg_roles WHERE rolname='north_app_login') \gexec
SELECT format('CREATE ROLE north_provider_login LOGIN PASSWORD %L', :'provider_password') WHERE NOT EXISTS(SELECT FROM pg_roles WHERE rolname='north_provider_login') \gexec
GRANT north_app TO north_app_login;
GRANT north_provider TO north_provider_login;
