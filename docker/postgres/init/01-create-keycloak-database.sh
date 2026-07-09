#!/bin/sh
set -eu

# The official PostgreSQL entrypoint runs this once, before either application
# has connected. psql variable quoting keeps special characters in the password
# from changing the SQL statement.
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=keycloak_password="$KEYCLOAK_DB_PASSWORD" <<'EOSQL'
CREATE USER keycloak WITH PASSWORD :'keycloak_password';
CREATE DATABASE keycloak OWNER keycloak;
EOSQL
