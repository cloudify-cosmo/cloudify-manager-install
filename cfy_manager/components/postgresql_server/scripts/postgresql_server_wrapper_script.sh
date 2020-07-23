#!/bin/bash
set -e

function stop_postgres() {
  echo "Stopping postgres.."
  /usr/pgsql-9.5/bin/pg_ctl stop -D /var/lib/pgsql/9.5/data/ -s -m fast
}

trap 'stop_postgres' EXIT

# Prepare the postgresql diretcorty under /run for pid
rm -rf /run/postgresql/
mkdir -p /run/postgresql
chown postgres. /run/postgresql
chmod 755 /run/postgresql

/usr/pgsql-9.5/bin/postgres -D /var/lib/pgsql/9.5/data/

