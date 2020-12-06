#!/bin/bash
set -e

function stop_postgres() {
  echo "Stopping postgres.."
  /usr/pgsql-9.5/bin/pg_ctl stop -D /var/lib/pgsql/9.5/data/ -s -m fast
}

trap 'stop_postgres' EXIT

/usr/pgsql-9.5/bin/postgres -D /var/lib/pgsql/9.5/data/

