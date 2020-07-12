#!/bin/bash
set -e

function stop_postgres() {
  echo "Stopping postgres.."
  echo "Stopping postgres.." >> /tmp/test.txt
  /usr/pgsql-9.5/bin/pg_ctl stop -D /var/lib/pgsql/9.5/data/ -s -m fast &>> /tmp/test.txt
}

trap 'stop_postgres' EXIT
/usr/pgsql-9.5/bin/postgres -D /var/lib/pgsql/9.5/data/

