#!/bin/bash

set -e

if [ $# -lt 1 ]; then
    echo "Missing arguments."
    echo "Usage: $0 postgres_password"
    exit
fi

postgres_password=$1

function run_psql() {
    cmd=$1
    echo "Going to run: ${cmd}"
    psql -c "${cmd}"
}

function update_postgres_password() {
    postgres_password=$1
    run_psql "ALTER USER postgres WITH PASSWORD '$postgres_password';"

    # Required to remove password trace in the command history
    rm -f ~/.psql_history
}

update_postgres_password ${postgres_password}
