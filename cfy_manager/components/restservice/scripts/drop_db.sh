#!/bin/bash

set -e

if [ $# -lt 3 ]; then
    echo "Missing arguments."
    echo "Usage: $0 db_name username password"
    exit 1
fi

db_name=$1
stage_db_name="stage"
composer_db_name="composer"
user=$2
password=$3

function run_psql() {
    cmd=$1
    echo "Going to run: ${cmd}"
    psql -c "${cmd}"
}

function clean_database_and_user() {
    db_name=$1
    user=$2
    run_psql "DROP DATABASE IF EXISTS $db_name;"
    run_psql "DROP DATABASE IF EXISTS $stage_db_name;"
    run_psql "DROP DATABASE IF EXISTS $composer_db_name;"
    run_psql "DROP USER IF EXISTS $user;"
}

clean_database_and_user ${db_name} ${user}
