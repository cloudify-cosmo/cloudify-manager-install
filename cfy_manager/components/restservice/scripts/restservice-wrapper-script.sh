#!/bin/bash
set -e

worker_count=$1
max_requests=$2
port=$3

rm -rf /run/cloudify-restservice/
mkdir -p /run/cloudify-restservice
chown cfyuser. /run/cloudify-restservice
chmod 755 /run/cloudify-restservice

exec /opt/manager/env/bin/gunicorn \
    -u cfyuser \
    -g cfyuser \
    --pid /run/cloudify-restservice/pid \
    --chdir / \
    --workers $worker_count \
    --max-requests $max_requests \
    --bind 127.0.0.1:$port \
    --timeout 300 manager_rest.wsgi:app \
    --log-file /var/log/cloudify/rest/gunicorn.log \
    --access-logfile /var/log/cloudify/rest/gunicorn-access.log
