#!/bin/bash
set -e

worker_count=$1
max_requests=$2
port=$3

rm -rf /run/cloudify-api/
mkdir -p /run/cloudify-api
chown cfyuser. /run/cloudify-api
chmod 755 /run/cloudify-api

exec /opt/manager/env/bin/ddtrace-run /opt/manager/env/bin/gunicorn \
    -k uvicorn.workers.UvicornWorker \
    -u cfyuser \
    -g cfyuser \
    --pid /run/cloudify-api/pid \
    --chdir / \
    --workers $worker_count \
    --max-requests $max_requests \
    --bind 127.0.0.1:$port \
    --timeout 300 cloudify_api.main:app \
    --log-file /var/log/cloudify/rest/api-gunicorn.log \
    --access-logfile /var/log/cloudify/rest/api-audit.log \
    --access-logformat '%(t)s %(h)s %({X-Cloudify-Audit-Username}o)s %({X-Cloudify-Audit-Tenant}o)s %({X-Cloudify-Audit-Auth-Method}o)s "%(r)s" %(s)s %(b)s "%(a)s" took %(M)sms'
