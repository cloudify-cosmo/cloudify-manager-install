#!/bin/bash

set -e

# Make sure that all services are stopped execpt (postgresql-9.5) before setting manager ip
echo "Stopping cloudify-mgmtworker"
/usr/bin/supervisorctl -c /etc/supervisord.conf stop cloudify-mgmtworker
echo "Stopping cloudify-restservice"
/usr/bin/supervisorctl -c /etc/supervisord.conf stop cloudify-restservice
echo "Stopping cloudify-stage"
/usr/bin/supervisorctl -c /etc/supervisord.conf stop cloudify-stage
echo "Stopping nginx"
/usr/bin/supervisorctl -c /etc/supervisord.conf stop nginx
echo "Stopping cloudify-rabbitmq"
/usr/bin/supervisorctl -c /etc/supervisord.conf stop cloudify-rabbitmq
echo "Stopping cloudify-amqp-postgres"
/usr/bin/supervisorctl -c /etc/supervisord.conf stop cloudify-amqp-postgres

echo "Starting manager ip setter"
/opt/cloudify/manager-ip-setter/manager-ip-setter.sh

# Start services again
echo "Starting cloudify-mgmtworker"
/usr/bin/supervisorctl -c /etc/supervisord.conf start cloudify-mgmtworker
echo "Starting cloudify-restservice"
/usr/bin/supervisorctl -c /etc/supervisord.conf start cloudify-restservice
echo "Starting cloudify-stage"
/usr/bin/supervisorctl -c /etc/supervisord.conf start cloudify-stage
echo "Starting nginx"
/usr/bin/supervisorctl -c /etc/supervisord.conf start nginx
echo "Starting cloudify-rabbitmq"
/usr/bin/supervisorctl -c /etc/supervisord.conf start cloudify-rabbitmq
echo "Starting cloudify-amqp-postgres"
/usr/bin/supervisorctl -c /etc/supervisord.conf start cloudify-amqp-postgres
