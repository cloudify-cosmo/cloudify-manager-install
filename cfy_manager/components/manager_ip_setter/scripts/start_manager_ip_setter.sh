#!/bin/bash

set -e
# Make sure that all services are stopped execpt (postgresql-9.5) before setting manager ip
echo "Stopping All services"
/usr/bin/supervisorctl -c /etc/supervisord.conf stop \
                        cloudify-mgmtworker \
                        cloudify-restservice \
                        cloudify-stage \
                        nginx \
                        cloudify-rabbitmq \
                        cloudify-amqp-postgres


echo "Starting manager ip setter"
/opt/cloudify/manager-ip-setter/manager-ip-setter.sh

# Start services again
echo "Starting All services"
/usr/bin/supervisorctl -c /etc/supervisord.conf start \
                        cloudify-mgmtworker \
                        cloudify-restservice \
                        cloudify-stage \
                        nginx \
                        cloudify-rabbitmq \
                        cloudify-amqp-postgres
