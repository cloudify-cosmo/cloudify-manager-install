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
/usr/bin/supervisorctl -c /etc/supervisord.conf start cloudify-manager-ip-setter

exited=$(/usr/bin/supervisorctl -c /etc/supervisord.conf status cloudify-manager-ip-setter | grep "EXITED")
while [ -z "$exited"]; do
        echo "The cloudify-manager-ip-setter service not finished yet"
        sleep 1
done
# Start services again

echo "Starting All services"
/usr/bin/supervisorctl -c /etc/supervisord.conf reread

echo "Starting All services"
/usr/bin/supervisorctl -c /etc/supervisord.conf start \
                        cloudify-mgmtworker \
                        cloudify-restservice \
                        cloudify-stage \
                        nginx \
                        cloudify-rabbitmq \
                        cloudify-amqp-postgres
