#!/bin/bash

set -e

# call "rabbitmqctl shutdown" when exiting
trap "{ echo Stopping rabbitmq; /usr/sbin/rabbitmqctl shutdown; exit 0; }" EXIT

echo "Starting rabbitmq"
exec /usr/sbin/rabbitmq-server
