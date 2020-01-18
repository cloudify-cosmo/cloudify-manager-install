#!/usr/bin/env bash
set -eux

configure_reporter() {
  echo "Configuring status reporter for $1"
  docker cp ca.crt $1:/tmp/rest_ca.pem
  docker exec $1 cfy_manager status-reporter configure --managers-ip $2 --token $3 --ca-path /tmp/rest_ca.pem
  docker exec $1 cfy_manager status-reporter start
}

for var in $1
do
    configure_reporter "$var" "$2" "$3"
done
