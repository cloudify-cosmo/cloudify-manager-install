#!/usr/bin/env bash
set -eux

validate_status() {
  manager_status="$(docker exec $1 cfy cluster status)"
  set +e
  grep -iq -e 'fail' -e 'error' <<< "$manager_status" && (echo "Found a failure in the cluster status" && exit 1)
  set -e
}

for var in "$@"
do
    validate_status "$var"
done
