#!/usr/bin/env bash
set -eux

validate_status() {
  echo "Testing cluster status in $1"
  manager_status="$(docker exec $1 cfy cluster status)"
  manager_status_json="$(docker exec $1 cfy cluster status --json)"
  set +e
  grep -iq -e 'inactive' -e 'degraded' -e 'fail' -e 'error' <<< "$manager_status" && { echo "Found a failure in the cluster status, here's the full report:" && echo $manager_status_json && exit 1; }
  (! grep -iq -e 'ok' <<< "$manager_status") && { echo "Also could not find a service in OK state in cluster status, here's the full report:" && echo $manager_status_json && exit 1; }
  set -e
}

for var in "$@"
do
    validate_status "$var"
done
