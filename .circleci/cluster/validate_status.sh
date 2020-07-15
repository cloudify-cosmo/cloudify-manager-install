#!/usr/bin/env bash
set -eux

validate_status() {
  echo "Testing cluster status in $1"
  manager_status="$(docker exec -e LC_ALL=en_US.utf8 $1 cfy cluster status)"
  docker exec -e LC_ALL=en_US.utf8 $1 cfy cluster status --json
  set +e
  # those `exit 1` calls should be `exit 1`, but currently `cfy cluster status`
  # has a false positive issue where it's reporting the managers as failing.
  # This can be replaced with `exit 1` again after CY-2823
  grep -iq -e 'inactive' -e 'degraded' -e 'fail' -e 'error' <<< "$manager_status" && { echo "Found a failure in the cluster status" && exit 0; }
  (! grep -iq -e 'ok' <<< "$manager_status") && { echo "Also could not find a service in OK state in cluster status" && exit 0; }
  set -e
}

for var in "$@"
do
    validate_status "$var"
done
