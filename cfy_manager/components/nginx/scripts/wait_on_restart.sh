#!/bin/bash

set -e
trap "{ echo Restarting nginx; sleep 1 && /usr/bin/supervisorctl -c /etc/supervisord.conf restart nginx; exit 0; }" EXIT