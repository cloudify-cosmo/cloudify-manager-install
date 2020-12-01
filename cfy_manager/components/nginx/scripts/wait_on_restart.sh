#!/bin/bash
set -e
echo Restarting nginx
/bin/bash -c "sleep 1 && supervisorctl -c /etc/supervisord.conf restart nginx > /dev/null 2>&1 &"