#!/bin/bash
set -e
echo Restarting nginx
sleep 1
/usr/bin/supervisorctl -c /etc/supervisord.conf restart nginx