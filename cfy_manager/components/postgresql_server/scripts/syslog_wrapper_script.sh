#!/bin/bash
set -e

rm -f /var/run/syslogd.pid

exec /usr/sbin/rsyslogd -n