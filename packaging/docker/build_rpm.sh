#!/usr/bin/env bash

set -eux

echo "Creating install RPM..."
chmod +x ${REMOTE_PATH:=/root/cloudify-manager-install}/packaging/create_rpm.sh
${REMOTE_PATH}/packaging/create_rpm.sh community true master ${REMOTE_PATH}
rpm -i /tmp/cloudify-manager-install*.rpm
rm -f /tmp/cloudify-manager-install*.rpm
