#!/usr/bin/env bash

set -eu

MANAGER_RESOURCES_URL=`curl https://raw.githubusercontent.com/cloudify-cosmo/cloudify-versions/master/packages-urls/manager-single-tar.yaml`
REMOTE_LOCATION='/root/cloudify-manager-install'

echo "Creating install RPM..."
docker cp ~/cloudify-manager-install ${CONTAINER_NAME}:${REMOTE_LOCATION}
docker exec -d ${CONTAINER_NAME} sh -c "systemctl start sshd"
docker exec -t ${CONTAINER_NAME} sh -c "chmod +x ${REMOTE_LOCATION}/packaging/create_rpm.sh"
docker exec -t ${CONTAINER_NAME} sh -c "${REMOTE_LOCATION}/packaging/create_rpm.sh community true master ${REMOTE_LOCATION}"
docker exec -t ${CONTAINER_NAME} sh -c "rpm -i /tmp/cloudify-manager-install*.rpm"
docker exec -t ${CONTAINER_NAME} sh -c "rm -f /tmp/cloudify-manager-install*.rpm"
docker exec -t ${CONTAINER_NAME} sh -c "rm -rf ${REMOTE_LOCATION}"
