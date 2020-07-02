#!/bin/bash

set -e

# First of all we need to make sure that services_to_install at least contain manager_service
manager_service=$(grep "manager_service" /home/centos/demo/config.yaml)
set_manager_ip_on_boot=$(grep "set_manager_ip_on_boot: true" /home/centos/demo/config.yaml)

# Run the image starter
/usr/bin/cfy_manager image-starter

# Check to see if the manager service is enabled
if [ -n "$manager_service" ] && [ -n "$set_manager_ip_on_boot" ]; then
  while [ -z "$(grep "Cloudify Manager services successfully started!" /var/log/cloudify/manager/cfy_manager.log)" ]; do
          echo "The starter image service not finished yet"
  done

  echo "Call manager ip setter to set the ip of the manager"
  /opt/cloudify/manager-ip-setter/start_manager_ip_setter.sh
fi