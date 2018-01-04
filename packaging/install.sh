#!/usr/bin/env bash

echo "###################################################################"
echo "Installing cloudify manager installer..."
echo "###################################################################"

CONFIG_FILE=/etc/cloudify/config.yaml

# Using $SUDO_USER instead of $USER here because fpm runs the script as sudo
# and needs access to the config file as the user
sudo chown $SUDO_USER:$SUDO_USER ${CONFIG_FILE}

echo "###################################################################"
echo "Cloudify installer is ready!"
echo "Edit ${CONFIG_FILE}, and run cfy_manager install"
echo "###################################################################"
