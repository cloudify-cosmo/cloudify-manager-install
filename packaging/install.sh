#!/usr/bin/env bash

echo "
###########################################################################
Cloudify installer is ready!
To install Cloudify Manager, run:
cfy_manager install --private-ip <PRIVATE_IP> --public-ip <PUBLIC_IP>
(Use cfy_manager -h for a full list of options)

You can specify more installation settings in /etc/cloudify/config.yaml. If you
specify the public and private IP addresses in the config.yaml file, run:
cfy_manager install
###########################################################################
"
