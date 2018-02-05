#!/usr/bin/env bash

echo "
###########################################################################
Cloudify installer is ready!
To use it run:
cfy_manager install --private-ip <PRIVATE_IP> --public-ip <PUBLIC_IP>
(Use cfy_manager -h for a full list of options)

Alternatively, edit /etc/cloudify/config.yaml to set IPs and other options,
and then run:
cfy_manager install

(Members of the 'wheel' group have write-level access to this config file)
###########################################################################
"
