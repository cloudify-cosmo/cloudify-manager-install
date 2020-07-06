#! /usr/bin/env bash
set -e

if [ ! -d /run/cloudify-restservice ]; then
   sudo mkdir -p /run/cloudify-restservice
   sudo chown cfyuser. /run/cloudify-restservice
   sudo chmod 755 /run/cloudify-restservice
fi