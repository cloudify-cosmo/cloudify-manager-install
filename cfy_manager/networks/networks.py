#!/usr/bin/env python
#########
# Copyright (c) 2018 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.

import json
import argh
from os.path import join
from cfy_manager.logger import get_logger
from cfy_manager.utils import common
from cfy_manager.utils.files import write_to_file
from cfy_manager.constants import (
    NETWORKS_DIR,
    CERT_METADATA_FILE_PATH,
    CLOUDIFY_USER,
    CLOUDIFY_GROUP
)

from cfy_manager.utils.certificates import (
    create_internal_certs,
    load_cert_metadata
)

logger = get_logger('networks')
SCRIPT_DIR = join(NETWORKS_DIR, 'scripts')
REST_HOME_DIR = '/opt/manager'


def _run_update_provider_context_script(args, cluster_node_ip):
    script_path = join(SCRIPT_DIR, 'add-networks-to-provider-context.py')

    # Directly calling with this python bin, in order to make sure it's run
    # in the correct venv
    python_path = join(REST_HOME_DIR, 'env', 'bin', 'python')
    cmd = [python_path, script_path, json.dumps(args), cluster_node_ip]

    return common.sudo(cmd)


def _update_metadata_file(networks):
    """
    Add the new networks to /etc/cloudify/ssl/certificate_metadata
    :param networks: a dict containing the new networks
    """
    metadata = load_cert_metadata()
    old_networks = metadata.get('networks', {})
    networks.update(old_networks)
    metadata['networks'] = networks
    write_to_file(metadata, CERT_METADATA_FILE_PATH, json_dump=True)
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, CERT_METADATA_FILE_PATH)


@argh.arg('--networks',
          help='A JSON string containing the new networks to be added to the'
               ' Manager. Example: `{"<network-name>": "<ip>"}`',
          required=True)
@argh.arg('--cluster-node-ip',
          help='Set the networks for the cluster node which uses this IP as '
               'the default network IP. Only available in a cluster.',
          required=True)
def add_networks(networks=None, cluster_node_ip=''):
    """
    Add new networks to a running Cloudify Manager
    """
    print('Trying to add new networks to Manager...')

    networks = json.loads(networks)

    _run_update_provider_context_script(networks, cluster_node_ip)

    if not cluster_node_ip:
        # in a cluster, those are run by the options handler
        _update_metadata_file(networks)
        create_internal_certs()

    print('New networks were added successfully. Please restart the'
          ' following services: `nginx`, `cloudify-mgmtworker`,'
          '`cloudify-rabbitmq`')
