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
from cfy_manager.constants import (
    NETWORKS_DIR,
)

from cfy_manager.utils.certificates import (
    create_internal_certs,
    load_cert_metadata,
    store_cert_metadata
)

logger = get_logger('networks')
SCRIPT_DIR = join(NETWORKS_DIR, 'scripts')
REST_HOME_DIR = '/opt/manager'


def _run_update_provider_context_script(host, networks):
    script_path = join(SCRIPT_DIR, 'add-networks-to-provider-context.py')

    # Directly calling with this python bin, in order to make sure it's run
    # in the correct venv
    python_path = join(REST_HOME_DIR, 'env', 'bin', 'python')
    cmd = [python_path, script_path, host, json.dumps(networks)]

    return common.sudo(cmd)


def _validate_duplicate_network(old_networks, new_networks):
    """Check that all networks have unique names"""
    for network in new_networks:
        if network in old_networks:
            raise Exception('Network name {0} already exists. Cannot add '
                            'new networks. Choose uniqe network names and '
                            'run the command again'.format(network))


def _update_metadata_file(metadata, networks):
    """
    Add the new networks to /etc/cloudify/ssl/certificate_metadata
    :param networks: a dict containing the new networks
    """

    old_networks = metadata['network_names']
    new_networks = networks.keys()
    _validate_duplicate_network(old_networks, new_networks)
    if metadata.get('broker_addresses'):
        new_brokers = networks.values()
    else:
        new_brokers = None
    if metadata.get('manager_addresses'):
        new_managers = networks.values()
    else:
        new_managers = None

    store_cert_metadata(
        new_networks=networks.keys(),
        new_brokers=new_brokers,
        new_managers=new_managers,
    )


@argh.arg('--networks',
          help='A JSON string containing the new networks to be added to the'
               ' Manager. Example: `{"<network-name>": "<ip>"}`',
          required=True)
def add_networks(networks=None):
    """
    Add new networks to a running Cloudify Manager
    """
    print('Trying to add new networks to Manager...')

    networks = json.loads(networks)
    metadata = load_cert_metadata()

    _update_metadata_file(metadata, networks)
    create_internal_certs()

    _run_update_provider_context_script(
        metadata['internal_rest_host'], networks)

    print('New networks were added successfully. Please restart the'
          ' following services: `nginx`, `cloudify-mgmtworker`,'
          '`cloudify-rabbitmq`')
