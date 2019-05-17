#!/usr/bin/env python
#########
# Copyright (c) 2018 Cloudify Platform Ltd. All rights reserved
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
import argparse

from sqlalchemy.orm.attributes import flag_modified

from manager_rest import config
from manager_rest.flask_utils import setup_flask_app
from manager_rest.storage import get_storage_manager, models
try:
    from cloudify_premium.ha.agents import update_agents
except ImportError:
    update_agents = None


RESTSERVICE_CONFIG_PATH = '/opt/manager/cloudify-rest.conf'


def _update_manager_networks(hostname, networks, with_broker=False):
    """
    Add the new networks to the `provider context` DB table
    :param networks: a dict containing the new networks
    """
    with setup_flask_app().app_context():
        sm = get_storage_manager()

        filters = {}
        if hostname:
            filters = {'hostname': hostname}
        managers = sm.list(models.Manager, filters=filters)
        if len(managers) != 1:
            raise RuntimeError(
                'Expected 1 manager, found {0} (passed hostname: {1}'
                .format(len(managers), hostname))
        manager = managers[0]

        if with_broker:
            brokers = sm.list(models.RabbitMQBroker)
            if len(brokers) != 1:
                raise RuntimeError('Expected 1 broker, found {0}'
                                   .format(len(brokers)))
            broker = brokers[0]
            broker.networks.update(networks)
            flag_modified(broker, 'networks')
            sm.update(broker)

        manager.networks.update(networks)
        flag_modified(manager, 'networks')
        sm.update(manager)

        if update_agents:
            update_agents(sm)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Store the new network in the database')
    parser.add_argument('--hostname', help='Hostname of the current node')
    parser.add_argument('--networks', required=True,
                        help='JSON string containing the new networks')
    parser.add_argument('--broker', dest='broker', action='store_true',
                        help='The broker networks will also be updated, '
                             'assuming there is only one broker (all-in-one '
                             'installation)')
    args = parser.parse_args()

    config.instance.load_from_file(RESTSERVICE_CONFIG_PATH)
    config.instance.load_configuration()
    _update_manager_networks(
        args.hostname, json.loads(args.networks), with_broker=args.broker)
