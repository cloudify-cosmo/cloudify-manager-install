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
import sys
from sqlalchemy.orm.attributes import flag_modified


from manager_rest import config
from manager_rest.flask_utils import setup_flask_app
from manager_rest.storage import get_storage_manager, models
try:
    from cloudify_premium.ha.agents import update_agents
except ImportError:
    update_agents = None


RESTSERVICE_CONFIG_PATH = '/opt/manager/cloudify-rest.conf'


def _update_manager_networks(hostname, networks):
    """
    Add the new networks to the `provider context` DB table
    :param networks: a dict containing the new networks
    """
    with setup_flask_app().app_context():
        sm = get_storage_manager()
        manager = sm.get(models.Manager, None, filters={'hostname': hostname})
        manager.networks.update(networks)
        flag_modified(manager, 'networks')
        sm.update(manager)
        if update_agents:
            update_agents(sm)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise RuntimeError('`{0}` expects exactly two arguments, it received '
                           '{1} arguments'.format(len(sys.argv) - 1))
    hostname = sys.argv[1]
    networks = sys.argv[2]
    networks = json.loads(networks)

    config.instance.load_from_file(RESTSERVICE_CONFIG_PATH)
    config.instance.load_configuration()
    _update_manager_networks(hostname, networks)
