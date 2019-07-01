#########
# Copyright (c) 2019 Cloudify Platform Ltd. All rights reserved
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

from manager_rest import config
from manager_rest.flask_utils import setup_flask_app
from manager_rest.storage import models, get_storage_manager

from cloudify_premium.ha import controller, syncthing


def run_syncthing_configuration(hostname, bootstrap_cluster):
    syncthing.configure(bootstrap_cluster)
    syncthing.start(hostname)

    if not bootstrap_cluster:
        sm = get_storage_manager()
        managers_list = sm.list(models.Manager)
        controller.add_manager(managers_list)
        syncthing.wait_for_replication()
    syncthing.finish()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Configure Syncthing replication for the cluster nodes'
    )
    parser.add_argument(
        'args_dict_config_path',
        help='The manager to update in the managers table with its syncthing '
             'ID'
    )
    args = parser.parse_args()
    with open(args.args_dict_config_path, 'r') as f:
        args_dict = json.load(f)

    config.instance.load_configuration()
    setup_flask_app(manager_ip=config.instance.postgresql_host)

    run_syncthing_configuration(args_dict['hostname'],
                                args_dict['bootstrap_cluster'])
