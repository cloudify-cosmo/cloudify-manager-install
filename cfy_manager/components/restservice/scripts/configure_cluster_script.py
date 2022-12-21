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

import os
import json
import argparse

from manager_rest import config
from manager_rest.flask_utils import setup_flask_app
from manager_rest.storage import models, get_storage_manager

from cloudify_premium.ha import controller, syncthing


def run_syncthing_configuration(hostname, bootstrap_cluster):
    syncthing.configure(
        bootstrap_cluster,
        service_management='supervisord',
    )
    syncthing.start(hostname, service_management='supervisord')

    if not bootstrap_cluster:
        sm = get_storage_manager()
        managers_list = sm.list(models.Manager)
        # controller.add_manager() will trigger manager-added workflow which
        # will also take care of upgrading Prometheus federation configuration
        controller.add_manager(managers_list)
        syncthing.wait_for_replication()
    syncthing.finish(service_management='supervisord')


def file_path(path):
    if os.path.isfile(path):
        return path
    else:
        raise argparse.ArgumentTypeError(
            "The file path \"{0}\" doesn't exist.".format(path))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Configure Syncthing replication for the cluster nodes'
    )
    parser.add_argument(
        '--input',
        help='Path to a config file containing info needed by this script. It '
             'should include the manager to update in the managers table with '
             'its syncthing ID.',
        type=file_path,
        required=True,
    )
    args = parser.parse_args()
    with open(args.input, 'r') as f:
        args_dict = json.load(f)

    with setup_flask_app().app_context():
        config.instance.load_configuration()
    setup_flask_app(manager_ip=config.instance.postgresql_host)

    run_syncthing_configuration(
        args_dict['hostname'],
        args_dict['bootstrap_syncthing'],
    )
