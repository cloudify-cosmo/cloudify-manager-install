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

from cloudify_premium.ha import syncthing


def run_syncthing_configuration(hostname, active_manager_ip,
                                rest_service_port, auth_headers):
    bootstrap_cluster = syncthing.configure(active_manager_ip,
                                            rest_service_port, auth_headers)
    syncthing.start(hostname, active_manager_ip, rest_service_port,
                    auth_headers, bootstrap_cluster=bootstrap_cluster)


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
    run_syncthing_configuration(args_dict['hostname'],
                                args_dict['active_manager_ip'],
                                args_dict['rest_service_port'],
                                args_dict['auth_headers'])
