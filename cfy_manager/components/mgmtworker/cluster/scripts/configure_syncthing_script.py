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

import argparse

from cloudify_premium.ha.syncthing import syncthing


def run_syncthing_configuration(hostname):
    syncthing.configure()
    syncthing.start(hostname)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Configure Syncthing replication for the cluster nodes'
    )
    parser.add_argument(
        'hostname',
        help='The manager to update in the managers table with its syncthing '
             'ID'
    )

    args = parser.parse_args()
    run_syncthing_configuration(args.hostname)
