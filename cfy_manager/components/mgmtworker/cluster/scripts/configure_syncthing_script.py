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

from manager_rest import config
from manager_rest.flask_utils import setup_flask_app
from cloudify_premium.ha import syncthing


def run_syncthing_configuration(hostname):
    import sys
    sys.path.append('/tmp/pycharm-debug.egg')
    import pydevd
    pydevd.settrace('172.17.0.1', port=53200, stdoutToServer=True, stderrToServer=True)
    print 'Setting up a Flask app'
    setup_flask_app(
        manager_ip=config.instance.postgresql_host,
        hash_salt=config.instance.security_hash_salt,
        secret_key=config.instance.security_secret_key
    )
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

    import sys
    sys.path.append('/tmp/pycharm-debug.egg')
    import pydevd
    pydevd.settrace('172.17.0.1', port=53200, stdoutToServer=True, stderrToServer=True)
    args = parser.parse_args()
    config.instance.load_configuration()
    run_syncthing_configuration(args.hostname)
