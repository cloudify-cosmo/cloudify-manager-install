#!/usr/bin/env python
#########
# Copyright (c) 2016 GigaSpaces Technologies Ltd. All rights reserved
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

from manager_rest.amqp_manager import AMQPManager
from manager_rest.constants import DEFAULT_TENANT_ID
from manager_rest.flask_utils import setup_flask_app
from manager_rest.storage import models, get_storage_manager


def _setup_flask_app(config):
    setup_flask_app(
        manager_ip=config['postgresql_host'],
        hash_salt=config['hash_salt'],
        secret_key=config['secret_key']
    )


def _get_amqp_manager(config):
    return AMQPManager(
        host=config['amqp_host'],
        username=config['amqp_username'],
        password=config['amqp_password'],
        verify=config['amqp_ca_cert']
    )


def _get_default_tenant():
    sm = get_storage_manager()
    return sm.get(models.Tenant, DEFAULT_TENANT_ID)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Create AMQP vhost/user for the default tenant'
    )
    parser.add_argument(
        'config_path',
        help='Path to a config file containing info needed by this script'
    )

    args = parser.parse_args()
    with open(args.config_path, 'r') as f:
        config = json.load(f)
    _setup_flask_app(config)
    amqp_manager = _get_amqp_manager(config)
    default_tenant = _get_default_tenant()
    amqp_manager.create_tenant_vhost_and_user(default_tenant)
    print 'Finished creating AMQP resources'
