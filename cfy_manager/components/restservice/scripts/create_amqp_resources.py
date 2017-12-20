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

import sys
import json

from manager_rest.amqp_manager import AMQPManager
from manager_rest.constants import DEFAULT_TENANT_ID
from manager_rest.storage import models, get_storage_manager


def _get_amqp_manager(config):
    return AMQPManager(
        host=config['amqp_host'],
        username=config['amqp_username'],
        password=config['amqp_password']
    )


def _get_default_tenant():
    sm = get_storage_manager()
    return sm.get(models.Tenant, DEFAULT_TENANT_ID)


if __name__ == '__main__':
    # We're expecting to receive as an argument the path to the config file
    assert len(sys.argv) == 2, 'No config file path was provided'
    with open(sys.argv[1], 'r') as f:
        config = json.load(f)
    amqp_manager = _get_amqp_manager(config)
    default_tenant = _get_default_tenant()
    amqp_manager.create_tenant_vhost_and_user(default_tenant)
    print 'Finished creating AMQP resources'
