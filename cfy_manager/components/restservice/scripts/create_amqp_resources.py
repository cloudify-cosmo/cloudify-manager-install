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

from manager_rest import config
from manager_rest.amqp_manager import AMQPManager
from manager_rest.constants import DEFAULT_TENANT_ID
from manager_rest.flask_utils import setup_flask_app
from manager_rest.storage import models, get_storage_manager


def _setup_flask_app():
    setup_flask_app(
        manager_ip=config.instance.postgresql_host,
        hash_salt=config.instance.security_hash_salt,
        secret_key=config.instance.security_secret_key
    )


def _get_amqp_manager():
    return AMQPManager(
        host=config.instance.amqp_management_host,
        username=config.instance.amqp_username,
        password=config.instance.amqp_password,
        verify=config.instance.amqp_ca_path
    )


def _get_default_tenant():
    sm = get_storage_manager()
    return sm.get(models.Tenant, DEFAULT_TENANT_ID)


if __name__ == '__main__':
    config.instance.load_configuration()
    _setup_flask_app()
    amqp_manager = _get_amqp_manager()
    default_tenant = _get_default_tenant()
    amqp_manager.create_tenant_vhost_and_user(default_tenant)
    amqp_manager.sync_metadata()
