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

from flask_migrate import upgrade

from manager_rest import config
from manager_rest.storage import db, models, get_storage_manager
from manager_rest.amqp_manager import AMQPManager
from manager_rest.flask_utils import setup_flask_app
from manager_rest.storage.storage_utils import \
    create_default_user_tenant_and_roles


def _init_db_tables(db_migrate_dir):
    print 'Setting up a Flask app'
    setup_flask_app(
        manager_ip=config.instance.postgresql_host,
        hash_salt=config.instance.security_hash_salt,
        secret_key=config.instance.security_secret_key
    )

    # Clean up the DB, in case it's not a clean install
    db.drop_all()
    db.engine.execute('DROP TABLE IF EXISTS alembic_version;')

    print 'Creating tables in the DB'
    upgrade(directory=db_migrate_dir)


def _add_default_user_and_tenant(amqp_manager, script_config):
    print 'Creating bootstrap admin, default tenant and security roles'
    create_default_user_tenant_and_roles(
        admin_username=script_config['admin_username'],
        admin_password=script_config['admin_password'],
        amqp_manager=amqp_manager,
        authorization_file_path=script_config['authorization_file_path']
    )


def _get_amqp_manager():
    return AMQPManager(
        host=config.instance.amqp_management_host,
        username=config.instance.amqp_username,
        password=config.instance.amqp_password,
        verify=config.instance.amqp_ca_path
    )


def _add_provider_context(context):
    sm = get_storage_manager()
    provider_context = models.ProviderContext(
        id='CONTEXT',
        name='provider',
        context=context
    )
    sm.put(provider_context)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Create SQL DB tables and populate them with defaults'
    )
    parser.add_argument(
        'config_path',
        help='Path to a config file containing info needed by this script'
    )

    args = parser.parse_args()
    config.instance.load_configuration()

    with open(args.config_path, 'r') as f:
        script_config = json.load(f)
    _init_db_tables(script_config['db_migrate_dir'])
    amqp_manager = _get_amqp_manager()
    _add_default_user_and_tenant(amqp_manager, script_config)
    _add_provider_context(script_config['provider_context'])
    print 'Finished creating bootstrap admin, default tenant and provider ctx'
