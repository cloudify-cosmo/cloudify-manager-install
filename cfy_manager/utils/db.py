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

from .common import sudo
from ..config import config
from ..constants import POSTGRESQL_CLIENT_CERT_PATH, POSTGRESQL_CLIENT_KEY_PATH

from cfy_manager.components.service_names import POSTGRESQL_CLIENT
from cfy_manager.components.service_components import DATABASE_SERVICE
from cfy_manager.components.components_constants import (
    SSL_ENABLED,
    SERVICES_TO_INSTALL,
    SSL_CLIENT_VERIFICATION
)


def run_psql_command(command, db_key):
    base_command = []
    if DATABASE_SERVICE in config[SERVICES_TO_INSTALL]:
        # In case the default user is postgres and we're in AIO installation,
        # "peer" authentication is used
        if config[POSTGRESQL_CLIENT]['server_username'] == 'postgres':
            base_command.extend(['-u', 'postgres'])

    # Run psql with just the results output without headers (-t),
    # and no psqlrc (-X)
    base_command.extend(['/usr/bin/psql', '-t', '-X'])
    command = base_command + command
    db_env = generate_db_env(database=config[POSTGRESQL_CLIENT][db_key])
    result = sudo(command, env=db_env)
    return result.aggr_stdout.strip()


def generate_db_env(database):
    pg_config = config[POSTGRESQL_CLIENT]

    if DATABASE_SERVICE in config[SERVICES_TO_INSTALL]:
        # If we're connecting to the actual local db we don't need to supply a
        # host
        host = ""
    else:
        host = pg_config['host']

    db_env = {
        'PGHOST': host,
        'PGUSER': pg_config['server_username'],
        'PGPASSWORD': pg_config['server_password'],
        'PGDATABASE': database,
    }

    if config[POSTGRESQL_CLIENT][SSL_ENABLED]:
        db_env['PGSSLMODE'] = 'verify-full'
        db_env['PGSSLROOTCERT'] = '/etc/cloudify/ssl/postgresql_ca.crt'

        # This only makes sense if SSL is used
        if config[POSTGRESQL_CLIENT][SSL_CLIENT_VERIFICATION]:
            db_env['PGSSLCERT'] = POSTGRESQL_CLIENT_CERT_PATH
            db_env['PGSSLKEY'] = POSTGRESQL_CLIENT_KEY_PATH
    return db_env
