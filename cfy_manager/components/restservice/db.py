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

import time
import uuid
from os.path import join

from .manager_config import make_manager_config
from ..components_constants import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    AGENT,
    HOSTNAME,
    PREMIUM_EDITION,
    PROVIDER_CONTEXT,
    SCRIPTS,
    SECURITY,
    SERVICES_TO_INSTALL,
    SSL_CLIENT_VERIFICATION,
    SSL_ENABLED,
)

from ..service_components import DATABASE_SERVICE
from ..service_names import (
    MANAGER,
    POSTGRESQL_CLIENT,
    RABBITMQ,
    RESTSERVICE,
)

from ... import constants
from ...config import config
from ...logger import get_logger

from ...utils import common
from ...utils.files import temp_copy, write_to_tempfile

logger = get_logger('DB')

SCRIPTS_PATH = join(constants.COMPONENTS_DIR, RESTSERVICE, SCRIPTS)
REST_HOME_DIR = '/opt/manager'


def drop_db():
    logger.notice('PREPARING TO DROP CLOUDIFY DATABASE...')
    logger.notice(
        'You have 10 seconds to press Ctrl+C if this was a mistake.'
    )
    time.sleep(10)
    _execute_db_script('drop_db.sh')
    logger.info('Cloudify database successfully dropped.')


def prepare_db():
    logger.notice('Configuring SQL DB...')
    _execute_db_script('create_default_db.sh')
    logger.notice('SQL DB successfully configured')


def _execute_db_script(script_name):
    pg_config = config[POSTGRESQL_CLIENT]

    script_path = join(SCRIPTS_PATH, script_name)
    tmp_script_path = temp_copy(script_path)
    common.chmod('o+rx', tmp_script_path)
    username = pg_config['cloudify_username'].split('@')[0]
    db_script_command = \
        '{cmd} {db} {user} {password}'.format(
            cmd=tmp_script_path,
            db=pg_config['cloudify_db_name'],
            user=username,
            password=pg_config['cloudify_password']
        )

    if DATABASE_SERVICE in config[SERVICES_TO_INSTALL]:
        # In case the default user is postgres and we're in AIO installation,
        # "peer" authentication is used
        if config[POSTGRESQL_CLIENT]['server_username'] == 'postgres':
            db_script_command = '-u postgres ' + db_script_command

    db_env = _generate_db_env(database=pg_config['server_db_name'])

    common.sudo(db_script_command, env=db_env)


def _generate_db_env(database):
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
            db_env['PGSSLCERT'] = constants.POSTGRESQL_CLIENT_CERT_PATH
            db_env['PGSSLKEY'] = constants.POSTGRESQL_CLIENT_KEY_PATH
    return db_env


def _get_provider_context():
    context = {'cloudify': config[PROVIDER_CONTEXT]}
    context['cloudify']['cloudify_agent'] = config[AGENT]
    return context


def _create_args_dict():
    """
    Create and return a dictionary with all the information necessary for the
    script that creates and populates the DB to run
    """
    args_dict = {
        'admin_username': config[MANAGER][SECURITY][ADMIN_USERNAME],
        'admin_password': config[MANAGER][SECURITY][ADMIN_PASSWORD],
        'provider_context': _get_provider_context(),
        'authorization_file_path': join(REST_HOME_DIR, 'authorization.conf'),
        'db_migrate_dir': join(constants.MANAGER_RESOURCES_HOME, 'cloudify',
                               'migrations'),
        'config': make_manager_config(),
        'premium': config[MANAGER][PREMIUM_EDITION],
        'rabbitmq_brokers': [
            {
                'name': name,
                'host': broker['default'],
                'management_host': (
                    '127.0.0.1' if config[RABBITMQ]['management_only_local']
                    else broker['default']
                ),
                'username': config[RABBITMQ]['username'],
                'password': config[RABBITMQ]['password'],
                'params': None,
                'networks': broker,
                'node_id': str(uuid.uuid4())
            }
            for name, broker in config[RABBITMQ]['cluster_members'].items()
        ],
    }
    rabbitmq_ca_cert_path = config['rabbitmq'].get('ca_path')
    if rabbitmq_ca_cert_path:
        with open(rabbitmq_ca_cert_path) as f:
            args_dict['rabbitmq_ca_cert'] = f.read()
    return args_dict


def _create_process_env(rest_config=None, authorization_config=None,
                        security_config=None):
    env = {}
    for value, envvar in [
            (rest_config, 'MANAGER_REST_CONFIG_PATH'),
            (security_config, 'MANAGER_REST_SECURITY_CONFIG_PATH'),
            (authorization_config, 'MANAGER_REST_AUTHORIZATION_CONFIG_PATH'),
    ]:
        if value is not None:
            env[envvar] = value
    return env


def _run_script(script_name, args_dict=None, configs=None):
    env_dict = None
    if configs is not None:
        env_dict = _create_process_env(**configs)

    script_path = join(SCRIPTS_PATH, script_name)

    # Directly calling with this python bin, in order to make sure it's run
    # in the correct venv
    python_path = join(REST_HOME_DIR, 'env', 'bin', 'python')
    cmd = [python_path, script_path]

    if args_dict:
        # The script won't have access to the config, so we dump the relevant
        # args to a JSON file, and pass its path to the script
        args_json_path = write_to_tempfile(args_dict, json_dump=True)
        cmd.append(args_json_path)

    result = common.sudo(cmd, env=env_dict)

    _log_results(result)


def populate_db(configs):
    logger.notice('Populating DB and creating AMQP resources...')
    args_dict = _create_args_dict()
    _run_script('create_tables_and_add_defaults.py', args_dict, configs)
    logger.notice('DB populated and AMQP resources successfully created')


def insert_manager(configs):
    logger.notice('Registering manager in the DB...')
    args = {
        'manager': {
            'public_ip': config['manager']['public_ip'],
            'hostname': config[MANAGER][HOSTNAME],
            'private_ip': config['manager']['private_ip'],
            'networks': config['networks'],
            'node_id': str(uuid.uuid4())
        }
    }
    try:
        with open(constants.CA_CERT_PATH) as f:
            args['manager']['ca_cert'] = f.read()
    except IOError:
        args['manager']['ca_cert'] = None
    _run_script('create_tables_and_add_defaults.py', args, configs)


def create_amqp_resources(configs=None):
    logger.notice('Creating AMQP resources...')
    _run_script('create_amqp_resources.py', configs=configs)
    logger.notice('AMQP resources successfully created')


def _run_psql_command(command, db_key):
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

    db_env = _generate_db_env(database=config[POSTGRESQL_CLIENT][db_key])

    result = common.sudo(command, env=db_env)

    return result.aggr_stdout.strip()


def check_db_exists():
    # Get the list of databases
    result = _run_psql_command(
        command=['-l'],
        db_key='server_db_name',
    )

    # Example of expected output:
    # cloudify_db | cloudify | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =Tc/cloudify         +  # noqa
    #             |          |          |             |             | cloudify=CTc/cloudify   # noqa
    # composer    | cloudify | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =Tc/cloudify         +  # noqa
    #             |          |          |             |             | cloudify=CTc/cloudify   # noqa
    # postgres    | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 |                         # noqa
    # stage       | cloudify | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =Tc/cloudify         +  # noqa
    #             |          |          |             |             | cloudify=CTc/cloudify   # noqa
    # template0   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +  # noqa
    #             |          |          |             |             | postgres=CTc/postgres   # noqa
    # template1   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +  # noqa
    #             |          |          |             |             | postgres=CTc/postgres   # noqa
    #                                                                                         # noqa

    result = result.splitlines()
    dbs = [db.split('|')[0].strip() for db in result]
    dbs = [db for db in dbs if db]  # Clear out empty strings

    return config[POSTGRESQL_CLIENT]['cloudify_db_name'] in dbs


def manager_is_in_db():
    result = _run_psql_command(
        command=[
            '-c', "SELECT COUNT(*) FROM managers where hostname='{0}'".format(
                config[MANAGER][HOSTNAME],
            ),
        ],
        db_key='cloudify_db_name',
    )

    # As the name is unique, there can only ever be at most 1 entry with the
    # expected name, and if there is then the manager is in the db.
    return int(result) == 1


def _log_results(result):
    """Log stdout/stderr output from the script
    """
    if result.aggr_stdout:
        output = result.aggr_stdout.split('\n')
        output = [line.strip() for line in output if line.strip()]
        for line in output[:-1]:
            logger.debug(line)
        logger.info(output[-1])
    if result.aggr_stderr:
        output = result.aggr_stderr.split('\n')
        output = [line.strip() for line in output if line.strip()]
        for line in output:
            logger.error(line)
