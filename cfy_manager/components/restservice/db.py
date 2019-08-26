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


def prepare_db():
    logger.notice('Configuring SQL DB...')
    pg_config = config[POSTGRESQL_CLIENT]

    script_path = join(SCRIPTS_PATH, 'create_default_db.sh')
    tmp_script_path = temp_copy(script_path)
    common.chmod('o+rx', tmp_script_path)
    username = pg_config['username'].split('@')[0]
    db_init_script_command = \
        '{cmd} {db} {user} {password}'.format(
            cmd=tmp_script_path,
            db=pg_config['db_name'],
            user=username,
            password=pg_config['password']
        )

    if DATABASE_SERVICE in config[SERVICES_TO_INSTALL]:
        # In case the default user is postgres and we're in AIO installation,
        # "peer" authentication is used
        if config[POSTGRESQL_CLIENT]['server_username'] == 'postgres':
            db_init_script_command = '-u postgres ' + db_init_script_command

    db_init_env = _generate_db_env(database=pg_config['server_db_name'])

    common.sudo(db_init_script_command, env=db_init_env)
    logger.notice('SQL DB successfully configured')


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


def check_manager_in_table():
    check_command = [
        'psql',
        '-t',  # Just return the result
        '-c', "SELECT COUNT(*) FROM managers where hostname='{0}'".format(
            config[MANAGER][HOSTNAME],
        ),
    ]
    db_env = _generate_db_env(database=config[POSTGRESQL_CLIENT]['db_name'])

    try:
        result = common.sudo(check_command, env=db_env)
        return int(result.aggr_stdout.strip())
    except Exception as err:
        logger.debug('{0} - Database not initialized yet, proceeding...'
                     .format(err))
        return constants.DB_NOT_INITIALIZED


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
