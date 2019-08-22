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
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool

from .manager_config import make_manager_config
from ..components_constants import (
    SCRIPTS,
    PROVIDER_CONTEXT,
    AGENT,
    SECURITY,
    SERVICES_TO_INSTALL,
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    HOSTNAME,
    PREMIUM_EDITION,
)

from ..service_components import DATABASE_SERVICE
from ..service_names import (
    POSTGRESQL_CLIENT,
    MANAGER,
    RESTSERVICE,
    RABBITMQ
)

from ... import constants
from ...config import config
from ...logger import get_logger

from ...utils import common
from ...utils.files import write_to_tempfile

logger = get_logger('DB')

SCRIPTS_PATH = join(constants.COMPONENTS_DIR, RESTSERVICE, SCRIPTS)
REST_HOME_DIR = '/opt/manager'
STAGE_DB_NAME = 'stage'
COMPOSER_DB_NAME = 'composer'


@contextmanager
def _connect_to_db(cloudify_db=False):
    pg_config = config[POSTGRESQL_CLIENT]
    db_to_use = pg_config['db_name'] if cloudify_db \
        else pg_config['server_db_name']
    db_connection_string = \
        'postgres://{user}:{password}@{hostname_and_port}/{db}'.format(
            user=pg_config['server_username'],
            password=pg_config['server_password'],
            hostname_and_port=pg_config['host'],
            db=db_to_use
        )
    # DROP and CREATE db queries are not permitted during a transaction
    # so we AUTOCOMMIT
    connection = create_engine(db_connection_string,
                               poolclass=NullPool,
                               isolation_level="AUTOCOMMIT").connect()
    yield connection
    connection.close()


def prepare_db():
    pg_config = config[POSTGRESQL_CLIENT]
    cloudify_db_name = pg_config['db_name']
    server_username = pg_config['server_username'].split('@')[0]
    username = pg_config['username'].split('@')[0]
    password = pg_config['password']

    drop_database_query = "DROP DATABASE IF EXISTS {db_name};"
    drop_user_query = "DROP USER IF EXISTS {username};"
    create_user_query = "CREATE USER {username} WITH PASSWORD '{password}';"
    grant_role_query = "GRANT {username} TO {pg_server_username};"
    create_db_query = "CREATE DATABASE {db_name};"
    grant_all_privileges_query = \
        "GRANT ALL PRIVILEGES ON DATABASE {db_name} TO {username};"
    alter_user_query = "ALTER USER {username} CREATEDB;"
    alter_db_query = "ALTER DATABASE {db_name} OWNER TO {username};"
    revoke_role_query = "REVOKE {username} FROM {pg_server_username};"

    db_creation_queries = [
        # Cleaning server of old DBs
        drop_database_query.format(db_name=cloudify_db_name),
        drop_database_query.format(db_name=STAGE_DB_NAME),
        drop_database_query.format(db_name=COMPOSER_DB_NAME),
        drop_user_query.format(username=username),

        # Creating Cloudify DB user
        create_user_query.format(username=username, password=password),
        # Adding the login user to be a member of the cloudify role since we
        # are not always superuser
        grant_role_query.format(
            pg_server_username=server_username,
            username=username),

        # Creating Cloudify DB
        create_db_query.format(db_name=cloudify_db_name),
        grant_all_privileges_query.format(db_name=cloudify_db_name,
                                          username=username),
        alter_user_query.format(username=username),
        alter_db_query.format(db_name=cloudify_db_name, username=username),

        # Creating Stage DB
        create_db_query.format(db_name=STAGE_DB_NAME),
        grant_all_privileges_query.format(db_name=STAGE_DB_NAME,
                                          username=username),
        alter_db_query.format(db_name=STAGE_DB_NAME, username=username),

        # Creating Composer DB
        create_db_query.format(db_name=COMPOSER_DB_NAME),
        grant_all_privileges_query.format(db_name=COMPOSER_DB_NAME,
                                          username=username),
        alter_db_query.format(db_name=COMPOSER_DB_NAME, username=username),

        # Revoking the login user from the cloudify role
        revoke_role_query.format(
            pg_server_username=server_username,
            username=username)
    ]
    logger.notice('Configuring SQL DB...')
    with _connect_to_db() as connection:
        for query in db_creation_queries:
            try:
                connection.execute(query)
            except Exception as e:
                logger.error(e.message)
    logger.notice('SQL DB successfully configured')


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
    try:
        with _connect_to_db(cloudify_db=True) as connection:
            result = (
                connection.execute(
                    "SELECT * FROM managers where hostname='{0}'".format(
                        config[MANAGER][HOSTNAME])
                ))
        return result.rowcount
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
