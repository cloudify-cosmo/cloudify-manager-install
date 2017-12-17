#########
# Copyright (c) 2017 GigaSpaces Technologies Ltd. All rights reserved
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

from .. import (
    SCRIPTS,
    ENDPOINT_IP,
    PROVIDER_CONTEXT,
    AGENT,
    SECURITY,
    CLEAN_DB
)

from ..service_names import (
    DB,
    POSTGRESQL,
    RABBITMQ,
    MANAGER
)

from ... import constants
from ...config import config
from ...logger import get_logger

from ...utils import common
from ...utils.files import temp_copy, write_to_tempfile

logger = get_logger(DB)

SCRIPTS_PATH = join(constants.COMPONENTS_DIR, DB, SCRIPTS)
REST_HOME_DIR = '/opt/manager'


def _create_default_db():
    pg_config = config[POSTGRESQL]

    logger.info('Creating default SQL DB: {0}...'.format(pg_config['db_name']))
    script_path = join(SCRIPTS_PATH, 'create_default_db.sh')
    tmp_script_path = temp_copy(script_path)
    common.chmod('+x', tmp_script_path)
    common.sudo(
        'su - postgres -c "{cmd} {db} {user} {password}"'.format(
            cmd=tmp_script_path,
            db=pg_config['db_name'],
            user=pg_config['username'],
            password=pg_config['password'])
    )


def _get_provider_context():
    context = {'cloudify': config[PROVIDER_CONTEXT]}
    context['cloudify']['cloudify_agent'] = config[AGENT]
    return context


def _create_args_dict():
    """
    Create and return a dictionary with all the information necessary for the
    script that creates and populates the DB to run
    """
    return {
        'hash_salt': config[DB][SECURITY]['hash_salt'],
        'secret_key': config[DB][SECURITY]['secret_key'],
        'admin_username': config[MANAGER][SECURITY]['admin_username'],
        'admin_password': config[MANAGER][SECURITY]['admin_password'],
        'amqp_host': config[RABBITMQ][ENDPOINT_IP],
        'amqp_username': config[RABBITMQ]['username'],
        'amqp_password': config[RABBITMQ]['password'],
        'postgresql_host': config[POSTGRESQL]['host'],
        'provider_context': _get_provider_context(),
        'authorization_file_path': join(REST_HOME_DIR, 'authorization.conf'),
        'db_migrate_dir':
            join(constants.MANAGER_RESOURCES_HOME, 'cloudify', 'migrations')
    }


def _create_db_tables_and_add_defaults():
    logger.info('Creating SQL tables and adding default values...')
    script_name = 'create_tables_and_add_defaults.py'
    script_path = join(SCRIPTS_PATH, script_name)

    args_dict = _create_args_dict()

    # The script won't have access to the config, so we dump the relevant args
    # to a JSON file, and pass its path to the script
    args_json_path = write_to_tempfile(args_dict, json_dump=True)

    # Directly calling with this python bin, in order to make sure it's run
    # in the correct venv
    python_path = join(REST_HOME_DIR, 'env', 'bin', 'python')
    result = common.sudo([python_path, script_path, args_json_path])

    _log_results(result)


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


def install():
    configure()


def configure():
    if config[DB][CLEAN_DB]:
        logger.notice('Configuring DB...')
        _create_default_db()
        _create_db_tables_and_add_defaults()
        logger.notice('DB successfully configured')
    else:
        logger.notice('Skipping DB creation and configuration...')


def remove():
    logger.notice('Removing DB...')

    logger.notice('DB successfully removed')
