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
    PROVIDER_CONTEXT,
    AGENT,
    SECURITY,
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    FLASK_SECURITY
)

from ..service_names import (
    POSTGRESQL,
    RABBITMQ,
    MANAGER,
    RESTSERVICE
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
    pg_config = config[POSTGRESQL]

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
    logger.notice('SQL DB successfully configured')


def _get_provider_context():
    context = {'cloudify': config[PROVIDER_CONTEXT]}
    context['cloudify']['cloudify_agent'] = config[AGENT]
    return context


def _create_args_dict(full_config=False):
    """
    Create and return a dictionary with all the information necessary for the
    script that creates and populates the DB to run
    """
    args_dict = {
        'amqp_host': config[RABBITMQ]['management_endpoint_ip'],
        'amqp_username': config[RABBITMQ]['username'],
        'amqp_password': config[RABBITMQ]['password'],
        'amqp_ca_cert': constants.CA_CERT_PATH,
        'hash_salt': config[FLASK_SECURITY]['hash_salt'],
        'secret_key': config[FLASK_SECURITY]['secret_key'],
        'postgresql_host': config[POSTGRESQL]['host']
    }
    if full_config:
        args_dict.update(
            {
                'admin_username': config[MANAGER][SECURITY][ADMIN_USERNAME],
                'admin_password': config[MANAGER][SECURITY][ADMIN_PASSWORD],
                'provider_context': _get_provider_context(),
                'authorization_file_path': join(REST_HOME_DIR,
                                                'authorization.conf'),
                'db_migrate_dir': join(constants.MANAGER_RESOURCES_HOME,
                                       'cloudify',
                                       'migrations')
            }
        )

    return args_dict


def _run_script(script_name, args_dict):
    script_path = join(SCRIPTS_PATH, script_name)

    # The script won't have access to the config, so we dump the relevant args
    # to a JSON file, and pass its path to the script
    args_json_path = write_to_tempfile(args_dict, json_dump=True)

    # Directly calling with this python bin, in order to make sure it's run
    # in the correct venv
    python_path = join(REST_HOME_DIR, 'env', 'bin', 'python')
    result = common.sudo([python_path, script_path, args_json_path])

    _log_results(result)


def populate_db():
    logger.notice('Populating DB and creating AMQP resources...')
    args_dict = _create_args_dict(full_config=True)
    _run_script('create_tables_and_add_defaults.py', args_dict)
    logger.notice('DB populated and AMQP resources successfully created')


def create_amqp_resources():
    logger.notice('Creating AMQP resources...')
    args_dict = _create_args_dict()
    _run_script('create_amqp_resources.py', args_dict)
    logger.notice('AMQP resources successfully created')


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
