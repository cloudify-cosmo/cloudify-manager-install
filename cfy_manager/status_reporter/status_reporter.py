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

from __future__ import print_function

import json
from os import environ
from os.path import join

import argh
import yaml

from ..utils import db
from ..config import config
from ..utils.systemd import systemd
from ..utils.common import allows_json_format
from ..utils.install import is_premium_installed
from ..logger import get_logger, setup_console_logger
from ..utils.files import update_yaml_file, sudo_read
from ..utils.scripts import run_script_on_manager_venv
from ..components.restservice.restservice import REST_SECURITY_CONFIG_PATH
from ..constants import (
    STATUS_REPORTER,
    STATUS_REPORTER_DIR,
    STATUS_REPORTER_CONFIGURATION_PATH,
)
from ..components.components_constants import (
    DB_STATUS_REPORTER,
    BROKER_STATUS_REPORTER,
    MANAGER_STATUS_REPORTER
)

SCRIPTS_PATH = join(STATUS_REPORTER_DIR, 'scripts')

logger = get_logger(STATUS_REPORTER)
setup_console_logger()


@argh.arg('--managers-ip',
          nargs='+',
          type=str,
          help='Cloudify managers ip list status reporter will report to, '
               'Example: `<ip-1> <ip-2> <ip-3>`'
          )
@argh.arg('--user-name',
          type=str,
          help='The status reporter\'s user name in the Cloudify system, '
               'Example: `manager_reporter`.'
          )
@argh.arg('--token',
          type=str,
          help='The login auth token for the status reporter\'s user'
               ' in the Cloudify system.'
          )
@argh.arg('--ca-path',
          type=str,
          help='A local path to the CA certificate for communication with'
               ' the Cloudify managers.'
          )
@argh.arg('--reporting-freq',
          type=int,
          help='The interval in seconds that the status reporter will report '
               'it\'s status to the Cloudify system.'
          )
@argh.arg('--reporter-configuration-path',
          type=str,
          help='A local path to the configuration yaml file that'
               ' will contain the relevant settings for updating '
               'status reporter configuration. Notice: You can only '
               'supply local file path or update one of the configuration '
               'params.'
          )
def configure(managers_ip=[], user_name='', token='', ca_path='',
              reporting_freq=None, reporter_configuration_path=''):
    logger.notice('Configuring Status Reporter service with...')
    conf_parameters_passed = any([managers_ip,
                                  user_name,
                                  token,
                                  ca_path,
                                  reporting_freq])
    if reporter_configuration_path and conf_parameters_passed:
        logger.error('Please provide status reporter configuration path '
                     'argument or the other configuration parameters, but '
                     'not together.')
        return
    elif reporter_configuration_path:
        logger.info('Provided configuration file for status reporter at'
                    ' {0}...'.format(reporter_configuration_path))
        try:
            file_content = sudo_read(reporter_configuration_path)
            update_content = yaml.safe_load(file_content)
        except yaml.YAMLError as e:
            logger.error('Failed to load yaml file, due to {0}'.format(str(e)))
            return
    elif conf_parameters_passed:
        update_content = {
            'user_name': user_name,
            'token': token,
            'ca_path': ca_path,
            'managers_ips': managers_ip,
            'reporting_freq': reporting_freq
            }
        logger.info('Provided the following params for updating the status'
                    ' reporter configuration: {0}...'.format(
                     json.dumps(update_content, indent=1)))
    else:
        logger.warning('No configuration param were given,'
                       ' so nothing to update')
        return

    update_yaml_file(STATUS_REPORTER_CONFIGURATION_PATH,
                     'cfyreporter',
                     'cfyreporter',
                     update_content)
    systemd.configure(STATUS_REPORTER)
    logger.info('Starting Status Reporter service...')
    systemd.restart(STATUS_REPORTER)
    logger.notice('Status Reporter successfully configured')


def start():
    logger.notice('Starting Status Reporter service...')
    systemd.start(STATUS_REPORTER)
    logger.notice('Started Status Reporter service')


def stop():
    logger.notice('Stopping Status Reporter service...')
    systemd.stop(STATUS_REPORTER)
    logger.notice('Status Reporter service stopped')


def remove():
    logger.notice('Removing component status reporting service...')
    systemd.remove(STATUS_REPORTER)
    logger.notice('Component status reporting service removed')


@allows_json_format(logger)
def get_tokens(json_format=None):
    """Retrieves the status reporters' tokens from the DB and prints them to
    STDOUT.

    This must be run from a Manager machine.
    """
    logger.notice('Trying to fetch status reporters tokens...')
    if not is_premium_installed():
        logger.error("This command can only be run on a Cloudify Manager "
                     "machine.")
        return
    tokens = _get_status_reporter_tokens()
    if not tokens:
        logger.error("Failed to fetch tokens.")
        return

    if json_format:
        print(json.dumps(tokens))
    else:
        for username, token in tokens.items():
            logger.notice('Token of "{0}" is "{1}"'.format(username, token))


def _get_status_reporter_tokens():
    config.load_config()
    sql_stmnt = (
        """
        SELECT
            json_build_object(
                'id', id,
                'username', username,
                'api_token_key', api_token_key
            )
        FROM users
        WHERE username IN ('{0}', '{1}', '{2}')
        """.format(
            MANAGER_STATUS_REPORTER,
            BROKER_STATUS_REPORTER,
            DB_STATUS_REPORTER
        )
    )
    query_result = db.run_psql_command(
        command=['-c', sql_stmnt],
        db_key='cloudify_db_name',
    )
    query_result = query_result.splitlines()
    users = [json.loads(result.strip()) for result in query_result]
    script_path = join(SCRIPTS_PATH, 'get_encoded_user_ids.py')
    rest_security_config_path = environ.get(
        'MANAGER_REST_SECURITY_CONFIG_PATH', REST_SECURITY_CONFIG_PATH)
    envvars = {'MANAGER_REST_SECURITY_CONFIG_PATH': rest_security_config_path}
    result = run_script_on_manager_venv(script_path, users, envvars=envvars)
    if not result:
        return None
    users = json.loads(result.aggr_stdout)
    tokens = {
        user['username']:
            '{0}{1}'.format(user['encoded_id'], user['api_token_key'])
        for user in users}
    return tokens
