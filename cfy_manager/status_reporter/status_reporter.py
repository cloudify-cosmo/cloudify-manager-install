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
import logging

import argh

from ..utils import db, service
from ..config import config
from ..utils.files import read_yaml_file

from ..utils.install import is_premium_installed
from ..utils.scripts import get_encoded_user_ids
from cfy_manager.utils.common import output_table
from ..logger import get_logger, setup_console_logger
from ..utils.node import update_status_reporter_config
from ..utils.common import allows_json_format, copy, sudo
from ..components.components_constants import (
    DB_STATUS_REPORTER,
    BROKER_STATUS_REPORTER,
    MANAGER_STATUS_REPORTER
)
from ..constants import (
    STATUS_REPORTER,
    VERBOSE_HELP_MSG,
    STATUS_REPORTER_TOKEN,
    CLOUDIFY_USER,
    CLOUDIFY_GROUP,
    SELECT_USER_TOKENS_QUERY,
    STATUS_REPORTER_MANAGERS_IPS,
    STATUS_REPORTER_CONFIGURATION_PATH,
)

CA_DEFAULT_PATH = '/etc/cloudify/ssl/status_reporter_cert.pem'

logger = get_logger(STATUS_REPORTER)


@argh.arg('--managers-ip',
          nargs='+',
          type=str,
          dest='managers_ips',
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
@argh.arg('--node-id',
          type=str,
          help='The status reporter\'s node id, '
               'Example: `e99315a0-a153-475a-9879-f41e84d46233`.'
          )
@argh.arg('--log-level',
          type=str,
          choices=[logging.getLevelName(logging.INFO),
                   logging.getLevelName(logging.WARN),
                   logging.getLevelName(logging.ERROR),
                   logging.getLevelName(logging.DEBUG)],
          help='The status reporter\'s logging level, default level is info'
               'Example: `error`.'
          )
@argh.arg('--request-timeout',
          type=int,
          help='The timeout in seconds that the status reporter will wait for '
               'an answer from the Cloudify manager on every http request.'
          )
@argh.arg('-v', '--verbose', help=VERBOSE_HELP_MSG, default=False)
@argh.arg('--no-restart',
          help='In case there is a need to not restart the status reporter '
               'after configuring it.',
          default=False)
def configure(managers_ips=None, user_name='', token='', ca_path='',
              reporting_freq=None, node_id='', log_level='', verbose=False,
              request_timeout=None, no_restart=False):
    managers_ips = managers_ips or []
    setup_console_logger(verbose=verbose)
    logger.notice('Configuring Status Reporter service with...')
    passed_parameters = _get_configure_args(ca_path,
                                            log_level,
                                            managers_ips,
                                            node_id,
                                            reporting_freq,
                                            token,
                                            user_name,
                                            request_timeout)
    if not passed_parameters:
        logger.warning('No configuration param were given,'
                       ' so nothing to update')
        return

    logger.info('Provided the following params for updating the status'
                ' reporter configuration: {0}...'.format(
                    json.dumps(passed_parameters, indent=1)))
    update_status_reporter_config(passed_parameters)
    _handle_ca_path(ca_path)
    if no_restart:
        logger.info('Status Reporter service\'s configuration change applied'
                    ' successfully, a restart is required to activate it')
        return
    logger.info('Starting Status Reporter service...')
    service.restart(STATUS_REPORTER)
    logger.notice('Status Reporter successfully configured')


def _handle_ca_path(ca_path):
    if not ca_path:
        return

    logger.info('Copying CA certificate from {0} to {1}...'.format(
        ca_path, CA_DEFAULT_PATH))
    copy(ca_path, CA_DEFAULT_PATH)
    sudo(['chown', '{owner}.{group}'.format(
        owner=CLOUDIFY_USER, group=CLOUDIFY_GROUP),
        CA_DEFAULT_PATH])


def _get_configure_args(ca_path, log_level, managers_ip, node_id,
                        reporting_freq, token, user_name, request_timeout):
    conf_parameters_passed = {
        'user_name': user_name,
        STATUS_REPORTER_TOKEN: token,
        'ca_path': ca_path,
        STATUS_REPORTER_MANAGERS_IPS: managers_ip,
        'reporting_freq': reporting_freq,
        'node_id': node_id,
        'log_level': log_level,
        'request_timeout': request_timeout
    }
    return {key: value for (key, value) in
            conf_parameters_passed.items() if value}


@argh.arg('-v', '--verbose', help=VERBOSE_HELP_MSG, default=False)
def start(verbose=False):
    setup_console_logger(verbose=verbose)
    logger.notice('Starting Status Reporter service...')
    service.start(STATUS_REPORTER, ignore_failure=True)
    logger.notice('Started Status Reporter service')


@argh.arg('-v', '--verbose', help=VERBOSE_HELP_MSG, default=False)
def stop(verbose=False):
    setup_console_logger(verbose=verbose)
    logger.notice('Stopping Status Reporter service...')
    service.stop(STATUS_REPORTER)
    logger.notice('Status Reporter service stopped')


@argh.arg('-v', '--verbose', help=VERBOSE_HELP_MSG, default=False)
def remove(verbose=False):
    setup_console_logger(verbose=verbose)
    logger.notice('Removing component status reporting service...')
    service.remove(STATUS_REPORTER)
    logger.notice('Component status reporting service removed')


@argh.arg('-v', '--verbose', help=VERBOSE_HELP_MSG, default=False)
@allows_json_format()
def get_tokens(json_format=None, verbose=False):
    """Retrieves the status reporters' tokens from the DB and prints them.

    This must be run from a Manager machine.
    """
    setup_console_logger(verbose=verbose)
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


@argh.arg('-v', '--verbose', help=VERBOSE_HELP_MSG, default=False)
@allows_json_format()
def show_configuration(json_format=None, verbose=False):
    """Prints the status reporter configuration.
    """
    setup_console_logger(verbose=verbose)
    logger.info('Fetching config...')
    _config = read_yaml_file(STATUS_REPORTER_CONFIGURATION_PATH)
    if not _config:
        logger.error("Config file doesn't exist.")
        return
    if json_format:
        print(json.dumps(_config))
    else:
        output_columns = ('Key', 'Value')
        output_rows = [{'Key': key, 'Value': value}
                       for key, value in _config.items()]
        output_table(output_rows, output_columns)


def _get_status_reporter_tokens():
    config.load_config()
    sql_stmnt = SELECT_USER_TOKENS_QUERY + " IN ('{0}', '{1}', '{2}')".format(
        MANAGER_STATUS_REPORTER,
        BROKER_STATUS_REPORTER,
        DB_STATUS_REPORTER
    )
    query_result = db.run_psql_command(
        command=['-c', sql_stmnt],
        db_key='cloudify_db_name',
    )
    query_result = query_result.splitlines()
    users = [json.loads(result.strip()) for result in query_result]
    return get_encoded_user_ids(users)
