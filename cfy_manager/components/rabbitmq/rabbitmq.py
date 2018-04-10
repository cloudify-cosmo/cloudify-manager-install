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

import json
from os.path import join

from .. import SOURCES, CONFIG

from ..service_names import RABBITMQ

from ... import constants
from ...config import config
from ...logger import get_logger
from ...exceptions import ValidationError, NetworkError

from ...utils.systemd import systemd
from ...utils.install import yum_install, yum_remove
from ...utils.network import wait_for_port, is_port_open
from ...utils.common import sudo, remove as remove_file


LOG_DIR = join(constants.BASE_LOG_DIR, RABBITMQ)
HOME_DIR = join('/etc', RABBITMQ)
CONFIG_PATH = join(constants.COMPONENTS_DIR, RABBITMQ, CONFIG)
SECURE_PORT = 5671

RABBITMQ_CTL = 'rabbitmqctl'
logger = get_logger(RABBITMQ)


def _install():
    sources = config[RABBITMQ][SOURCES]
    for source in sources.values():
        yum_install(source)


def _init_service():
    logger.info('Initializing RabbitMQ...')
    rabbit_config_path = join(HOME_DIR, 'rabbitmq.config')

    # Delete old mnesia node
    remove_file('/var/lib/rabbitmq/mnesia')
    remove_file(rabbit_config_path)
    systemd.systemctl('daemon-reload')

    # rabbitmq restart exits with 143 status code that is valid in this case.
    systemd.restart(RABBITMQ, ignore_failure=True)
    wait_for_port(SECURE_PORT)


def _rabbitmqctl(command, **kwargs):
    nodename = config[RABBITMQ]['nodename']
    return sudo([RABBITMQ_CTL, '-n', nodename] + command, **kwargs)


def user_exists(username):
    output = _rabbitmqctl(['list_users'], retries=5).aggr_stdout
    return username in output


def _delete_guest_user():
    if user_exists('guest'):
        logger.info('Disabling RabbitMQ guest user...')
        _rabbitmqctl(['clear_permissions', 'guest'], retries=5)
        _rabbitmqctl(['delete_user', 'guest'], retries=5)


def _create_rabbitmq_user():
    rabbitmq_username = config[RABBITMQ]['username']
    rabbitmq_password = config[RABBITMQ]['password']
    if not user_exists(rabbitmq_username):
        logger.info('Creating new user and setting permissions...'.format(
            rabbitmq_username, rabbitmq_password)
        )
        _rabbitmqctl(['add_user', rabbitmq_username, rabbitmq_password])
        _rabbitmqctl(['set_permissions', rabbitmq_username, '.*', '.*', '.*'],
                     retries=5)
        _rabbitmqctl(['set_user_tags', rabbitmq_username, 'administrator'])


def _set_rabbitmq_policy(name, expression, policy):
    policy = json.dumps(policy)
    logger.debug('Setting policy {0} on queues {1} to {2}'.format(
        name, expression, policy))
    # shlex screws this up because we need to pass json and shlex
    # strips quotes so we explicitly pass it as a list.
    _rabbitmqctl(['set_policy', name,
                  expression, policy, '--apply-to', 'queues'])


def _set_policies():
    metrics = config[RABBITMQ]['policy_metrics']
    logs_queue_message_policy = {
        'message-ttl': metrics['logs_queue_message_ttl'],
        'max-length': metrics['logs_queue_length_limit']
    }
    events_queue_message_policy = {
        'message-ttl': metrics['events_queue_message_ttl'],
        'max-length': metrics['events_queue_length_limit']
    }
    metrics_queue_message_policy = {
        'message-ttl': metrics['metrics_queue_message_ttl'],
        'max-length': metrics['metrics_queue_length_limit']
    }
    riemann_deployment_queues_message_ttl = {
        'message-ttl': metrics['metrics_queue_message_ttl'],
        'max-length': metrics['metrics_queue_length_limit']
    }

    logger.info("Setting RabbitMQ Policies...")
    _set_rabbitmq_policy(
        name='logs_queue_message_policy',
        expression='^cloudify-logs$',
        policy=logs_queue_message_policy
    )
    _set_rabbitmq_policy(
        name='events_queue_message_policy',
        expression='^cloudify-events$',
        policy=events_queue_message_policy
    )
    _set_rabbitmq_policy(
        name='metrics_queue_message_policy',
        expression='^amq\.gen.*$',
        policy=metrics_queue_message_policy
    )
    _set_rabbitmq_policy(
        name='riemann_deployment_queues_message_ttl',
        expression='^.*-riemann$',
        policy=riemann_deployment_queues_message_ttl
    )


def _start_rabbitmq():
    logger.info("Starting RabbitMQ Service...")
    # rabbitmq restart exits with 143 status code that is valid in this case.
    systemd.restart(RABBITMQ, ignore_failure=True)
    wait_for_port(SECURE_PORT)
    _set_policies()
    systemd.restart(RABBITMQ)


def _validate_rabbitmq_running():
    logger.info('Making sure RabbitMQ is live...')
    systemd.verify_alive(RABBITMQ)

    result = _rabbitmqctl(['status'])
    if result.returncode != 0:
        raise ValidationError('Rabbitmq failed to start')

    if not is_port_open(SECURE_PORT, host='127.0.0.1'):
        raise NetworkError(
            '{0} error: port {1}:{2} was not open'.format(
                RABBITMQ, '127.0.0.1', SECURE_PORT)
        )


def _configure():
    systemd.configure(RABBITMQ)
    _init_service()
    _delete_guest_user()
    _create_rabbitmq_user()
    _start_rabbitmq()
    _validate_rabbitmq_running()


def install():
    logger.notice('Installing RabbitMQ...')
    _install()
    _configure()
    logger.notice('RabbitMQ successfully installed')


def configure():
    logger.notice('Configuring RabbitMQ...')
    _configure()
    logger.notice('RabbitMQ successfully configured')


def remove():
    logger.notice('Removing RabbitMQ...')
    yum_remove('erlang')
    logger.info('Stopping the Erlang Port Mapper Daemon...')
    sudo(['epmd', '-kill'], ignore_failures=True)
    systemd.remove(RABBITMQ, service_file=False)
    logger.notice('RabbitMQ successfully removed')


def start():
    logger.notice('Starting RabbitMQ...')
    systemd.start(RABBITMQ)
    _validate_rabbitmq_running()
    logger.notice('RabbitMQ successfully started')


def stop():
    logger.notice('Stopping RabbitMQ...')
    systemd.stop(RABBITMQ)
    logger.notice('RabbitMQ successfully stopped')
