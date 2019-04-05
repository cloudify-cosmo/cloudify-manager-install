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

import os
import base64
import string
import random
import socket

from .. import constants
from ..config import config
from ..logger import (get_logger,
                      set_file_handlers_level,
                      get_file_handlers_level)
from ..exceptions import InputError

from .service_names import (
    RABBITMQ,
    MANAGER,
    POSTGRESQL_CLIENT
)

from .components_constants import (
    PRIVATE_IP,
    SECURITY,
    AGENT,
    CONSTANTS,
    ADMIN_PASSWORD,
    CLEAN_DB,
    FLASK_SECURITY,
    SERVICES_TO_INSTALL,
    SSL_ENABLED,
    HOSTNAME
)
from .service_components import MANAGER_SERVICE

import logging

BROKER_IP = 'broker_ip'
logger = get_logger('Globals')


def _set_external_port_and_protocol():
    if config[MANAGER][SECURITY]['ssl_enabled']:
        logger.info('SSL is enabled, setting rest port to 443 and '
                    'rest protocol to https...')
        external_rest_port = 443
        external_rest_protocol = 'https'
    else:
        logger.info('SSL is disabled, setting rest port '
                    'to 80 and rest protocols to http...')
        external_rest_port = 80
        external_rest_protocol = 'http'

    config[MANAGER]['external_rest_port'] = external_rest_port
    config[MANAGER]['external_rest_protocol'] = external_rest_protocol


def _set_ip_config():
    private_ip = config[MANAGER][PRIVATE_IP]
    config[AGENT][BROKER_IP] = [
        broker['ip']
        for broker in config[RABBITMQ]['cluster_members'].values()
    ]

    config[MANAGER]['file_server_root'] = constants.MANAGER_RESOURCES_HOME
    config[MANAGER]['file_server_url'] = 'https://{0}:{1}/resources'.format(
        private_ip,
        constants.INTERNAL_REST_PORT
    )

    config.setdefault('networks', {})
    config['networks'].setdefault('default', private_ip)


def _set_constant_config():
    const_conf = config.setdefault(CONSTANTS, {})

    const_conf['ca_cert_path'] = constants.CA_CERT_PATH
    const_conf['internal_cert_path'] = constants.INTERNAL_CERT_PATH
    const_conf['internal_key_path'] = constants.INTERNAL_KEY_PATH
    const_conf['external_cert_path'] = constants.EXTERNAL_CERT_PATH
    const_conf['external_key_path'] = constants.EXTERNAL_KEY_PATH
    if config[POSTGRESQL_CLIENT][SSL_ENABLED]:
        const_conf['postgresql_client_cert_path'] = \
            constants.POSTGRESQL_CLIENT_CERT_FILENAME
        const_conf['postgresql_client_key_path'] = \
            constants.POSTGRESQL_CLIENT_KEY_FILENAME

    const_conf['internal_rest_port'] = constants.INTERNAL_REST_PORT


def _set_admin_password():
    if not config[MANAGER][SECURITY][ADMIN_PASSWORD]:
        config[MANAGER][SECURITY][ADMIN_PASSWORD] = _generate_password()
    print_password_to_screen()


def _set_hostname():
    if not config[MANAGER][HOSTNAME]:
        config[MANAGER][HOSTNAME] = socket.gethostname()


def print_password_to_screen():
    if MANAGER_SERVICE not in config[SERVICES_TO_INSTALL]:
        return
    password = config[MANAGER][SECURITY][ADMIN_PASSWORD]
    current_level = get_file_handlers_level()
    set_file_handlers_level(logging.ERROR)
    logger.warning('Admin password: {0}'.format(password))
    set_file_handlers_level(current_level)


def _generate_password(length=12):
    chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
    password = ''.join(random.choice(chars) for _ in range(length))
    return password


def _random_alphanumeric(result_len=31):
    """
    :return: random string of unique alphanumeric characters
    """
    ascii_alphanumeric = string.ascii_letters + string.digits
    return ''.join(
        random.SystemRandom().sample(ascii_alphanumeric, result_len)
    )


def _generate_flask_security_config():
    logger.info('Generating random hash salt and secret key...')
    config[FLASK_SECURITY] = {
        'hash_salt': base64.b64encode(os.urandom(32)),
        'secret_key': base64.b64encode(os.urandom(32)),
        'encoding_alphabet': _random_alphanumeric(),
        'encoding_block_size': 24,
        'encoding_min_length': 5,
        'encryption_key': base64.urlsafe_b64encode(os.urandom(64))
    }


def _validate_admin_password_and_security_config():
    if not config[MANAGER][SECURITY][ADMIN_PASSWORD]:
        raise InputError(
            'Admin password not found in {config_path} and '
            'was not provided as an argument.\n'
            'The password was not generated because the `--clean-db` flag '
            'was not passed cfy_manager install/configure'.format(
                config_path=constants.USER_CONFIG_PATH
            )
        )
    if not config[FLASK_SECURITY]:
        raise InputError(
            'Flask security configuration not found in {config_path}.\n'
            'The Flask security configuration was not generated because '
            'the `--clean-db` flag was not passed cfy_manager '
            'install/configure'.format(
                config_path=constants.USER_CONFIG_PATH
            )
        )


def set_globals():
    _set_ip_config()
    _set_external_port_and_protocol()
    _set_constant_config()
    _set_hostname()
    if MANAGER_SERVICE in config[SERVICES_TO_INSTALL]:
        if config[CLEAN_DB]:
            _set_admin_password()
            _generate_flask_security_config()
        else:
            _validate_admin_password_and_security_config()
