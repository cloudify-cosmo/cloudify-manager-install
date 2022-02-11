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

import socket

from .. import constants
from ..config import config
from ..logger import get_logger
from ..utils.network import ipv6_url_compat

from ..service_names import (
    MANAGER,
    POSTGRESQL_CLIENT,
    POSTGRESQL_SERVER
)

from . import DATABASE_SERVICE, MANAGER_SERVICE
from ..components_constants import (
    PRIVATE_IP,
    SECURITY,
    CONSTANTS,
    SERVICES_TO_INSTALL,
    SSL_ENABLED,
    SSL_CLIENT_VERIFICATION,
    HOSTNAME,
    ENABLE_REMOTE_CONNECTIONS
)


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

    config[MANAGER]['file_server_root'] = constants.MANAGER_RESOURCES_HOME
    config[MANAGER]['file_server_url'] = 'https://{0}:{1}/resources'.format(
        ipv6_url_compat(private_ip),
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
    const_conf['monitoring_ca_cert_path'] = constants.MONITORING_CA_CERT_PATH
    const_conf['monitoring_cert_path'] = constants.MONITORING_CERT_PATH
    const_conf['monitoring_key_path'] = constants.MONITORING_KEY_PATH
    if config[POSTGRESQL_CLIENT][SSL_ENABLED]:
        const_conf['postgresql_ca_cert_path'] = \
            constants.POSTGRESQL_CA_CERT_PATH
        if config[POSTGRESQL_CLIENT][SSL_CLIENT_VERIFICATION]:
            const_conf['postgresql_client_cert_path'] = \
                constants.POSTGRESQL_CLIENT_CERT_PATH
            const_conf['postgresql_client_key_path'] = \
                constants.POSTGRESQL_CLIENT_KEY_PATH

    const_conf['internal_rest_port'] = constants.INTERNAL_REST_PORT
    const_conf['monitoring_port'] = constants.MONITORING_PORT


def _set_hostname():
    if not config[MANAGER][HOSTNAME]:
        config[MANAGER][HOSTNAME] = socket.gethostname()


def _apply_forced_settings():
    if (
        (
            MANAGER_SERVICE not in config[SERVICES_TO_INSTALL]
            and DATABASE_SERVICE in config[SERVICES_TO_INSTALL]
        )
        or (
            DATABASE_SERVICE not in config[SERVICES_TO_INSTALL]
            and MANAGER_SERVICE in config[SERVICES_TO_INSTALL]
        )
    ):
        config[POSTGRESQL_SERVER][SSL_ENABLED] = True
        config[POSTGRESQL_SERVER][ENABLE_REMOTE_CONNECTIONS] = True
        config[POSTGRESQL_CLIENT][SSL_ENABLED] = True


def set_globals(only_install=False):
    if only_install:
        return
    _apply_forced_settings()
    _set_ip_config()
    _set_external_port_and_protocol()
    _set_constant_config()
    _set_hostname()
