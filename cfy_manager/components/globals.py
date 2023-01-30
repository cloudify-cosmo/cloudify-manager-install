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
from typing import TypedDict

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
    SERVICES_TO_INSTALL,
    SSL_ENABLED,
    HOSTNAME,
    ENABLE_REMOTE_CONNECTIONS,
    LISTENERS,
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


class Listener(TypedDict, total=False):
    host: str
    port: int
    server_name: str
    ssl: bool
    cert_path: str
    key_path: str


def _format_listener(listener) -> Listener:
    if not listener:
        listener = {'host': 'localhost'}
    elif isinstance(listener, str):
        listener = {'host': listener}

    formatted = listener.copy()
    if not formatted.get('port'):
        formatted['port'] = config[MANAGER]['external_rest_port']
    if not formatted.get('ssl'):
        formatted['ssl'] = config[MANAGER][SECURITY]['ssl_enabled']
    return formatted


def _format_listeners(listeners) -> list[Listener]:
    """Format user-provided listeners, applying defaults."""
    if not isinstance(listeners, list):
        listeners = [listeners]
    listeners = [_format_listener(listener) for listener in listeners]
    return listeners


def _default_internal_listener() -> Listener:
    """Default "internal" listener, using private_ip"""
    return {
        'host': config[MANAGER]['private_ip'],
        'port': constants.INTERNAL_REST_PORT,
        'server_name': '_',
        'ssl': True,
        'cert_path': constants.INTERNAL_CERT_PATH,
        'key_path': constants.INTERNAL_KEY_PATH,
    }


def _default_external_listener() -> Listener:
    """Default "external" listener, using public_ip"""
    return {
        'host': config[MANAGER]['public_ip'],
        'port': (
            config['nginx'].get('port')
            or config[MANAGER]['external_rest_port']
        ),
        'server_name': '_',
        'ssl': config[MANAGER][SECURITY]['ssl_enabled'],
        'cert_path': constants.EXTERNAL_CERT_PATH,
        'key_path': constants.EXTERNAL_KEY_PATH,
    }


def _set_listeners():
    """Default & format the config.manager.listeners entries

    Listeners describe the endpoints on which nginx is listening.
    They are dicts of shape Listener
    """
    if config[MANAGER].get(LISTENERS):
        listeners = _format_listeners(config[MANAGER][LISTENERS])
    else:
        listeners = [
            _default_internal_listener(),
            _default_external_listener(),
        ]
    config[MANAGER][LISTENERS] = listeners


def set_globals(only_install=False):
    if only_install:
        return
    _apply_forced_settings()
    _set_ip_config()
    _set_external_port_and_protocol()
    _set_hostname()
    _set_listeners()
