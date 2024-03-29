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
from ..utils.network import ipv6_url_compat, parse_ip

from ..service_names import (
    MANAGER,
    POSTGRESQL_CLIENT,
    POSTGRESQL_SERVER,
    NGINX,
)

from . import DATABASE_SERVICE, MANAGER_SERVICE
from ..components_constants import (
    PRIVATE_IP,
    PUBLIC_IP,
    SECURITY,
    SERVICES_TO_INSTALL,
    SSL_ENABLED,
    HOSTNAME,
    ENABLE_REMOTE_CONNECTIONS,
)


BROKER_IP = 'broker_ip'
logger = get_logger('Globals')


def _set_external_port_and_protocol():
    if config[MANAGER][SECURITY]['ssl_enabled']:
        logger.info('SSL is enabled, setting rest port to 443 and '
                    'rest protocol to https...')
        external_rest_port = config[NGINX].get('port') or 443
        external_rest_protocol = 'https'
    else:
        logger.info('SSL is disabled, setting rest port '
                    'to 80 and rest protocols to http...')
        external_rest_port = config[NGINX].get('port') or 80
        external_rest_protocol = 'http'

    config[MANAGER]['external_rest_port'] = external_rest_port
    config[MANAGER]['external_rest_protocol'] = external_rest_protocol


def _set_ip_config():
    private_ip = config[MANAGER][PRIVATE_IP]
    public_ip = config[MANAGER][PUBLIC_IP]

    config[MANAGER]['file_server_root'] = constants.MANAGER_RESOURCES_HOME
    config[MANAGER]['file_server_url'] = 'https://{0}:{1}/resources'.format(
        ipv6_url_compat(private_ip),
        config[MANAGER]['internal_rest_port'],
    )

    config.setdefault('networks', {})
    config['networks'].setdefault('default', private_ip)

    # ...also add the public ip to networks for easy access by the user,
    # and so that it's always present on the internal cert
    config['networks'].setdefault('external', public_ip)


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


def _set_nginx_listeners():
    if config.get(NGINX, {}).get('listeners'):
        return

    # add the "internal" listener - always ssl, might be multiple ports,
    # in case the user configured additional "internal" ports
    internal_ports = {config[MANAGER]['internal_rest_port']}
    internal_ports.update(
        config[MANAGER].get('additional_internal_rest_listeners') or []
    )

    listeners = []

    # add the "external" listener, ssl or non-ssl, based on the config
    if config[MANAGER][SECURITY]['ssl_enabled']:
        config[NGINX]['nonssl_access_blocked'] = True
        # if the external ip is an IP (not hostname), then we cannot use
        # a separate certificate, because SNI won't work with IPs;
        # in that case, just add the public port to the internal
        # listeners, so it'll be served along with the internal ports
        if parse_ip(config[MANAGER][PUBLIC_IP]):
            internal_ports.add(config[MANAGER]['external_rest_port'])
        else:
            # this is a hostname, so SNI can work
            listeners.append({
                'port': config[MANAGER]['external_rest_port'],
                'server_name': config[MANAGER][PUBLIC_IP],
                'ssl': True,
                'cert_path': constants.EXTERNAL_CERT_PATH,
                'key_path': constants.EXTERNAL_KEY_PATH,
            })
    else:
        listeners.append({
            'port': config[MANAGER]['external_rest_port'],
            'server_name': '_',
            'ssl': False,
        })

    for internal_port in set(internal_ports):
        listeners.append({
            'port': internal_port,
            'server_name': '_',
            'ssl': True,
            'cert_path': constants.INTERNAL_CERT_PATH,
            'key_path': constants.INTERNAL_KEY_PATH,
        })
    config[NGINX]['listeners'] = listeners


def set_globals(only_install=False):
    if only_install:
        return
    _apply_forced_settings()
    _set_ip_config()
    _set_external_port_and_protocol()
    _set_hostname()
    _set_nginx_listeners()
