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

from collections import namedtuple
from os.path import join, exists

from ..base_component import BaseComponent
from ..components_constants import (
    CONFIG,
    PRIVATE_IP,
    PUBLIC_IP,
    SSL_INPUTS,
    CLEAN_DB,
    HOSTNAME,
    SERVICES_TO_INSTALL
)
from ..service_names import NGINX, MANAGER, MANAGER_SERVICE, MONITORING_SERVICE
from ... import constants
from ...config import config
from ...exceptions import ValidationError
from ...logger import get_logger
from ...utils import (
    common,
    certificates,
    service
)
from ...utils.files import remove_files, deploy, copy_notice, remove_notice
from ...utils.logrotate import set_logrotate, remove_logrotate

LOG_DIR = join(constants.BASE_LOG_DIR, NGINX)
CONFIG_PATH = join(constants.COMPONENTS_DIR, NGINX, CONFIG)
UNIT_OVERRIDE_PATH = '/etc/systemd/system/nginx.service.d'

logger = get_logger(NGINX)


class Nginx(BaseComponent):
    def _install(self):
        common.mkdir(LOG_DIR)
        copy_notice(NGINX)
        if config.get('service_management') != 'supervisord':
            self._deploy_unit_override()
        set_logrotate(NGINX)

    def _deploy_unit_override(self):
        logger.debug('Creating systemd unit override...')
        unit_override_path = '/etc/systemd/system/nginx.service.d'
        common.mkdir(unit_override_path)
        deploy(
            src=join(CONFIG_PATH, 'overrides.conf'),
            dst=join(unit_override_path, 'overrides.conf')
        )

    def _generate_internal_certs(self):
        logger.info('Generating internal certificate...')
        networks = config['networks']
        hostname = config[MANAGER][HOSTNAME]
        certificates.store_cert_metadata(
            hostname,
            new_managers=list(networks.values()),
            new_networks=list(networks.keys()),
        )

        certificates.generate_internal_ssl_cert(
            ips=list(networks.values()),
            cn=hostname
        )

    def _generate_external_certs(self):
        logger.info('Generating external certificate...')
        external_rest_host = config[MANAGER][PUBLIC_IP]
        internal_rest_host = config[MANAGER][PRIVATE_IP]

        certificates.generate_external_ssl_cert(
            ips=[external_rest_host, internal_rest_host],
            cn=external_rest_host,
            sign_cert=config[SSL_INPUTS]['external_ca_cert_path'],
            sign_key=config[SSL_INPUTS]['external_ca_key_path'],
            sign_key_password=config[SSL_INPUTS]['external_ca_key_password'],
        )
        # don't store the password in the config file
        if config[SSL_INPUTS]['external_ca_key_password']:
            config[SSL_INPUTS]['external_ca_key_password'] = '<removed>'

    def _handle_internal_cert(self):
        """
        The user might provide the internal cert and the internal key, or
        neither. It is an error to only provide one of them. If the user did
        not provide the internal cert+key, we must generate it, but we can only
        generate it if we have a CA key (either provided or generated).
        So it is an error to provide only the CA cert, and then not provide
        the internal cert+key.
        """
        logger.info('Handling internal certificate...')
        deployed = certificates.use_supplied_certificates(
            SSL_INPUTS,
            self.logger,
            cert_destination=constants.INTERNAL_CERT_PATH,
            key_destination=constants.INTERNAL_KEY_PATH,
            prefix='internal_',
        )

        if deployed:
            logger.info('Deployed user provided external cert and key')
        else:
            self._generate_internal_certs()

    def _internal_certs_exist(self):
        return (
            exists(constants.INTERNAL_CERT_PATH)
            and exists(constants.INTERNAL_KEY_PATH)
        )

    def _handle_external_cert(self):
        logger.info('Handling external certificate...')
        deployed = certificates.use_supplied_certificates(
            SSL_INPUTS,
            self.logger,
            cert_destination=constants.EXTERNAL_CERT_PATH,
            key_destination=constants.EXTERNAL_KEY_PATH,
            prefix='external_',
        )

        if deployed:
            logger.info('Deployed user provided external cert and key')
        else:
            self._generate_external_certs()

    def _external_certs_exist(self):
        return (
            exists(constants.EXTERNAL_CERT_PATH)
            and exists(constants.EXTERNAL_KEY_PATH)
        )

    def _handle_certs(self):
        certs_handled = False
        if config[CLEAN_DB] or not self._internal_certs_exist():
            certs_handled = True
            self._handle_internal_cert()
        if config[CLEAN_DB] or not self._external_certs_exist():
            certs_handled = True
            self._handle_external_cert()

        if not certs_handled:
            logger.info('Skipping certificate handling. '
                        'Pass the `--clean-db` flag in order to recreate '
                        'all certificates')

    def _config_files(self):
        do_monitoring = MONITORING_SERVICE in config.get(SERVICES_TO_INSTALL)
        do_manager = MANAGER_SERVICE in config.get(SERVICES_TO_INSTALL)
        resource = namedtuple('Resource', 'src dst')
        resources_list = [
            resource(
                src=join(CONFIG_PATH, 'nginx.conf'),
                dst='/etc/nginx/nginx.conf'
            ),
        ]
        resources_list += [
            resource(
                src=join(CONFIG_PATH, file_name),
                dst='/etc/nginx/conf.d/{0}'.format(file_name)) for
            file_name in [
                'https-internal-rest-server.cloudify',
                'cloudify.conf',
                'logs-conf.cloudify',
            ]
        ]
        if do_manager:
            resources_list += [
                resource(
                    src=join(CONFIG_PATH, file_name),
                    dst='/etc/nginx/conf.d/{0}'.format(file_name)) for
                file_name in [
                    'http-external-rest-server.cloudify',
                    'https-external-rest-server.cloudify',
                    'https-internal-rest-server.cloudify',
                    'https-file-server.cloudify',
                    'cloudify.conf',
                    'rest-location.cloudify',
                    'rest-proxy.cloudify',
                    'fileserver-location.cloudify',
                    'redirect-to-fileserver.cloudify',
                    'ui-locations.cloudify',
                    'composer-location.cloudify',
                ]
            ]
        if do_monitoring:
            resources_list += [
                resource(
                    src=join(CONFIG_PATH, 'redirect-to-monitoring.cloudify'),
                    dst='/etc/nginx/conf.d/redirect-to-monitoring.cloudify'
                ),
            ]
        return resources_list

    def _deploy_nginx_config_files(self):
        logger.info('Deploying Nginx configuration files...')
        for resource in self._config_files():
            deploy(resource.src, resource.dst)

        # remove the default configuration which reserves localhost:80 for a
        # nginx default landing page
        common.remove('/etc/nginx/conf.d/default.conf', ignore_failure=True)

    def _verify_nginx(self):
        # TODO: This code requires the restservice to be installed, but
        # restservice depends on rabbitmq, which in turn requires the
        # certificates created in nginx (here).
        # So we need to find an other way to validate it
        logger.info('Verifying NGINX service is up...')
        nginx_url = 'https://127.0.0.1:{0}/api/v2.1/version'.format(
            config[NGINX]['internal_rest_port']
        )
        output = common.run([
            'curl',
            nginx_url,
            '--cacert', constants.CA_CERT_PATH,
            # only output the http code
            '-o', '/dev/null',
            '-w', '%{http_code}'
        ])
        if output.aggr_stdout.strip() not in {'200', '401'}:
            raise ValidationError('Nginx HTTP check error: {0}'.format(output))

    def _configure(self):
        self._deploy_nginx_config_files()

    def install(self):
        logger.notice('Installing NGINX...')
        self._install()
        logger.notice('NGINX successfully installed')

    def configure(self):
        logger.notice('Configuring NGINX...')
        self._configure()
        if service._get_service_type() != 'supervisord':
            service.enable(NGINX, append_prefix=False)
        logger.notice('NGINX successfully configured')

    def remove(self):
        remove_notice(NGINX)
        remove_logrotate(NGINX)
        remove_files([
            join('/var/cache', NGINX),
            LOG_DIR,
            UNIT_OVERRIDE_PATH
        ] + [resource.dst for resource in self._config_files()])

    def start(self):
        logger.notice('Starting NGINX...')
        self._handle_certs()
        if service._get_service_type() == 'supervisord':
            service.configure(NGINX, append_prefix=False)
        service.start(NGINX, append_prefix=False)
        service.verify_alive(NGINX, append_prefix=False)
        logger.notice('NGINX successfully started')

    def stop(self):
        logger.notice('Stopping NGINX...')
        service.stop(NGINX, append_prefix=False)
        logger.notice('NGINX successfully stopped')
