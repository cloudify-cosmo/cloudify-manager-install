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
from collections import namedtuple

from ..components_constants import (
    SOURCES,
    CONFIG,
    PRIVATE_IP,
    PUBLIC_IP,
    AGENT,
    SSL_INPUTS,
    CLEAN_DB
)
from ..base_component import BaseComponent
from ..service_names import NGINX, MANAGER
from ... import constants
from ...config import config
from ...logger import get_logger
from ...exceptions import ValidationError
from ...utils import common
from ...utils import certificates
from ...utils.systemd import systemd
from ...utils.install import yum_install, yum_remove
from ...utils.logrotate import set_logrotate, remove_logrotate
from ...utils.files import remove_files, deploy, copy_notice, remove_notice


LOG_DIR = join(constants.BASE_LOG_DIR, NGINX)
CONFIG_PATH = join(constants.COMPONENTS_DIR, NGINX, CONFIG)
UNIT_OVERRIDE_PATH = '/etc/systemd/system/nginx.service.d'

logger = get_logger(NGINX)


class NginxComponent(BaseComponent):
    def __init__(self, skip_installation):
        super(NginxComponent, self).__init__(skip_installation)

    def _install(self):
        nginx_source_url = config[NGINX][SOURCES]['nginx_source_url']
        yum_install(nginx_source_url)

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
        networks = config[AGENT]['networks']

        certificates.store_cert_metadata(
            {network_name: network['manager']
             for network_name, network in networks.items()},
            component='nginx')
        certificates.create_internal_certs(for_component='nginx')

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

    def _handle_internal_cert(self, has_ca_key):
        """
        The user might provide the internal cert and the internal key, or
        neither. It is an error to only provide one of them. If the user did
        not provide the internal cert+key, we must generate it, but we can only
        generate it if we have a CA key (either provided or generated).
        So it is an error to provide only the CA cert, and then not provide
        the internal cert+key.
        :param has_ca_key: True if there's a CA key available
        """
        logger.info('Handling internal certificate...')
        cert_deployed, key_deployed = certificates.deploy_cert_and_key(
            prefix='internal',
            cert_dst_path=constants.INTERNAL_CERT_PATH,
            key_dst_path=constants.INTERNAL_KEY_PATH
        )

        if cert_deployed and key_deployed:
            logger.info('Deployed user provided internal cert and key')
        else:
            if not has_ca_key:
                raise RuntimeError(
                    'No CA key, but no internal cert+key provided')
            self._generate_internal_certs()

    def _handle_external_cert(self):
        logger.info('Handling external certificate...')
        cert_deployed, key_deployed = certificates.deploy_cert_and_key(
            prefix='external',
            cert_dst_path=constants.EXTERNAL_CERT_PATH,
            key_dst_path=constants.EXTERNAL_KEY_PATH
        )

        if cert_deployed and key_deployed:
            logger.info('Deployed user provided external cert and key')
        else:
            self._generate_external_certs()

    def _handle_certs(self):
        if not config[CLEAN_DB]:
            logger.info('Skipping certificate handling. '
                        'Pass the `--clean-db` flag in order to recreate '
                        'all certificates')
            return

        has_ca_key = certificates.handle_ca_cert()
        self._handle_internal_cert(has_ca_key)
        self._handle_external_cert()

    def _deploy_nginx_config_files(self):
        logger.info('Deploying Nginx configuration files...')
        resource = namedtuple('Resource', 'src dst')

        resources = [
            resource(
                src=join(CONFIG_PATH, 'http-external-rest-server.cloudify'),
                dst='/etc/nginx/conf.d/http-external-rest-server.cloudify'
            ),
            resource(
                src=join(CONFIG_PATH, 'https-external-rest-server.cloudify'),
                dst='/etc/nginx/conf.d/https-external-rest-server.cloudify'
            ),
            resource(
                src=join(CONFIG_PATH, 'https-internal-rest-server.cloudify'),
                dst='/etc/nginx/conf.d/https-internal-rest-server.cloudify'
            ),
            resource(
                src=join(CONFIG_PATH, 'https-file-server.cloudify'),
                dst='/etc/nginx/conf.d/https-file-server.cloudify'
            ),
            resource(
                src=join(CONFIG_PATH, 'nginx.conf'),
                dst='/etc/nginx/nginx.conf'
            ),
            resource(
                src=join(CONFIG_PATH, 'cloudify.conf'),
                dst='/etc/nginx/conf.d/cloudify.conf',
            ),
            resource(
                src=join(CONFIG_PATH, 'rest-location.cloudify'),
                dst='/etc/nginx/conf.d/rest-location.cloudify',
            ),
            resource(
                src=join(CONFIG_PATH, 'rest-proxy.cloudify'),
                dst='/etc/nginx/conf.d/rest-proxy.cloudify',
            ),
            resource(
                src=join(CONFIG_PATH, 'fileserver-location.cloudify'),
                dst='/etc/nginx/conf.d/fileserver-location.cloudify',
            ),
            resource(
                src=join(CONFIG_PATH, 'redirect-to-fileserver.cloudify'),
                dst='/etc/nginx/conf.d/redirect-to-fileserver.cloudify',
            ),
            resource(
                src=join(CONFIG_PATH, 'ui-locations.cloudify'),
                dst='/etc/nginx/conf.d/ui-locations.cloudify',
            ),
            resource(
                src=join(CONFIG_PATH, 'composer-location.cloudify'),
                dst='/etc/nginx/conf.d/composer-location.cloudify',
            ),
            resource(
                src=join(CONFIG_PATH, 'logs-conf.cloudify'),
                dst='/etc/nginx/conf.d/logs-conf.cloudify',
            )
        ]

        for resource in resources:
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

    def _start_and_verify_service(self):
        logger.info('Starting NGINX service...')
        systemd.enable(NGINX, append_prefix=False)
        systemd.restart(NGINX, append_prefix=False)
        systemd.verify_alive(NGINX, append_prefix=False)

    def _configure(self):
        common.mkdir(LOG_DIR)
        copy_notice(NGINX)
        self._deploy_unit_override()
        set_logrotate(NGINX)
        self._handle_certs()
        self._deploy_nginx_config_files()
        self._start_and_verify_service()

    def install(self):
        logger.notice('Installing NGINX...')
        self._install()
        self._configure()
        logger.notice('NGINX successfully installed')

    def configure(self):
        logger.notice('Configuring NGINX...')
        self._configure()
        logger.notice('NGINX successfully configured')

    def remove(self):
        logger.notice('Removing NGINX...')
        remove_notice(NGINX)
        remove_logrotate(NGINX)
        remove_files([
            join('/etc', NGINX),
            join('/var/log', NGINX),
            join('/var/cache', NGINX),
            LOG_DIR,
            UNIT_OVERRIDE_PATH
        ])
        yum_remove(NGINX)
        logger.notice('NGINX successfully removed')

    def start(self):
        logger.notice('Starting NGINX...')
        systemd.start(NGINX, append_prefix=False)
        systemd.verify_alive(NGINX, append_prefix=False)
        logger.notice('NGINX successfully started')

    def stop(self):
        logger.notice('Stopping NGINX...')
        systemd.stop(NGINX, append_prefix=False)
        logger.notice('NGINX successfully stopped')
