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
from tempfile import NamedTemporaryFile

from ..base_component import BaseComponent
from ..components_constants import (
    CONFIG,
    SCRIPTS,
    PRIVATE_IP,
    PUBLIC_IP,
    SSL_INPUTS,
    HOSTNAME,
    SERVICES_TO_INSTALL
)
from ..service_names import (NGINX, MANAGER, MANAGER_SERVICE,
                             MONITORING_SERVICE, PROMETHEUS,
                             DATABASE_SERVICE, POSTGRESQL_SERVER,
                             QUEUE_SERVICE, RABBITMQ, )
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
SCRIPTS_PATH = join(
    constants.COMPONENTS_DIR,
    NGINX,
    SCRIPTS
)
UNIT_OVERRIDE_PATH = '/etc/systemd/system/nginx.service.d'
HTPASSWD_FILE = '/etc/nginx/conf.d/monitoring-htpasswd.cloudify'

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

    def _handle_internal_cert(self, replacing_ca=False):
        """
        The user might provide the internal cert and the internal key, or
        neither. It is an error to only provide one of them. If the user did
        not provide the internal cert+key, we must generate it, but we can only
        generate it if we have a CA key (either provided or generated).
        So it is an error to provide only the CA cert, and then not provide
        the internal cert+key.
        """
        cert_destinations = {
            'cert_destination': constants.INTERNAL_CERT_PATH,
            'key_destination': constants.INTERNAL_KEY_PATH,
        }
        if ((MONITORING_SERVICE in config.get(SERVICES_TO_INSTALL) and
                MANAGER_SERVICE not in config.get(SERVICES_TO_INSTALL)) or
                replacing_ca):
            cert_destinations['ca_destination'] = constants.CA_CERT_PATH
        logger.info('Handling internal certificate...')
        deployed = certificates.use_supplied_certificates(
            SSL_INPUTS,
            logger,
            prefix='internal_',
            validate_certs_src_exist=True,
            **cert_destinations
        )

        if deployed:  # In case of replacing certs, deployed==True always
            logger.info('Deployed user provided internal cert and key')
        else:
            self._generate_internal_certs()

    def replace_certificates(self):
        if self._needs_to_replace_internal_certs():
            self._replace_internal_certs()
        if self._needs_to_replace_external_certs():
            self._replace_external_certs()

        if (self._needs_to_replace_internal_certs() or
                self._needs_to_replace_external_certs() or
                MONITORING_SERVICE in config[SERVICES_TO_INSTALL]):
            service.restart(NGINX, append_prefix=False)
            service.verify_alive(NGINX, append_prefix=False)

    @staticmethod
    def _needs_to_replace_internal_certs():
        return (exists(constants.NEW_INTERNAL_CERT_FILE_PATH) or
                exists(constants.NEW_INTERNAL_CA_CERT_FILE_PATH))

    @staticmethod
    def _needs_to_replace_external_certs():
        return (exists(constants.NEW_EXTERNAL_CERT_FILE_PATH) or
                exists(constants.NEW_EXTERNAL_CA_CERT_FILE_PATH))

    def validate_new_certs(self):
        self._validate_internal_certs()
        self._validate_external_certs()

    def _validate_internal_certs(self):
        if self._needs_to_replace_internal_certs():
            certificates.get_and_validate_certs_for_replacement(
                    default_cert_location=constants.INTERNAL_CERT_PATH,
                    default_key_location=constants.INTERNAL_KEY_PATH,
                    default_ca_location=constants.CA_CERT_PATH,
                    new_cert_location=constants.NEW_INTERNAL_CERT_FILE_PATH,
                    new_key_location=constants.NEW_INTERNAL_KEY_FILE_PATH,
                    new_ca_location=constants.NEW_INTERNAL_CA_CERT_FILE_PATH
                )

    def _validate_external_certs(self):
        if self._needs_to_replace_external_certs():
            certificates.get_and_validate_certs_for_replacement(
                default_cert_location=constants.EXTERNAL_CERT_PATH,
                default_key_location=constants.EXTERNAL_KEY_PATH,
                default_ca_location=constants.CA_CERT_PATH,
                new_cert_location=constants.NEW_EXTERNAL_CERT_FILE_PATH,
                new_key_location=constants.NEW_EXTERNAL_KEY_FILE_PATH,
                new_ca_location=constants.NEW_EXTERNAL_CA_CERT_FILE_PATH
            )

    def _replace_internal_certs(self):
        self._validate_internal_certs()
        logger.info('Replacing %s on nginx component', 'internal certificates')
        self._write_internal_certs_to_config()
        replacing_ca = exists(constants.NEW_INTERNAL_CA_CERT_FILE_PATH)
        self._handle_internal_cert(replacing_ca=replacing_ca)

    def _replace_external_certs(self):
        self._validate_external_certs()
        logger.info('Replacing %s on nginx component', 'external certificates')
        self._write_external_certs_to_config()
        replacing_ca = exists(constants.NEW_EXTERNAL_CA_CERT_FILE_PATH)
        self._handle_external_cert(replacing_ca=replacing_ca)

    @staticmethod
    def _write_internal_certs_to_config():
        if exists(constants.NEW_INTERNAL_CERT_FILE_PATH):
            config[SSL_INPUTS]['internal_cert_path'] = \
                constants.NEW_INTERNAL_CERT_FILE_PATH
            config[SSL_INPUTS]['internal_key_path'] = \
                constants.NEW_INTERNAL_KEY_FILE_PATH
        if exists(constants.NEW_INTERNAL_CA_CERT_FILE_PATH):
            config[SSL_INPUTS]['ca_cert_path'] = \
                constants.NEW_INTERNAL_CA_CERT_FILE_PATH

    @staticmethod
    def _write_external_certs_to_config():
        if exists(constants.NEW_EXTERNAL_CERT_FILE_PATH):
            config[SSL_INPUTS]['external_cert_path'] = \
                constants.NEW_EXTERNAL_CERT_FILE_PATH
            config[SSL_INPUTS]['external_key_path'] = \
                constants.NEW_EXTERNAL_KEY_FILE_PATH
        if exists(constants.NEW_EXTERNAL_CA_CERT_FILE_PATH):
            config[SSL_INPUTS]['external_ca_cert_path'] = \
                constants.NEW_EXTERNAL_CA_CERT_FILE_PATH

    def _handle_external_cert(self, replacing_ca=False):
        cert_destinations = {
            'cert_destination': constants.EXTERNAL_CERT_PATH,
            'key_destination': constants.EXTERNAL_KEY_PATH,
        }
        if replacing_ca:
            cert_destinations['ca_destination'] = \
                constants.EXTERNAL_CA_CERT_PATH
        logger.info('Handling external certificate...')
        deployed = certificates.use_supplied_certificates(
            SSL_INPUTS,
            logger,
            prefix='external_',
            **cert_destinations
        )

        if deployed:  # in case of replacing certs, deployed==True always
            logger.info('Deployed user provided external cert and key')
        else:
            self._generate_external_certs()

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
                'cloudify.conf',
            ]
        ]
        if do_manager:
            resources_list += [
                resource(
                    src=join(CONFIG_PATH, file_name),
                    dst='/etc/nginx/conf.d/{0}'.format(file_name)) for
                file_name in [
                    'logs-conf.cloudify',
                    'http-external-rest-server.cloudify',
                    'https-external-rest-server.cloudify',
                    'https-internal-rest-server.cloudify',
                    'rest-location.cloudify',
                    'rest-proxy.cloudify',
                    'fileserver-location.cloudify',
                    'ui-locations.cloudify',
                    'composer-location.cloudify',
                ]
            ]
        if do_monitoring:
            resources_list += [
                resource(
                    src=join(CONFIG_PATH, file_name),
                    dst='/etc/nginx/conf.d/{0}'.format(file_name)) for
                file_name in [
                    'https-monitoring-server.cloudify',
                    'redirect-to-monitoring.cloudify'
                ]
            ]
        return resources_list

    def _deploy_nginx_config_files(self):
        logger.info('Deploying Nginx configuration files...')
        if MONITORING_SERVICE in config.get(SERVICES_TO_INSTALL):
            self._update_credentials_config()
            self._create_htpasswd_file()
        for resource in self._config_files():
            deploy(resource.src, resource.dst)

        # remove the default configuration which reserves localhost:80 for a
        # nginx default landing page
        common.remove('/etc/nginx/conf.d/default.conf', ignore_failure=True)

    def _update_credentials_config(self):
        prometheus_credentials_cfg = config.get(PROMETHEUS).get('credentials',
                                                                {})
        if (prometheus_credentials_cfg.get('username') and
                prometheus_credentials_cfg.get('password')):
            return
        if 'credentials' not in config.get(PROMETHEUS):
            config[PROMETHEUS]['credentials'] = {}
        if MANAGER_SERVICE in config[SERVICES_TO_INSTALL]:
            manager_security_cfg = config.get(MANAGER).get('security', {})
            config[PROMETHEUS]['credentials']['username'] = \
                manager_security_cfg.get('admin_username')
            config[PROMETHEUS]['credentials']['password'] = \
                manager_security_cfg.get('admin_password')
        elif DATABASE_SERVICE in config[SERVICES_TO_INSTALL]:
            postgres_password = \
                config.get(POSTGRESQL_SERVER).get('postgres_password')
            config[PROMETHEUS]['credentials']['username'] = 'postgres'
            config[PROMETHEUS]['credentials']['password'] = postgres_password
        elif QUEUE_SERVICE in config[SERVICES_TO_INSTALL]:
            rabbitmq_cfg = config.get(RABBITMQ)
            config[PROMETHEUS]['credentials']['username'] = \
                rabbitmq_cfg.get('username')
            config[PROMETHEUS]['credentials']['password'] = \
                rabbitmq_cfg.get('password')

    def _create_htpasswd_file(self):
        username = config.get(PROMETHEUS).get('credentials').get('username')
        password = config.get(PROMETHEUS).get('credentials').get('password')
        with NamedTemporaryFile(delete=False, mode='w') as f:
            f.write('{0}:{1}'.format(username, common.run(
                ['openssl', 'passwd', '-apr1', password]).aggr_stdout))
        common.move(f.name, HTPASSWD_FILE)
        common.chown('nginx', 'nginx', HTPASSWD_FILE)
        common.chmod('600', HTPASSWD_FILE)

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

    def _configure_wait_on_restart_wrapper_service(self):
        deploy(
            join(
                SCRIPTS_PATH,
                'wait_on_restart.sh'
            ),
            '/etc/cloudify',
            render=False
        )
        common.chmod('755', '/etc/cloudify/wait_on_restart.sh')
        # Configure service wait_on_restart
        service.configure(
            'wait_on_restart',
            src_dir='nginx',
            append_prefix=False,
            render=False,
        )
        # Enable wait_on_restart service so that it can be called when
        # updating the ssl state as it required to restart nginx
        service.enable('wait_on_restart', append_prefix=False)

    def _configure(self):
        if self.service_type == 'supervisord':
            self._configure_wait_on_restart_wrapper_service()
        self._deploy_nginx_config_files()

    def install(self):
        logger.notice('Installing NGINX...')
        self._install()
        logger.notice('NGINX successfully installed')

    def configure(self):
        logger.notice('Configuring NGINX...')
        self._configure()
        if self.service_type != 'supervisord':
            service.enable(NGINX, append_prefix=False)
        logger.notice('NGINX successfully configured')

    def remove(self):
        remove_notice(NGINX)
        remove_logrotate(NGINX)
        remove_files([
            join('/var/cache', NGINX),
            LOG_DIR,
            UNIT_OVERRIDE_PATH,
            HTPASSWD_FILE,
        ] + [resource.dst for resource in self._config_files()])

    def start(self):
        logger.notice('Starting NGINX...')
        if MANAGER_SERVICE in config[SERVICES_TO_INSTALL]:
            self._handle_internal_cert()
            self._handle_external_cert()
        if self.service_type == 'supervisord':
            service.configure(NGINX, append_prefix=False)
        service.restart(NGINX, append_prefix=False)
        service.verify_alive(NGINX, append_prefix=False)
        logger.notice('NGINX successfully started')

    def stop(self):
        logger.notice('Stopping NGINX...')
        service.stop(NGINX, append_prefix=False)
        logger.notice('NGINX successfully stopped')
