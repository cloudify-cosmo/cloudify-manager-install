import re
from collections import namedtuple
from os.path import join, exists
from tempfile import NamedTemporaryFile, TemporaryDirectory

from cfy_manager.components.prometheus import prometheus
from ..base_component import BaseComponent
from ...components_constants import (
    CONFIG,
    SCRIPTS,
    PRIVATE_IP,
    PUBLIC_IP,
    SSL_INPUTS,
    HOSTNAME,
    SERVICES_TO_INSTALL
)
from ...service_names import (NGINX, MANAGER, MANAGER_SERVICE,
                              MONITORING_SERVICE)
from ... import constants
from ...config import config
from ...exceptions import ValidationError
from ...logger import get_logger
from ...utils import (
    common,
    certificates,
    service
)
from ...utils.files import remove, deploy, copy_notice, remove_notice
from ...utils.logrotate import set_logrotate, remove_logrotate
from ...utils.network import lo_has_ipv6_addr

LOG_DIR = join(constants.BASE_LOG_DIR, NGINX)
CONFIG_PATH = join(constants.COMPONENTS_DIR, NGINX, CONFIG)
SCRIPTS_PATH = join(
    constants.COMPONENTS_DIR,
    NGINX,
    SCRIPTS
)
HTPASSWD_FILE = '/etc/nginx/conf.d/monitoring-htpasswd.cloudify'

logger = get_logger(NGINX)


class Nginx(BaseComponent):
    services = {'nginx': {'is_group': False}}

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
        hostname = config[MANAGER][HOSTNAME]
        external_rest_host = config[MANAGER][PUBLIC_IP]
        internal_rest_host = config[MANAGER][PRIVATE_IP]

        ca_cert = config[SSL_INPUTS]['external_ca_cert_path']
        ca_key = config[SSL_INPUTS]['external_ca_key_path']
        key_password = config[SSL_INPUTS]['external_ca_key_password']
        if not (ca_cert and ca_key):
            if exists(constants.CA_CERT_PATH) and \
                    exists(constants.CA_KEY_PATH):
                ca_cert = constants.CA_CERT_PATH
                ca_key = constants.CA_KEY_PATH
                key_password = config[SSL_INPUTS]['ca_key_password']
        certificates.generate_external_ssl_cert(
            ips=[external_rest_host, internal_rest_host],
            cn=hostname,
            sign_cert=ca_cert,
            sign_key=ca_key,
            sign_key_password=key_password,
        )
        certificates.store_cert_metadata(
            hostname,
            new_managers=[external_rest_host, internal_rest_host],
            filename=constants.EXTERNAL_CERT_METADATA_FILE_PATH,
        )

    def _handle_internal_cert(
            self, replacing_ca=False, replacing_ca_key=False):
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
        if replacing_ca_key:
            cert_destinations['ca_key_destination'] = constants.CA_KEY_PATH
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
            self.stop()
            self.start()

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
                    default_ca_key_location=constants.CA_KEY_PATH,
                    new_cert_location=constants.NEW_INTERNAL_CERT_FILE_PATH,
                    new_key_location=constants.NEW_INTERNAL_KEY_FILE_PATH,
                    new_ca_location=constants.NEW_INTERNAL_CA_CERT_FILE_PATH,
                    new_ca_key_location=constants.NEW_EXTERNAL_CA_KEY_FILE_PATH
                )

    def _validate_external_certs(self):
        if self._needs_to_replace_external_certs():
            certificates.get_and_validate_certs_for_replacement(
                default_cert_location=constants.EXTERNAL_CERT_PATH,
                default_key_location=constants.EXTERNAL_KEY_PATH,
                default_ca_location=constants.CA_CERT_PATH,
                default_ca_key_location=constants.CA_KEY_PATH,
                new_cert_location=constants.NEW_EXTERNAL_CERT_FILE_PATH,
                new_key_location=constants.NEW_EXTERNAL_KEY_FILE_PATH,
                new_ca_location=constants.NEW_EXTERNAL_CA_CERT_FILE_PATH,
                new_ca_key_location=constants.NEW_EXTERNAL_CA_KEY_FILE_PATH
            )

    def _replace_internal_certs(self):
        self._validate_internal_certs()
        logger.info('Replacing %s on nginx component', 'internal certificates')
        self._write_internal_certs_to_config()
        replacing_ca = exists(constants.NEW_INTERNAL_CA_CERT_FILE_PATH)
        replacing_ca_key = exists(constants.NEW_INTERNAL_CA_KEY_FILE_PATH)
        self._handle_internal_cert(replacing_ca=replacing_ca,
                                   replacing_ca_key=replacing_ca_key)

    def _replace_external_certs(self):
        self._validate_external_certs()
        logger.info('Replacing %s on nginx component', 'external certificates')
        self._write_external_certs_to_config()
        replacing_ca = exists(constants.NEW_EXTERNAL_CA_CERT_FILE_PATH)
        replacing_ca_key = exists(constants.NEW_EXTERNAL_CA_KEY_FILE_PATH)
        self._handle_external_cert(replacing_ca=replacing_ca,
                                   replacing_ca_key=replacing_ca_key)

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

    @staticmethod
    def _internal_certs_exist():
        if config[SSL_INPUTS]['internal_cert_path']:  # Certificate provided
            if exists(constants.INTERNAL_CERT_PATH):
                return certificates.certs_identical(
                    config[SSL_INPUTS]['internal_cert_path'],
                    constants.INTERNAL_CERT_PATH)
            else:
                return False
        else:
            # cert not provided - check the current cert: if it exists,
            # and if it was autogenerated - does it still cover all ips
            metadata = certificates.load_cert_metadata()
            if metadata:
                addrs = metadata.get('manager_addresses', [])
                if not all(addr in addrs
                           for addr in config['networks'].values()):
                    return False
            return exists(constants.INTERNAL_CERT_PATH)

    def _handle_external_cert(
            self, replacing_ca=False, replacing_ca_key=False):
        cert_destinations = {
            'cert_destination': constants.EXTERNAL_CERT_PATH,
            'key_destination': constants.EXTERNAL_KEY_PATH,
        }
        if replacing_ca:
            cert_destinations['ca_destination'] = \
                constants.EXTERNAL_CA_CERT_PATH
        if replacing_ca_key:
            cert_destinations['ca_key_destination'] = \
                constants.EXTERNAL_CA_KEY_PATH
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

    @staticmethod
    def _external_certs_exist():
        if config[SSL_INPUTS]['external_cert_path']:  # Certificate provided
            if exists(constants.EXTERNAL_CERT_PATH):
                return certificates.certs_identical(
                    config[SSL_INPUTS]['external_cert_path'],
                    constants.EXTERNAL_CERT_PATH)
            else:
                return False
        else:
            # cert not provided - check the current cert: if it exists,
            # and if it was autogenerated - does it still cover both ips
            metadata = certificates.load_cert_metadata(
                filename=constants.EXTERNAL_CERT_METADATA_FILE_PATH,
            )
            if metadata:
                addrs = metadata.get('manager_addresses', [])
                if config[MANAGER][PUBLIC_IP] not in addrs:
                    return False
                if config[MANAGER][PRIVATE_IP] not in addrs:
                    return False
            return exists(constants.EXTERNAL_CERT_PATH)

    def _handle_certs(self):
        certs_handled = False
        if not self._internal_certs_exist():
            certs_handled = True
            self._handle_internal_cert()
            prometheus.handle_certs()
        if not self._external_certs_exist():
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
                    'rest-location.cloudify',
                    'rest-proxy.cloudify',
                    'api-proxy.cloudify',
                    'authd-location.cloudify',
                    'ui-locations.cloudify',
                    'composer-location.cloudify',
                    'api.upstream',
                    'manager.upstream',
                ]
            ]
        if do_monitoring:
            resources_list += [
                resource(
                    src=join(CONFIG_PATH, file_name),
                    dst='/etc/nginx/conf.d/{0}'.format(file_name)) for
                file_name in [
                    'redirect-to-monitoring.cloudify',
                    'monitoring.upstream',
                ]
            ]
        return resources_list

    def _deploy_nginx_config_files(self):
        logger.info('Deploying Nginx configuration files...')
        credentials = common.get_prometheus_credentials()
        if MONITORING_SERVICE in config.get(SERVICES_TO_INSTALL):
            self._create_htpasswd_file(credentials)
        for resource in self._config_files():
            deploy(resource.src, resource.dst,
                   additional_render_context={
                       'ipv6_enabled': lo_has_ipv6_addr(),
                       'credentials': credentials,
                   })

        # remove the default configuration which reserves localhost:80 for a
        # nginx default landing page
        remove('/etc/nginx/conf.d/default.conf', ignore_failure=True)

    def _create_htpasswd_file(self, credentials):
        username = credentials.get('username')
        password = credentials.get('password')
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
            render=False,
        )
        # Enable wait_on_restart service so that it can be called when
        # updating the ssl state as it required to restart nginx
        service.enable('wait_on_restart')

    def _set_selinux_policies(self):
        if not exists('/usr/sbin/semanage'):
            logger.info('SELinux binaries not found; '
                        'SELinux policies will not be deployed')
            return
        if MANAGER_SERVICE in config.get(SERVICES_TO_INSTALL):
            self._set_selinux_policy(
                'cloudify_manager', ['3000', '8088', '8100', '8101'])
        if MONITORING_SERVICE in config.get(SERVICES_TO_INSTALL):
            self._set_selinux_policy(
                'cloudify_monitoring', ['9090-9094'])

    def _set_selinux_policy(self, policy_module, ports):
        output = common.run(['/usr/sbin/semodule', '-l'])
        if re.search(r'^' + re.escape(policy_module) + r'\s+',
                     output.aggr_stdout, flags=re.MULTILINE):
            logger.info('SELinux policy already installed: %s',
                        policy_module)
            return
        with TemporaryDirectory() as tmp_dir_name:
            base_file_name = join(tmp_dir_name, policy_module)
            logger.info('Deploying SELinux policy %s', policy_module)
            deploy(join(CONFIG_PATH, '{0}.te'.format(policy_module)),
                   '{0}.te'.format(base_file_name))
            common.run(['/bin/checkmodule',
                        '-M', '-m',
                        '-o', '{0}.mod'.format(base_file_name),
                        '{0}.te'.format(base_file_name)])
            common.run(['/bin/semodule_package',
                        '-o', '{0}.pp'.format(base_file_name),
                        '-m', '{0}.mod'.format(base_file_name)])
            common.run(['/usr/sbin/semodule',
                        '-i', '{0}.pp'.format(base_file_name)])
        for port in ports:
            common.run(['/usr/sbin/semanage', 'port', '-a',
                        '-t', '{0}_port_t'.format(policy_module),
                        '-p', 'tcp', port])
        logger.info('SELinux policies in place: %s', policy_module)

    def install(self):
        logger.notice('Installing NGINX...')
        common.mkdir(LOG_DIR)
        copy_notice(NGINX)
        self._set_selinux_policies()
        set_logrotate(NGINX)
        logger.notice('NGINX successfully installed')

    def configure(self):
        logger.notice('Configuring NGINX...')
        self._configure_wait_on_restart_wrapper_service()
        self._deploy_nginx_config_files()
        if MANAGER_SERVICE in config[SERVICES_TO_INSTALL]:
            self._handle_certs()
        service.configure(NGINX)
        logger.notice('NGINX successfully configured')
        self.start()

    def remove(self):
        remove_notice(NGINX)
        remove_logrotate(NGINX)
        service.remove('nginx')
        service.remove('wait_on_restart')
        remove([
            join('/var/cache', NGINX),
            LOG_DIR,
            HTPASSWD_FILE,
            '/etc/nginx',
        ])

    def upgrade(self):
        logger.notice('Upgrading NGINX...')
        self._deploy_nginx_config_files()
