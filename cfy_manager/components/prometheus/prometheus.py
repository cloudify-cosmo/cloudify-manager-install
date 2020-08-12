#########
# Copyright (c) 2020 GigaSpaces Technologies Ltd. All rights reserved
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
from os import sep
from os.path import isfile, join, exists
import subprocess

from ..base_component import BaseComponent
from ..components_constants import (
    CONFIG,
    CONSTANTS,
    ENABLE_REMOTE_CONNECTIONS,
    HOSTNAME,
    PRIVATE_IP,
    SERVICES_TO_INSTALL,
)
from ..service_names import (
    COMPOSER,
    MANAGER,
    PROMETHEUS,
    NODE_EXPORTER,
    BLACKBOX_EXPORTER,
    POSTGRES_EXPORTER,
    POSTGRESQL_CLIENT,
    POSTGRESQL_SERVER,
    RABBITMQ,
    NGINX,

    DATABASE_SERVICE,
    MANAGER_SERVICE,
    MONITORING_SERVICE,
    QUEUE_SERVICE,
)
from ... import constants
from ...config import config
from ...constants import (
    CLOUDIFY_USER,
    CLOUDIFY_GROUP
)
from ...logger import get_logger
from ...exceptions import ValidationError
from ...utils import common, files, service, certificates
from ...utils.install import is_premium_installed


CONFIG_DIR = join(constants.COMPONENTS_DIR, PROMETHEUS, CONFIG)
LOG_DIR = join(constants.BASE_LOG_DIR, PROMETHEUS)
BIN_DIR = join(sep, 'usr', 'local', 'bin')
SYSTEMD_CONFIG_DIR = join(sep, 'etc', 'systemd', 'system')
SUPERVISORD_CONFIG_DIR = join(sep, 'etc', 'supervisord.d')
PROMETHEUS_DATA_DIR = join(sep, 'var', 'lib', 'prometheus')
PROMETHEUS_CONFIG_DIR = join(sep, 'etc', 'prometheus', )
PROMETHEUS_CONFIG_PATH = join(PROMETHEUS_CONFIG_DIR, 'prometheus.yml')
CLUSTER_DETAILS_PATH = '/tmp/cluster_details.json'

AVAILABLE_EXPORTERS = [
    {
        'name': BLACKBOX_EXPORTER,
        'description': 'Blackbox Exporter',
        'deploy_config': {
            'blackbox.yml':
                join(PROMETHEUS_CONFIG_DIR, 'exporters', 'blackbox.yml')
        },
        'for': (MANAGER_SERVICE,),
    },
    {
        'name': NODE_EXPORTER,
        'description': 'Node Exporter',
        'for': (
            DATABASE_SERVICE, MANAGER_SERVICE, MONITORING_SERVICE,
            QUEUE_SERVICE,)
    },
    {
        'name': POSTGRES_EXPORTER,
        'description': 'Postgres Exporter',
        'for': (DATABASE_SERVICE,),
    },
]


logger = get_logger(PROMETHEUS)


def _prometheus_exporters():
    # generate exporters required for configured services
    return (exporter for exporter in AVAILABLE_EXPORTERS if
            any(s for s in exporter.get('for', []) if
                s in config.get(SERVICES_TO_INSTALL, [])))


class Prometheus(BaseComponent):
    component_name = 'prometheus'

    def configure(self):
        logger.notice('Configuring Prometheus Service...')
        _set_selinux_permissive()
        _handle_certs()
        _create_prometheus_directories()
        _chown_resources_dir()
        _deploy_configuration()
        service.configure(PROMETHEUS, append_prefix=False)
        service.reload(PROMETHEUS, append_prefix=False, ignore_failure=True)
        for exporter in _prometheus_exporters():
            service.configure(
                exporter['name'],
                src_dir='prometheus',
                append_prefix=False
            )
            service.reload(
                exporter['name'],
                append_prefix=False,
                ignore_failure=True
            )
        logger.notice('Prometheus successfully configured')

    def replace_certificates(self):
        if (exists(constants.NEW_PROMETHEUS_CERT_FILE_PATH) or
                exists(constants.NEW_PROMETHEUS_CA_CERT_FILE_PATH)):
            self.validate_new_certs()
            logger.info('Replacing certificates on prometheus component')
            self.write_new_certs_to_config()
            _handle_certs()
            service.reload(PROMETHEUS, append_prefix=False,
                           ignore_failure=True)
        if exists(constants.NEW_INTERNAL_CA_CERT_FILE_PATH):
            self._handle_blackbox_exporter_ca()
            service.restart(BLACKBOX_EXPORTER, append_prefix=False,
                            ignore_failure=True)
            service.verify_alive(BLACKBOX_EXPORTER, append_prefix=False)
            service.restart(NGINX, append_prefix=False)
            service.verify_alive(NGINX, append_prefix=False)

    @staticmethod
    def _handle_blackbox_exporter_ca():
        blackbox_path = join(PROMETHEUS_CONFIG_DIR, 'exporters',
                             'blackbox.yml')
        blackbox_config = files.read_yaml_file(blackbox_path)
        for job in 'http_200', 'http_401':
            blackbox_config['modules'][job]['http']['tls_config'][
                'ca_file'] = constants.CA_CERT_PATH
        files.update_yaml_file(blackbox_path, CLOUDIFY_USER, CLOUDIFY_GROUP,
                               blackbox_config)

    def validate_new_certs(self):
        if (exists(constants.NEW_PROMETHEUS_CERT_FILE_PATH) or
                exists(constants.NEW_PROMETHEUS_CA_CERT_FILE_PATH)):
            certificates.get_and_validate_certs_for_replacement(
                    default_cert_location=constants.MONITORING_CERT_PATH,
                    default_key_location=constants.MONITORING_KEY_PATH,
                    default_ca_location=constants.MONITORING_CA_CERT_PATH,
                    new_cert_location=constants.NEW_PROMETHEUS_CERT_FILE_PATH,
                    new_key_location=constants.NEW_PROMETHEUS_KEY_FILE_PATH,
                    new_ca_location=constants.NEW_PROMETHEUS_CA_CERT_FILE_PATH
                )

    @staticmethod
    def write_new_certs_to_config():
        if exists(constants.NEW_PROMETHEUS_CERT_FILE_PATH):
            config['prometheus']['cert_path'] = \
                constants.NEW_PROMETHEUS_CERT_FILE_PATH
            config['prometheus']['key_path'] = \
                constants.NEW_PROMETHEUS_KEY_FILE_PATH
        if exists(constants.NEW_PROMETHEUS_CA_CERT_FILE_PATH):
            config['prometheus']['ca_path'] = \
                constants.NEW_PROMETHEUS_CA_CERT_FILE_PATH
        if exists(constants.NEW_INTERNAL_CA_CERT_FILE_PATH):
            config[PROMETHEUS][BLACKBOX_EXPORTER]['ca_cert_path'] = \
                constants.NEW_INTERNAL_CA_CERT_FILE_PATH

    def remove(self):
        logger.notice('Removing Prometheus and exporters...')
        remove_files_list = [PROMETHEUS_DATA_DIR, ]
        for dir_name in (
                'rules', 'rules.d', 'files_sd', 'exporters', 'alerts',):
            remove_files_list.append(join(PROMETHEUS_CONFIG_DIR, dir_name))
        for file_name in ('prometheus.yml',):
            remove_files_list.append(join(PROMETHEUS_CONFIG_DIR, file_name))
        files.remove_files(remove_files_list, ignore_failure=True)
        for exporter in _prometheus_exporters():
            service.remove(exporter['name'], append_prefix=False)
        service.remove(PROMETHEUS, append_prefix=False)
        logger.notice('Successfully removed Prometheus and exporters files')

    def start(self):
        if isfile(CLUSTER_DETAILS_PATH):
            logger.notice(
                'File {0} exists will update Prometheus config...'.format(
                    CLUSTER_DETAILS_PATH))
            _deploy_configuration()
        logger.notice('Starting Prometheus and exporters...')
        service.restart(PROMETHEUS, append_prefix=False,
                        ignore_failure=True)
        for exporter in _prometheus_exporters():
            service.restart(exporter['name'], append_prefix=False,
                            ignore_failure=True)
        _validate_prometheus_running()
        logger.notice('Prometheus and exporters successfully started')

    def stop(self):
        logger.notice('Stopping Prometheus and exporters...')
        service.stop(PROMETHEUS, append_prefix=False)
        for exporter in _prometheus_exporters():
            service.stop(exporter['name'], append_prefix=False)
        logger.notice('Prometheus and exporters successfully stopped')

    def join_cluster(self, join_node):  # , restore_users_on_fail=False):
        logger.info(
            'Would be joining cluster via node {target_node}.'.format(
                target_node=join_node,
            )
        )


def _set_selinux_permissive():
    """This sets SELinux to permissive mode both for the current session
    and systemwide.
    """
    selinux_state = _get_selinux_state()
    logger.debug('Checking whether SELinux in enforced...')
    if selinux_state == 'Enforcing':
        logger.info('SELinux is enforcing, setting permissive state...')
        common.sudo(['setenforce', 'permissive'])
        files.replace_in_file(
            'SELINUX=enforcing',
            'SELINUX=permissive',
            '/etc/selinux/config')
    else:
        logger.debug('SELinux is not enforced.')


def _get_selinux_state():
    try:
        return subprocess.check_output(['/usr/sbin/getenforce'])\
            .decode('utf-8').rstrip('\n\r')
    except OSError as e:
        logger.warning('SELinux is not installed ({0})'.format(e))
        return None


def _handle_certs():
    logger.info('Setting up TLS certificates.')
    supplied = certificates.use_supplied_certificates(
        PROMETHEUS,
        logger,
        cert_destination=constants.MONITORING_CERT_PATH,
        key_destination=constants.MONITORING_KEY_PATH,
        ca_destination=constants.MONITORING_CA_CERT_PATH)
    if supplied:  # When replacing certificates, supplied==True always
        logger.info('Deployed user provided external cert and key')
    else:
        config[PROMETHEUS]['ca_path'] = constants.MONITORING_CA_CERT_PATH
        config[PROMETHEUS]['cert_path'] = constants.MONITORING_CERT_PATH
        config[PROMETHEUS]['key_path'] = constants.MONITORING_KEY_PATH
        _generate_certs()


def _generate_certs():
    logger.info('Generating certificate...')
    if _installing_manager():
        has_ca_key = certificates.handle_ca_cert(logger)
    else:
        has_ca_key = False
        # If we're not installing the manager and user certs were not
        # supplied then we're about to generate self-signed certs.
        # As we're going to do this, we'll set the ca_path such that
        # anything consuming this value will get the path to the cert
        # that will allow them to trust the broker.
        config[PROMETHEUS]['ca_path'] = config[PROMETHEUS]['cert_path']
    if not common.is_all_in_one_manager():
        raise ValidationError(
            'Cannot generate self-signed certificates for Prometheus in a '
            'cluster - externally generated certificates must be provided '
            'as well as the appropriate CA certificate.'
        )
    # As we only support generating certificates on single-node setups,
    # we will take only the manager's details (having failed before now
    # if there is a different environment than all in one)
    hostname = config[MANAGER][HOSTNAME]
    private_ip = config[MANAGER][PRIVATE_IP]

    certificates.store_cert_metadata(
        hostname,
        new_networks=[private_ip],
    )

    sign_cert = constants.CA_CERT_PATH if has_ca_key else None
    sign_key = constants.CA_KEY_PATH if has_ca_key else None

    certificates._generate_ssl_certificate(
        ips=[private_ip],
        cn=hostname,
        cert_path=config[PROMETHEUS]['cert_path'],
        key_path=config[PROMETHEUS]['key_path'],
        sign_cert=sign_cert,
        sign_key=sign_key,
    )
    if has_ca_key:
        common.copy(constants.CA_CERT_PATH, constants.MONITORING_CA_CERT_PATH)


def _installing_manager():
    return MANAGER_SERVICE in config[SERVICES_TO_INSTALL]


def _create_prometheus_directories():
    logger.notice('Creating Prometheus directories')
    common.mkdir(PROMETHEUS_DATA_DIR)
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, PROMETHEUS_DATA_DIR)
    for dir_name in ('rules', 'exporters',):
        dest_dir_name = join(PROMETHEUS_CONFIG_DIR, dir_name)
        common.mkdir(dest_dir_name)
        common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, dest_dir_name)


def _chown_resources_dir():
    logger.notice('Changing files and directories ownership for Prometheus')
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP,
                 join(BIN_DIR, 'prometheus'))
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP,
                 join(BIN_DIR, 'promtool'))
    for exporter in _prometheus_exporters():
        common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP,
                     join(BIN_DIR, exporter['name']))
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, PROMETHEUS_CONFIG_DIR)
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, PROMETHEUS_DATA_DIR)


def _deploy_configuration():
    _update_config()
    _deploy_prometheus_configuration()
    _deploy_exporters_configuration()


def _update_config():
    def postgresql_username():
        if MANAGER_SERVICE in config.get(SERVICES_TO_INSTALL, []):
            return config.get(POSTGRESQL_CLIENT, {}).get('server_username')
        return 'postgres'

    def postgresql_password():
        if MANAGER_SERVICE in config.get(SERVICES_TO_INSTALL, []):
            return config.get(POSTGRESQL_CLIENT, {}).get('server_password')
        if DATABASE_SERVICE in config.get(SERVICES_TO_INSTALL, []):
            return config.get(POSTGRESQL_SERVER, {}).get('postgres_password')

    def postgresql_ip_address():
        if config.get(POSTGRESQL_SERVER, {}).get(ENABLE_REMOTE_CONNECTIONS):
            return config.get(MANAGER, {}).get(PRIVATE_IP)
        return 'localhost'

    def update_cluster_details(file_name):
        with open(file_name, 'r') as fp:
            cluster_cfg = json.load(fp)
        if (cluster_cfg.get(POSTGRESQL_SERVER, {}).get('cluster',
                                                       {}).get('nodes') and
                not config.get(POSTGRESQL_SERVER, {}).get('cluster',
                                                          {}).get('nodes')):
            config[POSTGRESQL_SERVER]['cluster'].update({
                'nodes': cluster_cfg[POSTGRESQL_SERVER]['cluster']['nodes']
            })
        if (cluster_cfg.get(RABBITMQ, {}).get('ca_path') and
                not config.get(RABBITMQ, {}).get('ca_path')):
            config[RABBITMQ]['ca_path'] = cluster_cfg[RABBITMQ]['ca_path']
        if (cluster_cfg.get(RABBITMQ, {}).get('cluster_members') and
                not config.get(RABBITMQ, {}).get('cluster_members')):
            config[RABBITMQ].update({
                'cluster_members': cluster_cfg[RABBITMQ]['cluster_members']
            })

    def update_monitoring_credentials():
        # Update configuration of credentials for federated Prometheus
        # instances working on database_service and queue_service nodes
        # of a cluster
        if len(config[POSTGRESQL_SERVER]['cluster']['nodes']) > 0:
            postgresql_monitoring_cfg = config.get(
                POSTGRESQL_CLIENT).get('monitoring', {})
            if (not postgresql_monitoring_cfg.get('username') or
                    not postgresql_monitoring_cfg.get('password')):
                if not postgresql_monitoring_cfg:
                    config[POSTGRESQL_CLIENT]['monitoring'] = {}
                config[POSTGRESQL_CLIENT]['monitoring']['username'] = \
                    config[POSTGRESQL_CLIENT]['server_username']
                config[POSTGRESQL_CLIENT]['monitoring']['password'] = \
                    config[POSTGRESQL_CLIENT]['server_password']
        if len(config[RABBITMQ]['cluster_members']) > 0:
            rabbitmq_monitoring_cfg = config.get(
                RABBITMQ).get('monitoring', {})
            if (not rabbitmq_monitoring_cfg.get('username') or
                    not rabbitmq_monitoring_cfg.get('password')):
                if not rabbitmq_monitoring_cfg:
                    config[RABBITMQ]['monitoring'] = {}
                config[RABBITMQ]['monitoring']['username'] = \
                    config[RABBITMQ]['username']
                config[RABBITMQ]['monitoring']['password'] = \
                    config[RABBITMQ]['password']

    logger.notice('Updating Prometheus configuration...')
    if POSTGRES_EXPORTER in config[PROMETHEUS]:
        if ('username' in config[PROMETHEUS][POSTGRES_EXPORTER] and
                not config[PROMETHEUS][POSTGRES_EXPORTER]['username']):
            config[PROMETHEUS][POSTGRES_EXPORTER].update(
                {'username': postgresql_username()})
        if ('password' in config[PROMETHEUS][POSTGRES_EXPORTER] and
                not config[PROMETHEUS][POSTGRES_EXPORTER]['password']):
            config[PROMETHEUS][POSTGRES_EXPORTER].update(
                {'password': postgresql_password()})
        if ('ip_address' not in config[PROMETHEUS][POSTGRES_EXPORTER] or
                not config[PROMETHEUS][POSTGRES_EXPORTER]['ip_address']):
            config[PROMETHEUS][POSTGRES_EXPORTER].update(
                {'ip_address': postgresql_ip_address()})
    if (MANAGER_SERVICE in config[SERVICES_TO_INSTALL] and
        ('ca_cert_path' not in config.get(PROMETHEUS,
                                          {}).get(BLACKBOX_EXPORTER, {}) or
         not config.get(PROMETHEUS,
                        {}).get(BLACKBOX_EXPORTER, {}).get('ca_cert_path'))):
        if not config[PROMETHEUS].get(BLACKBOX_EXPORTER):
            config[PROMETHEUS][BLACKBOX_EXPORTER] = {}
        config[PROMETHEUS][BLACKBOX_EXPORTER].update(
            {'ca_cert_path': config.get(CONSTANTS, {}).get('ca_cert_path')})

    if isfile(CLUSTER_DETAILS_PATH):
        update_cluster_details(CLUSTER_DETAILS_PATH)
        files.remove(CLUSTER_DETAILS_PATH, ignore_failure=True)

    if MANAGER_SERVICE in config[SERVICES_TO_INSTALL]:
        update_monitoring_credentials()


def _deploy_prometheus_configuration():
    logger.notice('Deploying Prometheus configuration...')
    files.deploy(join(CONFIG_DIR, 'prometheus.yml'),
                 PROMETHEUS_CONFIG_PATH,
                 additional_render_context={
                     'is_premium_installed':
                         is_premium_installed(),
                     'composer_skip_installation':
                         config[COMPOSER]['skip_installation'],
                 })
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, PROMETHEUS_CONFIG_PATH)
    if MANAGER_SERVICE not in config.get(SERVICES_TO_INSTALL, []):
        return
    # deploy rules configuration files
    for file_name in ['postgresql.yml', 'rabbitmq.yml', ]:
        dest_file_name = join(PROMETHEUS_CONFIG_DIR, 'rules', file_name)
        files.deploy(join(CONFIG_DIR, 'rules', file_name),
                     dest_file_name)
        common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, dest_file_name)
    # deploy alerts configuration files
    for file_name in ['postgresql.yml', 'rabbitmq.yml', 'manager.yml', ]:
        dest_file_name = join(PROMETHEUS_CONFIG_DIR, 'alerts', file_name)
        files.deploy(join(CONFIG_DIR, 'alerts', file_name),
                     dest_file_name)
        common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, dest_file_name)


def _deploy_exporters_configuration():
    for exporter in _prometheus_exporters():
        if 'deploy_config' not in exporter:
            continue
        logger.notice(
            'Deploying {0} configuration...'.format(exporter['description']))
        for file_name, dest_file_name in exporter['deploy_config'].items():
            files.deploy(join(CONFIG_DIR, file_name), dest_file_name)
            common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, dest_file_name)


def _validate_prometheus_running():
    logger.info('Making sure Prometheus is live...')
    service.verify_alive(PROMETHEUS, append_prefix=False)
