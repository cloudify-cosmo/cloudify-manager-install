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
from os.path import join, exists
import subprocess

from ..base_component import BaseComponent
from ..components_constants import (
    CONFIG,
    CONSTANTS,
    ENABLE_REMOTE_CONNECTIONS,
    HOSTNAME,
    PRIVATE_IP,
    PUBLIC_IP,
    SERVICES_TO_INSTALL,
    SSL_ENABLED,
)
from ..service_names import (
    COMPOSER,
    MANAGER,
    PROMETHEUS,
    NODE_EXPORTER,
    BLACKBOX_EXPORTER,
    POSTGRES_EXPORTER,
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
PROMETHEUS_TARGETS_DIR = join(PROMETHEUS_CONFIG_DIR, 'targets')
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
            service.restart(BLACKBOX_EXPORTER, append_prefix=False,
                            ignore_failure=True)
            service.verify_alive(BLACKBOX_EXPORTER, append_prefix=False)
            service.restart(NGINX, append_prefix=False)
            service.verify_alive(NGINX, append_prefix=False)

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
        logger.info('Updating prometheus configuration for removal...')
        _update_prometheus_configuration(uninstalling=True)

        if _prometheus_targets_exist():
            logger.info(
                'Prometheus targets still exist, not removing prometheus.')
            logger.info('To remove prometheus, remove remaining components.')
        else:
            logger.notice('Removing Prometheus and exporters...')
            remove_files_list = [PROMETHEUS_DATA_DIR, PROMETHEUS_CONFIG_DIR]
            files.remove_files(remove_files_list)
            for exporter in _prometheus_exporters():
                service.remove(exporter['name'], append_prefix=False)
            service.remove(PROMETHEUS, append_prefix=False)
            logger.notice(
                'Successfully removed Prometheus and exporters files')

    def start(self):
        if files.is_file(CLUSTER_DETAILS_PATH):
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


def _chown_resources_dir():
    logger.notice('Changing files and directories ownership for Prometheus')
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP,
                 join(BIN_DIR, 'prometheus'))
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP,
                 join(BIN_DIR, 'promtool'))
    for exporter in _prometheus_exporters():
        common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP,
                     join(BIN_DIR, exporter['name']))
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, PROMETHEUS_DATA_DIR)


def _deploy_configuration():
    _update_config()
    _update_prometheus_configuration()
    _deploy_exporters_configuration()


def _update_config():

    def postgresql_ip_address():
        if config.get(POSTGRESQL_SERVER, {}).get(ENABLE_REMOTE_CONNECTIONS):
            return config.get(MANAGER, {}).get(PRIVATE_IP)
        return 'localhost'

    def postgres_ca_cert_path():
        if ('ca_path' in config[POSTGRESQL_SERVER] and
                config[POSTGRESQL_SERVER]['ca_path']):
            return config[POSTGRESQL_SERVER]['ca_path']
        if ('postgresql_ca_cert_path' in config[CONSTANTS] and
                config[CONSTANTS]['postgresql_ca_cert_path']):
            return config[CONSTANTS]['postgresql_ca_cert_path']
        return ''

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

    logger.notice('Updating Prometheus configuration...')
    if POSTGRES_EXPORTER in config[PROMETHEUS]:
        if ('ip_address' not in config[PROMETHEUS][POSTGRES_EXPORTER] or
                not config[PROMETHEUS][POSTGRES_EXPORTER]['ip_address']):
            config[PROMETHEUS][POSTGRES_EXPORTER].update(
                {'ip_address': postgresql_ip_address()})
        if config.get(POSTGRESQL_SERVER, {}).get(SSL_ENABLED):
            config[PROMETHEUS][POSTGRES_EXPORTER].update(
                {'sslmode': 'verify-full'})
            if ('ca_cert_path' not in config[PROMETHEUS][POSTGRES_EXPORTER] or
                    not config[PROMETHEUS][POSTGRES_EXPORTER]['ca_cert_path']):
                config[PROMETHEUS][POSTGRES_EXPORTER].update(
                    {'ca_cert_path': postgres_ca_cert_path()})
        else:
            config[PROMETHEUS][POSTGRES_EXPORTER].update(
                {'sslmode': 'disable'})
    if (MANAGER_SERVICE in config[SERVICES_TO_INSTALL] and
        ('ca_cert_path' not in config.get(PROMETHEUS,
                                          {}).get(BLACKBOX_EXPORTER, {}) or
         not config.get(PROMETHEUS,
                        {}).get(BLACKBOX_EXPORTER, {}).get('ca_cert_path'))):
        if not config[PROMETHEUS].get(BLACKBOX_EXPORTER):
            config[PROMETHEUS][BLACKBOX_EXPORTER] = {}
        config[PROMETHEUS][BLACKBOX_EXPORTER].update(
            {'ca_cert_path': config.get(CONSTANTS, {}).get('ca_cert_path')})

    if files.is_file(CLUSTER_DETAILS_PATH):
        update_cluster_details(CLUSTER_DETAILS_PATH)
        files.remove(CLUSTER_DETAILS_PATH, ignore_failure=True)


def _update_prometheus_configuration(uninstalling=False):
    logger.notice('Updating Prometheus configuration...')

    if not uninstalling:
        files.deploy(join(CONFIG_DIR, 'prometheus.yml'),
                     PROMETHEUS_CONFIG_PATH)
        common.sudo(['mkdir', '-p', PROMETHEUS_TARGETS_DIR])

    private_ip = config[MANAGER][PRIVATE_IP]

    _update_base_targets(private_ip, uninstalling)

    if common.is_installed(MANAGER_SERVICE):
        _update_manager_targets(private_ip, uninstalling)

    if common.is_installed(DATABASE_SERVICE):
        _update_local_postgres_targets(private_ip, uninstalling)

    if common.is_installed(QUEUE_SERVICE):
        _update_local_rabbit_targets(private_ip, uninstalling)

    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, PROMETHEUS_CONFIG_DIR)


def _prometheus_targets_exist():
    logger.info('Checking whether any prometheus targets still exist.')
    for conf in [
        'http_200_manager.yml',
        'http_401_manager.yml',
        'local_postgres.yml',
        'local_rabbit.yml',
        'other_rabbits.yml',
        'other_postgres.yml',
    ]:
        conf_path = join(PROMETHEUS_TARGETS_DIR, conf)
        logger.debug('Checking %s', conf_path)
        config = files.read_yaml_file(conf_path)
        if config and config[0].get('targets'):
            logger.info('Found remaining prometheus targets.')
            return True
    logger.info('No prometheus targets remain.')
    return False


def _update_local_rabbit_targets(private_ip, uninstalling):
    if uninstalling:
        logger.info(
            'Uninstall: prometheus local rabbit targets will be cleared.')
        local_rabbit_targets = []
        local_rabbit_labels = {}
    else:
        logger.info('Generating prometheus local rabbit targets.')
        local_rabbit_targets = ['localhost:15692']
        local_rabbit_labels = {'host': private_ip}
    logger.info('Updating prometheus local rabbit target configs')
    _deploy_targets('local_rabbit.yml',
                    local_rabbit_targets, local_rabbit_labels)


def _update_local_postgres_targets(private_ip, uninstalling):
    if uninstalling:
        logger.info(
            'Uninstall: prometheus local postgres targets will be cleared.')
        local_postgres_targets = []
        local_postgres_labels = {}
    else:
        logger.info('Generating prometheus local postgres targets.')
        local_postgres_targets = ['localhost:9187']
        local_postgres_labels = {'host': private_ip}
    logger.info('Updating prometheus local postgres target configs')
    _deploy_targets('local_postgres.yml',
                    local_postgres_targets, local_postgres_labels)


def _update_manager_targets(private_ip, uninstalling):
    http_200_targets = []
    http_200_labels = {}
    http_401_targets = []
    http_401_labels = {}
    rabbit_targets = []
    rabbit_labels = {}
    postgres_targets = []
    postgres_labels = {}
    if uninstalling:
        logger.info('Uninstall: prometheus manager targets will be cleared.')
    else:
        logger.info('Generating prometheus manager targets.')
        http_200_labels['host'] = private_ip
        composer_installed = (
            is_premium_installed()
            and not config[COMPOSER]['skip_installation']
        )
        if composer_installed:
            # Monitor composer directly and via nginx
            http_200_targets.append('http://127.0.0.1:3000/')
            http_200_targets.append('http://{}/composer'.format(private_ip))
        # Monitor stage directly and via nginx
        http_200_targets.append('http://127.0.0.1:8088')
        http_200_targets.append(
            '{proto}://{public_ip}:{port}/'.format(
                proto=config[MANAGER]['external_rest_protocol'],
                public_ip=config[MANAGER][PUBLIC_IP],
                port=config[MANAGER]['external_rest_port'],
            )
        )
        # Monitor cloudify's internal port
        http_200_targets.append('https://{}:53333/'.format(private_ip))

        # Monitor cloudify restservice
        http_401_targets.append('http://127.0.0.1:8100/api/v3.1/status')
        http_401_labels['host'] = private_ip

        # Monitor remote rabbit nodes
        use_rabbit_host = config[RABBITMQ]['use_hostnames_in_db']
        for host, rabbit in config[RABBITMQ]['cluster_members'].items():
            target = (
                host if use_rabbit_host else rabbit['networks']['default']
            )
            if target != private_ip:
                rabbit_targets.append(
                    target + ':' + str(config[CONSTANTS]['monitoring_port']))

        # Monitor remote postgres nodes
        for node in config[POSTGRESQL_SERVER]['cluster']['nodes'].values():
            if node['ip'] != private_ip:
                postgres_targets.append(private_ip)

    logger.info('Updating prometheus manager target configs')
    _deploy_targets('http_200_manager.yml',
                    http_200_targets, http_200_labels)
    _deploy_targets('http_401_manager.yml',
                    http_401_targets, http_401_labels)
    _deploy_targets('other_rabbits.yml',
                    rabbit_targets, rabbit_labels)
    _deploy_targets('other_postgres.yml',
                    postgres_targets, postgres_labels)


def _update_base_targets(private_ip, uninstalling):
    if uninstalling:
        logger.info('Uninstall: Doing nothing with base prometheus targets.')
        return

    logger.info('Updating prometheus base monitoring targets.')
    prometheus_targets = ['127.0.0.1:{}'.format(config[PROMETHEUS]['port'])]
    prometheus_labels = {'host': private_ip}
    _deploy_targets('local_prometheus.yml',
                    prometheus_targets, prometheus_labels)
    node_exporter_targets = [
        'localhost:{}'.format(
            config[PROMETHEUS]['node_exporter']['metrics_port']
        )
    ]
    node_exporter_labels = {'host': private_ip}
    _deploy_targets('local_node_exporter.yml',
                    node_exporter_targets, node_exporter_labels)


def _deploy_targets(destination, targets, labels):
    """Deploy a target file for prometheus.
    :param destination: Target file name in targets dir.
    :param targets: List of targets for prometheus.
    :param labels: Dict of labels with values for prometheus."""
    files.deploy(
        join(CONFIG_DIR, 'targets.yml'),
        join(PROMETHEUS_TARGETS_DIR, destination),
        additional_render_context={
            'target_addresses': json.dumps(targets),
            'target_labels': json.dumps(labels),
        },
    )


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
