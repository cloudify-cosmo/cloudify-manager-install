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
from os.path import isfile, join

from ..base_component import BaseComponent
from ..components_constants import (
    CONFIG,
    CONSTANTS,
    SERVICES_TO_INSTALL,
    ENABLE_REMOTE_CONNECTIONS,
    PRIVATE_IP,
)
from ..service_names import (
    MANAGER,
    PROMETHEUS,
    NODE_EXPORTER,
    BLACKBOX_EXPORTER,
    POSTGRES_EXPORTER,
    POSTGRESQL_CLIENT,
    POSTGRESQL_SERVER,
    RABBITMQ,

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
from ...utils import common, files, service
from ...utils.users import create_service_user


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
        _create_cloudify_user()
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


def _create_cloudify_user():
    create_service_user(
        user=constants.CLOUDIFY_USER,
        group=constants.CLOUDIFY_GROUP,
        home=constants.CLOUDIFY_HOME_DIR
    )
    common.mkdir(constants.CLOUDIFY_HOME_DIR)
    common.chown(
        constants.CLOUDIFY_USER,
        constants.CLOUDIFY_GROUP,
        constants.CLOUDIFY_HOME_DIR,
    )


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
        if (cluster_cfg[POSTGRESQL_SERVER]['cluster']['nodes'] and
                not config[POSTGRESQL_SERVER]['cluster']['nodes']):
            config[POSTGRESQL_SERVER]['cluster'].update({
                'nodes': cluster_cfg[POSTGRESQL_SERVER]['cluster']['nodes']
            })
        if (cluster_cfg[RABBITMQ]['ca_path'] and
                not config[RABBITMQ]['ca_path']):
            config[RABBITMQ]['ca_path'] = cluster_cfg[RABBITMQ]['ca_path']
        if (cluster_cfg[RABBITMQ]['cluster_members'] and
                not config[RABBITMQ]['cluster_members']):
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
    if ('ca_cert_path' not in config.get(PROMETHEUS, {}) or
            not config.get(PROMETHEUS, {}).get('ca_cert_path')):
        config[PROMETHEUS].update(
            {'ca_cert_path': config.get(CONSTANTS, {}).get('ca_cert_path')})

    if isfile(CLUSTER_DETAILS_PATH):
        update_cluster_details(CLUSTER_DETAILS_PATH)
        files.remove(CLUSTER_DETAILS_PATH, ignore_failure=True)

    if MANAGER_SERVICE in config[SERVICES_TO_INSTALL]:
        update_monitoring_credentials()


def _deploy_prometheus_configuration():
    logger.notice('Deploying Prometheus configuration...')
    files.deploy(join(CONFIG_DIR, 'prometheus.yml'),
                 PROMETHEUS_CONFIG_PATH)
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
