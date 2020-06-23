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


from os import sep
from os.path import join

from ..base_component import BaseComponent
from ..components_constants import (
    CONFIG,
    CONSTANTS,
    SERVICES_TO_INSTALL,
)
from ..service_names import (
    PROMETHEUS,
    NODE_EXPORTER,
    BLACKBOX_EXPORTER,
    POSTGRES_EXPORTER,
    POSTGRESQL_CLIENT,

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

CONFIG_DIR = join(constants.COMPONENTS_DIR, PROMETHEUS, CONFIG)
LOG_DIR = join(constants.BASE_LOG_DIR, PROMETHEUS)
BIN_DIR = join(sep, 'usr', 'local', 'bin')
SYSTEMD_CONFIG_DIR = join(sep, 'etc', 'systemd', 'system')
SUPERVISORD_CONFIG_DIR = join(sep, 'etc', 'supervisord.d')
PROMETHEUS_DATA_DIR = join(sep, 'var', 'lib', 'prometheus')
PROMETHEUS_CONFIG_DIR = join(sep, 'etc', 'prometheus', )
PROMETHEUS_CONFIG_PATH = join(PROMETHEUS_CONFIG_DIR, 'prometheus.yml')

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

    def _configure_exporter_services(self):
        pass

    def configure(self):
        logger.notice('Configuring Prometheus Service...')
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
        for dir_name in ('rules', 'rules.d', 'files_sd', 'exporters',):
            remove_files_list.append(join(PROMETHEUS_CONFIG_DIR, dir_name))
        for file_name in ('prometheus.yml',):
            remove_files_list.append(join(PROMETHEUS_CONFIG_DIR, file_name))
        files.remove_files(remove_files_list, ignore_failure=True)
        for exporter in _prometheus_exporters():
            service.remove(exporter['name'], append_prefix=False)
        service.remove(PROMETHEUS, append_prefix=False)
        logger.notice('Successfully removed Prometheus and exporters files')

    def start(self):
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
    if PROMETHEUS in config:
        _update_config()
    _deploy_prometheus_configuration()
    _deploy_exporters_configuration()


def _update_config():
    if POSTGRES_EXPORTER in config[PROMETHEUS]:
        if ('username' in config[PROMETHEUS][POSTGRES_EXPORTER] and
                not config[PROMETHEUS][POSTGRES_EXPORTER]['username']):
            config[PROMETHEUS][POSTGRES_EXPORTER].update(
                {'username': config[POSTGRESQL_CLIENT]['server_username']})
        if ('password' in config[PROMETHEUS][POSTGRES_EXPORTER] and
                not config[PROMETHEUS][POSTGRES_EXPORTER]['password']):
            config[PROMETHEUS][POSTGRES_EXPORTER].update(
                {'password': config[POSTGRESQL_CLIENT]['server_password']})
    if ('ca_cert_path' not in config[PROMETHEUS] or
            not config[PROMETHEUS]['ca_cert_path']):
        config[PROMETHEUS].update(
            {'ca_cert_path': config[CONSTANTS]['ca_cert_path']})


def _deploy_prometheus_configuration():
    logger.notice('Deploying Prometheus configuration...')
    files.deploy(join(CONFIG_DIR, 'prometheus.yml'),
                 PROMETHEUS_CONFIG_PATH)
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, PROMETHEUS_CONFIG_PATH)


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
