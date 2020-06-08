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

import argh

from ..base_component import BaseComponent
from ..components_constants import (
    CONFIG,
)
from ..service_names import (
    PROMETHEUS,
    NODE_EXPORTER,
    BLACKBOX_EXPORTER,
    POSTGRES_EXPORTER,
    RABBITMQ_EXPORTER,
)
from ... import constants
from ...constants import (
    CLOUDIFY_USER,
    CLOUDIFY_GROUP
)
from ...logger import get_logger, setup_console_logger
from ...utils import common, files, service

CONFIG_DIR = join(constants.COMPONENTS_DIR, PROMETHEUS, CONFIG)
LOG_DIR = join(constants.BASE_LOG_DIR, PROMETHEUS)
BIN_DIR = join(sep, 'usr', 'local', 'bin')
SYSTEMD_CONFIG_DIR = join(sep, 'etc', 'systemd', 'system')
PROMETHEUS_DATA_DIR = join(sep, 'var', 'lib', 'prometheus')
PROMETHEUS_CONFIG_DIR = join(sep, 'etc', 'prometheus', )
PROMETHEUS_CONFIG_PATH = join(PROMETHEUS_CONFIG_DIR, 'prometheus.yml')
PROMETHEUS_VERSION = '2.18.1'
NODE_EXPORTER_VERSION = '1.0.0'
BLACKBOX_EXPORTER_VERSION = '0.16.0'
POSTGRES_EXPORTER_VERSION = '0.8.0'
RABBITMQ_EXPORTER_VERSION = '1.0.0-RC7'

EXPORTERS = [
    {
        'name': BLACKBOX_EXPORTER,
        'version': BLACKBOX_EXPORTER_VERSION,
        'description': 'Blackbox Exporter',
        'download_url': 'https://github.com/prometheus/{0}/releases/'
                        'download/v{1}/{0}-{1}.linux-amd64.tar.gz'.format(
                            BLACKBOX_EXPORTER, BLACKBOX_EXPORTER_VERSION),
        'deploy_config': {
            'blackbox.yml':
                join(PROMETHEUS_CONFIG_DIR, 'exporters', 'blackbox.yml')}
    },
    {
        'name': NODE_EXPORTER,
        'version': NODE_EXPORTER_VERSION,
        'description': 'Node Exporter',
        'download_url': 'https://github.com/prometheus/{0}/releases/'
                        'download/v{1}/{0}-{1}.linux-amd64.tar.gz'.format(
                            NODE_EXPORTER, NODE_EXPORTER_VERSION)
    },
    {
        'name': POSTGRES_EXPORTER,
        'version': POSTGRES_EXPORTER_VERSION,
        'description': 'Postgres Exporter',
        'download_url': 'https://github.com/wrouesnel/{0}/releases/'
                        'download/v{1}/{0}_v{1}_linux-amd64.tar.gz'.format(
                            POSTGRES_EXPORTER, POSTGRES_EXPORTER_VERSION)
    },
    {
        'name': RABBITMQ_EXPORTER,
        'version': RABBITMQ_EXPORTER_VERSION,
        'description': 'RabbitMQ Exporter',
        'download_url': 'https://github.com/kbudde/{0}/releases/'
                        'download/v{1}/{0}-{1}.linux-amd64.tar.gz'.format(
                            RABBITMQ_EXPORTER, RABBITMQ_EXPORTER_VERSION)
    },
]

logger = get_logger(PROMETHEUS)


class Prometheus(BaseComponent):
    component_name = 'prometheus'

    def install(self):
        _install_prometheus()
        _install_exporters()

    def configure(self):
        logger.notice('Configuring Prometheus Service...')
        _deploy_configuration()
        service.configure(PROMETHEUS, append_prefix=False)
        for exporter in EXPORTERS:
            service.configure(exporter['name'], append_prefix=False)
        logger.notice('Prometheus successfully configured')

    def remove(self):
        logger.notice('Removing Prometheus and exporters...')
        files.remove_files([PROMETHEUS_DATA_DIR, PROMETHEUS_CONFIG_DIR, ],
                           ignore_failure=True)
        files.remove_files([join(BIN_DIR, file_name) for file_name in
                            ('prometheus', 'promtool',)], ignore_failure=True)
        files.remove_files(
            [join(BIN_DIR, exporter['name']) for exporter in EXPORTERS],
            ignore_failure=True)
        for exporter in EXPORTERS:
            service.remove(exporter['name'], append_prefix=False)
        service.remove(PROMETHEUS, append_prefix=False)
        logger.notice('Successfully removed Prometheus and exporters files')

    def start(self):
        logger.notice('Starting Prometheus and exporters...')
        service.restart(PROMETHEUS, append_prefix=False,
                        ignore_failure=True)
        for exporter in EXPORTERS:
            service.restart(exporter['name'], append_prefix=False,
                            ignore_failure=True)
        _validate_prometheus_running()
        logger.notice('Prometheus and exporters successfully started')

    def stop(self):
        logger.notice('Stopping Prometheus and exporters...')
        service.stop(PROMETHEUS, append_prefix=False)
        for exporter in EXPORTERS:
            service.stop(exporter['name'], append_prefix=False)
        logger.notice('Prometheus and exporters successfully stopped')

    def join_cluster(self, join_node):  # , restore_users_on_fail=False):
        logger.info(
            'Would be joining cluster via node {target_node}.'.format(
                target_node=join_node,
            )
        )


def _create_directory(directory, use_sudo=True):
    common.mkdir(directory, use_sudo=use_sudo)
    return directory


def _download_release(dest_dir, base_url, name=None, version=None):
    if name and version:
        logger.notice(
            'Downloading {0}-{1} to {2}'.format(name, version, dest_dir))
        tarball_url = '{0}/{1}/releases/download/v{2}/{1}-{2}.{3}'.format(
            base_url, name, version, 'linux-amd64.tar.gz')
    else:
        logger.notice('Downloading {0} to {1}'.format(base_url, dest_dir))
        tarball_url = base_url
    archive_file_name = join(dest_dir, '{0}-{1}.tar.gz'.format(name, version))
    common.run(['curl', '-L', '-o', archive_file_name, tarball_url])
    return archive_file_name


def _download_exporter(exporter, dest_dir):
    logger.notice('Downloading {0}-{1} to {2}'.format(exporter['name'],
                                                      exporter['version'],
                                                      dest_dir))
    archive_file_name = join(dest_dir,
                             '{0}-{1}.tar.gz'.format(exporter['name'],
                                                     exporter['version']))
    common.run(
        ['curl', '-L', '-o', archive_file_name, exporter['download_url']])
    return archive_file_name


def _unpack_archive(archive_file_name, dest_dir):
    logger.notice('Unpacking archive {0}'.format(archive_file_name))
    common.untar(archive_file_name, dest_dir)


def _deploy_exporter(exporter, src_dir):
    logger.notice('Copying {0} binaries'.format(exporter['description']))
    dest_file_name = join(BIN_DIR, exporter['name'])
    common.copy(join(src_dir, exporter['name']), dest_file_name)
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, dest_file_name)
    if 'deploy_config' not in exporter:
        return
    for file_name, dest_file_name in exporter['deploy_config'].items():
        files.deploy(join(src_dir, file_name), dest_file_name)
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, dest_file_name)


def _install_prometheus():
    logger.notice('Installing Prometheus...')
    _create_prometheus_directories()
    working_dir = _create_directory(join(sep, 'tmp', 'prometheus'))
    archive_file_name = _download_release(working_dir,
                                          'https://github.com/prometheus',
                                          PROMETHEUS,
                                          PROMETHEUS_VERSION)
    _unpack_archive(archive_file_name, working_dir)
    _copy_prometheus(working_dir)
    common.remove(working_dir)
    logger.notice('Prometheus successfully installed')


def _create_prometheus_directories():
    logger.notice('Creating Prometheus directories')
    _create_directory(PROMETHEUS_DATA_DIR)
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, PROMETHEUS_DATA_DIR)
    for dir_name in ('rules', 'rules.d', 'files_sd', 'exporters',):
        _create_directory(join(PROMETHEUS_CONFIG_DIR, dir_name))
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, PROMETHEUS_CONFIG_DIR)


def _copy_prometheus(src_dir):
    logger.notice('Copying Prometheus binaries and default configuration')
    common.copy(join(src_dir, 'prometheus'), BIN_DIR)
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP,
                 join(BIN_DIR, 'prometheus'))
    common.copy(join(src_dir, 'promtool'), BIN_DIR)
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP,
                 join(BIN_DIR, 'promtool'))
    common.copy(join(src_dir, 'consoles'),
                PROMETHEUS_CONFIG_DIR)
    common.copy(join(src_dir, 'console_libraries'),
                PROMETHEUS_CONFIG_DIR)
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, PROMETHEUS_CONFIG_DIR)


def _install_exporters():
    for exporter in EXPORTERS:
        logger.notice('Installing {0}...'.format(exporter['description']))
        working_dir = _create_directory(join(sep, 'tmp', exporter['name']))
        archive_file_name = _download_exporter(exporter, working_dir)
        _unpack_archive(archive_file_name, working_dir)
        _deploy_exporter(exporter, working_dir)
        logger.notice(
            '{0} successfully installed'.format(exporter['description']))


def _deploy_configuration():
    logger.info('Initializing Prometheus...')
    _deploy_services_configuration()
    _deploy_prometheus_configuration()
    service.reload(PROMETHEUS,
                   append_prefix=False, ignore_failure=True)
    for exporter in EXPORTERS:
        service.reload(exporter['name'], append_prefix=False,
                       ignore_failure=True)


def _deploy_services_configuration():
    logger.notice('Adding Prometheus service configuration...')
    files.deploy(join(CONFIG_DIR, 'prometheus.service'),
                 join(SYSTEMD_CONFIG_DIR, 'prometheus.service'))
    for exporter in EXPORTERS:
        files.deploy(join(CONFIG_DIR,
                          '{0}.service'.format(exporter['name'])),
                     join(SYSTEMD_CONFIG_DIR,
                          '{0}.service'.format(exporter['name'])))


def _deploy_prometheus_configuration():
    logger.notice('Adding Prometheus and exporters\' configuration...')
    files.deploy(join(CONFIG_DIR, 'prometheus.yml'),
                 PROMETHEUS_CONFIG_PATH)


def _validate_prometheus_running():
    logger.info('Making sure Prometheus is live...')
    service.verify_alive(PROMETHEUS, append_prefix=False)


@argh.arg('-v', '--verbose', help=constants.VERBOSE_HELP_MSG, default=False)
def start(verbose=False):
    setup_console_logger(verbose=verbose)
    prometheus = Prometheus()
    prometheus.start()


@argh.arg('-v', '--verbose', help=constants.VERBOSE_HELP_MSG, default=False)
def stop(verbose=False):
    setup_console_logger(verbose=verbose)
    prometheus = Prometheus()
    prometheus.stop()
