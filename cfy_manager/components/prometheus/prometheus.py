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
from ...config import config
from ...constants import (
    CLOUDIFY_USER,
    CLOUDIFY_GROUP
)
from ...exceptions import NetworkError
from ...logger import get_logger, setup_console_logger
from ...utils import common, files, service
# from ...utils.network import wait_for_port
from ...utils.network import is_port_open

LOG_DIR = join(constants.BASE_LOG_DIR, PROMETHEUS)
BIN_DIR = join(sep, 'usr', 'local', 'bin')
CONFIG_PATH = join(constants.COMPONENTS_DIR, PROMETHEUS, CONFIG)
PROMETHEUS_CONFIG_DIR = join(sep, 'etc', 'prometheus', )
PROMETHEUS_CONFIG_PATH = join(PROMETHEUS_CONFIG_DIR, 'prometheus.yml')
SYSTEMD_CONFIG_DIR = join(sep, 'etc', 'systemd', 'system')
# PROMETHEUS_PORT = 9090
PROMETHEUS_VERSION = '2.18.1'
NODE_EXPORTER_VERSION = '1.0.0'
BLACKBOX_EXPORTER_VERSION = '0.16.0'
POSTGRES_EXPORTER_VERSION = '0.8.0'
RABBITMQ_EXPORTER_VERSION = '1.0.0-RC7'
GROUP_USER_ALREADY_EXISTS_EXIT_CODE = 9
PROMETHEUS_DATA_DIR = join(sep, 'var', 'lib', 'prometheus')
# PROMETHEUS_CTL = 'promtool'

logger = get_logger(PROMETHEUS)


class Prometheus(BaseComponent):
    component_name = 'prometheus'

    def install(self):
        _install_prometheus()
        _install_node_exporter()
        _install_blackbox_exporter()
        _install_postgres_exporter()
        _install_rabbitmq_exporter()

    def configure(self):
        logger.notice('Configuring Prometheus Service...')
        _deploy_configuration()
        service.configure(PROMETHEUS, append_prefix=False)
        service.configure(NODE_EXPORTER, append_prefix=False)
        service.configure(BLACKBOX_EXPORTER, append_prefix=False)
        service.configure(POSTGRES_EXPORTER, append_prefix=False)
        service.configure(RABBITMQ_EXPORTER, append_prefix=False)
        logger.notice('Prometheus successfully configured')

    def remove(self):
        logger.notice('Removing Prometheus and exporters...')
        files.remove_files([
            PROMETHEUS_DATA_DIR,
            PROMETHEUS_CONFIG_DIR,
        ], ignore_failure=True)
        files.remove_files([join(BIN_DIR, file_name) for file_name in
                            ('prometheus', 'promtool',
                             NODE_EXPORTER,
                             BLACKBOX_EXPORTER,
                             POSTGRES_EXPORTER,
                             RABBITMQ_EXPORTER,)],
                           ignore_failure=True)
        service.remove(NODE_EXPORTER, append_prefix=False)
        service.remove(BLACKBOX_EXPORTER, append_prefix=False)
        service.remove(POSTGRES_EXPORTER, append_prefix=False)
        service.remove(RABBITMQ_EXPORTER, append_prefix=False)
        service.remove(PROMETHEUS, append_prefix=False)
        logger.notice('Successfully removed Prometheus and exporters files')

    def start(self):
        logger.notice('Starting Prometheus and exporters...')
        service.restart(PROMETHEUS, append_prefix=False,
                        ignore_failure=True)
        # wait_for_port(config[PROMETHEUS]['port'])
        service.restart(NODE_EXPORTER, append_prefix=False,
                        ignore_failure=True)
        # wait_for_port(config[PROMETHEUS][NODE_EXPORTER]['metrics_port'])
        service.restart(BLACKBOX_EXPORTER, append_prefix=False,
                        ignore_failure=True)
        # wait_for_port(config[PROMETHEUS][BLACKBOX_EXPORTER]['metrics_port'])
        service.restart(POSTGRES_EXPORTER, append_prefix=False,
                        ignore_failure=True)
        # wait_for_port(config[PROMETHEUS][POSTGRES_EXPORTER]['metrics_port'])
        service.restart(RABBITMQ_EXPORTER, append_prefix=False,
                        ignore_failure=True)
        # wait_for_port(config[PROMETHEUS][RABBITMQ_EXPORTER]['metrics_port'])
        _validate_prometheus_running()
        logger.notice('Prometheus and exporters successfully started')

    def stop(self):
        logger.notice('Stopping Prometheus and exporters...')
        service.stop(PROMETHEUS, append_prefix=False)
        service.stop(NODE_EXPORTER, append_prefix=False)
        service.stop(BLACKBOX_EXPORTER, append_prefix=False)
        service.stop(POSTGRES_EXPORTER, append_prefix=False)
        service.stop(RABBITMQ_EXPORTER, append_prefix=False)
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


def _install_prometheus():
    logger.notice('Installing Prometheus...')
    _create_prometheus_directories()
    working_dir = _create_directory(join(sep, 'tmp', 'prometheus'))
    archive_file_name = _download_prometheus(PROMETHEUS_VERSION,
                                             working_dir)
    _unpack_prometheus(archive_file_name, working_dir)
    _copy_prometheus(working_dir)
    common.remove(working_dir)
    logger.notice('Prometheus successfully installed')


def _create_prometheus_directories():
    logger.notice('Creating Prometheus directories')
    _create_directory(PROMETHEUS_DATA_DIR)
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, PROMETHEUS_DATA_DIR)
    for dir_name in ('rules', 'rules.d', 'files_sd',):
        _create_directory('{0}/{1}'.format(PROMETHEUS_CONFIG_DIR, dir_name))
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, PROMETHEUS_CONFIG_DIR)


def _download_prometheus(version, dest_dir):
    logger.notice('Downloading Prometheus v{0} to {1}'.format(version,
                                                              dest_dir))
    tarball_url = '{0}/v{1}/prometheus-{1}.linux-amd64.tar.gz'.format(
        'https://github.com/prometheus/prometheus/releases/download',
        version)
    archive_file_name = join(dest_dir,
                             'prometheus-{0}.tar.gz'.format(version))
    common.run(['curl', '-L', '-o', archive_file_name, tarball_url])
    return archive_file_name


def _unpack_prometheus(archive_file_name, dest_dir):
    logger.notice('Unpacking Prometheus archive {0}'.format(archive_file_name))
    common.untar(archive_file_name, dest_dir)


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


def _unpack_exporter_archive(archive_file_name, dest_dir):
    logger.notice('Unpacking exporter archive {0}'.format(archive_file_name))
    common.untar(archive_file_name, dest_dir)


def _install_blackbox_exporter():
    logger.notice('Installing Blackbox Exporter...')
    working_dir = _create_directory(join(sep, 'tmp', 'blackbox_exporter'))
    archive_file_name = _download_blackbox_exporter(
        BLACKBOX_EXPORTER_VERSION, working_dir)
    _unpack_exporter_archive(archive_file_name, working_dir)
    _copy_blackbox_exporter(working_dir)
    common.remove(working_dir)
    logger.notice('Blackbox Exporter successfully installed')


def _download_blackbox_exporter(version, dest_dir):
    logger.notice('Downloading Blackbox Exporter v{0} to {1}'.format(version,
                                                                     dest_dir))
    tarball_url = '{0}/v{1}/blackbox_exporter-{1}.{2}'.format(
        'https://github.com/prometheus/blackbox_exporter/releases/download',
        version, 'linux-amd64.tar.gz')
    archive_file_name = join(dest_dir,
                             'blackbox_exporter-{0}.tar.gz'.format(
                                 version))
    common.run(['curl', '-L', '-o', archive_file_name, tarball_url])
    return archive_file_name


def _copy_blackbox_exporter(src_dir):
    logger.notice('Copying Blackbox Exporter binaries')
    common.copy(join(src_dir, 'blackbox_exporter'), BIN_DIR)
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP,
                 join(BIN_DIR, 'blackbox_exporter'))


def _install_node_exporter():
    logger.notice('Installing Node Exporter...')
    working_dir = _create_directory(join(sep, 'tmp', 'node_exporter'))
    archive_file_name = _download_node_exporter(
        NODE_EXPORTER_VERSION, working_dir)
    _unpack_exporter_archive(archive_file_name, working_dir)
    _copy_node_exporter(working_dir)
    common.remove(working_dir)
    logger.notice('Node Exporter successfully installed')


def _download_node_exporter(version, dest_dir):
    logger.notice('Downloading Node Exporter v{0} to {1}'.format(version,
                                                                 dest_dir))
    tarball_url = '{0}/v{1}/node_exporter-{1}.{2}'.format(
        'https://github.com/prometheus/node_exporter/releases/download',
        version, 'linux-amd64.tar.gz')
    archive_file_name = join(dest_dir,
                             'node_exporter-{0}.tar.gz'.format(
                                 version))
    common.run(['curl', '-L', '-o', archive_file_name, tarball_url])
    return archive_file_name


def _copy_node_exporter(src_dir):
    logger.notice('Copying Node Exporter binaries')
    common.copy(join(src_dir, 'node_exporter'), BIN_DIR)
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP,
                 join(BIN_DIR, 'node_exporter'))


def _install_postgres_exporter():
    logger.notice('Installing PostgreSQL Exporter...')
    working_dir = _create_directory(join(sep, 'tmp', 'postgres_exporter'))
    archive_file_name = _download_postgres_exporter(
        POSTGRES_EXPORTER_VERSION, working_dir)
    _unpack_exporter_archive(archive_file_name, working_dir)
    _copy_postgres_exporter(working_dir)
    common.remove(working_dir)
    logger.notice('PostgreSQL Exporter successfully installed')


def _download_postgres_exporter(version, dest_dir):
    logger.notice(
        'Downloading PostgreSQL Exporter v{0} to {1}'.format(version,
                                                             dest_dir))
    tarball_url = '{0}/v{1}/postgres_exporter_v{1}_{2}'.format(
        'https://github.com/wrouesnel/postgres_exporter/releases/download',
        version, 'linux-amd64.tar.gz')
    archive_file_name = join(dest_dir,
                             'postgres_exporter-{0}.tar.gz'.format(
                                 version))
    common.run(['curl', '-L', '-o', archive_file_name, tarball_url])
    return archive_file_name


def _copy_postgres_exporter(src_dir):
    logger.notice('Copying PostgreSQL Exporter binaries')
    common.copy(join(src_dir, 'postgres_exporter'), BIN_DIR)
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP,
                 join(BIN_DIR, 'postgres_exporter'))


def _install_rabbitmq_exporter():
    # As of RabbitMQ 3.8.0 https://github.com/rabbitmq/rabbitmq-prometheus
    # is also available
    logger.notice('Installing RabbitMQ Exporter...')
    working_dir = _create_directory(join(sep, 'tmp', 'rabbitmq_exporter'))
    archive_file_name = _download_rabbitmq_exporter(
        RABBITMQ_EXPORTER_VERSION, working_dir)
    _unpack_exporter_archive(archive_file_name, working_dir)
    _copy_rabbitmq_exporter(working_dir)
    common.remove(working_dir)
    logger.notice('RabbitMQ Exporter successfully installed')


def _download_rabbitmq_exporter(version, dest_dir):
    logger.notice(
        'Downloading RabbitMQ Exporter v{0} to {1}'.format(version,
                                                           dest_dir))
    tarball_url = '{0}/v{1}/rabbitmq_exporter-{1}.{2}'.format(
        'https://github.com/kbudde/rabbitmq_exporter/releases/download',
        version, 'linux-amd64.tar.gz')
    archive_file_name = join(dest_dir,
                             'rabbitmq_exporter-{0}.tar.gz'.format(
                                 version))
    common.run(['curl', '-L', '-o', archive_file_name, tarball_url])
    return archive_file_name


def _copy_rabbitmq_exporter(src_dir):
    logger.notice('Copying RabbitMQ Exporter binaries')
    common.copy(join(src_dir, 'rabbitmq_exporter'), BIN_DIR)
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP,
                 join(BIN_DIR, 'rabbitmq_exporter'))


def _deploy_configuration():
    logger.info('Initializing Prometheus...')
    _deploy_services_configuration()
    _copy_prometheus_configuration()
    _copy_prometheus_rules()
    service.reload(PROMETHEUS,
                   append_prefix=False, ignore_failure=True)
    service.reload(POSTGRES_EXPORTER,
                   append_prefix=False, ignore_failure=True)
    service.reload(RABBITMQ_EXPORTER,
                   append_prefix=False, ignore_failure=True)


def _deploy_services_configuration():
    logger.notice('Adding Prometheus service configuration...')
    # TODO: use files.deploy instead of common.copy here:
    common.copy(join(CONFIG_PATH, 'prometheus.service'),
                join(sep, 'etc', 'systemd', 'system'))
    files.deploy(join(CONFIG_PATH, '{0}.service'.format(NODE_EXPORTER)),
                 join(SYSTEMD_CONFIG_DIR,
                      '{0}.service'.format(NODE_EXPORTER)))
    files.deploy(join(CONFIG_PATH, '{0}.service'.format(BLACKBOX_EXPORTER)),
                 join(SYSTEMD_CONFIG_DIR,
                      '{0}.service'.format(BLACKBOX_EXPORTER)))
    files.deploy(join(CONFIG_PATH, '{0}.service'.format(POSTGRES_EXPORTER)),
                 join(SYSTEMD_CONFIG_DIR,
                      '{0}.service'.format(POSTGRES_EXPORTER)))
    files.deploy(join(CONFIG_PATH, '{0}.service'.format(RABBITMQ_EXPORTER)),
                 join(SYSTEMD_CONFIG_DIR,
                      '{0}.service'.format(RABBITMQ_EXPORTER)))


def _copy_prometheus_configuration():
    logger.notice('Adding Cloudify Prometheus configuration...')
    files.deploy(join(CONFIG_PATH, 'prometheus.yml'),
                 PROMETHEUS_CONFIG_PATH)


def _copy_prometheus_rules():
    logger.notice('Adding Cloudify Prometheus rules...')
    common.copy(join(CONFIG_PATH, 'postgresql.rules'),
                join(PROMETHEUS_CONFIG_DIR, 'rules'))
    common.copy(join(CONFIG_PATH, 'rabbitmq.rules'),
                join(PROMETHEUS_CONFIG_DIR, 'rules'))
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, PROMETHEUS_CONFIG_DIR)


def _validate_prometheus_running():
    logger.info('Making sure Prometheus is live...')
    service.verify_alive(PROMETHEUS, append_prefix=False)
    if not is_port_open(config[PROMETHEUS]['port'], host='127.0.0.1'):
        raise NetworkError(
            '{0} error: port {1}:{2} was not open'.format(
                PROMETHEUS, '127.0.0.1', config[PROMETHEUS]['port'])
        )


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
