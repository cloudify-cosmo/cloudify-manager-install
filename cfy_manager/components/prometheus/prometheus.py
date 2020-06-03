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
from ..service_names import PROMETHEUS, POSTGRES_EXPORTER
from ... import constants
from ...constants import (
    # CLOUDIFY_HOME_DIR,
    CLOUDIFY_USER,
    CLOUDIFY_GROUP
)
from ...logger import get_logger, setup_console_logger
from ...utils import common, files, service
from ...utils.network import wait_for_port

LOG_DIR = join(constants.BASE_LOG_DIR, PROMETHEUS)
BIN_DIR = join(sep, 'usr', 'local', 'bin')
CONFIG_PATH = join(constants.COMPONENTS_DIR, PROMETHEUS, CONFIG)
PROMETHEUS_CONFIG_DIR = join(sep, 'etc', 'prometheus', )
PROMETHEUS_CONFIG_PATH = join(PROMETHEUS_CONFIG_DIR, 'prometheus.yml')
SYSTEMD_CONFIG_DIR = join(sep, 'etc', 'systemd', 'system')
PROMETHEUS_PORT = 9090
PROMETHEUS_VERSION = '2.18.1'
POSTGRES_EXPORTER_VERSION = '0.8.0'
GROUP_USER_ALREADY_EXISTS_EXIT_CODE = 9
# PROMETHEUS_USER = PROMETHEUS_GROUP = 'prometheus'
# PROMETHEUS_USER_ID = PROMETHEUS_GROUP_ID = '90'
# PROMETHEUS_USER_COMMENT = 'Prometheus Server'
PROMETHEUS_DATA_DIR = join(sep, 'var', 'lib', 'prometheus')
# PROMETHEUS_CTL = 'prometheusctl'

logger = get_logger(PROMETHEUS)


class Prometheus(BaseComponent):
    component_name = 'prometheus'

    def install(self):
        _install_prometheus()
        _install_postgres_exporter()

    def configure(self):
        logger.notice('Configuring Prometheus Service...')
        _deploy_configuration()
        service.configure(PROMETHEUS, append_prefix=False)
        service.configure(POSTGRES_EXPORTER, append_prefix=False)
        logger.notice('Prometheus successfully configured')

    def remove(self):
        logger.notice('Removing Prometheus...')
        files.remove_files([
            PROMETHEUS_DATA_DIR,
            PROMETHEUS_CONFIG_DIR,
        ], ignore_failure=True)
        files.remove_files([join(BIN_DIR, file_name) for file_name in
                            ('prometheus', 'promtool', 'postgres_exporter',)],
                           ignore_failure=True)
        # files.remove_notice(PROMETHEUS)
        service.remove(POSTGRES_EXPORTER, append_prefix=False)
        service.remove(PROMETHEUS, append_prefix=False)
        logger.notice('Successfully removed Prometheus files...')

    def start(self):
        logger.notice('Starting Prometheus...')
        self._start_prometheus()
        self._start_postgres_exporter()
        # if not config[PROMETHEUS]['join_cluster']:
        #     # Users will be synced with the cluster if we're joining one
        #     self._manage_users()
        self._validate_prometheus_running()
        # self._possibly_join_cluster()
        logger.notice('Prometheus successfully started')

    def stop(self):
        logger.notice('Stopping Prometheus...')
        service.stop(PROMETHEUS, append_prefix=False)
        logger.notice('Prometheus successfully stopped')

    def join_cluster(self, join_node):  # , restore_users_on_fail=False):
        logger.info(
            'Would be joining cluster via node {target_node}.'.format(
                target_node=join_node,
            )
        )

    def _start_prometheus(self):
        service.restart(PROMETHEUS, append_prefix=False, ignore_failure=True)
        wait_for_port(PROMETHEUS_PORT)

    def _start_postgres_exporter(self):
        service.restart(POSTGRES_EXPORTER, append_prefix=False,
                        ignore_failure=True)
        # if not config[PROMETHEUS]['join_cluster']:
        #     # Policies will be obtained from the cluster if we're joining
        #     self._set_policies()
        #     systemd.restart(PROMETHEUS)

    def _validate_prometheus_running(self):
        logger.info('Making sure Prometheus is live...')
        service.verify_alive(PROMETHEUS, append_prefix=False)
        # if not is_port_open(PROMETHEUS_PORT, host='127.0.0.1'):
        #     raise NetworkError(
        #         '{0} error: port {1}:{2} was not open'.format(
        #             PROMETHEUS, '127.0.0.1', PROMETHEUS_PORT)
        #     )


@argh.arg('-v', '--verbose', help=constants.VERBOSE_HELP_MSG, default=False)
def start(verbose=False):
    setup_console_logger(verbose=verbose)
    logger.notice('Starting Prometheus service...')
    service.start(PROMETHEUS, append_prefix=False)
    logger.notice('Prometheus service started')


@argh.arg('-v', '--verbose', help=constants.VERBOSE_HELP_MSG, default=False)
def stop(verbose=False):
    setup_console_logger(verbose=verbose)
    logger.notice('Stopping Prometheus service...')
    service.stop(PROMETHEUS, append_prefix=False)
    logger.notice('Prometheus service stopped')


def _create_directory(directory, use_sudo=True):
    common.mkdir(directory, use_sudo=use_sudo)
    return directory


def _install_prometheus():
    logger.info('Installing Prometheus...')
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
    common.copy(join(src_dir, 'prometheus.yml'),
                PROMETHEUS_CONFIG_PATH)
    common.copy(join(src_dir, 'consoles'),
                PROMETHEUS_CONFIG_DIR)
    common.copy(join(src_dir, 'console_libraries'),
                PROMETHEUS_CONFIG_DIR)
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, PROMETHEUS_CONFIG_DIR)


def _install_postgres_exporter():
    logger.info('Installing PostgreSQL Exporter...')
    working_dir = _create_directory(join(sep, 'tmp', 'postgres_exporter'))
    archive_file_name = _download_postgres_exporter(
        POSTGRES_EXPORTER_VERSION, working_dir)
    _unpack_postgres_exporter(archive_file_name, working_dir)
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


def _unpack_postgres_exporter(archive_file_name, dest_dir, ):
    logger.notice('Unpacking PostgreSQL Exporter archive {0}'.format(
        archive_file_name))
    common.untar(archive_file_name, dest_dir)


def _copy_postgres_exporter(src_dir):
    logger.notice('Copying PostgreSQL Exporter binaries')
    common.copy(join(src_dir, 'postgres_exporter'), BIN_DIR)
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP,
                 join(BIN_DIR, 'postgres_exporter'))


def _deploy_configuration():
    logger.info('Initializing Prometheus...')
    _deploy_services_configuration()
    _copy_prometheus_configuration()
    _copy_prometheus_rules()
    service.reload(PROMETHEUS,
                   append_prefix=False, ignore_failure=True)
    service.reload(POSTGRES_EXPORTER,
                   append_prefix=False, ignore_failure=True)


def _deploy_services_configuration():
    logger.notice('Adding Prometheus service configuration...')
    common.copy(join(CONFIG_PATH, 'prometheus.service'),
                join(sep, 'etc', 'systemd', 'system'))
    # common.copy(join(CONFIG_PATH, 'postgres_exporter.service'),
    #             join(sep, 'etc', 'systemd', 'system'))
    files.deploy(join(CONFIG_PATH, 'postgres_exporter.service'),
                 join(SYSTEMD_CONFIG_DIR, 'postgres_exporter.service'))
    # common.chown(constants.CLOUDIFY_USER, constants.CLOUDIFY_GROUP,
    #              SYSTEMD_CONFIG_DIR)


def _copy_prometheus_configuration():
    logger.notice('Adding Cloudify Prometheus configuration...')
    common.copy(join(CONFIG_PATH, 'prometheus.yml'),
                PROMETHEUS_CONFIG_PATH)


def _copy_prometheus_rules():
    logger.notice('Adding Cloudify Prometheus rules...')
    common.copy(join(CONFIG_PATH, 'postgresql.rules'),
                join(PROMETHEUS_CONFIG_DIR, 'rules'))
    common.copy(join(CONFIG_PATH, 'rabbitmq.rules'),
                join(PROMETHEUS_CONFIG_DIR, 'rules'))
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, PROMETHEUS_CONFIG_DIR)
