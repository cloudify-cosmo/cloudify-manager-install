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
from ..service_names import PROMETHEUS
from ... import constants
from ...config import config
from ...exceptions import ProcessExecutionError
from ...logger import get_logger, setup_console_logger
from ...utils import common, files, service
from ...utils.network import wait_for_port

LOG_DIR = join(constants.BASE_LOG_DIR, PROMETHEUS)
CONFIG_PATH = join(constants.COMPONENTS_DIR, PROMETHEUS, CONFIG)
PROMETHEUS_CONFIG_DIR = join(sep, 'etc', 'prometheus', )
PROMETHEUS_CONFIG_PATH = join(PROMETHEUS_CONFIG_DIR, 'prometheus.yml')
PROMETHEUS_PORT = 9090
PROMETHEUS_VERSION = '2.18.1'
GROUP_USER_ALREADY_EXISTS_EXIT_CODE = 9
PROMETHEUS_USER = PROMETHEUS_GROUP = 'prometheus'
PROMETHEUS_USER_ID = PROMETHEUS_GROUP_ID = '90'
PROMETHEUS_USER_COMMENT = 'Prometheus Server'
PROMETHEUS_DATA_DIR = join(sep, 'var', 'lib', 'prometheus')

# PROMETHEUS_CTL = 'prometheusctl'

logger = get_logger(PROMETHEUS)


class Prometheus(BaseComponent):
    component_name = 'prometheus'

    def install(self):
        logger.notice('Installing Prometheus...')
        self._install()
        logger.notice('Prometheus successfully installed')

    def configure(self):
        logger.notice('Configuring PostgreSQL Server...')
        service.configure(PROMETHEUS,
                          user=PROMETHEUS_USER, group=PROMETHEUS_GROUP)
        self._init_service()
        logger.notice('Prometheus successfully configured')

    def remove(self):
        logger.notice('Removing Prometheus...')
        files.remove_files([
            PROMETHEUS_DATA_DIR,
            PROMETHEUS_CONFIG_DIR,
        ], ignore_failure=True)
        # files.remove_notice(PROMETHEUS)
        service.remove(PROMETHEUS, append_prefix=False)
        logger.notice('Successfully removed Prometheus files...')

    def start(self):
        logger.notice('Starting Prometheus...')
        self._start_prometheus()
        # if not config[PROMETHEUS]['join_cluster']:
        #     # Users will be synced with the cluster if we're joining one
        #     self._manage_users()
        self._validate_prometheus_running()
        # self._possibly_join_cluster()
        logger.notice('Prometheus successfully started')

    def stop(self):
        logger.notice('Stopping Prometheus...')
        service.stop(PROMETHEUS)
        logger.notice('Prometheus successfully stopped')

    def join_cluster(self, join_node, restore_users_on_fail=False):
        logger.info(
            'Would be joining cluster via node {target_node}.'.format(
                target_node=join_node,
            )
        )

    def _deploy_configuration(self):
        logger.info('Would deploy Prometheus config')

    def _init_service(self):
        logger.info('Would initialize Prometheus...')

    def _install(self):
        prometheus_username = config[PROMETHEUS]['username']
        if prometheus_username == PROMETHEUS_USER or not prometheus_username:
            config[PROMETHEUS]['username'] = PROMETHEUS_USER
            self._create_system_group()
            self._create_system_user()
        self._create_directories()
        working_dir = join(sep, 'tmp', 'prometheus')
        common.mkdir(working_dir)
        archive_file_name = self._download_release(working_dir,
                                                   PROMETHEUS_VERSION)
        self._unpack_release(working_dir, archive_file_name)
        self._copy_files(working_dir)
        common.remove(working_dir)

    def _create_system_group(self):
        logger.notice('Creating {0} group'.format(PROMETHEUS_GROUP))
        try:
            common.sudo(['groupadd',
                         '-g', PROMETHEUS_GROUP_ID,
                         '-o', '-r',
                         PROMETHEUS_GROUP])
        except ProcessExecutionError as ex:
            # Return code 9 for non-unique user/group
            if ex.return_code != GROUP_USER_ALREADY_EXISTS_EXIT_CODE:
                raise ex
            else:
                logger.info(
                    'Group {0} already exists'.format(PROMETHEUS_GROUP))

    def _create_system_user(self):
        logger.notice('Creating {0} user'.format(PROMETHEUS_USER))
        try:
            common.sudo(['useradd', '-m', '-N',
                         '-g', PROMETHEUS_GROUP_ID,
                         '-o', '-r',
                         # '-d', PROMETHEUS_USER_HOME_DIR,
                         '-s', '/sbin/nologin',
                         '-c', PROMETHEUS_USER_COMMENT,
                         '-u', PROMETHEUS_USER_ID, PROMETHEUS_USER])
        except ProcessExecutionError as ex:
            # Return code 9 for non-unique user/group
            if ex.return_code != GROUP_USER_ALREADY_EXISTS_EXIT_CODE:
                raise ex
            else:
                logger.info('User {0} already exists'.format(PROMETHEUS_USER))

    def _create_directories(self):
        logger.notice('Creating Prometheus directories')
        common.mkdir(PROMETHEUS_DATA_DIR, use_sudo=True)
        for dir_name in ('rules', 'rules.d', 'files_sd',):
            common.mkdir('{0}/{1}'.format(PROMETHEUS_CONFIG_DIR, dir_name),
                         use_sudo=True)
        # chown prometheus:prometheus ^^

    def _download_release(self, directory, version):
        logger.notice(
            'Downloading Prometheus v{0} to {1}'.format(version, directory))
        tarball_url = '{0}/v{1}/prometheus-{1}.linux-amd64.tar.gz'.format(
            'https://github.com/prometheus/prometheus/releases/download',
            version)
        archive_file_name = join(directory,
                                 'prometheus-{0}.tar.gz'.format(version))
        try:
            common.run(['curl', '-L', '-o', archive_file_name, tarball_url])
        except ProcessExecutionError as ex:
            logger.error('Error downloading prometheus: %s', ex)
            raise
        return archive_file_name

    def _unpack_release(self, directory, archive_file_name):
        logger.notice(
            'Unpacking Prometheus archive {0}'.format(archive_file_name))
        try:
            # common.run(['tar xvf', '-C', directory, archive_file_name])
            common.untar(archive_file_name, directory)
        except ProcessExecutionError as ex:
            logger.error('Error unpacking downloaded release: %s', ex)
            raise

    def _copy_files(self, directory):
        logger.notice(
            'Copying Prometheus binaries and default configuration')
        bin_dir = join('usr', 'local', 'bin')
        try:
            common.copy(join(directory, 'prometheus'), bin_dir)
            common.copy(join(directory, 'promtool'), bin_dir)
            common.copy(join(directory, 'prometheus.yml'),
                        PROMETHEUS_CONFIG_PATH)
        except ProcessExecutionError as ex:
            logger.error('Error copying files: %s', ex)
            raise

    def _start_prometheus(self):
        service.restart(PROMETHEUS, ignore_failure=True)
        wait_for_port(PROMETHEUS_PORT)
        # if not config[PROMETHEUS]['join_cluster']:
        #     # Policies will be obtained from the cluster if we're joining
        #     self._set_policies()
        #     systemd.restart(PROMETHEUS)

    def _validate_prometheus_running(self):
        logger.info('Making sure Prometheus is live...')
        service.verify_alive(PROMETHEUS)
        # if not is_port_open(PROMETHEUS_PORT, host='127.0.0.1'):
        #     raise NetworkError(
        #         '{0} error: port {1}:{2} was not open'.format(
        #             PROMETHEUS, '127.0.0.1', PROMETHEUS_PORT)
        #     )


@argh.arg('-v', '--verbose', help=constants.VERBOSE_HELP_MSG, default=False)
def start(verbose=False):
    setup_console_logger(verbose=verbose)
    logger.notice('Starting Prometheus service...')
    service.start(PROMETHEUS)
    logger.notice('Prometheus service started')


@argh.arg('-v', '--verbose', help=constants.VERBOSE_HELP_MSG, default=False)
def stop(verbose=False):
    setup_console_logger(verbose=verbose)
    logger.notice('Stopping Prometheus service...')
    service.stop(PROMETHEUS)
    logger.notice('Prometheus service stopped')
