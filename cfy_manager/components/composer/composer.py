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

import os
import json

from os.path import join, dirname

from ..components_constants import (
    SOURCES,
    SERVICE_USER,
    SERVICE_GROUP,
    SSL_INPUTS
)
from ..base_component import BaseComponent
from ..service_names import COMPOSER, POSTGRESQL_CLIENT
from ...config import config
from ...logger import get_logger
from ...exceptions import FileError
from ...constants import BASE_LOG_DIR, CLOUDIFY_USER
from ...utils import common, files, sudoers
from ...utils.systemd import systemd
from ...utils.network import wait_for_port
from ...utils.logrotate import set_logrotate, remove_logrotate
from ...utils.users import create_service_user

logger = get_logger(COMPOSER)

HOME_DIR = join('/opt', 'cloudify-{0}'.format(COMPOSER))
CONF_DIR = join(HOME_DIR, 'backend', 'conf')
NODEJS_DIR = join('/opt', 'nodejs')
LOG_DIR = join(BASE_LOG_DIR, COMPOSER)

COMPOSER_USER = '{0}_user'.format(COMPOSER)
COMPOSER_GROUP = '{0}_group'.format(COMPOSER)
COMPOSER_PORT = 3000


class ComposerComponent(BaseComponent):

    def __init__(self, skip_installation):
        super(ComposerComponent, self).__init__(skip_installation)

    def _create_paths(self):
        common.mkdir(NODEJS_DIR)
        common.mkdir(HOME_DIR)
        common.mkdir(LOG_DIR)

    def _install(self):
        composer_source_url = config[COMPOSER][SOURCES]['composer_source_url']
        try:
            composer_tar = files.get_local_source_path(composer_source_url)
        except FileError:
            logger.info(
                'Composer package not found in manager resources package')
            logger.notice('Composer will not be installed.')
            config[COMPOSER]['skip_installation'] = True
            return

        self._create_paths()

        logger.info('Installing Cloudify Composer...')
        common.untar(composer_tar, HOME_DIR)

    def _verify_composer_alive(self):
        systemd.verify_alive(COMPOSER)
        wait_for_port(COMPOSER_PORT)

    def _start_and_validate_composer(self):
        # Used in the service template
        config[COMPOSER][SERVICE_USER] = COMPOSER_USER
        config[COMPOSER][SERVICE_GROUP] = COMPOSER_GROUP
        systemd.configure(COMPOSER,
                          user=COMPOSER_USER, group=COMPOSER_GROUP)

        logger.info('Starting Composer service...')
        systemd.restart(COMPOSER)
        self._verify_composer_alive()

    def _run_db_migrate(self):
        npm_path = join(NODEJS_DIR, 'bin', 'npm')
        common.run(
            [
                'sudo', '-u', COMPOSER_USER, 'bash', '-c',
                'cd {path}; {npm} run db-migrate'.format(
                    path=HOME_DIR,
                    npm=npm_path,
                ),
            ],
        )

    def _create_user_and_set_permissions(self):
        create_service_user(COMPOSER_USER, COMPOSER_GROUP, HOME_DIR)
        # adding cfyuser to the composer group so that its files are r/w for
        # replication and snapshots
        common.sudo(['usermod', '-aG', COMPOSER_GROUP, CLOUDIFY_USER])

        logger.debug('Fixing permissions...')
        common.chown(COMPOSER_USER, COMPOSER_GROUP, HOME_DIR)
        common.chown(COMPOSER_USER, COMPOSER_GROUP, LOG_DIR)

        common.chmod('g+w', CONF_DIR)
        common.chmod('g+w', dirname(CONF_DIR))

    def _update_composer_config(self):
        config_path = os.path.join(CONF_DIR, 'prod.json')
        with open(config_path) as f:
            composer_config = json.load(f)

        if config[SSL_INPUTS]['internal_manager_host']:
            composer_config['managerConfig']['ip'] = \
                config[SSL_INPUTS]['internal_manager_host']

        host_details = config[POSTGRESQL_CLIENT]['host'].split(':')
        database_host = host_details[0]
        database_port = host_details[1] if 1 < len(host_details) else '5432'

        composer_config['db']['postgres'] = \
            'postgres://{0}:{1}@{2}:{3}/composer'.format(
                config[POSTGRESQL_CLIENT]['username'],
                config[POSTGRESQL_CLIENT]['password'],
                database_host,
                database_port)

        content = json.dumps(composer_config, indent=4, sort_keys=True)
        # Using `write_to_file` because the path belongs to the composer
        # user, so we need to move with sudo
        files.write_to_file(contents=content, destination=config_path)
        common.chown(COMPOSER_USER, COMPOSER_GROUP, config_path)
        common.chmod('640', config_path)

    def _add_snapshot_sudo_command(self):
        sudoers.allow_user_to_sudo_command(
            full_command='/opt/nodejs/bin/npm',
            description='Allow snapshots to restore composer',
            allow_as=COMPOSER_USER,
        )

    def _configure(self):
        files.copy_notice(COMPOSER)
        set_logrotate(COMPOSER)
        self._create_user_and_set_permissions()
        self._update_composer_config()
        self._run_db_migrate()
        self._start_and_validate_composer()

    def install(self):
        logger.notice('Installing Cloudify Composer...')
        self._install()
        if config[COMPOSER]['skip_installation']:
            return
        self._configure()
        logger.notice('Cloudify Composer successfully installed')

    def configure(self):
        logger.notice('Configuring Cloudify Composer...')
        self._configure()
        logger.notice('Cloudify Composer successfully configured')

    def remove(self):
        logger.notice('Removing Cloudify Composer...')
        files.remove_notice(COMPOSER)
        remove_logrotate(COMPOSER)
        systemd.remove(COMPOSER)
        files.remove_files([HOME_DIR, NODEJS_DIR, LOG_DIR])
        logger.notice('Cloudify Composer successfully removed')

    def start(self):
        logger.notice('Starting Cloudify Composer...')
        systemd.start(COMPOSER)
        self._verify_composer_alive()
        logger.notice('Cloudify Composer successfully started')

    def stop(self):
        logger.notice('Stopping Cloudify Composer...')
        systemd.stop(COMPOSER)
        logger.notice('Cloudify Composer successfully stopped')
