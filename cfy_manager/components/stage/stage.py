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
from os.path import join

from ..components_constants import (
    SOURCES,
    SERVICE_USER,
    SERVICE_GROUP,
    HOME_DIR_KEY
)
from ..components_constants import (
    SSL_INPUTS,
    SSL_ENABLED
)
from ..base_component import BaseComponent
from ..service_names import STAGE, MANAGER, POSTGRESQL_CLIENT
from ...config import config
from ...logger import get_logger
from ...exceptions import FileError
from ...constants import (
    BASE_LOG_DIR,
    BASE_RESOURCES_PATH,
    CLOUDIFY_GROUP,
    CLOUDIFY_USER,
)
from ...utils import sudoers
from ...utils import common, files
from ...utils.systemd import systemd
from ...utils.network import wait_for_port
from ...utils.users import create_service_user
from ...utils.logrotate import set_logrotate, remove_logrotate


logger = get_logger(STAGE)

STAGE_USER = '{0}_user'.format(STAGE)
STAGE_GROUP = '{0}_group'.format(STAGE)

HOME_DIR = join('/opt', 'cloudify-{0}'.format(STAGE))
NODEJS_DIR = join('/opt', 'nodejs')
LOG_DIR = join(BASE_LOG_DIR, STAGE)
RESOURCES_DIR = join(HOME_DIR, 'resources')
STAGE_RESOURCES = join(BASE_RESOURCES_PATH, STAGE)

NODE_EXECUTABLE_PATH = '/usr/bin/node'


class StageComponent(BaseComponent):
    def __init__(self, skip_installation):
        super(StageComponent, self).__init__(skip_installation)

    def _create_paths(self):
        common.mkdir(NODEJS_DIR)
        common.mkdir(HOME_DIR)
        common.mkdir(LOG_DIR)
        common.mkdir(RESOURCES_DIR)

    def _set_community_mode(self):
        premium_edition = config[MANAGER]['premium_edition']
        community_mode = '' if premium_edition else '-mode community'

        # This is used in the stage systemd service file
        config[STAGE]['community_mode'] = community_mode

    def _install(self):
        stage_source_url = config[STAGE][SOURCES]['stage_source_url']
        try:
            stage_tar = files.get_local_source_path(stage_source_url)
        except FileError:
            logger.info('Stage package not found in manager resources package')
            logger.notice('Stage will not be installed.')
            config[STAGE]['skip_installation'] = True
            return

        self._create_paths()

        logger.info('Extracting Stage package...')
        common.untar(stage_tar, HOME_DIR)

        logger.info('Creating symlink to {0}...'.format(NODE_EXECUTABLE_PATH))
        files.ln(
            source=join(NODEJS_DIR, 'bin', 'node'),
            target=NODE_EXECUTABLE_PATH,
            params='-sf'
        )

    def _create_user_and_set_permissions(self):
        create_service_user(STAGE_USER, STAGE_GROUP, HOME_DIR)

        # For snapshot restore purposes
        common.sudo(['usermod', '-aG', STAGE_GROUP, CLOUDIFY_USER])

        logger.debug('Fixing permissions...')
        common.chown(STAGE_USER, STAGE_GROUP, HOME_DIR)
        common.chown(STAGE_USER, STAGE_GROUP, NODEJS_DIR)
        common.chown(STAGE_USER, STAGE_GROUP, LOG_DIR)

    def _install_nodejs(self):
        logger.info('Installing NodeJS...')
        nodejs_source_url = config[STAGE][SOURCES]['nodejs_source_url']
        nodejs = files.get_local_source_path(nodejs_source_url)
        common.untar(nodejs, NODEJS_DIR)

    def _deploy_script(self, script_name, description, sudo_as=STAGE_USER):
        sudoers.deploy_sudo_command_script(
            script_name,
            description,
            component=STAGE,
            allow_as=sudo_as,
        )
        common.chmod('a+rx', join(STAGE_RESOURCES, script_name))
        common.sudo(['usermod', '-aG', CLOUDIFY_GROUP, STAGE_USER])

    def _deploy_scripts(self):
        config[STAGE][HOME_DIR_KEY] = HOME_DIR
        self._deploy_script(
            'restore-snapshot.py',
            'Restore stage directories from a snapshot path'
        )

    def _run_db_migrate(self):
        backend_dir = join(HOME_DIR, 'backend')
        npm_path = join(NODEJS_DIR, 'bin', 'npm')
        common.run(
            [
                'sudo', '-u', STAGE_USER, 'bash', '-c',
                'cd {path}; {npm} run db-migrate'.format(
                    path=backend_dir,
                    npm=npm_path,
                ),
            ],
        )

    def _set_db_url(self):
        pg_cert_path = 'postgresql_client_cert_path'
        pg_key_path = 'postgresql_client_key_path'
        config_path = os.path.join(HOME_DIR, 'conf', 'app.json')
        # We need to use sudo to read this or we break on configure
        stage_config = json.loads(files.sudo_read(config_path))

        host_details = config[POSTGRESQL_CLIENT]['host'].split(':')
        database_host = host_details[0]
        database_port = host_details[1] if 1 < len(host_details) else '5432'

        stage_config['db']['url'] = \
            'postgres://{0}:{1}@{2}:{3}/stage'.format(
                config[POSTGRESQL_CLIENT]['username'],
                config[POSTGRESQL_CLIENT]['password'],
                database_host,
                database_port)
        if config[POSTGRESQL_CLIENT][SSL_ENABLED]:
            stage_config['db']['url'] += \
                '?sslmode={sslmode}&' \
                'sslcert={sslcert}&' \
                'sslkey={sslkey}&' \
                'sslrootcert={sslrootcert}'.format(
                    sslmode='verify-full',
                    sslcert=config['constants'][pg_cert_path],
                    sslkey=config['constants'][pg_key_path],
                    sslrootcert=config['constants']['ca_cert_path']
                )

        content = json.dumps(stage_config, indent=4, sort_keys=True)

        # Using `write_to_file` because the path belongs to the stage user, so
        # we need to move with sudo
        files.write_to_file(contents=content, destination=config_path)
        common.chown(STAGE_USER, STAGE_GROUP, config_path)
        common.chmod('640', config_path)

    def _set_internal_manager_ip(self):
        config_path = os.path.join(HOME_DIR, 'conf', 'manager.json')
        with open(config_path) as f:
            stage_config = json.load(f)

        if config[SSL_INPUTS]['internal_manager_host']:
            stage_config['ip'] = config[SSL_INPUTS]['internal_manager_host']
            content = json.dumps(stage_config, indent=4, sort_keys=True)
            # Using `write_to_file` because the path belongs to the stage user,
            # so we need to move with sudo
            files.write_to_file(contents=content, destination=config_path)

    def _verify_stage_alive(self):
        systemd.verify_alive(STAGE)
        wait_for_port(8088)

    def _start_and_validate_stage(self):
        self._set_community_mode()
        # Used in the service template
        config[STAGE][SERVICE_USER] = STAGE_USER
        config[STAGE][SERVICE_GROUP] = STAGE_GROUP
        systemd.configure(STAGE,
                          user=STAGE_USER, group=STAGE_GROUP)

        logger.info('Starting Stage service...')
        systemd.restart(STAGE)
        self._verify_stage_alive()

    def _add_snapshot_sudo_command(self):
        sudoers.allow_user_to_sudo_command(
            full_command='/opt/nodejs/bin/node',
            description='Allow snapshots to restore stage',
            allow_as=STAGE_USER,
        )

    def _configure(self):
        files.copy_notice(STAGE)
        set_logrotate(STAGE)
        self._create_user_and_set_permissions()
        self._install_nodejs()
        self._deploy_scripts()
        self._set_db_url()
        self._set_internal_manager_ip()
        self._run_db_migrate()
        self._add_snapshot_sudo_command()
        self._start_and_validate_stage()

    def install(self):
        logger.notice('Installing Stage...')
        self._install()
        if config[STAGE]['skip_installation']:
            return
        self._configure()
        logger.notice('Stage successfully installed')

    def configure(self):
        logger.notice('Configuring Stage...')
        self._configure()
        logger.notice('Stage successfully configured')

    def remove(self):
        logger.notice('Removing Stage...')
        files.remove_notice(STAGE)
        remove_logrotate(STAGE)
        systemd.remove(STAGE)
        files.remove_files([
            HOME_DIR,
            NODEJS_DIR,
            LOG_DIR,
            NODE_EXECUTABLE_PATH,
            STAGE_RESOURCES
        ])
        logger.notice('Stage successfully removed')

    def start(self):
        logger.notice('Starting Stage...')
        systemd.start(STAGE)
        self._verify_stage_alive()
        logger.notice('Stage successfully started')

    def stop(self):
        logger.notice('Stopping Stage...')
        systemd.stop(STAGE)
        logger.notice('Stage successfully stopped')
