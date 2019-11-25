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

from cfy_manager.components import sources
from ..components_constants import (
    SSL_INPUTS,
    SSL_ENABLED,
    SSL_CLIENT_VERIFICATION,
    PREMIUM_EDITION,
    CLUSTER_JOIN
)
from ..base_component import BaseComponent
from ..service_names import (
    MANAGER,
    POSTGRESQL_CLIENT,
    STAGE,
)
from ...config import config
from ...logger import get_logger
from ...exceptions import FileError
from ...constants import (
    BASE_LOG_DIR,
    BASE_RESOURCES_PATH
)
from ...utils import (
    certificates,
    common,
    files,
    service,
)
from ...utils.network import wait_for_port
from ...utils.logrotate import set_logrotate, remove_logrotate


logger = get_logger(STAGE)

STAGE_USER = '{0}_user'.format(STAGE)
STAGE_GROUP = '{0}_group'.format(STAGE)

HOME_DIR = join('/opt', 'cloudify-{0}'.format(STAGE))
CONF_DIR = join(HOME_DIR, 'conf')
NODEJS_DIR = join('/opt', 'nodejs')
LOG_DIR = join(BASE_LOG_DIR, STAGE)
STAGE_RESOURCES = join(BASE_RESOURCES_PATH, STAGE)

# These are all the same key as the other db keys, but postgres is very strict
# about permissions (no group or other permissions allowed)
DB_CLIENT_KEY_PATH = '/etc/cloudify/ssl/stage_db.key'
DB_CLIENT_CERT_PATH = '/etc/cloudify/ssl/stage_db.crt'
DB_CA_PATH = join(CONF_DIR, 'db_ca.crt')

NODE_EXECUTABLE_PATH = '/usr/bin/node'


class Stage(BaseComponent):
    def __init__(self, skip_installation):
        super(Stage, self).__init__(skip_installation)

    def _create_paths(self):
        common.mkdir(NODEJS_DIR)
        common.mkdir(HOME_DIR)
        common.mkdir(LOG_DIR)

    def _set_community_mode(self):
        premium_edition = config[MANAGER][PREMIUM_EDITION]
        community_mode = '' if premium_edition else '-mode community'

        # This is used in the stage systemd service file
        config[STAGE]['community_mode'] = community_mode

    def _install(self):
        try:
            stage_tar = files.get_local_source_path(sources.stage)
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

        files.copy_notice(STAGE)
        set_logrotate(STAGE)
        self._install_nodejs()

    def _install_nodejs(self):
        logger.info('Installing NodeJS...')
        nodejs = files.get_local_source_path(sources.nodejs)
        common.untar(nodejs, NODEJS_DIR)

    def _run_db_migrate(self):
        if config.get(CLUSTER_JOIN):
            logger.debug('Joining cluster - not creating the stage db')
            return
        backend_dir = join(HOME_DIR, 'backend')
        npm_path = join(NODEJS_DIR, 'bin', 'npm')
        common.run(
            [
                'bash', '-c',
                'cd {path}; {npm} run db-migrate'.format(
                    path=backend_dir,
                    npm=npm_path,
                ),
            ],
        )

    def _set_db_url(self):
        config_path = os.path.join(HOME_DIR, 'conf', 'app.json')
        # We need to use sudo to read this or we break on configure
        stage_config = json.loads(files.sudo_read(config_path))

        host_details = config[POSTGRESQL_CLIENT]['host'].split(':')
        database_host = host_details[0]
        database_port = host_details[1] if 1 < len(host_details) else '5432'

        stage_config['db']['url'] = \
            'postgres://{0}:{1}@{2}:{3}/stage'.format(
                config[POSTGRESQL_CLIENT]['cloudify_username'],
                config[POSTGRESQL_CLIENT]['cloudify_password'],
                database_host,
                database_port)

        # For node-postgres
        dialect_options = stage_config['db']['options']['dialectOptions']
        # For building URL string
        params = {}

        if config[POSTGRESQL_CLIENT][SSL_ENABLED]:
            certificates.use_supplied_certificates(
                component_name=POSTGRESQL_CLIENT,
                logger=self.logger,
                ca_destination=DB_CA_PATH,
                owner=STAGE_USER,
                group=STAGE_GROUP,
                update_config=False,
            )

            params.update({
                'sslmode': 'verify-full',
                'sslrootcert': DB_CA_PATH,
            })

            dialect_options['ssl'] = {
                'ca': DB_CA_PATH,
                'rejectUnauthorized': True,
            }

            if config[POSTGRESQL_CLIENT][SSL_CLIENT_VERIFICATION]:
                certificates.use_supplied_certificates(
                    component_name=SSL_INPUTS,
                    prefix='postgresql_client_',
                    logger=self.logger,
                    cert_destination=DB_CLIENT_CERT_PATH,
                    key_destination=DB_CLIENT_KEY_PATH,
                    owner=STAGE_USER,
                    group=STAGE_GROUP,
                    key_perms='400',
                    update_config=False,
                )

                params.update({
                    'sslcert': DB_CLIENT_CERT_PATH,
                    'sslkey': DB_CLIENT_KEY_PATH,
                })

                dialect_options['ssl']['key'] = DB_CLIENT_KEY_PATH
                dialect_options['ssl']['cert'] = DB_CLIENT_CERT_PATH
        else:
            dialect_options = {
                'ssl': False
            }

        if any(params.values()):
            query = '&'.join('{0}={1}'.format(key, value)
                             for key, value in params.items()
                             if value)
            stage_config['db']['url'] = '{0}?{1}'.format(
                stage_config['db']['url'], query)

        content = json.dumps(stage_config, indent=4, sort_keys=True)

        # Using `write_to_file` because the path belongs to the stage user, so
        # we need to move with sudo
        files.write_to_file(contents=content, destination=config_path)
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
            common.chmod('640', config_path)

    def _verify_stage_alive(self):
        service.verify_alive(STAGE)
        wait_for_port(8088)

    def _configure(self):
        self._set_db_url()
        self._set_internal_manager_ip()
        self._set_community_mode()
        # Used in the service template
        service.configure(STAGE)

    def install(self):
        if config[STAGE]['skip_installation']:
            logger.info('Skipping Stage installation.')
            return
        logger.notice('Installing Stage...')
        self._install()
        logger.notice('Stage successfully installed!')

    def configure(self):
        logger.notice('Configuring Stage...')
        self._configure()
        logger.notice('Stage successfully configured!')

    def remove(self):
        logger.notice('Removing Stage...')
        files.remove_notice(STAGE)
        remove_logrotate(STAGE)
        service.remove(STAGE)
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
        self._run_db_migrate()
        service.start(STAGE)
        self._verify_stage_alive()
        logger.notice('Stage successfully started')

    def stop(self):
        logger.notice('Stopping Stage...')
        service.stop(STAGE)
        logger.notice('Stage successfully stopped')
