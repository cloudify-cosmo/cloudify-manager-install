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
    CLUSTER_JOIN,
)
from ..base_component import BaseComponent
from ..service_names import (
    POSTGRESQL_CLIENT,
    STAGE,
)
from ...config import config
from ...logger import get_logger
from ...exceptions import FileError
from ...utils import (
    certificates,
    common,
    files,
)
from ...utils.systemd import systemd
from ...utils.network import wait_for_port
from ...utils.install import yum_install, yum_remove, is_premium_installed


logger = get_logger(STAGE)

STAGE_USER = '{0}_user'.format(STAGE)
STAGE_GROUP = '{0}_group'.format(STAGE)

HOME_DIR = join('/opt', 'cloudify-{0}'.format(STAGE))
CONF_DIR = join(HOME_DIR, 'conf')

# These are all the same key as the other db keys, but postgres is very strict
# about permissions (no group or other permissions allowed)
DB_CLIENT_KEY_PATH = '/etc/cloudify/ssl/stage_db.key'
DB_CLIENT_CERT_PATH = '/etc/cloudify/ssl/stage_db.crt'
DB_CA_PATH = join(CONF_DIR, 'db_ca.crt')


class Stage(BaseComponent):
    def __init__(self, skip_installation):
        super(Stage, self).__init__(skip_installation)

    def _set_community_mode(self):
        community_mode = '' if is_premium_installed else '-mode community'

        # This is used in the stage systemd service file
        config[STAGE]['community_mode'] = community_mode

    def _install(self):
        try:
            files.get_local_source_path(sources.stage)
        except FileError:
            logger.info('Stage package not found in manager resources package')
            logger.notice('Stage will not be installed.')
            config[STAGE]['skip_installation'] = True
            return

        logger.info('Installing NodeJS package...')
        yum_install(sources.nodejs)
        logger.info('Installing Stage package...')
        yum_install(sources.stage)

    def _run_db_migrate(self):
        if config[CLUSTER_JOIN]:
            logger.debug('Joining cluster - not creating the stage db')
            return
        backend_dir = join(HOME_DIR, 'backend')
        npm_path = join('usr', 'bin', 'npm')
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
            common.chown(STAGE_USER, STAGE_GROUP, config_path)
            common.chmod('640', config_path)

    def _verify_stage_alive(self):
        systemd.verify_alive(STAGE)
        wait_for_port(8088)

    def _start_and_validate_stage(self):
        self._set_community_mode()
        systemd.configure(STAGE,
                          user=STAGE_USER, group=STAGE_GROUP)

        logger.info('Starting Stage service...')
        systemd.restart(STAGE)
        self._verify_stage_alive()

    def _configure(self):
        self._set_db_url()
        self._set_internal_manager_ip()
        self._run_db_migrate()
        self._start_and_validate_stage()

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
        systemd.remove(STAGE, service_file=False)
        yum_remove('cloudify-stage')
        yum_remove('nodejs')
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
