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
    SERVICE_USER,
    SERVICE_GROUP,
    SSL_INPUTS,
    SSL_ENABLED,
    SSL_CLIENT_VERIFICATION,
    CLUSTER_JOIN
)
from ..base_component import BaseComponent
from ..service_names import COMPOSER, POSTGRESQL_CLIENT
from ...config import config
from ...logger import get_logger
from ...exceptions import FileError
from ...constants import BASE_LOG_DIR
from ...utils import common, files, certificates, service
from ...utils.network import wait_for_port
from ...utils.logrotate import set_logrotate, remove_logrotate

logger = get_logger(COMPOSER)

HOME_DIR = join('/opt', 'cloudify-{0}'.format(COMPOSER))
CONF_DIR = join(HOME_DIR, 'backend', 'conf')
NODEJS_DIR = join('/opt', 'nodejs')
LOG_DIR = join(BASE_LOG_DIR, COMPOSER)

# These are all the same key as the other db keys, but postgres is very strict
# about permissions (no group or other permissions allowed)
DB_CLIENT_KEY_PATH = '/etc/cloudify/ssl/composer_db.key'
DB_CLIENT_CERT_PATH = '/etc/cloudify/ssl/composer_db.crt'
DB_CA_PATH = join(CONF_DIR, 'db_ca.crt')

COMPOSER_USER = '{0}_user'.format(COMPOSER)
COMPOSER_GROUP = '{0}_group'.format(COMPOSER)
COMPOSER_PORT = 3000


class Composer(BaseComponent):

    def __init__(self, skip_installation):
        super(Composer, self).__init__(skip_installation)

    def _create_paths(self):
        common.mkdir(NODEJS_DIR)
        common.mkdir(HOME_DIR)
        common.mkdir(LOG_DIR)

    def _install(self):
        try:
            composer_tar = files.get_local_source_path(sources.composer)
        except FileError:
            logger.info(
                'Composer package not found in manager resources package')
            logger.notice('Composer will not be installed.')
            config[COMPOSER]['skip_installation'] = True
            self.skip_installation = True
            return

        self._create_paths()

        logger.info('Installing Cloudify Composer...')
        common.untar(composer_tar, HOME_DIR)

        files.copy_notice(COMPOSER)
        set_logrotate(COMPOSER)

    def _verify_composer_alive(self):
        service.verify_alive(COMPOSER)
        wait_for_port(COMPOSER_PORT)

    def _run_db_migrate(self):
        if config.get(CLUSTER_JOIN):
            logger.debug('Joining cluster - not creating the composer db')
            return
        npm_path = join(NODEJS_DIR, 'bin', 'npm')
        common.run(
            [
                'bash', '-c',
                'cd {path}; {npm} run db-migrate'.format(
                    path=HOME_DIR,
                    npm=npm_path,
                ),
            ],
        )

    def _update_composer_config(self):
        config_path = os.path.join(CONF_DIR, 'prod.json')
        # We need to use sudo to read this or we break on configure
        composer_config = json.loads(files.sudo_read(config_path))

        if config[SSL_INPUTS]['internal_manager_host']:
            composer_config['managerConfig']['ip'] = \
                config[SSL_INPUTS]['internal_manager_host']

        host_details = config[POSTGRESQL_CLIENT]['host'].split(':')
        database_host = host_details[0]
        database_port = host_details[1] if 1 < len(host_details) else '5432'

        composer_config['db']['url'] = \
            'postgres://{0}:{1}@{2}:{3}/composer'.format(
                config[POSTGRESQL_CLIENT]['cloudify_username'],
                config[POSTGRESQL_CLIENT]['cloudify_password'],
                database_host,
                database_port)

        # For node-postgres
        dialect_options = composer_config['db']['options']['dialectOptions']
        # For building URL string
        params = {}

        if config[POSTGRESQL_CLIENT][SSL_ENABLED]:
            certificates.use_supplied_certificates(
                component_name=POSTGRESQL_CLIENT,
                logger=self.logger,
                ca_destination=DB_CA_PATH,
                owner=COMPOSER_USER,
                group=COMPOSER_GROUP,
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
                    owner=COMPOSER_USER,
                    group=COMPOSER_GROUP,
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
            composer_config['db']['url'] = '{0}?{1}'.format(
                composer_config['db']['url'], query)

        content = json.dumps(composer_config, indent=4, sort_keys=True)
        # Using `write_to_file` because the path belongs to the composer
        # user, so we need to move with sudo
        files.write_to_file(contents=content, destination=config_path)
        common.chmod('640', config_path)

    def install(self):
        if config[COMPOSER]['skip_installation']:
            logger.notice('Skipping Cloudify Composer installation.')
            return
        logger.notice('Installing Cloudify Composer...')
        self._install()
        logger.notice('Cloudify Composer successfully installed')

    def configure(self):
        logger.notice('Configuring Cloudify Composer...')
        self._update_composer_config()
        config[COMPOSER][SERVICE_USER] = COMPOSER_USER
        config[COMPOSER][SERVICE_GROUP] = COMPOSER_GROUP
        service.configure(COMPOSER,
                          user=COMPOSER_USER, group=COMPOSER_GROUP)
        logger.notice('Cloudify Composer successfully configured')

    def remove(self):
        logger.notice('Removing Cloudify Composer...')
        files.remove_notice(COMPOSER)
        remove_logrotate(COMPOSER)
        service.remove(COMPOSER)
        files.remove_files([HOME_DIR, NODEJS_DIR, LOG_DIR])
        logger.notice('Cloudify Composer successfully removed')

    def start(self):
        logger.notice('Starting Cloudify Composer...')
        self._run_db_migrate()
        service.start(COMPOSER)
        self._verify_composer_alive()
        logger.notice('Cloudify Composer successfully started')

    def stop(self):
        logger.notice('Stopping Cloudify Composer...')
        service.stop(COMPOSER)
        logger.notice('Cloudify Composer successfully stopped')
