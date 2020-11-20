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
    SSL_INPUTS,
    SSL_ENABLED,
    SSL_CLIENT_VERIFICATION,
    CLUSTER_JOIN
)
from ..base_component import BaseComponent
from ..service_names import COMPOSER, POSTGRESQL_CLIENT
from ...config import config
from ...logger import get_logger
from ...utils import (
    common,
    files,
    certificates,
    service
)
from cfy_manager.utils.db import get_ui_db_dialect_options_and_url
from ...utils.network import wait_for_port
from ...constants import (
    CLOUDIFY_USER,
    NEW_POSTGRESQL_CA_CERT_FILE_PATH,
    NEW_POSTGRESQL_CLIENT_CERT_FILE_PATH,
)

logger = get_logger(COMPOSER)

COMPOSER_USER = '{0}_user'.format(COMPOSER)
COMPOSER_GROUP = '{0}_group'.format(COMPOSER)

HOME_DIR = join('/opt', 'cloudify-{0}'.format(COMPOSER))
CONF_DIR = join(HOME_DIR, 'backend', 'conf')

# These are all the same key as the other db keys, but postgres is very strict
# about permissions (no group or other permissions allowed)
DB_CLIENT_KEY_PATH = '/etc/cloudify/ssl/composer_db.key'
DB_CLIENT_CERT_PATH = '/etc/cloudify/ssl/composer_db.crt'
DB_CA_PATH = join(CONF_DIR, 'db_ca.crt')


class Composer(BaseComponent):
    def _run_db_migrate(self):
        if config.get(CLUSTER_JOIN):
            logger.debug('Joining cluster - not creating the composer db')
            return
        backend_dir = join(HOME_DIR, 'backend')
        npm_path = join('/usr', 'bin', 'npm')
        common.run(
            [
                'sudo', '-u', COMPOSER_USER, 'bash', '-c',
                'cd {path}; {npm} run db-migrate'.format(
                    path=backend_dir,
                    npm=npm_path,
                ),
            ],
        )

    def _handle_ca_certificate(self):
        certificates.use_supplied_certificates(
            component_name=POSTGRESQL_CLIENT,
            logger=logger,
            ca_destination=DB_CA_PATH,
            owner=COMPOSER_USER,
            group=COMPOSER_GROUP,
            update_config=False
        )

    def _handle_cert_and_key(self):
        certificates.use_supplied_certificates(
            component_name=SSL_INPUTS,
            prefix='postgresql_client_',
            logger=logger,
            cert_destination=DB_CLIENT_CERT_PATH,
            key_destination=DB_CLIENT_KEY_PATH,
            owner=COMPOSER_USER,
            group=COMPOSER_GROUP,
            key_perms='400',
            update_config=False,
        )

    def replace_certificates(self):
        # The certificates are validated in the PostgresqlClient component
        replacing_ca = os.path.exists(NEW_POSTGRESQL_CA_CERT_FILE_PATH)
        replacing_cert_and_key = os.path.exists(
            NEW_POSTGRESQL_CLIENT_CERT_FILE_PATH)

        if config[POSTGRESQL_CLIENT][SSL_ENABLED]:
            if replacing_ca:
                self.log_replacing_certs('CA cert')
                self._handle_ca_certificate()
            if (config[POSTGRESQL_CLIENT][SSL_CLIENT_VERIFICATION] and
                    replacing_cert_and_key):
                self.log_replacing_certs('cert and key')
                self._handle_cert_and_key()

            service.restart(COMPOSER)
            self._verify_composer_alive()

    def log_replacing_certs(self, certs_type):
        logger.info('Replacing %s on composer component', certs_type)

    def update_composer_config(self):
        config_path = os.path.join(CONF_DIR, 'prod.json')
        # We need to use sudo to read this or we break on configure
        composer_config = json.loads(files.sudo_read(config_path))

        if config[SSL_INPUTS]['internal_manager_host']:
            composer_config['managerConfig']['ip'] = \
                config[SSL_INPUTS]['internal_manager_host']

        certs = {
            'cert': DB_CLIENT_CERT_PATH,
            'key': DB_CLIENT_KEY_PATH,
            'ca': DB_CA_PATH,
        }

        dialect_options, url = get_ui_db_dialect_options_and_url('composer',
                                                                 certs)
        composer_config['db']['url'] = url
        composer_config['db']['options']['dialectOptions'] = dialect_options

        if config[POSTGRESQL_CLIENT][SSL_ENABLED]:
            self._handle_ca_certificate()
        if config[POSTGRESQL_CLIENT][SSL_CLIENT_VERIFICATION]:
            self._handle_cert_and_key()

        content = json.dumps(composer_config, indent=4, sort_keys=True)
        # Using `write_to_file` because the path belongs to the composer
        # user, so we need to move with sudo
        files.write_to_file(contents=content, destination=config_path)
        common.chown(COMPOSER_USER, COMPOSER_GROUP, config_path)
        common.chmod('640', config_path)

    def _verify_composer_alive(self):
        service.verify_alive(COMPOSER)
        wait_for_port(3000)

    def _chown_for_syncthing(self):
        logger.info('Applying permissions changes for syncthing')
        common.chown(CLOUDIFY_USER, COMPOSER_GROUP, CONF_DIR)
        for excluded_file in ['db_ca.crt', 'prod.json']:
            excluded_file = os.path.join(
                CONF_DIR, excluded_file,
            )
            if files.is_file(excluded_file):
                common.chown(COMPOSER_USER, COMPOSER_GROUP, excluded_file)

    def configure(self):
        logger.notice('Configuring Cloudify Composer...')
        self.update_composer_config()
        external_configure_params = {}
        if service._get_service_type() == 'supervisord':
            external_configure_params['service_user'] = COMPOSER_USER
            external_configure_params['service_group'] = COMPOSER_GROUP
        service.configure(
            COMPOSER,
            user=COMPOSER_USER,
            group=COMPOSER_GROUP,
            external_configure_params=external_configure_params
        )
        self._chown_for_syncthing()
        self._run_db_migrate()
        logger.notice('Cloudify Composer successfully configured')
        self.start()

    def remove(self):
        logger.notice('Removing Cloudify Composer...')
        service.remove(COMPOSER, service_file=False)
        logger.notice('Removing Composer data....')
        common.sudo(['rm', '-rf', '/opt/cloudify-composer'])
        logger.notice('Cloudify Composer successfully removed')

    def start(self):
        logger.notice('Starting Cloudify Composer...')
        service.restart(COMPOSER)
        self._verify_composer_alive()
        logger.notice('Cloudify Composer successfully started')

    def stop(self):
        logger.notice('Stopping Cloudify Composer...')
        service.stop(COMPOSER)
        logger.notice('Cloudify Composer successfully stopped')
