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
    CLUSTER_JOIN,
    PRIVATE_IP,
    SSL_CLIENT_VERIFICATION,
    SSL_ENABLED,
    SSL_INPUTS,
)
from ..base_component import BaseComponent
from ..service_names import (
    MANAGER,
    POSTGRESQL_CLIENT,
    STAGE,
)
from ...config import config
from ...logger import get_logger
from ...utils import (
    certificates,
    common,
    files,
    service
)
from cfy_manager.utils.db import get_ui_db_dialect_options_and_url
from ...utils.network import wait_for_port
from ...utils.install import is_premium_installed
from ...constants import (
    CLOUDIFY_USER,
    NEW_POSTGRESQL_CA_CERT_FILE_PATH,
    NEW_POSTGRESQL_CLIENT_CERT_FILE_PATH,
)

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
    services = ['cloudify-stage']

    def _set_community_mode(self):
        community_mode = '' if is_premium_installed else '-mode community'

        # This is used in the stage systemd service file
        config[STAGE]['community_mode'] = community_mode

    def _run_db_migrate(self):
        if config.get(CLUSTER_JOIN):
            logger.debug('Joining cluster - not creating the stage db')
            return
        backend_dir = join(HOME_DIR, 'backend')
        npm_path = join('/usr', 'bin', 'npm')
        common.run(
            [
                'sudo', '-u', STAGE_USER, 'bash', '-c',
                'cd {path}; {npm} run db-migrate'.format(
                    path=backend_dir,
                    npm=npm_path,
                ),
            ],
        )

    @staticmethod
    def _handle_ca_certificate():
        certificates.use_supplied_certificates(
            component_name=POSTGRESQL_CLIENT,
            logger=logger,
            ca_destination=DB_CA_PATH,
            owner=STAGE_USER,
            group=STAGE_GROUP,
            update_config=False,
        )

    @staticmethod
    def _handle_cert_and_key():
        certificates.use_supplied_certificates(
            component_name=SSL_INPUTS,
            prefix='postgresql_client_',
            logger=logger,
            cert_destination=DB_CLIENT_CERT_PATH,
            key_destination=DB_CLIENT_KEY_PATH,
            owner=STAGE_USER,
            group=STAGE_GROUP,
            # Group access is required for snapshots
            key_perms='440',
            update_config=False,
        )

    def replace_certificates(self):
        # The certificates are validated in the PostgresqlClient component
        replacing_ca = os.path.exists(NEW_POSTGRESQL_CA_CERT_FILE_PATH)
        replacing_cert_and_key = os.path.exists(
            NEW_POSTGRESQL_CLIENT_CERT_FILE_PATH)

        if config[POSTGRESQL_CLIENT][SSL_ENABLED]:
            self.stop()
            if replacing_ca:
                self.log_replacing_certs('CA cert')
                self._handle_ca_certificate()

            if (config[POSTGRESQL_CLIENT][SSL_CLIENT_VERIFICATION] and
                    replacing_cert_and_key):
                self.log_replacing_certs('cert and key')
                self._handle_cert_and_key()
            self.start()

    @staticmethod
    def log_replacing_certs(certs_type):
        logger.info(
            'Replacing {0} on stage component'.format(certs_type))

    def set_db_url(self):
        config_path = os.path.join(HOME_DIR, 'conf', 'app.json')
        # We need to use sudo to read this or we break on configure
        stage_config = json.loads(files.sudo_read(config_path))

        certs = {
            'cert': DB_CLIENT_CERT_PATH,
            'key': DB_CLIENT_KEY_PATH,
            'ca': DB_CA_PATH,
        }

        dialect_options, url = get_ui_db_dialect_options_and_url('stage',
                                                                 certs)
        stage_config['db']['url'] = url
        stage_config['db']['options']['dialectOptions'] = dialect_options

        if config[POSTGRESQL_CLIENT][SSL_ENABLED]:
            self._handle_ca_certificate()
        if config[POSTGRESQL_CLIENT][SSL_CLIENT_VERIFICATION]:
            self._handle_cert_and_key()

        content = json.dumps(stage_config, indent=4, sort_keys=True)

        # Using `write_to_file` because the path belongs to the stage user, so
        # we need to move with sudo
        files.write_to_file(contents=content, destination=config_path)
        common.chown(STAGE_USER, STAGE_GROUP, config_path)
        common.chmod('640', config_path)

    def _set_internal_manager_ip(self):
        config_path = os.path.join(HOME_DIR, 'conf', 'manager.json')
        # We need to use sudo to read this or we break on configure
        stage_config = json.loads(files.sudo_read(config_path))

        stage_config['ip'] = config[MANAGER][PRIVATE_IP]
        content = json.dumps(stage_config, indent=4, sort_keys=True)
        # Using `write_to_file` because the path belongs to the stage user,
        # so we need to move with sudo
        files.write_to_file(contents=content, destination=config_path)
        common.chown(STAGE_USER, STAGE_GROUP, config_path)
        common.chmod('640', config_path)

    def verify_started(self):
        wait_for_port(8088)

    def _chown_for_syncthing(self):
        logger.info('Applying permissions changes for syncthing')
        config_path = os.path.join(HOME_DIR, 'conf')
        common.chown(CLOUDIFY_USER, STAGE_GROUP, config_path)
        for excluded_file in ['db_ca.crt', 'manager.json']:
            excluded_file = os.path.join(
                config_path, excluded_file,
            )
            if files.is_file(excluded_file):
                common.chown(STAGE_USER, STAGE_GROUP, excluded_file)

    def configure(self):
        logger.notice('Configuring Stage...')
        self.set_db_url()
        self._set_internal_manager_ip()
        self._set_community_mode()
        external_configure_params = {}
        if self.service_type == 'supervisord':
            external_configure_params['service_user'] = STAGE_USER
            external_configure_params['service_group'] = STAGE_GROUP
        service.configure(
            'cloudify-stage',
            user=STAGE_USER,
            group=STAGE_GROUP,
            external_configure_params=external_configure_params
        )
        self._chown_for_syncthing()
        self._run_db_migrate()
        logger.notice('Stage successfully configured!')
        self.start()

    def remove(self):
        logger.notice('Removing Stage...')
        service.remove('cloudify-stage', service_file=False)
        logger.notice('Removing Stage data....')
        common.sudo(['rm', '-rf', '/opt/cloudify-stage'])
        logger.notice('Stage successfully removed')

    def upgrade(self):
        logger.notice('Upgrading Cloudify Stage...')
        self._run_db_migrate()
        logger.notice('Cloudify Stage successfully upgraded')
