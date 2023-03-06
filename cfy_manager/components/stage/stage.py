import os
import json
from os.path import join, isfile

from ...components_constants import (
    CLUSTER_JOIN,
    PRIVATE_IP,
    SSL_CLIENT_VERIFICATION,
    SSL_ENABLED,
    SSL_INPUTS,
)
from ..base_component import BaseComponent
from ...service_names import (
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
from cfy_manager.utils.scripts import run_snapshot_script
from ...utils.network import wait_for_port, ipv6_url_compat
from ...utils.install import is_premium_installed
from ...constants import (
    CLOUDIFY_USER,
    NEW_POSTGRESQL_CA_CERT_FILE_PATH,
    NEW_POSTGRESQL_CA_KEY_FILE_PATH,
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
DB_CA_KEY_PATH = join(CONF_DIR, 'db_ca.key')


class Stage(BaseComponent):
    services = {'cloudify-stage': {'is_group': False}}

    def _run_db_migrate(self):
        if config.get(CLUSTER_JOIN):
            logger.debug('Joining cluster - not creating the stage db')
            return
        backend_dir = join(HOME_DIR, 'backend')
        common.run(
            [
                '/usr/bin/sudo', '-u', STAGE_USER, '/usr/bin/bash', '-c',
                # PATH can be empty, but npm internally requires /usr/bin
                'cd {path}; PATH=/usr/bin npm run db-migrate'
                .format(path=backend_dir),
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
    def _handle_ca_key_certificate():
        certificates.use_supplied_certificates(
            component_name=POSTGRESQL_CLIENT,
            logger=logger,
            ca_key_destination=DB_CA_KEY_PATH,
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
        replacing_ca_key = os.path.exists(NEW_POSTGRESQL_CA_KEY_FILE_PATH)
        replacing_cert_and_key = os.path.exists(
            NEW_POSTGRESQL_CLIENT_CERT_FILE_PATH)

        if config[POSTGRESQL_CLIENT][SSL_ENABLED]:
            self.stop()
            self.stop()
            if replacing_ca:
                self.log_replacing_certs('CA cert')
                self._handle_ca_certificate()
            if replacing_ca_key:
                self.log_replacing_certs('CA key')
                self._handle_ca_key_certificate()

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
        stage_config = json.loads(files.read(config_path))

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

        files.write(contents=content, destination=config_path,
                    owner=STAGE_USER, group=STAGE_GROUP, mode=0o640)

    def _set_internal_manager_ip(self):
        config_path = os.path.join(HOME_DIR, 'conf', 'manager.json')
        stage_config = json.loads(files.read(config_path))

        stage_config['ip'] = ipv6_url_compat(config[MANAGER][PRIVATE_IP])
        stage_config['port'] = config[MANAGER]['internal_rest_port']
        content = json.dumps(stage_config, indent=4, sort_keys=True)
        files.write(contents=content, destination=config_path,
                    owner=STAGE_USER, group=STAGE_GROUP, mode=0o640)

    def verify_started(self):
        wait_for_port(8088)

    def _chown_for_syncthing(self):
        if not common.filesystem_replication_enabled():
            logger.debug('FS replication disabled - skip stage chown')
            return
        logger.info('Applying permissions changes for syncthing')
        config_path = os.path.join(HOME_DIR, 'conf')
        common.chown(CLOUDIFY_USER, STAGE_GROUP, config_path)
        for excluded_file in ['db_ca.crt', 'manager.json']:
            excluded_file = os.path.join(
                config_path, excluded_file,
            )
            if isfile(excluded_file):
                common.chown(STAGE_USER, STAGE_GROUP, excluded_file)

    def configure(self):
        logger.notice('Configuring Stage...')
        self.set_db_url()
        self._set_internal_manager_ip()
        external_configure_params = {
            'service_user': STAGE_USER,
            'service_group': STAGE_GROUP,
            'community_mode': '' if is_premium_installed else '-mode community'
        }
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
        service.remove('cloudify-stage')
        logger.notice('Removing Stage data....')
        files.remove('/opt/cloudify-stage')
        logger.notice('Stage successfully removed')

    def upgrade(self):
        logger.notice('Upgrading Cloudify Stage...')
        self._run_db_migrate()
        # This script must run after stage DB migration
        run_snapshot_script('copy_icons')
        logger.notice('Cloudify Stage successfully upgraded')
