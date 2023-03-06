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
from ...service_names import COMPOSER, MANAGER, POSTGRESQL_CLIENT
from ...config import config
from ...logger import get_logger
from ...utils import (
    common,
    files,
    certificates,
    service,
    syslog,
)
from cfy_manager.utils.db import get_ui_db_dialect_options_and_url
from ...utils.network import wait_for_port, ipv6_url_compat
from ...constants import (
    CLOUDIFY_USER,
    NEW_POSTGRESQL_CA_CERT_FILE_PATH,
    NEW_POSTGRESQL_CA_KEY_FILE_PATH,
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
DB_CA_KEY_PATH = join(CONF_DIR, 'db_ca.key')


class Composer(BaseComponent):
    services = {'cloudify-composer': {'is_group': False}}

    def _run_db_migrate(self):
        if config.get(CLUSTER_JOIN):
            logger.debug('Joining cluster - not creating the composer db')
            return
        backend_dir = join(HOME_DIR, 'backend')
        common.run(
            [
                '/usr/bin/sudo', '-u', COMPOSER_USER, '/usr/bin/bash', '-c',
                # PATH can be empty, but npm internally requires /usr/bin
                'cd {path}; PATH=/usr/bin npm run db-migrate'
                .format(path=backend_dir),
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

    def _handle_ca_key_certificate(self):
        certificates.use_supplied_certificates(
            component_name=POSTGRESQL_CLIENT,
            logger=logger,
            ca_destination=DB_CA_KEY_PATH,
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

            self.stop()
            self.start()

    def log_replacing_certs(self, certs_type):
        logger.info('Replacing %s on composer component', certs_type)

    def update_composer_config(self):
        config_path = os.path.join(CONF_DIR, 'prod.json')
        composer_config = json.loads(files.read(config_path))

        composer_config['managerConfig']['ip'] = \
            ipv6_url_compat(config[MANAGER][PRIVATE_IP])
        composer_config['managerConfig']['port'] = \
            config[MANAGER]['internal_rest_port']
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
        files.write(contents=content, destination=config_path,
                    owner=COMPOSER_USER, group=COMPOSER_GROUP, mode=0o640)

    def verify_started(self):
        wait_for_port(3000)

    def _chown_for_syncthing(self):
        if not common.filesystem_replication_enabled():
            logger.debug('FS replication disabled - skip composer chown')
            return
        logger.info('Applying permissions changes for syncthing')
        common.chown(CLOUDIFY_USER, COMPOSER_GROUP, CONF_DIR)
        for excluded_file in ['db_ca.crt', 'prod.json']:
            excluded_file = os.path.join(
                CONF_DIR, excluded_file,
            )
            if isfile(excluded_file):
                common.chown(COMPOSER_USER, COMPOSER_GROUP, excluded_file)

    def configure(self):
        logger.notice('Configuring Cloudify Composer...')
        syslog.deploy_rsyslog_filters('composer', ['cloudify-composer'],
                                      logger)
        self.update_composer_config()
        external_configure_params = {
            'service_user': COMPOSER_USER,
            'service_group': COMPOSER_GROUP,
        }
        service.configure(
            'cloudify-composer',
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
        service.remove('cloudify-composer')
        logger.notice('Removing Composer data....')
        files.remove('/opt/cloudify-composer')
        logger.notice('Cloudify Composer successfully removed')

    def upgrade(self):
        logger.notice('Upgrading Cloudify Composer...')
        self._run_db_migrate()
        logger.notice('Cloudify Composer successfully upgraded')
