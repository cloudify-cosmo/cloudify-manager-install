import os

from ...components_constants import (
    SERVICES_TO_INSTALL,
    SSL_CLIENT_VERIFICATION,
    SSL_ENABLED,
    SSL_INPUTS,
)
from ..base_component import BaseComponent
from ...service_names import (
    MANAGER_SERVICE,
    POSTGRESQL_CLIENT,
    POSTGRESQL_SERVER,
)
from ...constants import (
    POSTGRESQL_CLIENT_CERT_PATH,
    POSTGRESQL_CLIENT_KEY_PATH,
    POSTGRESQL_CLIENT_SU_CERT_PATH,
    POSTGRESQL_CLIENT_SU_KEY_PATH,
    POSTGRESQL_CA_CERT_PATH,
    POSTGRESQL_CA_KEY_PATH,
    CLOUDIFY_HOME_DIR,
    CLOUDIFY_USER,
    CLOUDIFY_GROUP,
    NEW_POSTGRESQL_CA_CERT_FILE_PATH,
    NEW_POSTGRESQL_CA_KEY_FILE_PATH,
    NEW_POSTGRESQL_CLIENT_CERT_FILE_PATH,
    NEW_POSTGRESQL_CLIENT_KEY_FILE_PATH
)
from ...config import config
from ...logger import get_logger
from ...utils import (
    certificates,
    files,
)

CLOUDIFY_PGPASS_PATH = os.path.join(CLOUDIFY_HOME_DIR, '.pgpass')

PG_PORT = 5432

logger = get_logger(POSTGRESQL_CLIENT)


class PostgresqlClient(BaseComponent):
    def _create_pgpass(self, hosts, port, db_name, user, password, pgpass_path,
                       owning_user, owning_group):
        logger.debug('Creating postgresql pgpass file: {0}'
                     .format(pgpass_path))
        line_template = '{host}:{port}:{db_name}:{user}:{password}\n'

        pgpass_content = ''
        for host in hosts:
            pgpass_content += line_template.format(
                host=host,
                port=port,
                db_name=db_name,
                user=user,
                password=password
            )
        files.write(pgpass_content, pgpass_path,
                    owner=owning_user, group=owning_group, mode=0o400)

        logger.debug('Postgresql pass file {0} created'.format(pgpass_path))

    def create_postgres_pgpass_files(self, hosts=None):
        if MANAGER_SERVICE not in config[SERVICES_TO_INSTALL]:
            logger.info('Skipping pgpass creation on non-manager node.')
            return
        pg_config = config[POSTGRESQL_CLIENT]
        if not hosts:
            cluster_nodes = config[POSTGRESQL_SERVER]['cluster']['nodes']
            if cluster_nodes:
                hosts = [node['ip'] for node in cluster_nodes.values()]
            else:
                hosts = [pg_config['host']]
        port = PG_PORT

        # Creating Cloudify .pgpass file
        db_name = '*'  # Allowing for the multiple DBs we have
        user = pg_config['cloudify_username']
        password = pg_config['cloudify_password']
        self._create_pgpass(
            hosts=hosts,
            port=port,
            db_name=db_name,
            user=user,
            password=password,
            pgpass_path=CLOUDIFY_PGPASS_PATH,
            owning_user=CLOUDIFY_USER,
            owning_group=CLOUDIFY_GROUP
        )

    def _configure_ssl(self):
        if config[POSTGRESQL_CLIENT][SSL_ENABLED]:
            self._handle_ca_certificate()

            if config[POSTGRESQL_CLIENT][SSL_CLIENT_VERIFICATION]:
                self._handle_cert_and_key()

    @staticmethod
    def _handle_ca_certificate():
        certificates.use_supplied_certificates(
            logger=logger,
            ca_destination=POSTGRESQL_CA_CERT_PATH,
            component_name=POSTGRESQL_CLIENT
        )

    @staticmethod
    def _handle_ca_key_certificate():
        certificates.use_supplied_certificates(
            logger=logger,
            ca_destination=POSTGRESQL_CA_KEY_PATH,
            component_name=POSTGRESQL_CLIENT
        )

    @staticmethod
    def _handle_cert_and_key():
        certificates.use_supplied_certificates(
            logger=logger,
            cert_destination=POSTGRESQL_CLIENT_CERT_PATH,
            key_destination=POSTGRESQL_CLIENT_KEY_PATH,
            key_perms='400',
            component_name=SSL_INPUTS,
            prefix='postgresql_client_'
        )
        certificates.use_supplied_certificates(
            logger=logger,
            cert_destination=POSTGRESQL_CLIENT_SU_CERT_PATH,
            key_destination=POSTGRESQL_CLIENT_SU_KEY_PATH,
            key_perms='400',
            component_name=SSL_INPUTS,
            prefix='postgresql_superuser_client_'
        )

    def replace_certificates(self):
        replacing_ca = os.path.exists(NEW_POSTGRESQL_CA_CERT_FILE_PATH)
        replacing_ca_key = os.path.exists(NEW_POSTGRESQL_CA_KEY_FILE_PATH)
        replacing_cert_and_key = os.path.exists(
            NEW_POSTGRESQL_CLIENT_CERT_FILE_PATH)
        if config[POSTGRESQL_CLIENT][SSL_ENABLED]:
            self.validate_new_certs()
            if replacing_ca:
                logger.info(
                    'Replacing CA cert on postgresql_client component')
                config[POSTGRESQL_CLIENT]['ca_path'] = \
                    NEW_POSTGRESQL_CA_CERT_FILE_PATH
                self._handle_ca_certificate()
            if replacing_ca_key:
                logger.info(
                    'Replacing CA key on postgresql_client component')
                config[POSTGRESQL_CLIENT]['ca_key_path'] = \
                    NEW_POSTGRESQL_CA_KEY_FILE_PATH
                self._handle_ca_key_certificate()
            if (config[POSTGRESQL_CLIENT][SSL_CLIENT_VERIFICATION] and
                    replacing_cert_and_key):
                logger.info(
                    'Replacing cert and key on postgresql_client component')
                config[SSL_INPUTS]['postgresql_client_cert_path'] = \
                    NEW_POSTGRESQL_CLIENT_CERT_FILE_PATH
                config[SSL_INPUTS]['postgresql_client_key_path'] = \
                    NEW_POSTGRESQL_CLIENT_KEY_FILE_PATH
                self._handle_cert_and_key()

    def validate_new_certs(self):
        if config[POSTGRESQL_CLIENT][SSL_ENABLED]:
            cert_filename, key_filename = None, None
            if config[POSTGRESQL_CLIENT][SSL_CLIENT_VERIFICATION]:
                cert_filename, key_filename = \
                    certificates.get_cert_and_key_filenames(
                        NEW_POSTGRESQL_CLIENT_CERT_FILE_PATH,
                        NEW_POSTGRESQL_CLIENT_KEY_FILE_PATH,
                        POSTGRESQL_CLIENT_CERT_PATH,
                        POSTGRESQL_CLIENT_KEY_PATH)
                # We don't handle superuser certs as they're only used at
                # install time.

            ca_filename = certificates.get_ca_filename(
                NEW_POSTGRESQL_CA_CERT_FILE_PATH,
                POSTGRESQL_CA_CERT_PATH)
            ca_key_filename = certificates.get_ca_filename(
                NEW_POSTGRESQL_CA_KEY_FILE_PATH,
                POSTGRESQL_CA_KEY_PATH)

            certificates.validate_certificates(
                cert_filename, key_filename, ca_filename, ca_key_filename)

    def configure(self):
        logger.notice('Configuring PostgreSQL Client...')
        self.create_postgres_pgpass_files()
        self._configure_ssl()
        logger.notice('PostgreSQL successfully configured')
        self.start()

    def remove(self):
        files.remove_notice(POSTGRESQL_CLIENT)
