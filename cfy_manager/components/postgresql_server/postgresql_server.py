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
import re
import time
from tempfile import mkstemp
from os.path import join, isdir, islink

from ..components_constants import (
    CONFIG,
    ENABLE_REMOTE_CONNECTIONS,
    POSTGRES_PASSWORD,
    PRIVATE_IP,
    SCRIPTS,
    SERVICES_TO_INSTALL,
    SOURCES,
    SSL_CLIENT_VERIFICATION,
    SSL_ENABLED,
)
from cfy_manager.exceptions import FileError
from ..base_component import BaseComponent
from ..service_components import MANAGER_SERVICE
from ..service_names import (
    POSTGRESQL_SERVER,
    MANAGER
)
from ... import constants
from ...config import config
from ...logger import get_logger
from ...utils import common, files
from ...utils.systemd import systemd
from ...utils.install import yum_install, yum_remove

POSTGRESQL_SCRIPTS_PATH = join(constants.COMPONENTS_DIR, POSTGRESQL_SERVER,
                               SCRIPTS)

SYSTEMD_SERVICE_NAME = 'postgresql-9.5'
POSTGRES_USER = POSTGRES_GROUP = 'postgres'

# Etcd used only in clusters
ETCD_USER = 'etcd'
ETCD_GROUP = 'etcd'

HOST = 'host'
LOG_DIR = join(constants.BASE_LOG_DIR, POSTGRESQL_SERVER)

PGSQL_LIB_DIR = '/var/lib/pgsql'
PGSQL_USR_DIR = '/usr/pgsql-9.5'
PG_HBA_CONF = '/var/lib/pgsql/9.5/data/pg_hba.conf'
PG_BASE_CONF_PATH = '/var/lib/pgsql/9.5/data/postgresql.conf'
PG_CONF_PATH = '/var/lib/pgsql/9.5/data/cloudify-postgresql.conf'
PGPASS_PATH = join(constants.CLOUDIFY_HOME_DIR, '.pgpass')

PG_CA_CERT_PATH = os.path.join(os.path.dirname(PG_CONF_PATH), 'root.crt')
PG_SERVER_CERT_PATH = os.path.join(os.path.dirname(PG_CONF_PATH), 'server.crt')
PG_SERVER_KEY_PATH = os.path.join(os.path.dirname(PG_CONF_PATH), 'server.key')

# Cluster CA cert locations
ETCD_SERVER_CERT_PATH = '/etc/etcd/etcd.crt'
ETCD_SERVER_KEY_PATH = '/etc/etcd/etcd.key'
ETCD_CA_PATH = '/etc/etcd/ca.crt'
PATRONI_REST_CERT_PATH = '/var/lib/patroni/rest.crt'
PATRONI_REST_KEY_PATH = '/var/lib/patroni/rest.key'
PATRONI_DB_CERT_PATH = '/var/lib/patroni/db.crt'
PATRONI_DB_KEY_PATH = '/var/lib/patroni/db.key'
PATRONI_DB_CA_PATH = '/var/lib/patroni/ca.crt'

# Cluster file locations
ETCD_CONFIG_PATH = '/etc/etcd/etcd.conf'
PATRONI_CONFIG_PATH = '/etc/patroni.conf'

# Postgres bin files needing symlinking for patroni
PG_BIN_DIR = '/usr/pgsql-9.5/bin'
PG_BINS = [
    'clusterdb', 'createdb', 'createlang', 'createuser', 'dropdb', 'droplang',
    'dropuser', 'pg_archivecleanup', 'pg_basebackup', 'pg_config', 'pg_dump',
    'pg_dumpall', 'pg_isready', 'pg_receivexlog', 'pg_restore', 'pg_rewind',
    'pg_test_fsync', 'pg_test_timing', 'pg_upgrade', 'pg_xlogdump', 'pgbench',
    'psql', 'reindexdb', 'vacuumdb', 'oid2name', 'pg_recvlogical',
    'pg_standby', 'vacuumlo', 'initdb', 'pg_controldata', 'pg_ctl',
    'pg_resetxlog', 'postgres', 'postgresql95-check-db-dir',
    'postgresql95-setup', 'postmaster', 'ecpg'
]

PG_HBA_LISTEN_ALL_REGEX_PATTERN = r'host\s+all\s+all\s+0\.0\.0\.0\/0\s+md5'
PG_HBA_HOSTSSL_REGEX_PATTERN = \
    r'hostssl\s+all\s+all\s+0\.0\.0\.0\/0\s+md5\s+.*'

PG_PORT = 5432

CONFIG_PATH = join(constants.COMPONENTS_DIR, POSTGRESQL_SERVER, CONFIG)

logger = get_logger(POSTGRESQL_SERVER)


class PostgresqlServer(BaseComponent):
    component_name = 'postgresql_server'

    def __init__(self, skip_installation):
        super(PostgresqlServer, self).__init__(skip_installation)

    def _init_postgresql_server(self):
        logger.debug('Initializing PostgreSQL Server DATA folder...')
        postgresql95_setup = join(PGSQL_USR_DIR, 'bin', 'postgresql95-setup')
        try:
            common.sudo(command=[postgresql95_setup, 'initdb'])
        except Exception:
            logger.debug('PostreSQL Server DATA folder already initialized...')
            pass

        logger.debug('Installing PostgreSQL Server service...')
        systemd.enable(SYSTEMD_SERVICE_NAME, append_prefix=False)
        systemd.restart(SYSTEMD_SERVICE_NAME, append_prefix=False)

        logger.debug('Setting PostgreSQL Server logs path...')
        ps_95_logs_path = join(PGSQL_LIB_DIR, '9.5', 'data', 'pg_log')
        common.mkdir(LOG_DIR)
        if not isdir(ps_95_logs_path) and not islink(join(LOG_DIR, 'pg_log')):
            files.ln(source=ps_95_logs_path, target=LOG_DIR, params='-s')

        logger.info('Starting PostgreSQL Server service...')
        systemd.restart(SYSTEMD_SERVICE_NAME, append_prefix=False)

    def _read_old_file_lines(self, file_path):
        temp_file_path = files.write_to_tempfile('')
        common.copy(file_path, temp_file_path)
        common.chmod('777', temp_file_path)
        with open(temp_file_path, 'r') as f:
            lines = f.readlines()
        return lines

    def _write_new_pgconfig_file(self):
        """Create the postgres config override file.
        """
        fd, temp_pgconfig_path = mkstemp()
        os.close(fd)
        with open(temp_pgconfig_path, 'a') as conf_handle:
            conf_handle.write('# Cloudify postgres config overrides\n')
            if config[POSTGRESQL_SERVER][ENABLE_REMOTE_CONNECTIONS]:
                conf_handle.write(
                    "listen_addresses = '{address}'\n".format(
                        address=config[MANAGER][PRIVATE_IP],
                    )
                )
            if config[POSTGRESQL_SERVER][SSL_ENABLED]:
                conf_handle.write(
                    "ssl = on\n"
                    "ssl_ca_file = '{ca_path}'\n".format(
                        ca_path=PG_CA_CERT_PATH,
                    )
                )
        return temp_pgconfig_path

    def _write_new_hba_file(self, lines, enable_remote_connections):
        fd, temp_hba_path = mkstemp()
        os.close(fd)
        with open(temp_hba_path, 'a') as f:
            for line in lines:
                if line.startswith(('host', 'local')):
                    line = line.replace('ident', 'md5')
                f.write(line)
            if not re.search(PG_HBA_LISTEN_ALL_REGEX_PATTERN,
                             '\n'.join(lines)) and enable_remote_connections\
                    and not config[POSTGRESQL_SERVER]['ssl_only_connections']:
                f.write('host all all 0.0.0.0/0 md5\n')
            if config[POSTGRESQL_SERVER][SSL_ENABLED] and not \
                    re.search(PG_HBA_HOSTSSL_REGEX_PATTERN, '\n'.join(lines)):
                # This will require the client to supply a certificate as well
                if config[POSTGRESQL_SERVER][SSL_CLIENT_VERIFICATION]:
                    f.write('hostssl all all 0.0.0.0/0 md5 clientcert=1')
                else:
                    f.write('hostssl all all 0.0.0.0/0 md5')
        return temp_hba_path

    def _configure_ssl(self):
        """Copy SSL certificates to postgres data directory.
        postgresql.conf and pg_hba.conf configurations are handled in
        the update_configuration step.
        Cluster certificates are7 handled in _configure_cluster.
        """
        if config[POSTGRESQL_SERVER][SSL_ENABLED]:
            self.use_supplied_certificates(
                cert_destination=PG_SERVER_CERT_PATH,
                key_destination=PG_SERVER_KEY_PATH,
                ca_destination=PG_CA_CERT_PATH,
                owner=POSTGRES_USER,
                group=POSTGRES_GROUP,
                key_perms='400',
            )

    def _update_configuration(self, enable_remote_connections):
        logger.info('Updating PostgreSQL Server configuration...')
        logger.debug('Modifying {0}'.format(PG_HBA_CONF))
        common.copy(PG_HBA_CONF, '{0}.backup'.format(PG_HBA_CONF))
        lines = self._read_old_file_lines(PG_HBA_CONF)
        temp_hba_path = self._write_new_hba_file(lines,
                                                 enable_remote_connections)
        common.move(temp_hba_path, PG_HBA_CONF)
        common.chown(POSTGRES_USER, POSTGRES_USER, PG_HBA_CONF)

        common.sudo(
            'tee -a {path}'.format(path=PG_BASE_CONF_PATH),
            stdin="include = '{config}'".format(config=PG_CONF_PATH),
        )

        temp_pg_conf_path = self._write_new_pgconfig_file()
        common.move(temp_pg_conf_path, PG_CONF_PATH)
        common.chown(POSTGRES_USER, POSTGRES_USER, PG_CONF_PATH)
        self._configure_ssl()

    def _update_postgres_password(self):
        logger.notice('Updating postgres password...')
        postgres_password = \
            config[POSTGRESQL_SERVER][POSTGRES_PASSWORD]

        update_password_script_path = join(POSTGRESQL_SCRIPTS_PATH,
                                           'update_postgres_password.sh')
        tmp_script_path = files.temp_copy(update_password_script_path)
        common.chmod('o+rx', tmp_script_path)
        common.sudo(
            'su - postgres -c "{cmd} {postgres_password}"'.format(
                cmd=tmp_script_path,
                postgres_password=postgres_password)
        )
        logger.info('Removing postgres password from config.yaml')
        config[POSTGRESQL_SERVER][POSTGRES_PASSWORD] = '<removed>'
        logger.notice('postgres password successfully updated')

    def _etcd_is_running(self):
        status = common.run(['systemctl', 'is-active', 'etcd'],
                            ignore_failures=True).aggr_stdout.strip()
        return status in ('active', 'activating')

    def _start_etcd(self):
        # On the first node, etcd start via systemd will fail because of the
        # other nodes not being up, so we use this approach instead
        logger.info('Starting etcd')
        common.sudo(['systemctl', 'start', 'etcd', '--no-block'])
        while not self._etcd_is_running():
            logger.info('Waiting for etcd to start...')
            time.sleep(1)
        logger.info('etcd has started')

    def _configure_cluster(self):
        logger.info('Disabling postgres (will be managed by patroni)')
        systemd.stop(SYSTEMD_SERVICE_NAME, append_prefix=False)
        systemd.disable(SYSTEMD_SERVICE_NAME, append_prefix=False)

        logger.info('Deploying cluster certificates')
        # We need access to the certs, which by default we don't have
        common.sudo(['chmod', 'a+x', '/var/lib/patroni'])
        # We currently use the same certificates for etcd, patroni,
        # and postgres. This should be a reasonable starting approach as
        # these reside on the same machine and all have the same impact if
        # compromised (full access to data directly or via injected
        # configuration changes).
        self.use_supplied_certificates(
            cert_destination=ETCD_SERVER_CERT_PATH,
            key_destination=ETCD_SERVER_KEY_PATH,
            ca_destination=ETCD_CA_PATH,
            owner=ETCD_USER,
            group=ETCD_GROUP,
            key_perms='400',
        )
        self.use_supplied_certificates(
            cert_destination=PATRONI_REST_CERT_PATH,
            key_destination=PATRONI_REST_KEY_PATH,
            owner=POSTGRES_USER,
            group=POSTGRES_GROUP,
            key_perms='400',
        )
        self.use_supplied_certificates(
            cert_destination=PATRONI_DB_CERT_PATH,
            key_destination=PATRONI_DB_KEY_PATH,
            ca_destination=PATRONI_DB_CA_PATH,
            owner=POSTGRES_USER,
            group=POSTGRES_GROUP,
            key_perms='400',
        )
        common.sudo(['chmod', 'a-x', '/var/lib/patroni'])

        logger.info('Deploying cluster config files.')
        files.deploy(os.path.join(CONFIG_PATH, 'patroni.conf'),
                     PATRONI_CONFIG_PATH)
        common.sudo(['chown', 'root.postgres', PATRONI_CONFIG_PATH])
        common.sudo(['chmod', '640', PATRONI_CONFIG_PATH])
        files.deploy(os.path.join(CONFIG_PATH, 'etcd.conf'), ETCD_CONFIG_PATH)
        common.sudo(['chown', 'etcd.', ETCD_CONFIG_PATH])
        common.sudo(['chmod', '440', ETCD_CONFIG_PATH])
        common.sudo(['chown', 'postgres.', '/var/lib/patroni'])
        common.sudo(['chmod', '700', '/var/lib/patroni'])
        common.sudo(['chmod', '700', '/var/lib/patroni/data'])

        logger.info('Configuring etcd')
        systemd.enable('etcd', append_prefix=False)
        self._start_etcd()
        etcdctl_base_command = [
            'etcdctl', '--endpoints', 'https://127.0.0.1:2379',
            '--ca-file', ETCD_CA_PATH,
        ]
        cluster_state = common.run(
            etcdctl_base_command + ['cluster-health'],
            ignore_failures=True,
        ).aggr_stdout
        if 'cluster is degraded' in cluster_state:
            cluster_config = config[POSTGRESQL_SERVER]['cluster']
            # We want to configure etcd auth when the second node joins
            # because that's the earliest we can do so.
            logger.info('Configuring etcd authentication')
            # Note that, per the etcd documentation, the root user must exist
            # if authentication is to be enabled for etcd
            common.run(
                etcdctl_base_command + ['user', 'add', 'root'],
                stdin=cluster_config['etcd']['root_password'],
            )
            common.run(
                etcdctl_base_command + ['user', 'add', 'patroni'],
                stdin=cluster_config['etcd']['patroni_password'],
            )
            common.run(
                etcdctl_base_command +
                ['user', 'grant', 'patroni', '--roles', 'guest']
            )
            common.run(etcdctl_base_command + ['auth', 'enable'])

        logger.info('Creating postgres bin links for patroni')
        for pg_bin in PG_BINS:
            common.sudo(['ln', '-s', os.path.join(PG_BIN_DIR, pg_bin),
                         '/usr/sbin'])

        logger.info('Starting patroni')
        files.deploy(
            os.path.join(CONFIG_PATH, 'patroni.service'),
            '/usr/lib/systemd/system/patroni.service',
            render=False,
        )
        systemd.enable('patroni', append_prefix=False)
        systemd.start('patroni', append_prefix=False)

    def install(self):
        logger.notice('Installing PostgreSQL Server...')
        sources = config[POSTGRESQL_SERVER][SOURCES]

        logger.debug('Installing PostgreSQL Server dependencies...')
        yum_install(sources['libxslt_rpm_url'])

        logger.debug('Installing PostgreSQL Server...')
        yum_install(sources['ps_libs_rpm_url'])
        yum_install(sources['ps_rpm_url'])
        yum_install(sources['ps_contrib_rpm_url'])
        yum_install(sources['ps_server_rpm_url'])
        yum_install(sources['ps_devel_rpm_url'])
        # As we don't support installing community as anything other than AIO,
        # not having manager service installed means that this must be premium
        if MANAGER_SERVICE not in config[SERVICES_TO_INSTALL]:
            try:
                yum_install(sources['etcd_rpm_url'])
                yum_install(sources['patroni_rpm_url'])
            except FileError:
                logger.info(
                    'DB cluster component RPMs not available, skipping.'
                )
        logger.notice('PostgreSQL Server successfully installed')

    def configure(self):
        logger.notice('Configuring PostgreSQL Server...')
        files.copy_notice(POSTGRESQL_SERVER)

        if config[POSTGRESQL_SERVER]['cluster']['nodes']:
            self._configure_cluster()
        else:
            self._init_postgresql_server()
            enable_remote_connections = \
                config[POSTGRESQL_SERVER][ENABLE_REMOTE_CONNECTIONS]
            self._update_configuration(enable_remote_connections)
            if config[POSTGRESQL_SERVER][POSTGRES_PASSWORD]:
                self._update_postgres_password()

            systemd.restart(SYSTEMD_SERVICE_NAME, append_prefix=False)
            systemd.verify_alive(SYSTEMD_SERVICE_NAME, append_prefix=False)
        logger.notice('PostgreSQL Server successfully configured')

    def remove(self):
        if MANAGER_SERVICE not in config[SERVICES_TO_INSTALL]:
            logger.notice('Removing cluster components')
            yum_remove('etcd')
            yum_remove('patroni')
            files.remove_files([
                '/var/lib/patroni',
                '/var/lib/etcd',
                '/etc/patroni.conf',
                '/etc/etcd',
            ])
            systemd.remove('patroni', append_prefix=False)
            logger.notice('Cluster components removed')
        logger.notice('Removing PostgreSQL...')
        files.remove_notice(POSTGRESQL_SERVER)
        systemd.remove(SYSTEMD_SERVICE_NAME)
        files.remove_files([PGSQL_LIB_DIR, PGSQL_USR_DIR, LOG_DIR])
        yum_remove('postgresql95')
        yum_remove('postgresql95-libs')
        logger.notice('PostgreSQL successfully removed')

    def start(self):
        logger.notice('Starting PostgreSQL Server...')
        systemd.start(SYSTEMD_SERVICE_NAME, append_prefix=False)
        systemd.verify_alive(SYSTEMD_SERVICE_NAME, append_prefix=False)
        if config[POSTGRESQL_SERVER]['cluster']['nodes']:
            self._start_etcd()
            systemd.start('patroni', append_prefix=False)
            systemd.verify_alive('patroni', append_prefix=False)
        logger.notice('PostgreSQL Server successfully started')

    def stop(self):
        logger.notice('Stopping PostgreSQL Server...')
        systemd.stop(SYSTEMD_SERVICE_NAME, append_prefix=False)
        if config[POSTGRESQL_SERVER]['cluster']['nodes']:
            systemd.stop('etcd', append_prefix=False)
            systemd.stop('patroni', append_prefix=False)
        logger.notice('PostgreSQL Server successfully stopped')

    def validate_dependencies(self):
        super(PostgresqlServer, self).validate_dependencies()
