import os
import re
import time
import json
import psutil
import socket
import subprocess
from copy import copy
from getpass import getuser
from tempfile import mkstemp
from os.path import join, isdir, islink

import ipaddress
import requests
from retrying import retry
from ruamel.yaml import YAML

from cfy_manager.exceptions import (
    BootstrapError,
    ClusteringError,
    DBNodeListError,
    DBManagementError,
    ProcessExecutionError,
)
from ...components_constants import (
    CONFIG,
    ENABLE_REMOTE_CONNECTIONS,
    ETCD_CA_PATH,
    ETCD_CA_KEY_PATH,
    PATRONI_DB_CA_PATH,
    POSTGRES_PASSWORD,
    PRIVATE_IP,
    PUBLIC_IP,
    SCRIPTS,
    SERVICES_TO_INSTALL,
    SSL_CLIENT_VERIFICATION,
    SSL_ENABLED,
)
from ..base_component import BaseComponent
from ...service_names import (
    POSTGRESQL_SERVER,
    MANAGER,
    MANAGER_SERVICE,
    MONITORING_SERVICE,
    DATABASE_SERVICE
)
from ... import constants
from ...config import config
from ...logger import get_logger
from ...utils import (
    certificates,
    common,
    db,
    files,
    network,
    service,
    syslog,
)

POSTGRESQL_SCRIPTS_PATH = join(constants.COMPONENTS_DIR, POSTGRESQL_SERVER,
                               SCRIPTS)

POSTGRES_SERVICE_NAME = 'postgresql-14'
OLD_POSTGRES_SERVICE_NAME = 'postgresql-9.5'
POSTGRES_USER = POSTGRES_GROUP = 'postgres'

# Etcd used only in clusters
ETCD_USER = 'etcd'
ETCD_GROUP = 'etcd'

HOST = 'host'
LOG_DIR = join(constants.BASE_LOG_DIR, POSTGRESQL_SERVER)

PGSQL_SOCK_DIR = '/var/run/postgresql'
PGSQL_LIB_DIR = '/var/lib/pgsql'
PGSQL_USR_DIR = '/usr/pgsql-14'
PGSQL_DATA_DIR = '/var/lib/pgsql/14/data'
OLD_PGSQL_USR_DIR = '/usr/pgsql-9.5'
OLD_PGSQL_DATA_DIR = '/var/lib/pgsql/9.5/data'
PG_HBA_CONF = '{0}/pg_hba.conf'.format(PGSQL_DATA_DIR)
PG_BASE_CONF_PATH = '{0}/postgresql.conf'.format(PGSQL_DATA_DIR)
PG_CONF_PATH = '{0}/cloudify-postgresql.conf'.format(PGSQL_DATA_DIR)
PGPASS_PATH = join(constants.CLOUDIFY_HOME_DIR, '.pgpass')

PG_CA_CERT_PATH = os.path.join(os.path.dirname(PG_CONF_PATH), 'root.crt')
PG_CA_KEY_PATH = os.path.join(os.path.dirname(PG_CONF_PATH), 'root.key')
PG_SERVER_CERT_PATH = os.path.join(os.path.dirname(PG_CONF_PATH), 'server.crt')
PG_SERVER_KEY_PATH = os.path.join(os.path.dirname(PG_CONF_PATH), 'server.key')

# Cluster CA cert locations
ETCD_SERVER_CERT_PATH = '/etc/etcd/etcd.crt'
ETCD_SERVER_KEY_PATH = '/etc/etcd/etcd.key'
PATRONI_REST_CERT_PATH = '/var/lib/patroni/rest.crt'
PATRONI_REST_KEY_PATH = '/var/lib/patroni/rest.key'
PATRONI_DB_CERT_PATH = '/var/lib/patroni/db.crt'
PATRONI_DB_KEY_PATH = '/var/lib/patroni/db.key'
PATRONI_PGPASS_PATH = '/var/lib/patroni/pgpass'

# Cluster file locations
ETCD_DATA_DIR = '/var/lib/etcd'
ETCD_CONFIG_PATH = '/etc/etcd/etcd.conf'
ETCD_LOG_PATH = join(constants.BASE_LOG_DIR, 'db_cluster/etcd')
PATRONI_DATA_DIR = '/var/lib/patroni/data'
PATRONI_CONFIG_PATH = '/etc/patroni.conf'
PATRONI_LOG_PATH = join(constants.BASE_LOG_DIR, 'db_cluster/patroni')
POSTGRES_LOG_PATH = join(constants.BASE_LOG_DIR, 'db_cluster/postgres')
POSTGRES_PATRONI_CONFIG_PATH = '/var/lib/pgsql/14/data/pg_patroni_base.conf'

# Postgres bin files needing symlinking for patroni
PG_BIN_DIR = '/usr/pgsql-14/bin'
PG_BINS = [
    'clusterdb', 'createdb', 'createuser', 'dropdb', 'dropuser',
    'pg_amcheck', 'pg_archivecleanup', 'pg_basebackup', 'pg_checksums',
    'pg_config', 'pg_controldata', 'pg_ctl', 'pg_dump', 'pg_dumpall',
    'pg_isready', 'pg_receivewal', 'pg_recvlogical', 'pg_resetwal',
    'pg_restore', 'pg_rewind', 'pg_test_fsync', 'pg_test_timing', 'pg_upgrade',
    'pg_verifybackup', 'pg_waldump', 'pgbench', 'postgres',
    'postgresql-14-check-db-dir', 'postgresql-14-setup', 'postmaster', 'psql',
    'reindexdb', 'vacuumdb', 'vacuumlo',
]

PG_HBA_LISTEN_ALL_REGEX_PATTERN = r'host\s+all\s+all\s+0\.0\.0\.0\/0\s+md5'
PG_HBA_HOSTSSL_REGEX_PATTERN = \
    r'hostssl\s+all\s+all\s+0\.0\.0\.0\/0\s+md5\s+.*'

PG_PORT = 5432

CONFIG_PATH = join(constants.COMPONENTS_DIR, POSTGRESQL_SERVER, CONFIG)
SCRIPTS_PATH = join(constants.COMPONENTS_DIR, POSTGRESQL_SERVER, 'scripts')

POSTGRESQL_WORK_MEM_MIN_BYTES = 4 * 1024 * 1024
POSTGRESQL_MAINTENANCE_WORK_MEM_MIN_BYTES = 64 * 1024 * 1024
POSTGRESQL_WAL_BUFFERS_MAX_BYTES = 2047 * 1024 * 1024

logger = get_logger(POSTGRESQL_SERVER)


class PostgresqlServer(BaseComponent):
    component_name = 'postgresql_server'
    # Status codes for listing nodes
    HEALTHY = 0
    DEGRADED = 1
    DOWN = 2

    def _init_postgresql_server(self, encoding='UTF8', locale='en_GB.UTF-8'):
        if os.path.exists(PG_HBA_CONF):
            logger.info('PostreSQL Server DATA folder already initialized...')
            return
        logger.debug('Initializing PostgreSQL Server DATA folder...')
        initdb_cmd = ['sudo', '-u', 'postgres',
                      join(PGSQL_USR_DIR, 'bin', 'initdb'),
                      '-D', PGSQL_DATA_DIR, '-E', encoding,
                      '--locale', locale]
        common.run(initdb_cmd)

        logger.debug('Setting PostgreSQL Server logs path...')
        pg_14_logs_path = join(PGSQL_LIB_DIR, '14', 'data', 'log')
        common.mkdir(LOG_DIR)
        common.chown(POSTGRES_USER, 'cfylogs', LOG_DIR)
        common.chmod('750', LOG_DIR)
        if not isdir(pg_14_logs_path) and not islink(join(LOG_DIR, 'log')):
            files.ln(source=pg_14_logs_path, target=LOG_DIR, params='-s')

        common.mkdir(PGSQL_SOCK_DIR)
        common.chown(POSTGRES_USER, POSTGRES_GROUP, PGSQL_SOCK_DIR)

    @staticmethod
    def _configure_postgresql_server_service():
        service.configure(
            POSTGRES_SERVICE_NAME,
            src_dir='postgresql_server',
            config_path='config/supervisord'
        )
        files.deploy(
            join(
                SCRIPTS_PATH,
                'postgresql_server_wrapper_script.sh'
            ),
            '/var/lib/pgsql/',
            render=False
        )
        common.chown(
            'postgres',
            'postgres',
            '/var/lib/pgsql/postgresql_server_wrapper_script.sh'
        )
        common.chmod(
            '755',
            '/var/lib/pgsql/postgresql_server_wrapper_script.sh'
        )

    @staticmethod
    def _bytes_as_mb(value_in_bytes):
        return '{}MB'.format(value_in_bytes // 1024 // 1024)

    def _generate_default_shared_buffers(self):
        """Calculate `shared_buffers` PostgreSQL parameter as 25% of RAM."""
        return self._bytes_as_mb(psutil.virtual_memory().total // 4)

    def _generate_default_effective_cache_size(self):
        """
        Calculate `effective_cache_size` PostgreSQL parameter.

        Depending on the installation, make it 50% of the RAM size for
        standalone database installation (like in cluster) or 25% for the
        all-in-one installation.
        """
        if common.service_is_configured(MANAGER_SERVICE):
            return self._bytes_as_mb(psutil.virtual_memory().total // 4)
        else:
            return self._bytes_as_mb(psutil.virtual_memory().total // 2)

    def _generate_work_mem(self):
        return self._bytes_as_mb(max(POSTGRESQL_WORK_MEM_MIN_BYTES,
                                     psutil.virtual_memory().total // 256))

    def _generate_maintenance_work_mem(self):
        return self._bytes_as_mb(max(POSTGRESQL_MAINTENANCE_WORK_MEM_MIN_BYTES,
                                     psutil.virtual_memory().total // 16))

    def _generate_wal_buffers(self):
        return self._bytes_as_mb(min(POSTGRESQL_WAL_BUFFERS_MAX_BYTES,
                                     psutil.virtual_memory().total // 128))

    def _generate_pg_params(self, overrides):
        params = {
            'log_destination': "stderr",
            'logging_collector': "on",
            'log_filename': "'postgresql-%a.log'",
            'log_file_mode': '0644',
            'log_truncate_on_rotation': "on",
            'log_rotation_age': "1d",
            'log_rotation_size': 0,
            'log_line_prefix': "'< %m >'",
            'log_timezone': "'UCT'",
            'datestyle': "'iso, mdy'",
            'timezone': "'UCT'",
            'default_text_search_config': "'pg_catalog.english'",
            'lc_messages': "en_US.UTF-8",
            'lc_monetary': "en_US.UTF-8",
            'lc_numeric': "en_US.UTF-8",
            'lc_time': "en_US.UTF-8",
            'shared_buffers': self._generate_default_shared_buffers(),
            'effective_cache_size':
            self._generate_default_effective_cache_size(),
            'max_connections': 250,
            'work_mem': self._generate_work_mem(),
            'maintenance_work_mem': self._generate_maintenance_work_mem(),
            'wal_buffers': self._generate_wal_buffers(),
            'checkpoint_completion_target': 0.9,
        }
        params.update(overrides)
        return params

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
            for name, value in self._generate_pg_params(
                    config[POSTGRESQL_SERVER]['config']).items():
                conf_handle.write("{0} = {1}\n".format(name, value))

        return temp_pgconfig_path

    @staticmethod
    def _get_monitoring_user_hba_entry(host):
        try:
            host = ipaddress.ip_address(host)
            suffix = '/{}'.format(host.max_prefixlen)
        except ValueError:
            host = host
            suffix = ''
        return 'hostssl all {monitoring_user} {host}{suffix} md5'.format(
            monitoring_user=config[POSTGRESQL_SERVER][
                'db_monitoring']['username'],
            host=host,
            suffix=suffix,
        )

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
                f.write('host all all ::0/0 md5\n')
            if config[POSTGRESQL_SERVER][SSL_ENABLED] and not \
                    re.search(PG_HBA_HOSTSSL_REGEX_PATTERN, '\n'.join(lines)):
                # Allow access for monitoring user, locally only, without
                # client certs
                f.write(self._get_monitoring_user_hba_entry(
                    config[MANAGER][PRIVATE_IP],
                ) + '\n')
                # This will require the client to supply a certificate as well
                if config[POSTGRESQL_SERVER][SSL_CLIENT_VERIFICATION]:
                    f.write('hostssl all all 0.0.0.0/0 md5 '
                            'clientcert=verify-full\n')
                    f.write('hostssl all all ::0/0 md5 '
                            'clientcert=verify-full\n')
                else:
                    f.write('hostssl all all 0.0.0.0/0 md5\n')
                    f.write('hostssl all all ::0/0 md5\n')
        return temp_hba_path

    def _configure_ssl(self):
        """Copy SSL certificates to postgres data directory.
        postgresql.conf and pg_hba.conf configurations are handled in
        the update_configuration step.
        Cluster certificates are handled in _configure_cluster.
        """
        if config[POSTGRESQL_SERVER][SSL_ENABLED]:
            self.handle_all_in_one_certificates()

    def _update_configuration(self, enable_remote_connections):
        logger.info('Updating PostgreSQL Server configuration...')
        logger.debug('Modifying {0}'.format(PG_HBA_CONF))
        common.copy(PG_HBA_CONF, '{0}.backup'.format(PG_HBA_CONF))
        lines = files.read(PG_HBA_CONF).splitlines(True)
        temp_hba_path = self._write_new_hba_file(lines,
                                                 enable_remote_connections)
        common.move(temp_hba_path, PG_HBA_CONF)
        common.chown(POSTGRES_USER, POSTGRES_USER, PG_HBA_CONF)

        include_line = "include = '{config}'".format(config=PG_CONF_PATH)
        already_included = common.run(
            ['grep', include_line, PG_BASE_CONF_PATH],
            ignore_failures=True,
        ).returncode == 0
        if not already_included:
            common.run(
                ['tee', '-a', PG_BASE_CONF_PATH],
                stdin="{include}\n".format(include=include_line),
            )

        temp_pg_conf_path = self._write_new_pgconfig_file()
        common.move(temp_pg_conf_path, PG_CONF_PATH)
        common.chown(POSTGRES_USER, POSTGRES_USER, PG_CONF_PATH)
        self._configure_ssl()

    def _update_postgres_password(self):
        logger.notice('Updating postgres password...')
        postgres_password = config[POSTGRESQL_SERVER][POSTGRES_PASSWORD]
        delimiter = self._delimiter_for(postgres_password)
        db.run_psql_command(
            "ALTER ROLE postgres WITH PASSWORD {delim}{pwd}{delim};".format(
                delim=delimiter,
                pwd=postgres_password,
            ),
            'server_db_name',
            logger,
        )
        logger.notice('postgres password successfully updated')

    def _create_db_monitoring_account(self):
        logger.notice('Creating db_monitoring account...')
        cluster_nodes = config[POSTGRESQL_SERVER]['cluster']['nodes']
        if cluster_nodes:
            try:
                self._etcd_command(['member', 'list'], )
            except Exception as ex:
                logger.notice('db_monitoring account not yet created. '
                              'Database cluster not yet ready (will '
                              'try on the next database node). %s', ex)
                return
        try:
            self._run_create_db_monitoring_user_query()
        except Exception:
            if cluster_nodes:
                logger.notice('db_monitoring account not yet created '
                              '(will try on the next database node).')
            else:
                raise

    @retry(stop_max_attempt_number=60, wait_fixed=1000)
    def _run_create_db_monitoring_user_query(self):
        credentials = config[POSTGRESQL_SERVER]['db_monitoring']

        if self._db_user_exists(credentials.get('username')):
            logger.info('db_monitoring account already exists, skipping.')
            return

        delimiter = self._delimiter_for(credentials.get('password'))
        db.run_psql_command(
            "CREATE USER {user} WITH PASSWORD {delim}{pwd}{delim};".format(
                user=credentials.get('username'),
                delim=delimiter,
                pwd=credentials.get('password'),
            ),
            'server_db_name',
            logger,
        )
        logger.notice('db_monitoring account successfully created')

    @staticmethod
    def _delimiter_for(text):
        delim = '$password$'
        while delim in text:
            delim = delim.rstrip('$')
            delim = delim + 'a$'
        return delim

    @staticmethod
    def _etcd_is_running():
        return service.is_active('etcd')

    @staticmethod
    def _start_etcd():
        logger.info('Starting etcd')
        service.start(
            'etcd',
            # On the first node, etcd start will fail because of the
            # other nodes not being up
            ignore_failure=True,
        )
        logger.info('etcd has started')

    def _restart_etcd(self):
        logger.info('Restarting etcd')
        service.restart('etcd', ignore_failure=True)
        self._wait_for_etcd()
        logger.info('etcd has restarted')

    def _wait_for_etcd(self):
        while not self._etcd_is_running():
            logger.info('Waiting for etcd to start...')
            time.sleep(1)

    @staticmethod
    def _patronictl_command(command):
        """Execute a patronictl command."""
        patronictl_base_command = [
            '/opt/patroni/bin/patronictl', '-c', PATRONI_CONFIG_PATH,
        ]
        return common.run(patronictl_base_command + command)

    @staticmethod
    def _etcd_command(command, ignore_failures=False, stdin=None,
                      local_only=False, username=None):
        """Execute an etcdctl command."""
        supported_etcd_users = ['root', 'patroni']
        if username and username not in supported_etcd_users:
            raise ValueError(
                'Cluster configuration only supports these etcd users: '
                '{users}'.format(users=', '.join(supported_etcd_users))
            )

        if local_only:
            addresses = [config[MANAGER][PRIVATE_IP]]
        else:
            addresses = [
                node['ip'] for node in
                config[POSTGRESQL_SERVER]['cluster']['nodes'].values()
            ]

        endpoints = ','.join(
            'https://{addr}:2379'.format(addr=network.ipv6_url_compat(addr))
            for addr in addresses
        )
        etcdctl_base_command = [
            'etcdctl', '--endpoints', endpoints,
            '--ca-file', ETCD_CA_PATH,
        ]
        env = copy(os.environ)
        if username:
            pg_conf = config[POSTGRESQL_SERVER]
            password = pg_conf['cluster']['etcd'][username + '_password']
            env['ETCDCTL_USERNAME'] = username + ':' + password
        env['ETCDCTL_API'] = '2'
        return common.run(
            etcdctl_base_command + command,
            ignore_failures=ignore_failures,
            stdin=stdin,
            env=env,
        )

    def _set_patroni_dcs_conf(self, patroni_config, local_only=True):
        self._etcd_command(
            ['set', '/db/postgres/config', json.dumps(patroni_config)],
            username='root',
            local_only=local_only,
        )

    # We retry on this so that an install of several
    # cluster nodes at once won't suffer from a race condition
    # (e.g. we install like this in the tests)
    @retry(stop_max_attempt_number=20, wait_fixed=3000)
    def _get_patroni_dcs_conf(self, local_only=True):
        return json.loads(self._etcd_command(
            ['get', '/db/postgres/config'],
            username='root',
            local_only=local_only,
        ).aggr_stdout)

    @staticmethod
    def _get_etcd_id(ip):
        return 'etcd' + _ip_to_identifier(ip)

    @staticmethod
    def _get_patroni_id(address):
        return 'pg' + _ip_to_identifier(address)

    def _etcd_requires_auth(self):
        logger.info('Checking whether etcd requires auth.')
        # This allows ~15 seconds for the etcd cluster to become available
        # It shouldn't wait too long because this will always timeout before
        # a majority of the nodes are installed.
        # Using a longer sleep and fewer attempts because when the cluster is
        # not up it causes delaysto the queries meaning that more attempts add
        # more delay.
        attempts = 5
        wait_time = 3

        for attempt in range(attempts):
            cluster_auth_check = self._etcd_command(['ls', '/'],
                                                    ignore_failures=True)
            # This command will only succeed if the cluster is up and auth is
            # not yet enabled
            if cluster_auth_check.returncode == 0:
                logger.info('Etcd does not require auth.')
                return False
            elif cluster_auth_check.returncode == 4:
                # This will be insufficient if etcdctl starts localising error
                # messages
                if 'user authentication' in cluster_auth_check.aggr_stderr:
                    logger.info('Etcd requires auth.')
                    return True

            logger.debug('Etcd connection error: {err}'.format(
                err=cluster_auth_check.aggr_stderr,
            ))
            time.sleep(wait_time)
        raise ClusteringError(
            'Etcd not up yet, this is likely the first node.'
        )

    @staticmethod
    def _configure_patroni():
        logger.info('Starting patroni')
        service.configure(
            'patroni',
            src_dir='postgresql_server',
            render=False
        )

    def handle_cluster_certificates(self):
        # We currently use the same certificates for etcd, patroni,
        # and postgres. This should be a reasonable starting approach as
        # these reside on the same machine and all have the same impact if
        # compromised (full access to data directly or via injected
        # configuration changes).

        etcd_certs_config = {
            'cert_destination': ETCD_SERVER_CERT_PATH,
            'key_destination': ETCD_SERVER_KEY_PATH,
            'ca_destination': ETCD_CA_PATH,
            'owner': ETCD_USER,
            'group': ETCD_GROUP,
            'key_perms': '400'
        }

        patroni_rest_certs_config = {
            'cert_destination': PATRONI_REST_CERT_PATH,
            'key_destination': PATRONI_REST_KEY_PATH,
            'owner': POSTGRES_USER,
            'group': POSTGRES_GROUP,
            'key_perms': '400',
        }

        patroni_db_certs_config = {
            'cert_destination': PATRONI_DB_CERT_PATH,
            'key_destination': PATRONI_DB_KEY_PATH,
            'ca_destination': PATRONI_DB_CA_PATH,
            'owner': POSTGRES_USER,
            'group': POSTGRES_GROUP,
            'key_perms': '400'
        }

        for cert_config in [etcd_certs_config,
                            patroni_rest_certs_config,
                            patroni_db_certs_config]:
            cert_config.update({'component_name': self.component_name,
                                'logger': logger,
                                'cert_perms': '444'})
            certificates.use_supplied_certificates(**cert_config)

    def handle_all_in_one_certificates(self):
        cert_config = {
            'component_name': self.component_name,
            'logger': logger,
            'cert_destination': PG_SERVER_CERT_PATH,
            'key_destination': PG_SERVER_KEY_PATH,
            'ca_destination': PG_CA_CERT_PATH,
            'owner': POSTGRES_USER,
            'group': POSTGRES_GROUP,
            'key_perms': '400',
            'cert_perms': '444'
        }

        certificates.use_supplied_certificates(**cert_config)

    def replace_certificates(self):
        if (os.path.exists(constants.NEW_POSTGRESQL_CERT_FILE_PATH) or
                os.path.exists(constants.NEW_POSTGRESQL_CA_CERT_FILE_PATH)):
            logger.info(
                'Replacing certificates on the postgresql_server component')
            self._write_certs_to_config()
            if common.is_all_in_one_manager():
                if config[POSTGRESQL_SERVER][SSL_ENABLED]:
                    self.handle_all_in_one_certificates()
                    service.restart(POSTGRES_SERVICE_NAME, ignore_failure=True)
                    service.verify_alive(POSTGRES_SERVICE_NAME)

            else:
                self.handle_cluster_certificates()
                self._restart_etcd()
                service.restart('patroni')
                service.verify_alive('patroni')

    @staticmethod
    def _write_certs_to_config():
        if os.path.exists(constants.NEW_POSTGRESQL_CERT_FILE_PATH):
            config[POSTGRESQL_SERVER]['cert_path'] = \
                constants.NEW_POSTGRESQL_CERT_FILE_PATH
            config[POSTGRESQL_SERVER]['key_path'] = \
                constants.NEW_POSTGRESQL_KEY_FILE_PATH
        if os.path.exists(constants.NEW_POSTGRESQL_CA_CERT_FILE_PATH):
            config[POSTGRESQL_SERVER]['ca_path'] = \
                constants.NEW_POSTGRESQL_CA_CERT_FILE_PATH

    def validate_new_certs(self):
        if common.is_all_in_one_manager():
            if config[POSTGRESQL_SERVER][SSL_ENABLED]:
                certificates.get_and_validate_certs_for_replacement(
                    default_cert_location=PG_SERVER_CERT_PATH,
                    default_key_location=PG_SERVER_KEY_PATH,
                    default_ca_location=PG_CA_CERT_PATH,
                    default_ca_key_location=PG_CA_KEY_PATH,
                    new_cert_location=constants.NEW_POSTGRESQL_CERT_FILE_PATH,
                    new_key_location=constants.NEW_POSTGRESQL_KEY_FILE_PATH,
                    new_ca_location=constants.NEW_POSTGRESQL_CA_CERT_FILE_PATH,
                    new_ca_key_location=constants.
                    NEW_POSTGRESQL_CA_KEY_FILE_PATH
                )
        else:
            certificates.get_and_validate_certs_for_replacement(
                default_cert_location=ETCD_SERVER_CERT_PATH,
                default_key_location=ETCD_SERVER_KEY_PATH,
                default_ca_location=ETCD_CA_PATH,
                default_ca_key_location=ETCD_CA_KEY_PATH,
                new_cert_location=constants.NEW_POSTGRESQL_CERT_FILE_PATH,
                new_key_location=constants.NEW_POSTGRESQL_KEY_FILE_PATH,
                new_ca_location=constants.NEW_POSTGRESQL_CA_CERT_FILE_PATH,
                new_ca_key_location=constants.NEW_POSTGRESQL_CA_KEY_FILE_PATH
            )

    def _configure_cluster(self):
        logger.info('Disabling postgres (will be managed by patroni)')
        service.stop(POSTGRES_SERVICE_NAME)
        service.disable(POSTGRES_SERVICE_NAME)

        logger.info('Deploying cluster certificates')
        # We need access to the certs, which by default we don't have
        common.chmod('a+x', '/var/lib/patroni')

        self.handle_cluster_certificates()
        common.chmod('a-x', '/var/lib/patroni')

        logger.info('Deploying patroni initial startup monitor.')
        self._deploy_patroni_startup_check()

        logger.info('Deploying cluster config files.')
        self._create_patroni_config(PATRONI_CONFIG_PATH)
        common.chown('root', 'postgres', PATRONI_CONFIG_PATH)
        common.chmod('640', PATRONI_CONFIG_PATH)

        # The etcd name must match one of the cluster node IP/hostnames
        valid_names = [
            node['ip']
            for node in config[POSTGRESQL_SERVER]['cluster']['nodes'].values()
        ]
        private_ip = config[MANAGER][PRIVATE_IP]
        public_ip = config[MANAGER][PUBLIC_IP]
        if private_ip in valid_names or public_ip in valid_names:
            etcd_name_suffix = (
                private_ip if private_ip in valid_names else public_ip
            )
        else:
            hostname_lookup = {
                socket.gethostbyname(name): name
                for name in valid_names
            }
            if private_ip in hostname_lookup:
                etcd_name_suffix = hostname_lookup[private_ip]
            elif public_ip in hostname_lookup:
                etcd_name_suffix = hostname_lookup[public_ip]
            else:
                raise BootstrapError(
                    'Could not match this node with any cluster node '
                    'members. No members matched or could be resolved to '
                    'public IP {public} or private IP {private}. '
                    'Members were: {members}.'.format(
                        public=public_ip,
                        private=private_ip,
                        members=valid_names,
                    )
                )
        ip_urlized = network.ipv6_url_compat(private_ip)\
            if network.is_ipv6(private_ip)\
            else socket.gethostbyname(private_ip)
        cluster_nodes = {k: v for k, v in
                         config[POSTGRESQL_SERVER]['cluster']['nodes'].items()}
        for k, v in cluster_nodes.items():
            if 'ip' in v:
                v['ip'] = network.ipv6_url_compat(v['ip'])
        etcd_name_suffix = _ip_to_identifier(etcd_name_suffix)

        files.deploy(
            os.path.join(CONFIG_PATH, 'etcd.conf'), ETCD_CONFIG_PATH,
            additional_render_context={
                'ip': ip_urlized,
                'manager_private_ip': network.ipv6_url_compat(private_ip),
                'postgresql_server_cluster_nodes': cluster_nodes,
                'etcd_name_suffix': etcd_name_suffix,
            })
        common.chown('etcd', '', ETCD_CONFIG_PATH)
        common.chmod('440', ETCD_CONFIG_PATH)
        common.chown('postgres', '', '/var/lib/patroni')
        common.chmod('700', '/var/lib/patroni')
        common.chmod('700', '/var/lib/patroni/data')

        logger.info('Configuring logs')
        common.mkdir(PATRONI_LOG_PATH)
        common.mkdir(ETCD_LOG_PATH)
        common.mkdir(POSTGRES_LOG_PATH)
        common.chown('postgres', 'cfylogs', PATRONI_LOG_PATH)
        common.chown('postgres', 'cfylogs', POSTGRES_LOG_PATH)
        common.chmod('750', PATRONI_LOG_PATH)
        common.chmod('750', POSTGRES_LOG_PATH)

        syslog.deploy_rsyslog_filters('db_cluster', ['etcd', 'patroni'],
                                      logger)

        # create custom postgresql conf file with log settings
        fd, tmp_path = mkstemp()
        os.close(fd)
        pg_params = self._generate_pg_params(
            {'log_directory': "'{0}'".format(POSTGRES_LOG_PATH)})
        with open(tmp_path, 'w') as pg_conf:
            for name, value in pg_params.items():
                pg_conf.write("{0} = {1}\n".format(name, value))

        common.run(['mv', '-T', tmp_path, POSTGRES_PATRONI_CONFIG_PATH])
        common.run(['chown', 'postgres.', POSTGRES_PATRONI_CONFIG_PATH])

        logger.info('Configuring etcd')
        service.configure(
            'etcd',
            user='etcd',
            group='etcd',
            src_dir='postgresql_server',
            config_path='config/supervisord',
            external_configure_params={
                'ip': ip_urlized,
                'manager_private_ip': network.ipv6_url_compat(private_ip),
                'postgresql_server_cluster_nodes': cluster_nodes,
            }
        )
        self._start_etcd()

        try:
            if self._etcd_requires_auth():
                # Authentication is enabled, we should add this node to the
                # pg_hba in case this is being added to an existing cluster
                patroni_conf = self._get_patroni_dcs_conf(local_only=False)
                node_ip = private_ip
                look_for = ' {address} '.format(
                    address=self._format_pg_hba_address(node_ip))
                if not any(
                    look_for in entry
                    for entry in patroni_conf['postgresql']['pg_hba']
                ):
                    self._add_node_to_pg_hba(
                        pg_hba=patroni_conf['postgresql']['pg_hba'],
                        node=node_ip
                    )
                    self._set_patroni_dcs_conf(patroni_conf, local_only=False)

                # Handle joining a new node to an existing cluster
                # (post-install)
                etcd_members = self._etcd_command(
                    ['cluster-health'],
                    ignore_failures=True,
                ).aggr_stdout
                # Cluster health command queries on 2379...
                healthy_result = (
                    'healthy result from https://{ip}:2379'.format(
                        ip=network.ipv6_url_compat(node_ip))
                )
                if healthy_result not in etcd_members:
                    # ...but node should be added on 2380
                    etcd_node_address = 'https://{ip}:2380'.format(
                        ip=network.ipv6_url_compat(node_ip))
                    etcd_node_id = self._get_etcd_id(node_ip)
                    self._add_etcd_member(etcd_node_id, etcd_node_address)
                    common.run([
                        'sed', '-i',
                        's/ETCD_INITIAL_CLUSTER_STATE.*/'
                        "ETCD_INITIAL_CLUSTER_STATE='existing'/",
                        ETCD_CONFIG_PATH,
                    ])
                    files.remove(ETCD_DATA_DIR)
                    common.mkdir(ETCD_DATA_DIR)
                    common.chown('etcd', 'etcd', ETCD_DATA_DIR)
                    service.restart('etcd')
            else:
                # In case multiple nodes are being installed at the same time,
                # check whether we should be setting up auth
                should_configure_auth = False
                auth_setup_role = 'cloudifyauthsetup'

                # Try to create the role as a 'lock', as that's the only
                # command the etcdctl v2 provides that won't be 'helpful' and
                # succeed when it already exists.
                # We can't use etcd v3 api because patroni doesn't support it
                # yet.
                setup_role_exists = self._etcd_command(
                    ['role', 'add', auth_setup_role], ignore_failures=True,
                )
                if setup_role_exists.returncode != 0:
                    stderr = setup_role_exists.aggr_stderr.strip()
                    if 'already exists' in stderr:
                        logger.info(
                            'Another node is currently configuring etcd '
                            'authentication.'
                        )
                    elif 'Insufficient credentials' in stderr:
                        logger.info(
                            'Etcd auth is already configured.'
                        )
                else:
                    logger.info('Setting up etcd authentication.')
                    should_configure_auth = True

                if should_configure_auth:
                    cluster_config = config[POSTGRESQL_SERVER]['cluster']
                    # We want to configure etcd auth when the second node
                    # joins because that's the earliest we can do so.
                    logger.info('Configuring etcd authentication')
                    # Note that, per the etcd documentation, the root user
                    # must exist if authentication is to be enabled for etcd
                    self._etcd_command(
                        ['user', 'add', 'root'],
                        stdin=cluster_config['etcd']['root_password'],
                    )
                    self._etcd_command(
                        ['user', 'add', 'patroni'],
                        stdin=cluster_config['etcd']['patroni_password'],
                    )
                    self._etcd_command(['role', 'add', 'patroni'])
                    self._etcd_command(['role', 'grant', 'patroni',
                                        '--path', '/db/*', '--readwrite'])
                    self._etcd_command(['user', 'grant', 'patroni',
                                        '--roles', 'patroni'])
                    self._etcd_command(['role', 'add', 'guest'])
                    self._etcd_command(['role', 'revoke', 'guest',
                                        '--path', '/*', '--readwrite'])
                    self._etcd_command(['auth', 'enable'])
                    setup_role_exists = self._etcd_command(
                        ['role', 'remove', auth_setup_role],
                        username='root'
                    )
        except ClusteringError:
            logger.warning(
                'Could not finish etcd configuration. '
                'If the majority of cluster nodes are not yet installed then '
                'this warning can be ignored.'
            )

        logger.info('Creating postgres bin links for patroni')
        for pg_bin in PG_BINS:
            common.run(['ln', '-s', '-f', os.path.join(PG_BIN_DIR, pg_bin),
                        '/usr/sbin'])

        logger.info('Starting patroni')
        self._configure_patroni()
        service.enable('patroni')
        service.start('patroni')
        logger.info('Activating patroni initial startup monitor.')
        self._activate_patroni_startup_check()
        logger.info('Patroni started.')

    # Joining the cluster sometimes runs into problems while the cluster is
    # electing a leader, but just retrying makes it work.
    @retry(stop_max_attempt_number=15, wait_fixed=2000)
    def _add_etcd_member(self, etcd_node_id, etcd_node_address):
        add_result = self._etcd_command(
            [
                'member', 'add',
                etcd_node_id, etcd_node_address,
            ],
            username='root',
            ignore_failures=True,
        )
        if add_result.returncode == 0:
            return
        err = add_result.aggr_stderr
        if 'peerURL exists' in err:
            # This succeeded on a previous attempt
            return
        # Debug level logging because this is not unexpected
        logger.debug('Etcd member add failed: %s', err)
        raise BootstrapError(
            'Error was: {err}\n'
            'Failed to join etcd cluster. '
            'If this node is being reinstalled you may need '
            'to uninstall it then run the DB node '
            'removal command on a healthy DB node before '
            'attempting to install again.'.format(err=err)
        )

    def _get_etcd_members(self):
        """Get a dict mapping etcd member IPs to their IDs."""
        etcd_members = {}

        etcd_id_list = self._etcd_command(
            ['member', 'list'],
        ).aggr_stdout
        # Expected output style:
        # abc123def: name=etcd192_0_2_1 peerURLs=https://192.0.2.1:2380 clientURLs=https://192.0.2.1:2379 isLeader=false  # noqa
        # abc223def: name=etcd192_0_2_2 peerURLs=https://192.0.2.2:2380 clientURLs=https://192.0.2.2:2379 isLeader=false  # noqa
        # abc323def: name=etcd192_0_2_3 peerURLs=https://192.0.2.3:2380 clientURLs=https://192.0.2.3:2379 isLeader=false  # noqa
        member_regex = re.compile(
            # The ID is everything from the start of the line until the
            # first colon
            '^(?P<id>[^:]+):'
            '.*peerURLs=https://'
            # Then we just want to get the IP address from the peerURLs,
            # but we should support IPv6 addresses as well so we can't
            # just get everything until the next colon
            '(?P<ip>.+)'
            # Match on ':2380 clientURLs' to avoid greedily consuming too
            # much if someone manages to make the client listen on 2380 too
            ':2380 clientURLs'
        )
        # It would be much nicer to do this without ugly parsing, but etcdctl
        # on the version we're using now ignores the request for json output
        # when listing members

        for line in etcd_id_list.splitlines():
            line = line.strip()
            result = member_regex.match(line).groupdict()
            etcd_members[network.ipv6_url_strip(result['ip'])] = result['id']

        return etcd_members

    def _deploy_patroni_startup_check(self):
        files.deploy(
            os.path.join(SCRIPTS_PATH, 'patroni_startup_check'),
            '/opt/patroni/bin/patroni_startup_check',
            additional_render_context={
                'config_files': config['config_files'],
            }
        )
        common.chown('root', '', '/opt/patroni/bin/patroni_startup_check')
        common.chmod('500', '/opt/patroni/bin/patroni_startup_check')

    @staticmethod
    def _activate_patroni_startup_check():
        # Similarly to the current snapshot post restore commands, this will
        # continue to run after the installer finishes, until its task is
        # complete (patroni starts healthily)
        # WARNING: Do not use anything other than Popen, this must not block
        subprocess.Popen(['/opt/patroni/bin/patroni_startup_check'])

    def _create_patroni_config(self, patroni_config_path):
        manager_ip = config['manager'][PRIVATE_IP]
        pgsrv = config[POSTGRESQL_SERVER]

        hba_entries = ['hostssl replication replicator 127.0.0.1/32 md5']
        for node in config[POSTGRESQL_SERVER]['cluster']['nodes'].values():
            hba_entries.append(
                self._get_monitoring_user_hba_entry(node['ip']))
        hba_entries.extend([
            'hostssl all all 0.0.0.0/0 md5{0}'.format(
                ' clientcert=verify-full'
                if pgsrv['ssl_client_verification'] else '',
            ),
            'hostssl all all ::0/0 md5{0}'.format(
                ' clientcert=verify-full'
                if pgsrv['ssl_client_verification'] else '',
            ),
        ])

        patroni_name = _ip_to_identifier(manager_ip)
        ip_urlized = network.ipv6_url_compat(manager_ip)
        patroni_conf = {
            'scope': 'postgres',
            'namespace': '/db/',
            'log': {'dir': PATRONI_LOG_PATH},
            'name': 'pg{0}'.format(patroni_name),
            'restapi': {
                'listen': '{0}:8008'.format(ip_urlized),
                'connect_address': '{0}:8008'.format(ip_urlized),
                'authentication': {
                    'username': pgsrv['cluster']['patroni']['rest_user'],
                    'password': pgsrv['cluster']['patroni']['rest_password']
                },
                'cafile': PATRONI_DB_CA_PATH,
                'certfile': PATRONI_REST_CERT_PATH,
                'keyfile': PATRONI_REST_KEY_PATH,
            },
            'bootstrap': {
                'dcs': {
                    'ttl': 30,
                    'loop_wait': 10,
                    'retry_timeout': 10,
                    'maximum_lag_on_failover': 0,
                    'synchronous_mode': True,
                    'synchronous_mode_strict': True,
                    'check_timeline': True,
                    'postgresql': {
                        'pg_hba': hba_entries,
                        'parameters': {
                            'unix_socket_directories': '.',
                            'synchronous_commit': 'on',
                            'ssl': 'on',
                            'ssl_ca_file': PATRONI_DB_CA_PATH,
                            'ssl_cert_file': PATRONI_DB_CERT_PATH,
                            'ssl_key_file': PATRONI_DB_KEY_PATH,
                            'ssl_ciphers': 'HIGH',
                        },
                    },
                },
                'initdb': [{'encoding': 'UTF8'}, 'data-checksums']
            },
            'postgresql': {
                'listen': '{0}:5432'.format(ip_urlized),
                'connect_address': '{0}:5432'.format(ip_urlized),
                'data_dir': PATRONI_DATA_DIR,
                'pgpass': PATRONI_PGPASS_PATH,
                'log_file_mode': '0644',
                'authentication': {
                    'replication': {
                        'username': 'replicator',
                        'password': (
                            pgsrv['cluster']['postgres']['replicator_password']
                        ),
                        'sslmode': 'verify-full',
                        'sslrootcert': PATRONI_DB_CA_PATH,
                    },
                    'superuser': {
                        'username': 'postgres',
                        'password': pgsrv['postgres_password'],
                        'sslmode': 'verify-full',
                        'sslrootcert': PATRONI_DB_CA_PATH,
                    }
                },
                'custom_conf': POSTGRES_PATRONI_CONFIG_PATH,
                'use_pg_rewind': True,
                'remove_data_directory_on_rewind_failure': True,
                'remove_data_directory_on_diverged_timelines': True,
            },
            'tags': {
                'nofailover': False,
                'noloadbalance': False,
                'clonefrom': False,
                'nosync': False
            },
            'etcd': {
                'hosts': ['{0}:2379'.format(ip_urlized)],
                'protocol': 'https',
                'cacert': ETCD_CA_PATH,
                'username': 'patroni',
                'password': pgsrv['cluster']['etcd']['patroni_password']
            },
        }
        for node in pgsrv['cluster']['nodes'].values():
            self._add_node_to_pg_hba(
                patroni_conf['bootstrap']['dcs']['postgresql']['pg_hba'],
                node['ip']
            )
        common.run([
            'touch', patroni_config_path,
        ])
        common.chown(getuser(), '', patroni_config_path)
        yaml = YAML()
        yaml.default_flow_style = False
        with open(patroni_config_path, 'w') as f:
            yaml.dump(patroni_conf, f)

    @staticmethod
    def _format_pg_hba_address(address):
        """Format the address for use in pg_hba

        Postgresql expects the following in pg_hba:
         - for ipv4 addresses: ip/32
         - for ipv6 addresses: ip/128
         - for names: no postfix
        """
        parsed = network.parse_ip(address)
        if not parsed:  # name, not IP
            return address
        if parsed.version == 4:
            return '{0}/32'.format(address)
        elif parsed.version == 6:
            return '{0}/128'.format(address)
        else:
            raise ValueError('Unexpected IP version in {0}: {1}'
                             .format(address, parsed.version))

    def _add_node_to_pg_hba(self, pg_hba, node):
        address = self._format_pg_hba_address(node)
        pg_hba[:0] = [
            'hostssl all postgres {address} md5'.format(address=address),
            'hostssl replication replicator {address} md5'.format(
                address=address)
        ]

    def _get_cluster_addresses(self):
        master = None
        replicas = []
        if DATABASE_SERVICE in config[SERVICES_TO_INSTALL]:
            etcd_cluster_health = self._etcd_command(
                ['cluster-health'], ignore_failures=True
            ).aggr_stdout
            if (
                'cluster is unavailable' in etcd_cluster_health
                or 'failed to list members' in etcd_cluster_health
            ):
                raise DBNodeListError(
                    'Etcd is not responding on this node. '
                    'Please retry this command on another DB cluster node.'
                )

            nodes = self._get_etcd_members()

            master_dsn = self._patronictl_command(['dsn']).aggr_stdout
            # Expected response form:
            # host=192.0.2.1 port=5432
            master_finder = re.compile('host=(.*) port=5432')
            try:
                master = master_finder.findall(master_dsn)[0]
            except IndexError:
                master = None

            replicas = [node for node in nodes if node != master]
        elif MANAGER_SERVICE in config[SERVICES_TO_INSTALL]:
            manager_conf = files.read_yaml_file(
                '/opt/manager/cloudify-rest.conf')
            db_nodes = manager_conf['postgresql_host']
            master = db.select_db_host(logger)
            replicas = [node for node in db_nodes if node != master]
        else:
            raise DBNodeListError(
                'Can only list DB nodes from a manager or DB node.'
            )
        return master, replicas

    @staticmethod
    def _get_raw_node_status(address, target_type):
        if address is None:
            return

        url = {
            'etcd': 'https://{address}:2379/v2/stats/self',
            'DB': 'https://{address}:8008',
        }[target_type].format(address=network.ipv6_url_compat(address))

        dead_node_exceptions = (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
        )

        if DATABASE_SERVICE in config[SERVICES_TO_INSTALL]:
            # Using the etcd CA cert as it's the same, and the permissions
            # to its directory are more permissive than postgres', which does
            # not allow access even to the CA cert
            ca_path = ETCD_CA_PATH
        else:
            ca_path = constants.POSTGRESQL_CA_CERT_PATH

        try:
            return requests.get(
                url,
                verify=ca_path,
                timeout=5,
            ).json()
        except dead_node_exceptions as err:
            logger.warning(
                'Failed to get status of {target_type} node from {url}. '
                'Error was: {err}'.format(
                    target_type=target_type,
                    url=url,
                    err=err,
                )
            )
            return {}

    def _get_node_status(self, address,
                         sync_replica=False, master=False):
        status = self._get_raw_node_status(address, 'DB')
        etcd_status = self._get_raw_node_status(address, 'etcd')

        node = {
            'node_ip': address,
            'alive': False,
            'errors': [],
            'raw_status': status or {},
        }

        if status:
            xlog = status.get('xlog', {})
            if master:
                node['log_location'] = xlog.get('location')
                node['state'] = 'leader'
            elif sync_replica:
                node['log_location'] = xlog.get('replayed_location')
                node['state'] = 'sync_replica'
            else:
                node['log_location'] = xlog.get('replayed_location')
                node['state'] = 'async_replica'

            if status.get('state') == 'running':
                node['alive'] = True
            else:
                node['errors'].append('Node not running')

            if status.get('pause'):
                node['errors'].append('Failover disabled')

            node['timeline'] = status.get('timeline')
        else:
            node['state'] = 'dead'
            node['errors'].append('Could not retrieve DB status')

        if etcd_status:
            node['etcd_state'] = etcd_status['state']
        else:
            node['etcd_state'] = 'dead'
            node['errors'].append('Could not retrieve etcd status')

        return node

    @staticmethod
    def _get_sync_replicas(master_status):
        sync_nodes = []
        master_replication = master_status.get('replication', [])
        if master_replication:
            for replica in master_replication:
                if replica['sync_state'] == 'sync':
                    sync_nodes.append(replica['application_name'])
        return sync_nodes

    def _determine_cluster_status(self, db_nodes):
        status = self.HEALTHY
        master = db_nodes[0]
        replicas = db_nodes[1:]

        member_count = 1 + len(replicas)
        majority_requirement = member_count // 2

        master_log_location = master['raw_status'].get(
            'xlog', {}
        ).get('location')
        master_timeline = master['raw_status'].get('timeline')
        sync_nodes = self._get_sync_replicas(master['raw_status'])

        if master['node_ip'] is None:
            logger.error('No master found.')
            status = max(status, self.DOWN)
            db_nodes = replicas

        # Master checks
        if not master['alive']:
            status = max(status, self.DOWN)
        if not sync_nodes:
            logger.error('No synchronous replicas found.')
            # The cluster is down if there are no sync replicas, because
            # writes will not be allowed
            status = max(status, self.DOWN)

        # Etcd checks
        etcd_followers = 0
        etcd_leaders = 0
        for node in db_nodes:
            if node['etcd_state'] == 'StateFollower':
                etcd_followers += 1
            elif node['etcd_state'] == 'StateLeader':
                etcd_leaders += 1
        if etcd_leaders != 1:
            logger.error(
                'Expected to find 1 etcd leader, but found {num}, '
                'cluster consensus lost.'.format(
                    num=etcd_leaders,
                )
            )
            status = max(status, self.DOWN)
        if etcd_followers < majority_requirement:
            logger.error(
                'Insufficient etcd followers found, cluster consensus lost.'
            )
            status = max(status, self.DOWN)
        elif etcd_followers < len(replicas):
            logger.warning(
                'Missing one or more etcd followers.'
            )
            status = max(status, self.DEGRADED)

        for replica in replicas:
            if replica['state'] == 'sync_replica':
                if (
                    master_log_location
                    and replica.get('log_location') < master_log_location
                ):
                    logger.error(
                        'Synchronous replica not in sync with master. '
                        'Writes will be blocked until replica is in sync.'
                    )
                    replica['errors'].append('Out of sync')
                    status = max(status, self.DOWN)
            else:
                if (
                    master_timeline
                    and replica.get('timeline') != master_timeline
                ):
                    logger.warning(
                        'Asynchronous replica not on same timeline as '
                        'master.'
                    )
                    replica['errors'].append('Out of sync')
                    status = max(status, self.DEGRADED)
                replica_log_location = replica.get('log_location')
                if (master_log_location is None or
                        replica_log_location is None):
                    logger.warning(
                        'Could not get lag details for replica.'
                    )
                    replica['errors'].append('Could not get lag details.')
                else:
                    lag_bytes = master_log_location - replica_log_location
                    lag_mb = lag_bytes / 1024.0 / 1024.0
                    if lag_mb > 2:
                        logger.warning(
                            'Asynchronous replica appears to be lagging '
                            'excessively.'
                        )
                        replica['errors'].append('Lag: {amount:.2f}MiB'.format(
                            amount=lag_mb,
                        ))

            if replica['raw_status'].get('state') == 'master':
                # This should only happen if a failover happened literally as
                # the status check was taking place
                logger.error(
                    'MULTIPLE MASTERS DETECTED! '
                    'PLEASE RUN THIS STATUS COMMAND AGAIN. '
                    'IF THIS ERROR OCCURS AGAIN THEN STOP ALL USERS OF '
                    'CLOUDIFY MANAGERS IN THIS CLUSTER AND CONTACT SUPPORT!'
                )
                replica['errors'].append('EXTRA MASTER')

        return status, db_nodes

    def get_cluster_status(self):
        master_address, replica_addresses = self._get_cluster_addresses()

        master = self._get_node_status(master_address, master=True)
        replicas = []
        for address in replica_addresses:
            patroni_id = self._get_patroni_id(address)
            replicas.append(
                self._get_node_status(
                    address,
                    sync_replica=patroni_id in self._get_sync_replicas(
                        master['raw_status'],
                    ),
                )
            )
        db_nodes = [master] + replicas

        status, db_nodes = self._determine_cluster_status(db_nodes)

        return status, db_nodes

    @staticmethod
    def _db_user_exists(user):
        result = db.run_psql_command(
            "SELECT COUNT(*) FROM pg_catalog.pg_roles "
            "WHERE rolname = '{user}';".format(
                user=user,
            ),
            'server_db_name',
            logger,
        )

        # There can only be 0 or 1 of a particular named user
        return int(result) == 1

    @staticmethod
    def _node_is_in_db(host):
        result = db.run_psql_command(
            "SELECT COUNT(*) FROM db_nodes where host='{0}';".format(
                host,
            ),
            'cloudify_db_name',
            logger,
        )

        # As the name is a primary key, there can only ever be at most 1 entry
        # with the expected name
        return int(result) == 1

    @staticmethod
    def _add_node_to_db(host):
        db.run_psql_command(
            "INSERT INTO db_nodes (name, host) VALUES ('{0}', '{1}');".format(
                host, host
            ),
            'cloudify_db_name',
            logger,
        )

    @staticmethod
    def _remove_node_from_db(host):
        db.run_psql_command(
            "DELETE FROM db_nodes WHERE host = '{0}';".format(host),
            'cloudify_db_name',
            logger,
        )

    def add_cluster_node(self, address, stage, composer):
        if DATABASE_SERVICE in config[SERVICES_TO_INSTALL]:
            raise DBManagementError(
                'Database cluster nodes should be added to the cluster '
                'during install, by setting the appropriate entries in the '
                'config.yaml.'
            )

        master, replicas = self._get_cluster_addresses()

        if address in [master] + replicas:
            raise DBManagementError(
                'Cannot add DB node {addr} to cluster, as it is already '
                'part of the cluster.'.format(addr=address)
            )

        node_status = self._get_raw_node_status(address, 'DB')

        if not node_status:
            raise DBManagementError(
                'DB cluster node {address} does not appear to be '
                'operational. Please ensure DB cluster management '
                'software is installed and running before trying to '
                'add the node.'.format(address=address)
            )

        logger.info('Updating rest service configuration')
        manager_conf = files.read_yaml_file('/opt/manager/cloudify-rest.conf')
        manager_conf['postgresql_host'].append(address)
        files.update_yaml_file('/opt/manager/cloudify-rest.conf',
                               manager_conf)
        logger.info('Restarting rest service')
        service.restart('cloudify-restservice')

        logger.info('Setting UI DB configuration')
        stage.set_db_url()
        composer.update_composer_config()
        logger.info('Restarting UI services')
        service.restart('cloudify-stage')
        service.restart('cloudify-composer')

        # The new db node maybe exists in db_nodes table, because `dbs add`
        # command should run on each manager in a cluster
        if not self._node_is_in_db(address):
            self._add_node_to_db(address)
        return [master, address] + replicas

    def remove_cluster_node(self, address, stage, composer):
        master, replicas = self._get_cluster_addresses()

        if len(replicas) < 2:
            raise DBManagementError(
                'The last replica cannot be removed. A new replica must be '
                'added before removing the target node.'
            )

        if address == master:
            raise DBManagementError(
                'The currently active DB master node cannot be removed. '
                'Please set the master to a different node before retrying '
                'this command.'
            )

        if address not in replicas:
            raise DBManagementError(
                'Cannot find node with address{addr} for removal. '
                'The following nodes can be removed: {valid}'.format(
                    addr=address,
                    valid=', '.join(replicas),
                )
            )

        if DATABASE_SERVICE in config[SERVICES_TO_INSTALL]:
            member_id = self._get_etcd_members().get(address)

            logger.info(
                'Removing etcd node {name}'.format(name=address)
            )
            self._etcd_command(
                ['member', 'remove', member_id],
                username='root',
                local_only=True,
            )

            logger.info(
                'Updating pg_hba to remove {address}'.format(address=address)
            )
            patroni_config = self._get_patroni_dcs_conf()
            exclusion_string = ' {address} '.format(
                address=self._format_pg_hba_address(address))
            patroni_config['postgresql']['pg_hba'] = [
                entry for entry in patroni_config['postgresql']['pg_hba']
                if exclusion_string not in entry
            ]
            self._set_patroni_dcs_conf(patroni_config)
            logger.info('Node {addr} removed.'.format(addr=address))
        elif MANAGER_SERVICE in config[SERVICES_TO_INSTALL]:
            manager_conf = files.read_yaml_file(
                '/opt/manager/cloudify-rest.conf')
            logger.info('Updating rest service configuration')
            manager_conf['postgresql_host'].remove(address)
            files.update_yaml_file('/opt/manager/cloudify-rest.conf',
                                   manager_conf)
            logger.info('Restarting rest service')
            service.restart('cloudify-restservice')

            logger.info('Setting UI DB configuration')
            stage.set_db_url()
            composer.update_composer_config()
            logger.info('Restarting UI services')
            service.restart('cloudify-stage')
            service.restart('cloudify-composer')
            if self._node_is_in_db(address):
                self._remove_node_from_db(address)
        remaining = [master] + replicas
        remaining.remove(address)
        return remaining

    def reinit_cluster_node(self, address):
        master, replicas = self._get_cluster_addresses()

        if address == master:
            raise DBManagementError(
                'The currently active DB master node cannot be reinitialised.'
            )

        if address not in [master] + replicas:
            raise DBManagementError(
                'Cannot reinitialise DB node {addr}, as it is '
                'not part of the cluster.'.format(addr=address)
            )

        if DATABASE_SERVICE in config[SERVICES_TO_INSTALL]:
            logger.info('Reinitialising DB node {addr}'.format(addr=address))
            self._patronictl_command([
                'reinit', '--force',
                'postgres', self._get_patroni_id(address),
            ])
            logger.info('DB node {addr} reinitialised.'.format(addr=address))
        else:
            raise DBManagementError(
                'Reinitialise can only be run from a DB node.'
            )

    def _become_synchronous(self, candidate, master_address,
                            sync_nodes):
        for i in range(30):
            if sync_nodes and i % 5 == 0:
                # Retry this every 5 attempts. If there are more than 3 nodes
                # this gives a chance to have the target node become sync.
                logger.info(
                    'Attempting to promote {addr} to sync replica.'.format(
                        addr=candidate,
                    )
                )
                self._patronictl_command(['restart', '--force', 'postgres',
                                          sync_nodes[0]])
            master_status = self._get_node_status(master_address,
                                                  master=True)
            sync_nodes = self._get_sync_replicas(
                master_status['raw_status']
            )
            if sync_nodes:
                if self._get_patroni_id(candidate) in sync_nodes:
                    logger.info(
                        '{addr} has become synchronous replica.'.format(
                            addr=candidate,
                        )
                    )
                    break
                else:
                    raise DBManagementError(
                        '{addr} did not manage to become synchronous '
                        'replica. Before you retry, please ensure the DB '
                        'cluster is healthy and the managers are in '
                        'maintenance mode.'.format(addr=candidate)
                    )
            else:
                logger.info(
                    'Waiting for {addr} to become synchronous '
                    'replica.'.format(
                        addr=candidate,
                    )
                )
                time.sleep(1)

    def set_master(self, address):
        master_address, replicas = self._get_cluster_addresses()

        if DATABASE_SERVICE not in config[SERVICES_TO_INSTALL]:
            raise DBManagementError(
                'Set master can only be run from a DB node.'
            )

        if address == master_address:
            logger.info('The selected node is the current master.')
            return

        if address not in [master_address] + replicas:
            raise DBManagementError(
                'Cannot make DB node {addr} master, as it is '
                'not part of the cluster.'.format(addr=address)
            )

        master_status = self._get_node_status(master_address, master=True)
        sync_nodes = self._get_sync_replicas(master_status['raw_status'])
        if self._get_patroni_id(address) not in sync_nodes:
            # Patroni will only fail over to a synchronous replica, so we will
            # restart the current synchronous replica which will force the
            # current async replica to become synchronous
            logger.info(
                '{addr} is async replica. Only sync replicas can become '
                'master.'.format(
                    addr=address,
                )
            )
            self._become_synchronous(address, master_address,
                                     sync_nodes)

        for i in range(30):
            if i in [0, 10, 20]:
                # We will retry the command in case of timing issues, e.g.
                # after promoting an async replica to sync
                logger.info('Changing master to {addr}'.format(addr=address))
                self._patronictl_command([
                    'switchover', '--force',
                    '--candidate', self._get_patroni_id(address),
                ])
            master, _ = self._get_cluster_addresses()
            if master == address:
                break
            else:
                logger.info(
                    'Waiting for master to change to {addr}. '
                    'Current master is {master}.'.format(
                        addr=address,
                        master=master,
                    )
                )
                time.sleep(1)
        if master == address:
            logger.info('Master changed to {addr}'.format(addr=address))
        else:
            logger.warning(
                'Master has not changed to {addr}. '
                'Master is currently {master}. '
                'This may indicate the master changed to the specified '
                'node and then changed again, or that the change did not '
                'occur. Please check cluster health before retrying this '
                'operation.'.format(
                    addr=address,
                    master=master,
                )
            )

    def configure(self):
        logger.notice('Configuring PostgreSQL Server...')
        self._configure_postgresql_server_service()
        if config[POSTGRESQL_SERVER]['cluster']['nodes']:
            self._configure_cluster()
            service.remove(POSTGRES_SERVICE_NAME)
        else:
            self._init_postgresql_server()
            enable_remote_connections = \
                config[POSTGRESQL_SERVER][ENABLE_REMOTE_CONNECTIONS]
            self._update_configuration(enable_remote_connections)
            service.enable(POSTGRES_SERVICE_NAME)

        self.start()

        if not config[POSTGRESQL_SERVER]['cluster']['nodes']:
            if config[POSTGRESQL_SERVER][POSTGRES_PASSWORD]:
                self._update_postgres_password()

        if MONITORING_SERVICE in config[SERVICES_TO_INSTALL]:
            self._create_db_monitoring_account()
        logger.notice('PostgreSQL Server successfully configured')

    def remove(self):
        if MANAGER_SERVICE not in config[SERVICES_TO_INSTALL]:
            files.remove([
                '/var/lib/patroni',
                '/var/lib/etcd',
                '/etc/patroni.conf',
                '/etc/etcd',
            ])
        logger.notice('Removing PostgreSQL...')
        files.remove([
            '/var/lib/pgsql/14/data',
            '/var/lib/pgsql/14/backups'  # might be missing
        ], ignore_failure=True)
        files.remove_notice(POSTGRESQL_SERVER)
        if config[POSTGRESQL_SERVER]['cluster']['nodes']:
            service.remove('etcd')
            service.remove('patroni')
        else:
            service.remove(POSTGRES_SERVICE_NAME)
        logger.info('Removing postgres bin links')
        files.remove(
            [os.path.join('/usr/sbin', pg_bin) for pg_bin in PG_BINS],
            ignore_failure=True)

    def start(self):
        logger.notice('Starting PostgreSQL Server...')
        if config[POSTGRESQL_SERVER]['cluster']['nodes']:
            self._start_etcd()
            service.start('patroni')
            service.verify_alive('patroni')
        else:
            service.start(POSTGRES_SERVICE_NAME)
            service.verify_alive(POSTGRES_SERVICE_NAME)
        logger.notice('PostgreSQL Server successfully started')

    @staticmethod
    def _get_encoding_and_locale():
        encoding = common.run(
            ['psql', '-U', 'postgres', '-c', 'SHOW SERVER_ENCODING', '-t'],
        ).aggr_stdout.strip()

        locale = common.run(
            ['psql', '-U', 'postgres', '-c', 'SHOW LC_CTYPE', '-t'],
        ).aggr_stdout.strip()
        return encoding, locale

    def stop(self, force=True):
        logger.notice('Stopping PostgreSQL Server...')

        if config[POSTGRESQL_SERVER]['cluster']['nodes']:
            service.stop('etcd')
            service.stop('patroni')
        else:
            try:
                service.stop(POSTGRES_SERVICE_NAME)
            except ProcessExecutionError:
                service.stop(OLD_POSTGRES_SERVICE_NAME)
        logger.notice('PostgreSQL Server successfully stopped')

    def _upgrade_single_db(self):
        logger.debug('Configuring and initializing new PostgreSQL '
                     'service...')
        service.remove(OLD_POSTGRES_SERVICE_NAME)
        self._configure_postgresql_server_service()
        service.reread()
        self._init_postgresql_server(encoding=self.orig_encoding,
                                     locale=self.orig_locale)

        logger.debug('Upgrading PostgreSQL...')
        bindir = join(PGSQL_USR_DIR, 'bin')
        old_bindir = join(OLD_PGSQL_USR_DIR, 'bin')
        pg_upgrade = join(bindir, 'pg_upgrade')

        # `cwd=/tmp` because otherwise I get:
        #  could not open log file "pg_upgrade_internal.log": Permission denied
        res = common.run(
            ['sudo', '-u', 'postgres', pg_upgrade,
             '--old-bindir', old_bindir, '--new-bindir', bindir,
             '--old-datadir', OLD_PGSQL_DATA_DIR,
             '--new-datadir', PGSQL_DATA_DIR,
             '--link'],
            ignore_failures=True, cwd='/tmp'
        )
        if 'Upgrade Complete' not in res.aggr_stdout:
            raise ProcessExecutionError(
                f"Error upgrading PostgreSQL database:\n"
                f"{res.aggr_stdout}\n{res.aggr_stderr}")
        logger.info('PostgreSQL database upgrade complete!')

        service.enable(POSTGRES_SERVICE_NAME)

    def _upgrade_cluster_node(self):
        logger.notice('THIS WILL BE WHERE THINGS HAPPEN')

    def _get_pg_control_version(self, data_dir: str) -> str:
        result = common.run(
            ['/usr/sbin/pg_controldata', '-D', data_dir]
        ).aggr_stdout.strip()
        for line in result.splitlines():
            param, _, value = line.partition(':')
            if param == 'pg_control version number':
                return value.strip()
        raise ProcessExecutionError(
            'Could not detect postgres version.')

    def _postgres_needs_upgrade(self) -> bool:
        data_dir = '/var/lib/pgsql/9.5/data'
        if config[POSTGRESQL_SERVER]['cluster']['nodes']:
            data_dir = '/var/lib/patroni/data'

        if not os.path.exists(data_dir):
            return False

        expected_pg_control_version = '1300'
        current_pg_control_version = self._get_pg_control_version(data_dir)
        return expected_pg_control_version != current_pg_control_version

    def upgrade(self):
        if not self._postgres_needs_upgrade():
            logger.notice('Postgres version is up to date.')
            return

        logger.notice("Upgrading PostgreSQL database version...")
        if config[POSTGRESQL_SERVER]['cluster']['nodes']:
            self._upgrade_cluster_node()
        else:
            self._upgrade_single_db()

    @retry(stop_max_attempt_number=60, wait_fixed=1000)
    def _verify_postgres_stopped(self):
        assert not service.is_active(POSTGRES_SERVICE_NAME)

    def validate_dependencies(self):
        super(PostgresqlServer, self).validate_dependencies()


def _ip_to_identifier(ip):
    return ip.replace('.', '_').replace(':', '_')
