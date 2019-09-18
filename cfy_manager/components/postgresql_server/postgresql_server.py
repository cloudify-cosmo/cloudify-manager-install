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

import json
import os
import re
import time
from tempfile import mkstemp
from os.path import join, isdir, islink

import requests

from cfy_manager.exceptions import DBNodeListError, DBManagementError
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
from ..base_component import BaseComponent
from ..service_components import MANAGER_SERVICE, DATABASE_SERVICE
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

HAPROXY_NODE_ENTRY = (
    '    server postgresql_{addr}_5432 {addr}:5432 '
    'maxconn 100 check check-ssl port 8008 ca-file /etc/haproxy/ca.crt'
)

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

    # Status codes for listing nodes
    HEALTHY = 0
    DEGRADED = 1
    DOWN = 2

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

        include_line = "include = '{config}'".format(config=PG_CONF_PATH)
        already_included = common.sudo(
            ['grep', include_line, PG_BASE_CONF_PATH],
            ignore_failures=True,
        ).returncode == 0
        if not already_included:
            common.sudo(
                ['tee', '-a', PG_BASE_CONF_PATH],
                stdin="{include}\n".format(include=include_line),
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

    def _etcd_conf_command(self, command, ignore_failures=False, stdin=None):
        """Execute an etcdctl command at configure time.
        Not to be used for day 2 operations as config.yaml may be out of date.
        """
        endpoints = ','.join(
            'https://{addr}:2379'.format(addr=addr)
            for addr in config[POSTGRESQL_SERVER]['cluster']['nodes']
        )
        etcdctl_base_command = [
            'etcdctl', '--endpoints', endpoints,
            '--ca-file', ETCD_CA_PATH,
        ]
        return common.run(
            etcdctl_base_command + command,
            ignore_failures=ignore_failures,
            stdin=stdin,
        )

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
        cluster_auth_check = self._etcd_conf_command(['ls', '/'],
                                                     ignore_failures=True)
        # This command will only succeed if the cluster is up and auth is not
        # yet enabled
        if cluster_auth_check.returncode == 0:
            cluster_config = config[POSTGRESQL_SERVER]['cluster']
            # We want to configure etcd auth when the second node joins
            # because that's the earliest we can do so.
            logger.info('Configuring etcd authentication')
            # Note that, per the etcd documentation, the root user must exist
            # if authentication is to be enabled for etcd
            self._etcd_conf_command(
                ['user', 'add', 'root'],
                stdin=cluster_config['etcd']['root_password'],
            )
            self._etcd_conf_command(
                ['user', 'add', 'patroni'],
                stdin=cluster_config['etcd']['patroni_password'],
            )
            self._etcd_conf_command(['role', 'add', 'patroni'])
            self._etcd_conf_command(['role', 'grant', 'patroni',
                                     '--path', '/db/*', '--readwrite'])
            self._etcd_conf_command(['user', 'grant', 'patroni',
                                     '--roles', 'patroni'])
            self._etcd_conf_command(['role', 'add', 'guest'])
            self._etcd_conf_command(['role', 'revoke', 'guest',
                                     '--path', '/*', '--readwrite'])
            self._etcd_conf_command(['auth', 'enable'])

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

    def _get_cluster_addresses(self):
        master = None
        replicas = []
        if DATABASE_SERVICE in config[SERVICES_TO_INSTALL]:
            etcd_cluster_health = common.run(
                [
                    'etcdctl',
                    '--endpoint', 'https://127.0.0.1:2379',
                    '--ca-file', ETCD_CA_PATH,
                    'cluster-health',
                ],
                ignore_failures=True
            ).aggr_stdout
            if (
                'cluster is unavailable' in etcd_cluster_health
                or 'failed to list members' in etcd_cluster_health
            ):
                raise DBNodeListError(
                    'Etcd is not responding on this node. '
                    'Please retry this command on another DB cluster node.'
                )

            nodes = json.loads(common.sudo([
                '/opt/patroni/bin/patronictl', '-c', '/etc/patroni.conf',
                'list', '--format', 'json'
            ]).aggr_stdout)
            for node in nodes:
                server_name = node['Host']
                if node['Role'] == 'Leader':
                    master = server_name
                else:
                    replicas.append(server_name)
        elif MANAGER_SERVICE in config[SERVICES_TO_INSTALL]:
            backends = common.get_haproxy_servers(self.logger)
            for backend in backends:
                # svname will be in the form postgresql_192.0.2.48_5432
                server_name = backend['svname'].split('_')[1]
                if backend['status'] == 'UP':
                    master = server_name
                else:
                    replicas.append(server_name)
        else:
            raise DBNodeListError(
                'Can only list DB nodes from a manager or DB node.'
            )
        return master, replicas

    def _get_raw_node_status(self, address, target_type):
        url = {
            'etcd': 'https://{address}:2379/v2/stats/self',
            'DB': 'https://{address}:8008',
        }[target_type].format(address=address)

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
                    address=address,
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
            'raw_status': status,
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

    def _get_sync_replicas(self, master_status):
        sync_ips = []
        master_replication = master_status.get('replication', [])
        if master_replication:
            for replica in master_replication:
                if replica['sync_state'] == 'sync':
                    sync_ips.append(replica['client_addr'])
        return sync_ips

    def _determine_cluster_status(self, db_nodes):
        status = self.HEALTHY
        master = db_nodes[0]
        replicas = db_nodes[1:]

        master_log_location = master['raw_status'].get('log_location')
        master_timeline = master['raw_status'].get('timeline')
        sync_ips = self._get_sync_replicas(master['raw_status'])

        # Master checks
        if not master['alive']:
            status = max(status, self.DOWN)
        if not sync_ips:
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
        if etcd_followers < 1:
            logger.error(
                'No etcd followers found, cluster consensus lost.'
            )
            status = max(status, self.DOWN)
        elif etcd_followers < 2:
            logger.warning(
                'Missing one etcd follower.'
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
            replicas.append(
                self._get_node_status(
                    address,
                    sync_replica=address in self._get_sync_replicas(
                        master['raw_status'],
                    ),
                )
            )
        db_nodes = [master] + replicas

        status, db_nodes = self._determine_cluster_status(db_nodes)

        return status, db_nodes

    def add_cluster_node(self, address):
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

        if DATABASE_SERVICE in config[SERVICES_TO_INSTALL]:
            raise NotImplementedError('Coming soon.')
        else:
            common.sudo(
                ['tee', '-a', '/etc/haproxy/haproxy.cfg'],
                stdin=HAPROXY_NODE_ENTRY.format(addr=address),
            )

            logger.info('Restarting DB proxy service.')
            common.sudo(['systemctl', 'restart', 'haproxy'])

    def remove_cluster_node(self, address, force=False):
        master, replicas = self._get_cluster_addresses()

        if address == master and not force:
            raise DBManagementError(
                'The currently active DB master node cannot be removed '
                "without the '--force' flag."
            )

        if address not in [master] + replicas:
            raise DBManagementError(
                'Cannot remove DB node {addr} from cluster, as it is not '
                'part of the cluster.'.format(addr=address)
            )

        if DATABASE_SERVICE in config[SERVICES_TO_INSTALL]:
            raise NotImplementedError('Coming soon.')
        else:
            entry = HAPROXY_NODE_ENTRY.format(addr=address).replace(
                '/', '\\/',
            )
            common.sudo(
                [
                    'sed', '-i',
                    '/{entry}/d'.format(entry=entry),
                    '/etc/haproxy/haproxy.cfg',
                ]
            )

            logger.info('Restarting DB proxy service.')
            common.sudo(['systemctl', 'restart', 'haproxy'])

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
            rpms = [
                sources['etcd_rpm_url'],
                sources['patroni_rpm_url'],
            ]
            if files.check_rpms_are_present(rpms):
                for rpm in rpms:
                    yum_install(rpm)
            else:
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
