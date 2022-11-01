import itertools
import time

import requests

from cfy_manager.utils.common import (
    is_all_in_one_manager,
    run,
    service_is_in_config,
)
from ..config import config
from cfy_manager.constants import (
    POSTGRESQL_CA_CERT_PATH,
    POSTGRESQL_CLIENT_CERT_PATH,
    POSTGRESQL_CLIENT_KEY_PATH,
    POSTGRESQL_CLIENT_SU_CERT_PATH,
    POSTGRESQL_CLIENT_SU_KEY_PATH,
)

from cfy_manager.service_names import (
    DATABASE_SERVICE,
    POSTGRESQL_CLIENT,
    POSTGRESQL_SERVER,
)
from cfy_manager.components_constants import (
    ETCD_CA_PATH,
    PATRONI_DB_CA_PATH,
    SSL_CLIENT_VERIFICATION,
    SSL_ENABLED,
)
from cfy_manager.exceptions import BootstrapError
from cfy_manager.utils import files
from cfy_manager.utils.network import ipv6_url_compat, ipv6_url_strip


def run_psql_command(command, db_key, logger):
    db_env, base_command = get_psql_env_and_base_command(logger, db_key)

    # Run psql with just the results output without headers (-t),
    # no psqlrc (-X), and not storing history (-n),
    # and exit with non-zero status if a provided query/command fails
    base_command.extend(['-t', '-X', '-n', '-v', 'ON_ERROR_STOP=1'])

    result = run(base_command, env=db_env, stdin=command)
    return result.aggr_stdout.strip()


def get_psql_env_and_base_command(logger, db_key='cloudify_db_name',
                                  db_override=None):
    base_command = []
    pg_config = config[POSTGRESQL_CLIENT]
    pg_cluster_nodes = config[POSTGRESQL_SERVER]['cluster']['nodes']
    peer_authentication = False

    if service_is_in_config(DATABASE_SERVICE) and not pg_cluster_nodes:
        # In case the default user is postgres and we're in AIO installation,
        # or if we're installing a single database node,
        # "peer" authentication is used
        if pg_config['server_username'] == 'postgres':
            base_command.extend(['/usr/bin/sudo', '-E', '-u', 'postgres'])
            peer_authentication = True

    base_command.append('/usr/bin/psql')

    db_kwargs = {}
    if db_key == 'cloudify_db_name' and not peer_authentication:
        db_kwargs['username'] = pg_config['cloudify_username']
        db_kwargs['password'] = pg_config['cloudify_password']

    db_name = db_override or pg_config[db_key]

    db_env = generate_db_env(db_name, logger, **db_kwargs)

    if peer_authentication:
        db_env.pop('PGHOST')

    return db_env, base_command


def generate_db_env(database, logger, username=None, password=None):
    pg_config = config[POSTGRESQL_CLIENT]
    host = select_db_host(logger)

    db_env = {
        'PGHOST': ipv6_url_strip(host),
        'PGUSER': username or pg_config['server_username'],
        'PGPASSWORD': (
            password
            or pg_config['server_password']
            or config[POSTGRESQL_SERVER]['postgres_password']
        ),
        'PGDATABASE': database,
    }

    if pg_config[SSL_ENABLED]:
        db_env['PGSSLMODE'] = 'verify-full'

        if (
            service_is_in_config(DATABASE_SERVICE)
            and config[POSTGRESQL_SERVER]['cluster']['nodes']
        ):
            ca_path = PATRONI_DB_CA_PATH
        else:
            ca_path = POSTGRESQL_CA_CERT_PATH

        db_env['PGSSLROOTCERT'] = ca_path

        # This only makes sense if SSL is used
        if pg_config[SSL_CLIENT_VERIFICATION]:
            if db_env['PGUSER'] == pg_config['server_username']:
                db_env['PGSSLCERT'] = POSTGRESQL_CLIENT_SU_CERT_PATH
                db_env['PGSSLKEY'] = POSTGRESQL_CLIENT_SU_KEY_PATH
            else:
                db_env['PGSSLCERT'] = POSTGRESQL_CLIENT_CERT_PATH
                db_env['PGSSLKEY'] = POSTGRESQL_CLIENT_KEY_PATH
    else:
        # If we're not using SSL then we should fail if we try to talk to an
        # ssl-enabled server, rather than leaking credentials on an untrusted
        # connection
        db_env['PGSSLMODE'] = 'disable'
    return db_env


def select_db_host(logger):

    if is_all_in_one_manager():
        # If we're connecting to the actual local db we don't need to supply a
        # host
        return ''

    client_config = config[POSTGRESQL_CLIENT]
    server_config = config[POSTGRESQL_SERVER]

    if server_config['cluster']['nodes']:
        cluster_nodes = [
            node['ip'] for node in server_config['cluster']['nodes'].values()]
        max_attempts = 10
        delay = 2
        attempt = 1
        for i, candidate in enumerate(itertools.cycle(cluster_nodes)):
            result = None
            if service_is_in_config(DATABASE_SERVICE):
                # Use the etcd CA if this is a DB node as it'll be readable
                ca_path = ETCD_CA_PATH
            else:
                # Otherwise, use the postgrs client cert
                ca_path = POSTGRESQL_CA_CERT_PATH
            try:
                result = requests.get(
                    'https://{}:8008'.format(ipv6_url_compat(candidate)),
                    verify=ca_path,
                )
            except Exception as err:
                logger.error(
                    'Error trying to get state of DB %s: %s', candidate, err)

            if result:
                logger.debug(
                    'Checking DB for leader selection. %s has status %s',
                    candidate,
                    result.status_code,
                )
                if result.status_code == 200:
                    logger.debug('Selected %s as DB leader', candidate)
                    return candidate

            if i and i % len(cluster_nodes) == 0:
                # No DB found after trying all once, wait before trying again
                time.sleep(delay)
                if attempt == max_attempts:
                    raise BootstrapError(
                        'No DB leader found in {} attempts.'.format(
                            max_attempts,
                        )
                    )
                logger.info('No active DB found yet. Attempt %s/%s',
                            attempt, max_attempts)
                attempt += 1
    else:
        return client_config['host']


def get_postgres_host():
    rest_config = files.read_yaml_file('/opt/manager/cloudify-rest.conf')
    if rest_config:
        cluster_nodes = rest_config['postgresql_host']
    else:
        cluster_nodes = [
            db['ip'] for db in
            config[POSTGRESQL_SERVER]['cluster']['nodes'].values()
        ]

    if cluster_nodes:
        return cluster_nodes
    return config[POSTGRESQL_CLIENT]['host']


def get_ui_db_dialect_options_and_url(database, certs):
    conn_string = 'postgres://{username}:{password}@{host}:{port}/{db}{params}'
    postgres_host = get_postgres_host()

    # For building URL string
    params = {}

    dialect_options = {}
    if config[POSTGRESQL_CLIENT][SSL_ENABLED]:
        params.update({
            'sslmode': 'verify-full',
            'sslrootcert': certs['ca'],
        })

        dialect_options['ssl'] = {
            'ca': certs['ca'],
            'rejectUnauthorized': True,
        }

        if config[POSTGRESQL_CLIENT][SSL_CLIENT_VERIFICATION]:
            params.update({
                'sslcert': certs['cert'],
                'sslkey': certs['key'],
            })

            dialect_options['ssl']['cert'] = certs['cert']
            dialect_options['ssl']['key'] = certs['key']
    else:
        dialect_options['ssl'] = False

    if any(params.values()):
        params = '?' + '&'.join('{0}={1}'.format(key, value)
                                for key, value in params.items()
                                if value)
    else:
        params = ''

    if isinstance(postgres_host, list):
        return dialect_options, [
            conn_string.format(
                username=config[POSTGRESQL_CLIENT]['cloudify_username'],
                password=config[POSTGRESQL_CLIENT]['cloudify_password'],
                host=ipv6_url_compat(host),
                port=5432,
                db=database,
                params=params,
            )
            for host in postgres_host
        ]
    host, _, port = postgres_host.rpartition(':')
    if not port.isdigit():
        host = postgres_host
        port = '5432'
    return dialect_options, conn_string.format(
        username=config[POSTGRESQL_CLIENT]['cloudify_username'],
        password=config[POSTGRESQL_CLIENT]['cloudify_password'],
        host=host,
        port=port,
        db=database,
        params=params,
    )
