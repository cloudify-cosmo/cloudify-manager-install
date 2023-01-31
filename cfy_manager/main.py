#!/usr/bin/env python
from __future__ import print_function

import os
import re
import sys
import time
import json
import subprocess
import pkg_resources
from platform import architecture
from tempfile import NamedTemporaryFile
from traceback import format_exception
import zipfile

import argh

from . import components
from .components import (
    MANAGER_SERVICE,
    QUEUE_SERVICE,
    DATABASE_SERVICE,
    MONITORING_SERVICE,
    ENTROPY_SERVICE,
    sources,
)
from .components_constants import (
    SECURITY,
    PUBLIC_IP,
    PRIVATE_IP,
    ADMIN_PASSWORD,
    SERVICES_TO_INSTALL,
    UNCONFIGURED_INSTALL,
)
from .components.globals import set_globals
from cfy_manager.utils.common import output_table
from .service_names import (
    CLI,
    COMPOSER,
    MANAGER,
    POSTGRESQL_SERVER,
    SANITY,
    AMQP_POSTGRES,
    MGMTWORKER,
    STAGE,
    MAIN_SERVICES_NAMES,
)
from .components.validations import (validate,
                                     validate_dependencies,
                                     _get_os_distro)
from .config import config
from .constants import (
    VERBOSE_HELP_MSG,
    CLOUDIFY_HOME_DIR,
    SUPERVISORD_CONFIG_DIR,
    NEW_CERTS_TMP_DIR_PATH,
    CONFIG_FILE_HELP_MSG,
    INITIAL_INSTALL_DIR,
    INITIAL_CONFIGURE_DIR,
    INSTALLED_COMPONENTS,
    INSTALLED_PACKAGES,
    USER_CONFIG_PATH,
    CA_CERT_FILENAME,
    EXTERNAL_CA_CERT_FILENAME,
    EXTERNAL_CA_CERT_PATH,
)
from .encryption.encryption import update_encryption_key
from .exceptions import BootstrapError
from .logger import (
    get_logger,
    setup_console_logger,
)
from .networks.networks import add_networks
from .accounts import reset_admin_password
from .utils import CFY_UMASK, service
from .utils.certificates import (
    clean_certs,
    create_internal_certs,
    create_external_certs,
    generate_ca_cert,
    _generate_ssl_certificate,
)
from .utils.common import (
    run,
    chown,
    copy,
    can_lookup_hostname,
    is_all_in_one_manager,
    get_main_services_from_config,
    service_is_configured,
    service_is_in_config,
)
from cfy_manager.utils.db import get_psql_env_and_base_command
from .utils.install import (
    is_package_installed,
    is_premium_installed,
    yum_install,
    yum_remove
)
from .utils.files import (
    remove as remove_files,
    remove_temp_files,
    touch,
    read_yaml_file,
    update_yaml_file,
)
from cfy_manager.utils.install_state import (
    get_configured_services,
    get_installed_services,
)
import xmlrpc.client

logger = get_logger('Main')

STARTER_SERVICE = 'cloudify-starter'
START_TIME = time.time()
TEST_CA_ROOT_PATH = os.path.expanduser('~/.cloudify-test-ca')
TEST_CA_CERT_PATH = os.path.join(TEST_CA_ROOT_PATH, 'ca.crt')
TEST_CA_KEY_PATH = os.path.join(TEST_CA_ROOT_PATH, 'ca.key')

TEST_CA_GENERATE_SAN_HELP_TEXT = (
    'Comma separated list of names or IPs that the generated certificate '
    'should be valid for. '
    'The first SAN entered will be the certificate name and used as the CN.'
)
ADMIN_PASSWORD_HELP_MSG = (
    'The password of the Cloudify Manager system administrator. '
)
ONLY_INSTALL_HELP_MSG = (
    'Whether to only perform the install, and not configuration. '
    'Intended to be used to create images for joining to clusters. '
    'If this is set then all packages will be installed but configuration '
    'will not be performed. `cfy_manager configure` will need to be run '
    'before the manager is usable.'
)
PRIVATE_IP_HELP_MSG = (
    "The private IP of the manager. This is the address which will be "
    "used by the manager's internal components. It is also the "
    "default address through which agents connect to the manager."
)
PUBLIC_IP_HELP_MSG = (
    'The public IP of the manager. This is the IP through which users '
    'connect to the manager via the CLI, the UI or the REST API. '
    'If your environment does not require a public IP, you can enter the '
    'private IP here.'
)
BROKER_ADD_JOIN_NODE_HELP_MSG = (
    "The hostname of the node you are joining to the rabbit cluster. "
    "This node must be resolvable via DNS or a hosts file entry. "
    "If not using a rabbit@<hostname> nodename, the prefix should also be "
    "supplied."
)
BROKER_REMOVE_NODE_HELP_MSG = (
    "Broker node to remove. Before removal, the target broker must be taken "
    "offline by stopping its service or shutting down its host."
)
DB_NODE_ADDRESS_HELP_MSG = (
    "Address of target DB cluster node."
)
DB_SHELL_DBNAME_HELP_MSG = (
    "Which DB to connect to using DB shell"
)
DB_SHELL_QUERY_HELP_MSG = (
    "Optional query to run with the DB shell. If this is provided, the query "
    "will be run and then the command will exit."
)
VALIDATE_HELP_MSG = (
    "Validate the provided certificates. If this flag is on, then the "
    "certificates will only be validated and not replaced."
)
INPUT_PATH_MSG = (
    "The replace-certificates yaml configuration file path."
)
LOGS_SKIP_DB_HELP_MSG = (
    'Get cluster node addresses from config instead of DB.'
)
LOCAL_LOGS_HELP_MSG = (
    'Get local logs archive.'
)

config_arg = argh.arg('-c', '--config-file', action='append', default=None,
                      help=CONFIG_FILE_HELP_MSG)
private_ip_arg = argh.arg('--private-ip', help=PRIVATE_IP_HELP_MSG)
public_ip_arg = argh.arg('--public-ip', help=PUBLIC_IP_HELP_MSG)
admin_password_arg = argh.arg('-a', '--admin-password',
                              help=ADMIN_PASSWORD_HELP_MSG)


@argh.decorators.arg('-s', '--sans', help=TEST_CA_GENERATE_SAN_HELP_TEXT,
                     required=True)
def generate_test_cert(**kwargs):
    """Generate keys with certificates signed by a test CA.
    Not for production use. """
    setup_console_logger()
    sans = kwargs['sans'].split(',')
    if not os.path.exists(TEST_CA_CERT_PATH):
        print('CA cert not found, generating CA certs.')
        run(['mkdir', '-p', TEST_CA_ROOT_PATH])
        generate_ca_cert(TEST_CA_CERT_PATH, TEST_CA_KEY_PATH)

    cn = sans[0]

    cert_path = os.path.join(TEST_CA_ROOT_PATH, '{cn}.crt'.format(cn=cn))
    key_path = os.path.join(TEST_CA_ROOT_PATH, '{cn}.key'.format(cn=cn))
    try:
        _generate_ssl_certificate(
            sans,
            cn,
            cert_path,
            key_path,
            TEST_CA_CERT_PATH,
            TEST_CA_KEY_PATH,
        )
    except Exception as err:
        sys.stderr.write(
            'Certificate creation failed: {err_type}- {msg}\n'.format(
                err_type=type(err),
                msg=str(err),
            )
        )
        raise

    print(
        'Created cert and key:\n'
        '  {cert}\n'
        '  {key}\n'
        '\n'
        'CA cert: {ca_cert}'.format(
            cert=cert_path,
            key=key_path,
            ca_cert=TEST_CA_CERT_PATH,
        )
    )


@argh.named('add')
@config_arg
@argh.decorators.arg('-j', '--join-node', help=BROKER_ADD_JOIN_NODE_HELP_MSG,
                     required=True)
@argh.decorators.arg('-v', '--verbose', help=VERBOSE_HELP_MSG,
                     default=False)
def brokers_add(**kwargs):
    """Add a new broker to the broker cluster. This should not be done while
    the manager cluster has any running executions.
    Use the cfy command afterwards to register it with the manager cluster.
    """
    setup_console_logger(verbose=kwargs['verbose'])
    config.load_config(kwargs.get('config_file'))
    _validate_components_prepared('brokers_add', kwargs.get('config_file'))
    _validate_supported_services_configured('brokers_add', [QUEUE_SERVICE])
    join_node = kwargs['join_node']
    rabbitmq = components.RabbitMQ()

    nodes = rabbitmq.list_rabbit_nodes()
    complain_about_dead_broker_cluster(nodes)
    if len(nodes['nodes']) > 1:
        logger.error(
            'This node is already in a rabbit cluster. '
            'The brokers-add command must be run on the node that is joining '
            'the rabbit cluster, not one of the existing members.'
        )
        sys.exit(1)

    if not can_lookup_hostname(join_node):
        logger.error(
            'Could not get address for "{node}".\n'
            'Node must be resolvable by DNS or as a hosts entry.'.format(
                node=join_node,
            )
        )
        sys.exit(1)
    rabbitmq.join_cluster(join_node, restore_users_on_fail=True)


@argh.named('remove')
@config_arg
@argh.decorators.arg('-r', '--remove-node', help=BROKER_REMOVE_NODE_HELP_MSG,
                     required=True)
@argh.decorators.arg('-v', '--verbose', help=VERBOSE_HELP_MSG,
                     default=False)
def brokers_remove(**kwargs):
    """Remove a lost broker from the broker cluster. This should not be done
    while the manager cluster has any running executions. This should only be
    done with a broker that has been verified uninstalled or otherwise
    destroyed.
    Use the cfy command afterwards to unregister it from the manager cluster.
    """
    setup_console_logger(verbose=kwargs['verbose'])
    config.load_config(kwargs.get('config_file'))
    _validate_components_prepared('brokers_remove', kwargs.get('config_file'))
    _validate_supported_services_configured('brokers_remove', [QUEUE_SERVICE])
    rabbitmq = components.RabbitMQ()

    remove_node = rabbitmq.add_missing_nodename_prefix(kwargs['remove_node'])
    nodes = rabbitmq.list_rabbit_nodes()
    complain_about_dead_broker_cluster(nodes)

    if remove_node in nodes['running_nodes']:
        logger.error(
            'Broker nodes to be removed must be shut down. '
            'If you recently shut down the node, please wait up to one '
            'minute before re-running this command.'
        )
        sys.exit(1)

    if remove_node not in nodes['nodes']:
        logger.error(
            'Broker node {node_name} not found in cluster. '
            'Valid nodes are: {nodes}'.format(
                node_name=remove_node,
                nodes=', '.join(sorted(nodes['nodes'])),
            )
        )
        sys.exit(1)

    rabbitmq.remove_node(remove_node)
    logger.info('Broker {node} removed from cluster.'.format(
        node=remove_node,
    ))


@argh.named('list')
@config_arg
@argh.decorators.arg('-v', '--verbose', help=VERBOSE_HELP_MSG,
                     default=False)
def brokers_list(**kwargs):
    """List brokers in the broker cluster.
    Use the cfy command to list brokers registered with the manager cluster.
    """
    setup_console_logger(verbose=kwargs['verbose'])
    config.load_config(kwargs.get('config_file'))
    _validate_components_prepared('brokers_list', kwargs.get('config_file'))
    _validate_supported_services_configured('brokers_list', [QUEUE_SERVICE])
    rabbitmq = components.RabbitMQ()

    brokers = rabbitmq.list_rabbit_nodes()
    complain_about_dead_broker_cluster(brokers)
    output_columns = ('broker_name', 'running', 'alarms')
    output_rows = []
    for node in sorted(brokers['nodes']):
        output_rows.append({
            'broker_name': node,
            'running': node in brokers['running_nodes'],
            'alarms': ', '.join(brokers['alarms'].get(node, [])),
        })

    output_table(output_rows, output_columns)


def complain_about_dead_broker_cluster(nodes):
    if not nodes:
        logger.error(
            'Broker node status could not be determined. This may mean that '
            'the broker cluster has failed. '
            'Please try to recover enough cluster nodes to make a majority '
            'be online. '
            'If this is not possible, please contact support.'
        )
        sys.exit(1)


@argh.named('list')
@config_arg
@argh.decorators.arg('-v', '--verbose', help=VERBOSE_HELP_MSG,
                     default=False)
def db_node_list(**kwargs):
    """List DB cluster members and DB cluster health."""
    setup_console_logger(verbose=kwargs['verbose'])
    config.load_config(kwargs.get('config_file'))
    _validate_components_prepared('db_cluster_list', kwargs.get('config_file'))
    _validate_supported_services_configured(
        'db_cluster_list', [DATABASE_SERVICE, MANAGER_SERVICE])

    db = components.PostgresqlServer()

    if config[POSTGRESQL_SERVER]['cluster']['nodes']:
        state, db_nodes = db.get_cluster_status()
        if state == db.HEALTHY:
            logger.info('DB cluster is healthy.')
        elif state == db.DEGRADED:
            logger.warning('DB cluster is unhealthy.')
        else:
            logger.error('DB cluster is down.')
        output_table(db_nodes,
                     ('node_ip', 'state', 'alive', 'etcd_state', 'errors'))
        sys.exit(state)
    else:
        logger.info('There is no database cluster associated with this node.')


@argh.named('add')
@config_arg
@argh.decorators.arg('-v', '--verbose', help=VERBOSE_HELP_MSG,
                     default=False)
@argh.decorators.arg('-a', '--address', help=DB_NODE_ADDRESS_HELP_MSG,
                     required=True)
def db_node_add(**kwargs):
    """Add a DB cluster node."""
    setup_console_logger(verbose=kwargs['verbose'])
    config.load_config(kwargs.get('config_file'))
    _validate_components_prepared('db_node_add', kwargs.get('config_file'))
    _validate_supported_services_configured(
        'db_node_add', [DATABASE_SERVICE, MANAGER_SERVICE])
    db = components.PostgresqlServer()
    client = components.PostgresqlClient()
    stage = components.Stage()
    composer = components.Composer()
    if config[POSTGRESQL_SERVER]['cluster']['nodes']:
        hosts = db.add_cluster_node(kwargs['address'], stage, composer)
        client.create_postgres_pgpass_files(
            hosts=hosts,
        )
    else:
        logger.info('There is no database cluster associated with this node.')


@argh.named('remove')
@config_arg
@argh.decorators.arg('-v', '--verbose', help=VERBOSE_HELP_MSG,
                     default=False)
@argh.decorators.arg('-a', '--address', help=DB_NODE_ADDRESS_HELP_MSG,
                     required=True)
def db_node_remove(**kwargs):
    """Remove a DB cluster node."""
    setup_console_logger(verbose=kwargs['verbose'])
    config.load_config(kwargs.get('config_file'))
    _validate_components_prepared('db_node_remove', kwargs.get('config_file'))
    _validate_supported_services_configured(
        'db_node_remove', [DATABASE_SERVICE, MANAGER_SERVICE])
    db = components.PostgresqlServer()
    client = components.PostgresqlClient()
    stage = components.Stage()
    composer = components.Composer()
    if config[POSTGRESQL_SERVER]['cluster']['nodes']:
        hosts = db.remove_cluster_node(kwargs['address'],
                                       stage,
                                       composer)
        client.create_postgres_pgpass_files(
            hosts=hosts,
        )
    else:
        logger.info('There is no database cluster associated with this node.')


@argh.named('reinit')
@config_arg
@argh.decorators.arg('-v', '--verbose', help=VERBOSE_HELP_MSG,
                     default=False)
@argh.decorators.arg('-a', '--address', help=DB_NODE_ADDRESS_HELP_MSG,
                     required=True)
def db_node_reinit(**kwargs):
    """Re-initialise an unhealthy DB cluster node."""
    setup_console_logger(verbose=kwargs['verbose'])
    config.load_config(kwargs.get('config_file'))
    _validate_components_prepared('db_node_reinit', kwargs.get('config_file'))
    _validate_supported_services_configured(
        'db_node_reinit', [DATABASE_SERVICE, MANAGER_SERVICE])
    db = components.PostgresqlServer()
    if config[POSTGRESQL_SERVER]['cluster']['nodes']:
        db.reinit_cluster_node(kwargs['address'])
    else:
        logger.info('There is no database cluster associated with this node.')


@argh.named('set-master')
@config_arg
@argh.decorators.arg('-v', '--verbose', help=VERBOSE_HELP_MSG,
                     default=False)
@argh.decorators.arg('-a', '--address', help=DB_NODE_ADDRESS_HELP_MSG,
                     required=True)
def db_node_set_master(**kwargs):
    """Switch the current DB master node."""
    setup_console_logger(verbose=kwargs['verbose'])
    config.load_config(kwargs.get('config_file'))
    _validate_components_prepared(
        'db_node_set_master', kwargs.get('config_file'))
    _validate_supported_services_configured(
        'db_node_set_master', [DATABASE_SERVICE, MANAGER_SERVICE])
    db = components.PostgresqlServer()
    if config[POSTGRESQL_SERVER]['cluster']['nodes']:
        db.set_master(kwargs['address'])
    else:
        logger.info('There is no database cluster associated with this node.')


@argh.named('shell')
@config_arg
@argh.decorators.arg('-v', '--verbose', help=VERBOSE_HELP_MSG,
                     default=False)
@argh.decorators.arg('-d', '--dbname', help=DB_SHELL_DBNAME_HELP_MSG,
                     default='cloudify_db')
@argh.decorators.arg('query', nargs='?', help=DB_SHELL_QUERY_HELP_MSG)
def db_shell(**kwargs):
    """Access the current DB leader using psql"""
    setup_console_logger(verbose=kwargs['verbose'])
    config.load_config(kwargs.get('config_file'))
    if service_is_in_config(MANAGER_SERVICE):
        db_env, command = get_psql_env_and_base_command(
            logger, db_override=kwargs['dbname'])
        if kwargs['query']:
            command += ['-c', kwargs['query']]
        os.execve(command[0], command, db_env)
    else:
        logger.error(
            'DB shell is only accessible with the installed manager config.')


@argh.named('fetch')
@config_arg
@argh.decorators.arg('-v', '--verbose', help=VERBOSE_HELP_MSG, default=False)
@argh.decorators.arg('-s', '--skip-db', help=LOGS_SKIP_DB_HELP_MSG,
                     default=False)
@argh.decorators.arg('-l', '--local', help=LOCAL_LOGS_HELP_MSG, default=False)
def logs_fetch(**kwargs):
    """Download logs from all cloudify managers/dbs/brokers."""
    setup_console_logger(verbose=kwargs['verbose'])
    sudo_user = os.environ.get('SUDO_USER')

    if kwargs['local']:
        zip_file = NamedTemporaryFile(prefix='cfylogs_local', suffix='.zip',
                                      delete=False)
        zip_file.close()

        zip_path = zip_file.name
        logs_dir = '/var/log/cloudify'

        # Inspired by the shutil._make_zipfile; we should use that when it
        # supports symlinks
        with zipfile.ZipFile(zip_path, "w",
                             compression=zipfile.ZIP_DEFLATED) as zf:
            path = os.path.normpath(logs_dir)
            if path != os.curdir:
                zf.write(path, path)
            for dirpath, dirnames, filenames in os.walk(logs_dir,
                                                        followlinks=True):
                for name in sorted(dirnames):
                    path = os.path.normpath(os.path.join(dirpath, name))
                    zf.write(path, path)
                for name in filenames:
                    path = os.path.normpath(os.path.join(dirpath, name))
                    if os.path.isfile(path):
                        zf.write(path, path)

        if sudo_user:
            chown(sudo_user, '', zip_path)
        logger.notice(f'Local logs collected in {zip_path}')
        return

    config.load_config(kwargs.get('config_file'))
    if service_is_configured(MANAGER_SERVICE):
        if is_all_in_one_manager():
            # We could log an error, but since we add the monitoring service
            # by default, we might as well just allow it.
            nodes = {config[MANAGER][PRIVATE_IP]}
        else:
            nodes = _get_all_nodes_from_config(config, logger,
                                               kwargs['skip_db'])
        nodes = {node for node in nodes if node}
        if nodes:
            logger.debug('Checking cluster nodes: %s', ','.join(nodes))
            credentials = config['prometheus']['credentials']
            log_bundle = run(
                ['/opt/mgmtworker/scripts/fetch-logs', '-a', ','.join(nodes)],
                env={'MONITORING_USERNAME': credentials['username'],
                     'MONITORING_PASSWORD': credentials['password']},
            ).aggr_stdout
            if sudo_user:
                chown(sudo_user, '', log_bundle.strip())
            logger.notice(f'Logs downloaded to {log_bundle}')
        else:
            logger.error('No nodes found. Ensure the correct config is used.')
    else:
        logger.error('Log fetching can only be performed with the installed '
                     'manager config.')


def _get_all_nodes_from_config(config, logger, skip_db=False):
    if skip_db:
        logger.warning('Cluster nodes will be loaded from config. '
                       'All brokers and DBs should be included, but only '
                       'the current manager will be included.')
        # We naively grab all the nodes from the config here in case this is
        # being run when the db is down.
        manager_nodes = {config[MANAGER][PRIVATE_IP]}
        postgres_nodes = {
            node['ip']
            for node in config[POSTGRESQL_SERVER]['cluster']['nodes'].values()
        }
        rabbit_nodes = {
            node['networks']['default']
            for node in config['rabbitmq']['cluster_members'].values()
        }
    else:
        monitoring_config = components.restservice.db.get_monitoring_config()
        manager_nodes = set(monitoring_config['manager_nodes'])
        postgres_nodes = set(monitoring_config['db_nodes'])
        rabbit_nodes = set(monitoring_config['rabbitmq_nodes'].values())
    logger.debug('Found manager nodes: %s', ','.join(manager_nodes))
    logger.debug('Found DB nodes: %s', ','.join(postgres_nodes))
    logger.debug('Found broker nodes: %s', ','.join(rabbit_nodes))

    return manager_nodes | postgres_nodes | rabbit_nodes


def _print_time():
    running_time = time.time() - START_TIME
    m, s = divmod(running_time, 60)
    logger.notice(
        'Finished in {0} minutes and {1} seconds'.format(int(m), int(s))
    )


def _exception_handler(type_, value, traceback):
    remove_temp_files()

    error = type_.__name__
    if str(value):
        error = '{0}: {1}'.format(error, str(value))
    logger.error(error)
    debug_traceback = ''.join(format_exception(type_, value, traceback))
    logger.debug(debug_traceback)


sys.excepthook = _exception_handler


def _populate_and_validate_config_values(private_ip, public_ip,
                                         admin_password):
    manager_config = config[MANAGER]

    if private_ip:
        manager_config[PRIVATE_IP] = private_ip
    if public_ip:
        manager_config[PUBLIC_IP] = public_ip
    if admin_password:
        manager_config[SECURITY][ADMIN_PASSWORD] = admin_password


def _prepare_execution(verbose=False,
                       private_ip=None,
                       public_ip=None,
                       admin_password=None,
                       only_install=False,
                       config_file=None):
    setup_console_logger(verbose)

    config.load_config(config_file)
    if not only_install:
        # We don't validate anything that applies to the install anyway,
        # but we do populate things that are not relevant.
        _populate_and_validate_config_values(private_ip, public_ip,
                                             admin_password)


def _print_finish_message(config_file=None):
    if service_is_in_config(MANAGER_SERVICE):
        manager_config = config[MANAGER]
        public_ip = manager_config[PUBLIC_IP] or manager_config[PRIVATE_IP]
        protocol = \
            'https' if config[MANAGER][SECURITY]['ssl_enabled'] else 'http'
        public_ip_message = 'Manager is up at {protocol}://{ip}'.format(
            protocol=protocol,
            ip=public_ip,
        )
        password = config[MANAGER][SECURITY][ADMIN_PASSWORD]
        use_message = (
            'cfy profiles use {ip} -u admin -p {password} -t default_tenant'
            .format(
                ip=public_ip,
                password=password,
            )
        )
        if protocol == 'https':
            if os.path.exists(EXTERNAL_CA_CERT_PATH):
                cert_filename = EXTERNAL_CA_CERT_FILENAME
            else:
                cert_filename = CA_CERT_FILENAME
            use_message += ' -ssl -c path/to/' + cert_filename

        print('#' * 50)
        if public_ip:
            print(public_ip_message)
        print('Admin password: {0}'.format(password))
        print('#' * 50)
        if public_ip:
            print('To connect to the manager, use:')
            print(use_message)
            print('#' * 50)
        print("To install the default plugins bundle run:")
        print("'cfy plugins bundle-upload'")
        print('#' * 50)


def _all_services_installed():
    return all(service_name in get_installed_services()
               for service_name in config[SERVICES_TO_INSTALL])


def _all_services_configured():
    return all(service_name in get_configured_services()
               for service_name in config[SERVICES_TO_INSTALL])


def _create_initial_install_files():
    """
    If the installation finished successfully for the first time,
    create the file /etc/cloudify/.installed/<service_name>.
    """
    if not _all_services_installed():
        for service_name in config[SERVICES_TO_INSTALL]:
            touch(os.path.join(INITIAL_INSTALL_DIR, service_name))


def _create_initial_configure_files():
    """
    If the configuration finished successfully for the first time,
    create the file /etc/cloudify/.configured/<service_name>.
    """
    if not _all_services_configured():
        for service_name in config[SERVICES_TO_INSTALL]:
            touch(os.path.join(INITIAL_CONFIGURE_DIR, service_name))


def _finish_configuration(only_install):
    remove_temp_files()
    _create_initial_install_files()
    if not only_install:
        _create_initial_configure_files()
    _print_time()


def _validate_components_prepared(cmd, config_path):
    error_message = (
         'Files in {configure_dir} do not match configured services.\n'
         'Make sure you use the correct config file (currently used: '
         '{config_path}).\n'
         'This can also mean you need to run `cfy_manager configure` '
         'before running `cfy_manager {cmd}`.'
     )
    if not _all_services_configured() and cmd != 'configure':
        raise BootstrapError(
            error_message.format(
                configure_dir=INITIAL_CONFIGURE_DIR,
                config_path=(config_path or USER_CONFIG_PATH),
                cmd=cmd
            )
        )


def _validate_supported_services_configured(cmd, supported_services):
    if not any(x in get_configured_services() for x in supported_services):
        raise BootstrapError(
            'Running `cfy_manager {cmd}` requires at least one of {services} '
            'to be configured on this node'.format(
                cmd=cmd,
                services=supported_services
            )
        )


def _get_components(include_components=None,
                    only_configured=False):
    """Get the component objects based on the config.

    This looks at the config, and returns only the component objects
    that are supposed to be installed(/configured/started/removed).

    All the "should we install this" config checks are done here.
    """
    if only_configured:
        check = service_is_configured
    else:
        check = service_is_in_config

    _components = [components.Rsyslog()]

    if check(ENTROPY_SERVICE):
        _components += [components.Haveged()]

    if check(DATABASE_SERVICE):
        _components += [components.PostgresqlServer()]

    if check(QUEUE_SERVICE):
        _components += [components.RabbitMQ()]

    if check(MANAGER_SERVICE):
        _components += [
            components.Manager(),
            components.PostgresqlClient(),
            components.RestService(),
            components.Nginx(),
            components.AmqpPostgres(),
            components.MgmtWorker(),
        ]
        if not config[STAGE]['skip_installation']:
            _components += [components.Stage()]
        if (
            is_premium_installed()
            and not config[COMPOSER]['skip_installation']
        ):
            _components += [components.Composer()]
        _components += [
            components.ExecutionScheduler(),
            components.UsageCollector(),
        ]
        if not config[CLI]['skip_installation']:
            _components += [components.Cli()]

    if check(MONITORING_SERVICE):
        _components += [components.Prometheus()]
        if not check(MANAGER_SERVICE):
            _components += [components.Nginx()]

    if (
        check(MANAGER_SERVICE)
        and not config[SANITY]['skip_sanity']
    ):
        _components += [components.Sanity()]

    if include_components:
        _components = _filter_components(_components, include_components)
    return _components


def _filter_components(components, include_components):
    """Filter the components list based on the includes given by the user.

    This allows `cfy_manager start --include-components amqp_postgres`,
    which should only then start amqppostgres and nothing else.

    This translates "amqp_postgres" -> "amqppostgres", and then filters
    the components by class name.
    """
    include_components = {
        name.lower().replace('_', '') for name in include_components
    }
    return [
        component for component in components
        if component.__class__.__name__.lower() in include_components
    ]


def install_args(f):
    """Apply all the args that are used by `cfy_manager install`"""
    args = [
        private_ip_arg, public_ip_arg, admin_password_arg, config_arg]
    for arg in args:
        f = arg(f)
    return f


@argh.decorators.named('validate')
@install_args
def validate_command(verbose=False,
                     private_ip=None,
                     public_ip=None,
                     admin_password=None,
                     config_file=None):
    _prepare_execution(
        verbose,
        private_ip,
        public_ip,
        admin_password,
        config_file=config_file,
    )
    components = _get_components()
    validate(components=components)
    validate_dependencies(components=components)


@argh.arg('--private-ip', help=PRIVATE_IP_HELP_MSG)
@config_arg
def sanity_check(verbose=False, private_ip=None, config_file=None):
    """Run the Cloudify Manager sanity check"""
    _prepare_execution(
        verbose=verbose,
        private_ip=private_ip,
        config_file=config_file,
    )
    sanity = components.Sanity()
    with sanity.sanity_check_mode():
        sanity.run_sanity_check()


def _get_packages():
    """Yum packages to install/uninstall, based on the current config"""
    packages = ['rsyslog']
    packages_per_service_dict = {}
    # Adding premium components on all, even if we're on community, because
    # yum will return 0 (success) if any packages install successfully even if
    # some of the specified packages don't exist.
    _, rh_version = _get_os_distro()
    if service_is_in_config(MANAGER_SERVICE):
        manager_packages = sources.manager
        # RedHat version-specific packages
        if rh_version == "7":
            manager_packages += sources.manager_rh7
        elif rh_version == "8":
            manager_packages += sources.manager_rh8
        # Premium components
        manager_packages += sources.manager_cluster + sources.manager_premium
        packages += manager_packages
        packages_per_service_dict[MANAGER_SERVICE] = manager_packages

    if service_is_in_config(DATABASE_SERVICE):
        db_packages = sources.db
        # Premium components
        db_packages += sources.db_cluster
        packages += db_packages
        packages_per_service_dict[DATABASE_SERVICE] = db_packages

    if service_is_in_config(QUEUE_SERVICE):
        queue_packages = sources.queue
        if rh_version == "8" and architecture() == "x86_64":
            queue_packages += sources.queue_rh8_x86
        else:
            queue_packages += sources.queue_other
        # Premium components
        queue_packages += sources.queue_cluster
        packages += queue_packages
        packages_per_service_dict[QUEUE_SERVICE] = queue_packages

    if service_is_in_config(MONITORING_SERVICE):
        monitoring_packages = sources.prometheus
        # Premium components
        monitoring_packages += sources.prometheus_cluster
        packages += monitoring_packages
        for main_service in packages_per_service_dict:
            packages_per_service_dict[main_service] += monitoring_packages

    if service_is_in_config(ENTROPY_SERVICE):
        packages += sources.haveged
        for main_service in packages_per_service_dict:
            packages_per_service_dict[main_service] += sources.haveged

    return packages, packages_per_service_dict


def _configure_supervisord():
    # These services will be relevant for using supervisord on VM not on
    # containers
    is_active = run('systemctl is-active supervisord',
                    ignore_failures=True
                    ).aggr_stdout.strip()
    if is_active not in ('active', 'activating'):
        run('systemctl enable supervisord.service', ignore_failures=True)
        run('systemctl restart supervisord', ignore_failures=True)


def _create_components_installed_file(components_list):
    installed_components_names = [component.__class__.__name__.lower()
                                  for component in components_list]
    for service_name in config[SERVICES_TO_INSTALL]:
        if service_name in MAIN_SERVICES_NAMES:
            update_yaml_file(INSTALLED_COMPONENTS,
                             {service_name: installed_components_names})


@argh.arg('--only-install', help=ONLY_INSTALL_HELP_MSG, default=False)
@install_args
def install(verbose=False,
            private_ip=None,
            public_ip=None,
            admin_password=None,
            only_install=None,
            config_file=None):
    """ Install Cloudify Manager """

    _prepare_execution(
        verbose,
        private_ip,
        public_ip,
        admin_password,
        config_file=config_file,
        only_install=only_install,
    )
    logger.notice('Installing desired components...')
    set_globals(only_install=only_install)
    packages_to_install, packages_per_service_dict = _get_packages()
    update_yaml_file(INSTALLED_PACKAGES, packages_per_service_dict)
    yum_install(packages_to_install)

    _configure_supervisord()

    components = _get_components()
    validate(components=components, only_install=only_install)
    validate_dependencies(components=components)

    _create_components_installed_file(components)
    for component in components:
        component.install()

    if not only_install:
        for component in components:
            component.configure()

    config[UNCONFIGURED_INSTALL] = only_install
    logger.notice('Installation finished successfully!')
    _finish_configuration(only_install)
    if not only_install:
        _print_finish_message(config_file=config_file)


@install_args
def configure(verbose=False,
              private_ip=None,
              public_ip=None,
              admin_password=None,
              config_file=None,
              print_finish_message=False):
    """ Configure Cloudify Manager """

    _prepare_execution(
        verbose,
        private_ip,
        public_ip,
        admin_password,
        config_file=config_file,
    )

    if not _all_services_installed():
        raise BootstrapError(
            'Not all services {services_to_install} are installed.\n'
            'You may need to run `cfy_manager install` first.\nAlso make sure '
            'you use the correct config file (currently used: '
            '{config_path}).\n'.format(
                services_to_install=config[SERVICES_TO_INSTALL],
                config_path=(config_file or USER_CONFIG_PATH),
            )
        )
    _validate_components_prepared('configure', config_file)
    logger.notice('Configuring desired components...')
    components = _get_components()
    validate(components=components)
    set_globals()

    _configure_supervisord()

    for component in components:
        component.configure()

    config[UNCONFIGURED_INSTALL] = False
    logger.notice('Configuration finished successfully!')
    _finish_configuration(only_install=False)
    if print_finish_message:
        _print_finish_message(config_file=config_file)


def _all_main_services_removed():
    if os.path.exists(INSTALLED_PACKAGES):
        installed_components_dict = read_yaml_file(INSTALLED_PACKAGES)
        return all(not packages_list for packages_list in
                   installed_components_dict.values())
    else:
        return True


def _remove_installation_files():
    for dir_path in INITIAL_INSTALL_DIR, INITIAL_CONFIGURE_DIR:
        for installed_service in get_main_services_from_config():
            service_file_path = os.path.join(dir_path, installed_service)
            if os.path.exists(service_file_path):
                remove_files(service_file_path)

    if _all_main_services_removed():
        remove_files([INITIAL_INSTALL_DIR, INITIAL_CONFIGURE_DIR])


def _get_items_to_remove(items_file):
    """
    :param items_file: Either INSTALLED_COMPONENTS or INSTALLED_PACKAGES.
    :return: A list of items (components or packages) that can be removed
             without affecting the remaining services.

    We use lists instead of sets to keep the items' order.
    """
    items_to_remove = []
    items_dict = read_yaml_file(items_file)
    removed_services = get_main_services_from_config()
    # We must base this on configured services to avoid partially removing
    # (e.g.) nginx but leaving its package behind, which will break reinstall.
    remaining_services = (set(get_configured_services())
                          - set(removed_services))

    for removed_service in removed_services:
        for item in items_dict[removed_service]:
            if item in items_to_remove:
                continue
            if remaining_services:
                if all(item not in items_dict.get(remaining_service, [])
                       for remaining_service in remaining_services):
                    items_to_remove.append(item)
            else:
                items_to_remove.append(item)

    return items_to_remove


@config_arg
def remove(verbose=False, config_file=None):
    """ Uninstall Cloudify Manager """

    _prepare_execution(verbose, config_file=config_file)

    removed_services = [service_name.split('_')[0].capitalize() for
                        service_name in get_main_services_from_config()]

    logger.notice('Removing Cloudify %s...', (
        'Manager' if is_all_in_one_manager() else ', '.join(removed_services)))

    if os.path.exists(INSTALLED_COMPONENTS):
        components_to_remove = list(reversed(_get_components(
            include_components=_get_items_to_remove(INSTALLED_COMPONENTS))))
        logger.debug('Removing following components: %s',
                     [component.__class__.__name__ for component
                      in components_to_remove])

        should_stop = _all_services_configured()
        for component in components_to_remove:
            if should_stop:
                component.stop()
            component.remove()

        for installed_service in get_main_services_from_config():
            update_yaml_file(INSTALLED_COMPONENTS, {installed_service: []})
    else:
        logger.debug('No components to remove')

    if os.path.exists(INSTALLED_PACKAGES):
        yum_remove(_get_items_to_remove(INSTALLED_PACKAGES))
        for installed_service in get_main_services_from_config():
            update_yaml_file(INSTALLED_PACKAGES, {installed_service: []})
    else:
        logger.debug('No packages to remove')

    _remove_installation_files()

    if _all_main_services_removed():
        remove_files(SUPERVISORD_CONFIG_DIR)

    clean_certs()

    logger.notice('Cloudify %s successfully removed!', (
        'Manager' if is_all_in_one_manager() else ', '.join(removed_services)))
    _print_time()


@argh.arg('include_components', nargs='*')
@install_args
def start(include_components,
          verbose=False,
          private_ip=None,
          public_ip=None,
          admin_password=None,
          config_file=None,
          only_install=None):
    """ Start Cloudify Manager services """
    _prepare_execution(
        verbose,
        private_ip,
        public_ip,
        admin_password,
        config_file=config_file,
    )
    _validate_components_prepared('start', config_file)
    set_globals()
    logger.notice('Starting Cloudify Manager services...')
    service.reread()
    for component in _get_components(include_components):
        component.start()
    logger.notice('Cloudify Manager services successfully started!')
    _print_time()


@argh.arg('include_components', nargs='*')
@config_arg
def stop(include_components, verbose=False, config_file=None):
    """ Stop Cloudify Manager services """
    _prepare_execution(verbose, config_file=config_file)
    _validate_components_prepared('stop', config_file)

    logger.notice('Stopping Cloudify Manager services...')
    for component in _get_components(include_components):
        component.stop()
    logger.notice('Cloudify Manager services successfully stopped!')
    _print_time()


@argh.arg('include_components', nargs='*')
@config_arg
def restart(include_components, verbose=False, config_file=None):
    """ Restart Cloudify Manager services """

    _prepare_execution(verbose, config_file=config_file)
    _validate_components_prepared('restart', config_file)
    service.reread()
    components = _get_components(include_components)
    for component in components:
        component.stop()
    for component in components:
        component.start()
    _print_time()


@private_ip_arg
@public_ip_arg
@config_arg
def upgrade(verbose=False, private_ip=None, public_ip=None, config_file=None):
    """Update the current manager using the available yum repos."""
    _prepare_execution(verbose, private_ip, public_ip,
                       config_file=config_file)
    _validate_components_prepared('restart', config_file)
    components = _get_components()
    validate(components=components, only_install=False)
    upgrade_components = _get_components()
    packages_to_update, _ = _get_packages()
    run(['yum', 'clean', 'all'],
        stdout=sys.stdout, stderr=sys.stderr)

    _handle_erlang_package_change(packages_to_update)

    run([
        'yum', 'update', '-y', '--disablerepo=*', '--enablerepo=cloudify'
    ] + packages_to_update, stdout=sys.stdout, stderr=sys.stderr)
    for component in reversed(upgrade_components):
        component.stop(force=False)
    set_globals()
    service.reread()
    for component in upgrade_components:
        component.upgrade()
        component.start()


def _handle_erlang_package_change(packages_to_update):
    """
    In CM 7.0 for RedHat/Centos 7 we started using esl-erlang rather than
    just erlang. In that case, we uninstall the existing erlang package using
    `rpm -e` (`yum remove` also uninstalls dependencies, which we don't want),
    otherwise we get a dependency conflict when trying to install esl-erlang.
    """
    if 'esl-erlang' in packages_to_update and is_package_installed('erlang'):
        packages_to_update.remove('esl-erlang')
        erlang_pkg = run(['rpm', '-q', 'erlang']).aggr_stdout.strip()
        run(['rpm', '-e', '--nodeps', erlang_pkg],
            stdout=sys.stdout, stderr=sys.stderr)
        yum_install(['esl-erlang'])


def _get_starter_service_response():
    server = xmlrpc.client.Server(
        'http://',
        transport=service.UnixSocketTransport("/var/run/supervisord.sock"))
    try:
        status_response = server.supervisor.getProcessInfo(STARTER_SERVICE)
    except xmlrpc.client.Fault as e:
        raise BootstrapError(
            'Error {0} while trying to lookup {1}'.format(e, STARTER_SERVICE)
        )
    return status_response


def _is_supervisord_service_finished():
    status_response = _get_starter_service_response()
    service_status = status_response['statename']
    exit_status = status_response['exitstatus']
    if service_status == 'EXITED':
        if exit_status != 0:
            raise BootstrapError(
                '{0} service exit with error status '
                'code {1}'.format(STARTER_SERVICE, exit_status)
            )
        return True
    return False


class _FileFollow(object):
    """Follow a text file and print lines from it.

    Like tail -F, but as resilient as possible. tail -F will give up
    when a file doesn't exist on some filesystems ()
    """
    def __init__(self, filename):
        self._filename = filename
        self._offset = 0

    def seek_to_end(self):
        """Set the initial file offset.

        If the file doesn't exist or is otherwise inaccessible, keep
        the default offset of 0.
        """
        try:
            with open(self._filename) as f:
                f.seek(0, 2)
                self._offset = f.tell()
        except IOError:
            pass

    def poll(self):
        """Try and read all new lines from the file.

        If we can't access the file, just do nothing. Maybe it will
        become available later.
        """
        try:
            with open(self._filename) as f:
                f.seek(self._offset)
                while True:
                    line = f.readline()
                    if not line:
                        break
                    print(line, end='')
                self._offset = f.tell()
        except IOError:
            pass


def _wait_for_supervisord_start(deadline):
    while time.time() < deadline:
        if os.path.exists('/var/run/supervisord.sock'):
            return
        time.sleep(0.5)
    raise BootstrapError(
        'supervisord never started: /var/run/supervisord.sock missing')


def _has_supervisord_starter_service():
    try:
        _get_starter_service_response()
    except BootstrapError:
        return False
    else:
        return True


def _has_systemd_starter_service():
    try:
        unit_details = subprocess.check_output(
            ['/bin/systemctl', 'show', f'{STARTER_SERVICE}.service'],
            stderr=subprocess.STDOUT
        ).splitlines()
    except subprocess.CalledProcessError:
        return False
    for line in unit_details:
        name, _, value = line.strip().partition(b'=')
        if name == b'LoadState':
            return value != b'not-found'
    return False


def _is_systemd_starter_service_finished():
    try:
        unit_details = subprocess.check_output(
            ['/bin/systemctl', 'show', f'{STARTER_SERVICE}.service'],
            stderr=subprocess.STDOUT
        ).splitlines()
    except subprocess.CalledProcessError:
        # systemd is not ready yet
        return False
    for line in unit_details:
        name, _, value = line.strip().partition(b'=')
        if name == b'ExecMainExitTimestampMonotonic':
            rv = int(value) > 0
        if name == b'ExecMainStatus':
            try:
                value = int(value)
            except ValueError:
                continue
            if value > 0:
                raise BootstrapError(
                    'Starter service exited with code {0}'.format(value))
    return rv


def _choose_starter_service_poller(deadline):
    while time.time() < deadline:
        if _has_supervisord_starter_service():
            return _is_supervisord_service_finished
        elif _has_systemd_starter_service():
            return _is_systemd_starter_service_finished
        time.sleep(0.5)
    raise BootstrapError(
        'Neither a supervisord starter service, nor a systemd starter '
        'service exists'
    )


@argh.decorators.named('wait-for-starter')
@config_arg
def wait_for_starter(timeout=600, config_file=None):
    config.load_config(config_file)
    deadline = time.time() + timeout

    _wait_for_supervisord_start(deadline)
    _follow = _FileFollow('/var/log/cloudify/manager/cfy_manager.log')
    _follow.seek_to_end()

    is_started = _choose_starter_service_poller(deadline)
    while time.time() < deadline:
        _follow.poll()
        if is_started():
            break
        time.sleep(0.5)
    else:
        raise BootstrapError('Timed out waiting for starter')
    _follow.poll()
    _print_finish_message(config_file=config_file)


def _guess_private_ip():
    ip_a = subprocess.check_output(['ip', 'a', 's']).decode('utf-8', 'replace')
    # `ip a s` output includes `inet <IP HERE>/cidr` several times
    inets = [
        addr for addr in re.findall('inet ([^/]+)', ip_a)
        if not addr.startswith(('127.', '169.254.'))
    ]
    if not inets:
        raise BootstrapError('No non-local ip addresses found')
    return inets[0]


@argh.decorators.named('image-starter')
@config_arg
def image_starter(verbose=False, config_file=None):
    """Guess the IPs if needed and run cfy_manager configure + start

    This is to be used as a "starter service" for an image: with a
    preinstalled image, set this to run on boot, and it will start
    a configured manager.
    """
    _prepare_execution(
        verbose,
        config_file=config_file,
    )
    config.load_config(config_file)
    executable = os.path.join(os.path.dirname(sys.executable), 'cfy_manager')
    command = [executable, 'configure', '--print-finish-message']
    private_ip = config[MANAGER].get(PRIVATE_IP)
    if not private_ip:
        private_ip = _guess_private_ip()
        command += ['--private-ip', private_ip]
    if not config[MANAGER].get(PUBLIC_IP):
        # if public ip is not given, default it to the same as private
        command += ['--public-ip', private_ip]
    if not config[MANAGER].get(SECURITY, {}).get(ADMIN_PASSWORD) \
            and not _all_services_configured():
        command += ['--admin-password', 'admin']
    os.execv(executable, command)


@argh.named('replace')
@argh.arg('--only-validate', help=VALIDATE_HELP_MSG)
@argh.arg('-i', '--input-path', help=INPUT_PATH_MSG)
@config_arg
@argh.decorators.arg('-v', '--verbose', help=VERBOSE_HELP_MSG)
def replace_certificates(input_path=None,
                         only_validate=False,
                         config_file=None,
                         verbose=False):
    """ Replacing the certificates on the current instance """
    setup_console_logger(verbose)
    config.load_config(config_file)
    set_globals()
    _handle_replace_certs_config_path(input_path)
    if only_validate:
        _only_validate()
    else:
        _replace_certificates()


def _replace_certificates():
    logger.info('Replacing certificates')
    for component in _get_components(only_configured=True):
        component.replace_certificates()

    if service_is_configured(MANAGER_SERVICE):
        # restart services that might not have been restarted
        for service_name in MGMTWORKER, AMQP_POSTGRES, STAGE, COMPOSER:
            service_name = 'cloudify-{0}'.format(service_name)
            service.restart(service_name)
            service.verify_alive(service_name)


def _handle_replace_certs_config_path(replace_certs_config_path):
    if not replace_certs_config_path:
        return
    replace_certs_config = read_yaml_file(replace_certs_config_path)
    for _, svc in replace_certs_config.items():
        for cert_name, cert_path in svc.items():
            new_cert_local_path = NEW_CERTS_TMP_DIR_PATH + cert_name
            if cert_path != new_cert_local_path:
                copy(cert_path, new_cert_local_path)


def _only_validate():
    logger.info('Validating new certificates')
    for component in _get_components(only_configured=True):
        component.validate_new_certs()


@argh.named('version')
@argh.decorators.arg('-v', '--verbose', help=VERBOSE_HELP_MSG, default=0,
                     action='count')
def version(**kwargs):
    setup_console_logger()
    cfy_version = pkg_resources.require('cloudify-manager-install')[0].version
    logger.info('Cloudify {}'.format(cfy_version))
    verbose = kwargs['verbose']
    if not verbose:
        return
    with open('{}/metadata.json'.format(CLOUDIFY_HOME_DIR)) as f:
        package_data = json.load(f)
    package_names = ['common', 'manager', 'premium', 'agent', 'cli', 'agent',
                     'stage', 'composer', 'manager-install']
    logger.info('Release date: %s', package_data['@creation_date'])
    mgr_install_info = next(r for r in package_data['repos']
                            if r['name'] == 'cloudify-manager-install')
    logger.info('Release branch: %s', mgr_install_info['branch_name'])
    logger.info('')
    logger.info('Packages commit IDs:')
    for repo in package_data['repos']:
        if repo['name'].replace('cloudify-', '') in package_names:
            if verbose == 1:
                logger.info(' * %-27s %s', repo['name'], repo['sha_id'][:7])
            else:
                logger.info(' * %-27s %s  [%s]',
                            repo['name'], repo['sha_id'][:7],
                            repo['branch_name'])


@argh.decorators.named('run-init')
@config_arg
def run_init(config_file=None):
    """Run the service management system."""
    # this function is left here for build-related reasons. To be removed ASAP
    os.execv(
        "/usr/bin/supervisord",
        ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisord.conf"])


def main():
    _ensure_root()
    # Set the umask to 0022; restore it later.
    current_umask = os.umask(CFY_UMASK)
    """Main entry point"""
    parser = argh.ArghParser()
    parser.add_commands([
        validate_command,
        install,
        configure,
        remove,
        start,
        stop,
        restart,
        sanity_check,
        add_networks,
        update_encryption_key,
        create_internal_certs,
        create_external_certs,
        generate_test_cert,
        reset_admin_password,
        image_starter,
        wait_for_starter,
        version,
        upgrade,
        run_init,
    ])

    parser.add_commands(
        [
            replace_certificates
        ],
        namespace='certificates',
        namespace_kwargs={'title': 'Commands to manage certificates.'},
    )

    parser.add_commands(
        [
            brokers_add,
            brokers_list,
            brokers_remove
        ],
        namespace='brokers',
        namespace_kwargs={'title': 'Commands to manage brokers.'},
    )

    parser.add_commands(
        [
            db_node_list,
            db_node_add,
            db_node_remove,
            db_node_reinit,
            db_node_set_master,
            db_shell,
        ],
        namespace='dbs',
        namespace_kwargs={'title': 'Commands to manage DBs.'},
    )

    parser.add_commands(
        [
            logs_fetch,
        ],
        namespace='logs',
        namespace_kwargs={'title': 'Commands to handle logs.'},
    )

    parser.dispatch()

    os.umask(current_umask)


def _ensure_root():
    excluded_subcommands = ['generate-test-cert']

    # To get the subcommand we need the second argument that does not begin
    # with a hyphen. The first will be the command itself
    # (e.g. /usr/bin/cfy_manager), and any beginning with hyphens will be
    # arguments such as --verbose or -h
    commands = [arg for arg in sys.argv
                if not arg.startswith('-')]

    skip_root_check = '--skip-root-check'
    if skip_root_check in sys.argv:
        sys.argv.remove(skip_root_check)
    else:
        # Checking subcommands here so we never pass through --skip-root-check
        if len(commands) < 2 or commands[1] in excluded_subcommands:
            return
        if os.geteuid() != 0:
            sys.exit(subprocess.call(
                ['/usr/bin/sudo'] + sys.argv + [skip_root_check]))
