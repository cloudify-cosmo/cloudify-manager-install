#!/usr/bin/env python
#########
# Copyright (c) 2017-2019 Cloudify Platform Ltd. All rights reserved
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
import sys
import logging
from time import time
from traceback import format_exception

import argh

from .components import (
    ComponentsFactory,
    SERVICE_COMPONENTS,
    MANAGER_SERVICE,
    QUEUE_SERVICE,
    SERVICE_INSTALLATION_ORDER
)
from .components.components_constants import (
    TOKEN,
    CLEAN_DB,
    SECURITY,
    PUBLIC_IP,
    PRIVATE_IP,
    ADMIN_PASSWORD,
    DB_STATUS_REPORTER,
    SERVICES_TO_INSTALL,
    UNCONFIGURED_INSTALL,
    QUEUE_STATUS_REPORTER,
    MANAGER_STATUS_REPORTER,
)
from .components.globals import set_globals
from .components.service_names import MANAGER, POSTGRESQL_SERVER
from .components.validations import validate
from .config import config
from .constants import INITIAL_CONFIGURE_FILE, INITIAL_INSTALL_FILE
from .encryption.encryption import update_encryption_key
from .exceptions import BootstrapError
from .logger import (
    get_file_handlers_level,
    get_logger,
    setup_console_logger,
    set_file_handlers_level,
)
from .networks.networks import add_networks
from .status_reporter import status_reporter
from .utils import CFY_UMASK
from .utils.certificates import (
    create_internal_certs,
    create_external_certs,
    generate_ca_cert,
    _generate_ssl_certificate,
)
from .utils.common import run, sudo, can_lookup_hostname
from .utils.files import (
    replace_in_file,
    remove as _remove,
    remove_temp_files,
    touch
)
from .utils.node import get_node_id

logger = get_logger('Main')

START_TIME = time()
TEST_CA_ROOT_PATH = os.path.expanduser('~/.cloudify-test-ca')
TEST_CA_CERT_PATH = os.path.join(TEST_CA_ROOT_PATH, 'ca.crt')
TEST_CA_KEY_PATH = os.path.join(TEST_CA_ROOT_PATH, 'ca.key')

TEST_CA_GENERATE_SAN_HELP_TEXT = (
    'Comma separated list of names or IPs that the generated certificate '
    'should be valid for. '
    'The first SAN entered will be the certificate name and used as the CN.'
)
CLEAN_DB_HELP_MSG = (
    'If set to "false", the DB will not be recreated when '
    'installing/configuring the Manager. Must be set to "true" on the first '
    'installation. If set to "false", the hash salt and admin password '
    'will not be generated'
)
ADMIN_PASSWORD_HELP_MSG = (
    'The password of the Cloudify Manager system administrator. '
    'Can only be used on the first install of the manager, or when using '
    'the --clean-db flag'
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
VERBOSE_HELP_MSG = (
    "Used to give more verbose output."
)
DB_NODE_ADDRESS_HELP_MSG = (
    "Address of target DB cluster node."
)
DB_NODE_FORCE_HELP_MSG = (
    "Force removal of cluster node even if it is the master."
)
DB_NODE_ID_HELP_MSG = (
    "Cloudify's auto-generated id of target DB cluster node."
)
DB_HOSTNAME_HELP_MSG = (
    "Hostname of target DB cluster node."
)

components = []


@argh.decorators.arg('-s', '--sans', help=TEST_CA_GENERATE_SAN_HELP_TEXT,
                     required=True)
def generate_test_cert(**kwargs):
    """Generate keys with certificates signed by a test CA.
    Not for production use. """
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


def _only_on_brokers():
    if QUEUE_SERVICE not in config[SERVICES_TO_INSTALL]:
        logger.error(
            'Broker management tasks must be performed on nodes with '
            'installed brokers.'
        )
        sys.exit(1)


@argh.named('add')
@argh.decorators.arg('-j', '--join-node', help=BROKER_ADD_JOIN_NODE_HELP_MSG,
                     required=True)
@argh.decorators.arg('-v', '--verbose', help=VERBOSE_HELP_MSG,
                     default=False)
def brokers_add(**kwargs):
    """Add a new broker to the broker cluster. This should not be done while
    the manager cluster has any running executions.
    Use the cfy command afterwards to register it with the manager cluster.
    """
    _validate_components_prepared('brokers_add')
    join_node = kwargs['join_node']

    rabbitmq = _prepare_component_management('rabbitmq', kwargs['verbose'])
    _only_on_brokers()

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
    _validate_components_prepared('brokers_remove')
    rabbitmq = _prepare_component_management('rabbitmq', kwargs['verbose'])
    _only_on_brokers()

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
@argh.decorators.arg('-v', '--verbose', help=VERBOSE_HELP_MSG,
                     default=False)
def brokers_list(**kwargs):
    """List brokers in the broker cluster.
    Use the cfy command to list brokers registered with the manager cluster.
    """
    _validate_components_prepared('brokers_list')
    rabbitmq = _prepare_component_management('rabbitmq', kwargs['verbose'])
    _only_on_brokers()

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
@argh.decorators.arg('-v', '--verbose', help=VERBOSE_HELP_MSG,
                     default=False)
def db_node_list(**kwargs):
    """List DB cluster members and DB cluster health."""
    _validate_components_prepared('db_cluster_list')
    db = _prepare_component_management('postgresql_server', kwargs['verbose'])

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
@argh.decorators.arg('-v', '--verbose', help=VERBOSE_HELP_MSG,
                     default=False)
@argh.decorators.arg('-a', '--address', help=DB_NODE_ADDRESS_HELP_MSG,
                     required=True)
@argh.decorators.arg('-i', '--node-id', help=DB_NODE_ID_HELP_MSG,
                     required=True)
@argh.decorators.arg('-n', '--hostname', help=DB_HOSTNAME_HELP_MSG)
def db_node_add(**kwargs):
    """Add a DB cluster node."""
    _validate_components_prepared('db_node_add')
    db = _prepare_component_management('postgresql_server', kwargs['verbose'])
    if config[POSTGRESQL_SERVER]['cluster']['nodes']:
        db.add_cluster_node(kwargs['address'], kwargs['node_id'],
                            kwargs.get('hostname'))
    else:
        logger.info('There is no database cluster associated with this node.')


@argh.named('remove')
@argh.decorators.arg('-v', '--verbose', help=VERBOSE_HELP_MSG,
                     default=False)
@argh.decorators.arg('-a', '--address', help=DB_NODE_ADDRESS_HELP_MSG,
                     required=True)
@argh.decorators.arg('-i', '--node-id', help=DB_NODE_ID_HELP_MSG)
def db_node_remove(**kwargs):
    """Remove a DB cluster node."""
    _validate_components_prepared('db_node_remove')
    db = _prepare_component_management('postgresql_server', kwargs['verbose'])
    if config[POSTGRESQL_SERVER]['cluster']['nodes']:
        if (MANAGER_SERVICE in config[SERVICES_TO_INSTALL] and
                kwargs.get('node_id') is None):
            logger.error('Argument -i/--node-id is required when running '
                         '`dbs remove` on a manager')
            return
        db.remove_cluster_node(kwargs['address'], kwargs.get('node_id'))
    else:
        logger.info('There is no database cluster associated with this node.')


@argh.named('reinit')
@argh.decorators.arg('-v', '--verbose', help=VERBOSE_HELP_MSG,
                     default=False)
@argh.decorators.arg('-a', '--address', help=DB_NODE_ADDRESS_HELP_MSG,
                     required=True)
def db_node_reinit(**kwargs):
    """Re-initialise an unhealthy DB cluster node."""
    _validate_components_prepared('db_node_reinit')
    db = _prepare_component_management('postgresql_server', kwargs['verbose'])
    if config[POSTGRESQL_SERVER]['cluster']['nodes']:
        db.reinit_cluster_node(kwargs['address'])
    else:
        logger.info('There is no database cluster associated with this node.')


@argh.named('set-master')
@argh.decorators.arg('-v', '--verbose', help=VERBOSE_HELP_MSG,
                     default=False)
@argh.decorators.arg('-a', '--address', help=DB_NODE_ADDRESS_HELP_MSG,
                     required=True)
def db_node_set_master(**kwargs):
    _validate_components_prepared('db_node_set_master')
    db = _prepare_component_management('postgresql_server', kwargs['verbose'])
    if config[POSTGRESQL_SERVER]['cluster']['nodes']:
        db.set_master(kwargs['address'])
    else:
        logger.info('There is no database cluster associated with this node.')


def get_id():
    """Get Cloudify's auto-generated id for this node"""
    node_id = get_node_id()
    print('The node id is: {0}'.format(node_id))


def output_table(data, fields):
    field_lengths = []
    for field in fields:
        for entry in data:
            if isinstance(entry[field], list):
                entry[field] = ', '.join(entry[field])
        if data:
            field_length = max(
                2 + len(str(entry[field])) for entry in data
            )
        else:
            field_length = 2
        field_length = max(
            field_length,
            2 + len(field)
        )
        field_lengths.append(field_length)

    output_table_divider(field_lengths)
    # Column headings
    output_table_row(field_lengths, fields)
    output_table_divider(field_lengths)

    for entry in data:
        row = [
            entry[field] for field in fields
        ]
        output_table_row(field_lengths, row)
    output_table_divider(field_lengths)


def output_table_divider(lengths):
    output = '+'
    for length in lengths:
        output += '-' * length
        output += '+'
    print(output)


def output_table_row(lengths, entries):
    output = '|'
    for i in range(len(lengths)):
        output += str(entries[i]).center(lengths[i])
        output += '|'
    print(output)


def _print_time():
    running_time = time() - START_TIME
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
                                         admin_password, clean_db):
    manager_config = config[MANAGER]

    config[CLEAN_DB] = clean_db

    if private_ip:
        manager_config[PRIVATE_IP] = private_ip
    if public_ip:
        manager_config[PUBLIC_IP] = public_ip
    if admin_password:
        if config[CLEAN_DB] or not _are_components_configured():
            manager_config[SECURITY][ADMIN_PASSWORD] = admin_password
        else:
            raise BootstrapError(
                'The --admin-password argument can only be used in '
                'conjunction with the --clean-db flag or on a first '
                'install.'
            )


def _prepare_component_management(component, verbose):
    setup_console_logger(verbose=verbose)
    config.load_config()
    return ComponentsFactory.create_component(component,
                                              skip_installation=True)


def _prepare_execution(verbose=False,
                       private_ip=None,
                       public_ip=None,
                       admin_password=None,
                       clean_db=False,
                       config_write_required=False,
                       only_install=False):
    setup_console_logger(verbose)

    config.load_config()
    if not only_install:
        # We don't validate anything that applies to the install anyway,
        # but we do populate things that are not relevant.
        _populate_and_validate_config_values(private_ip, public_ip,
                                             admin_password, clean_db)
    _create_component_objects()


def _print_finish_message():
    if MANAGER_SERVICE in config[SERVICES_TO_INSTALL]:
        manager_config = config[MANAGER]
        protocol = \
            'https' if config[MANAGER][SECURITY]['ssl_enabled'] else 'http'
        logger.notice(
            'Manager is up at {protocol}://{ip}'.format(
                protocol=protocol,
                ip=manager_config[PUBLIC_IP])
        )
        print_credentials_to_screen()
        logger.notice('#' * 50)
        logger.notice("To install the default plugins bundle run:")
        logger.notice("'cfy plugins bundle-upload'")
        logger.notice('#' * 50)


def print_credentials_to_screen():
    password = config[MANAGER][SECURITY][ADMIN_PASSWORD]
    manager_status_reporter_token = config.get(
        MANAGER_STATUS_REPORTER, {}).get(TOKEN, None)
    db_status_reporter_token = config.get(
        DB_STATUS_REPORTER, {}).get(TOKEN, None)
    queue_status_reporter_token = config.get(
        QUEUE_STATUS_REPORTER, {}).get(TOKEN, None)

    current_level = get_file_handlers_level()
    set_file_handlers_level(logging.ERROR)
    logger.warning('Admin password: %s', password)
    if manager_status_reporter_token:
        logger.warning('Manager Status Reported token: %s',
                       manager_status_reporter_token)
    if db_status_reporter_token:
        logger.warning('Database Status Reported token: %s',
                       db_status_reporter_token)
    if queue_status_reporter_token:
        logger.warning('Queue Service Status Reported token: %s',
                       queue_status_reporter_token)
    set_file_handlers_level(current_level)


def _are_components_installed():
    return os.path.isfile(INITIAL_INSTALL_FILE)


def _are_components_configured():
    return os.path.isfile(INITIAL_CONFIGURE_FILE)


def _create_initial_install_file():
    """
    Create /etc/cloudify/.installed if install finished successfully
    for the first time
    """
    if not _are_components_installed():
        touch(INITIAL_INSTALL_FILE)


def _create_initial_configure_file():
    """
    Create /etc/cloudify/.configured if configure finished successfully
    for the first time
    """
    if not _are_components_configured():
        touch(INITIAL_CONFIGURE_FILE)


def _finish_configuration(only_install=None):
    remove_temp_files()
    _create_initial_install_file()
    if not only_install:
        _print_finish_message()
        _create_initial_configure_file()
    _print_time()
    config.dump_config()


def _validate_force(force, cmd):
    if not force:
        raise BootstrapError(
            'The --force flag must be passed to `cfy_manager {0}`'.format(cmd)
        )


def _validate_components_prepared(cmd):
    error_message = (
        'Could not find {touched_file}.\nThis most likely means '
        'that you need to run `cfy_manager {fix_cmd}` before '
        'running `cfy_manager {cmd}`'
    )
    if not _are_components_installed():
        raise BootstrapError(
            error_message.format(
                fix_cmd='install',
                touched_file=INITIAL_INSTALL_FILE,
                cmd=cmd
            )
        )
    if not _are_components_configured() and cmd != 'configure':
        raise BootstrapError(
            error_message.format(
                fix_cmd='configure',
                touched_file=INITIAL_INSTALL_FILE,
                cmd=cmd
            )
        )


def _get_components_list():
    """
    Match all available services to install with all desired ones and
    return a unique list ordered by service installation order
    """
    # Order the services to install by service installation order
    ordered_services = sorted(
        config[SERVICES_TO_INSTALL],
        key=SERVICE_INSTALLATION_ORDER.index
    )
    # Can't easily use list comprehension here because this is a list of lists
    ordered_components = []
    for service in ordered_services:
        ordered_components.extend(SERVICE_COMPONENTS[service])
    return ordered_components


def _create_component_objects():
    components_to_install = _get_components_list()
    for component_name in components_to_install:
        component_config = config.get(component_name, {})
        skip_installation = component_config.get('skip_installation', False)
        components.append(
            ComponentsFactory.create_component(component_name,
                                               skip_installation)
        )


def _remove_rabbitmq_service_unit():
    prefix = "/lib/systemd/system"
    rabbitmq_pattern = "cloudify-rabbitmq.service"
    mgmt_patterns = ["Wants={0}".format(rabbitmq_pattern),
                     "After={0}".format(rabbitmq_pattern)]
    services_and_patterns = \
        [("cloudify-amqp-postgres.service", [rabbitmq_pattern]),
         ("cloudify-mgmtworker.service", mgmt_patterns)]
    for service, pattern_list in services_and_patterns:
        path = os.path.join(prefix, service)
        for pattern in pattern_list:
            replace_in_file(pattern, "", path)
    sudo("systemctl daemon-reload")


def install_args(f):
    """Apply all the args that are used by `cfy_manager install`"""
    args = [
        argh.arg('--clean-db', help=CLEAN_DB_HELP_MSG),
        argh.arg('--private-ip', help=PRIVATE_IP_HELP_MSG),
        argh.arg('--public-ip', help=PUBLIC_IP_HELP_MSG),
        argh.arg('-a', '--admin-password', help=ADMIN_PASSWORD_HELP_MSG)
    ]
    for arg in args:
        f = arg(f)
    return f


@argh.decorators.named('validate')
@install_args
def validate_command(verbose=False,
                     private_ip=None,
                     public_ip=None,
                     admin_password=None,
                     clean_db=False):
    _prepare_execution(
        verbose,
        private_ip,
        public_ip,
        admin_password,
        clean_db,
        config_write_required=False
    )
    validate(components=components)


@argh.arg('--private-ip', help=PRIVATE_IP_HELP_MSG)
def sanity_check(verbose=False, private_ip=None):
    """Run the Cloudify Manager sanity check"""
    _prepare_execution(verbose=verbose, private_ip=private_ip)
    sanity = ComponentsFactory.create_component('sanity')
    sanity.run_sanity_check()


@argh.arg('--only-install', help=ONLY_INSTALL_HELP_MSG, default=False)
@install_args
def install(verbose=False,
            private_ip=None,
            public_ip=None,
            admin_password=None,
            clean_db=False,
            only_install=None):
    """ Install Cloudify Manager """

    _prepare_execution(
        verbose,
        private_ip,
        public_ip,
        admin_password,
        clean_db,
        config_write_required=True,
        only_install=only_install,
    )
    logger.notice('Installing desired components...')
    validate(components=components, only_install=only_install)
    set_globals(only_install=only_install)

    for component in components:
        if not component.skip_installation:
            component.install()

    if not only_install:
        for component in components:
            # Separate check because some components set 'skip' if they don't
            # find the install package, and because if we're set to only
            # install then we shouldn't configure
            if not component.skip_installation:
                component.configure()

    if (MANAGER_SERVICE in config[SERVICES_TO_INSTALL] and
            QUEUE_SERVICE not in config[SERVICES_TO_INSTALL]):
        _remove_rabbitmq_service_unit()

    config[UNCONFIGURED_INSTALL] = only_install
    logger.notice('Installation finished successfully!')
    _finish_configuration(only_install)


@install_args
def configure(verbose=False,
              private_ip=None,
              public_ip=None,
              admin_password=None,
              clean_db=False):
    """ Configure Cloudify Manager """

    _prepare_execution(
        verbose,
        private_ip,
        public_ip,
        admin_password,
        clean_db,
        config_write_required=True
    )

    _validate_components_prepared('configure')
    logger.notice('Configuring desired components...')
    validate(components=components)
    set_globals()

    if clean_db:
        for component in components:
            if not component.skip_installation:
                component.stop()

    for component in components:
        if not component.skip_installation:
            component.configure()

    config[UNCONFIGURED_INSTALL] = False
    logger.notice('Configuration finished successfully!')
    _finish_configuration()


def remove(verbose=False, force=False):
    """ Uninstall Cloudify Manager """

    _prepare_execution(verbose)
    _validate_force(force, 'remove')
    logger.notice('Removing Cloudify Manager...')

    should_stop = _are_components_configured()

    for component in reversed(components):
        if not component.skip_installation:
            if should_stop:
                component.stop()
            component.remove()

    if _are_components_installed():
        _remove(INITIAL_INSTALL_FILE)

    if _are_components_configured():
        _remove(INITIAL_CONFIGURE_FILE)

    logger.notice('Cloudify Manager successfully removed!')
    _print_time()


def start(verbose=False):
    """ Start Cloudify Manager services """

    _prepare_execution(verbose)
    _validate_components_prepared('start')
    logger.notice('Starting Cloudify Manager services...')
    for component in components:
        if not component.skip_installation:
            component.start()
    logger.notice('Cloudify Manager services successfully started!')
    _print_time()


def stop(verbose=False, force=False):
    """ Stop Cloudify Manager services """

    _prepare_execution(verbose)
    _validate_components_prepared('stop')
    _validate_force(force, 'stop')

    logger.notice('Stopping Cloudify Manager services...')
    for component in components:
        if not component.skip_installation:
            component.stop()
    logger.notice('Cloudify Manager services successfully stopped!')
    _print_time()


def restart(verbose=False, force=False):
    """ Restart Cloudify Manager services """

    _prepare_execution(verbose)
    _validate_components_prepared('restart')
    _validate_force(force, 'restart')

    stop(verbose, force)
    start(verbose)
    _print_time()


def main():
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
        generate_test_cert
    ])

    parser.add_commands([
        brokers_add,
        brokers_list,
        brokers_remove
    ], namespace='brokers')

    parser.add_commands([
        db_node_list,
        db_node_add,
        db_node_remove,
        db_node_reinit,
        db_node_set_master
    ], namespace='dbs')

    parser.add_commands([
        status_reporter.start,
        status_reporter.stop,
        status_reporter.remove,
        status_reporter.configure
    ], namespace='status-reporter')

    parser.add_commands([
        get_id
    ], namespace='node',
        namespace_kwargs={'title': 'Handle node details'})
    parser.dispatch()

    os.umask(current_umask)


if __name__ == '__main__':
    main()
