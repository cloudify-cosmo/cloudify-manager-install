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

from __future__ import print_function

import os
import re
import sys
import json
import time
import logging
import subprocess
from traceback import format_exception

import argh

from . import components
from .components import (
    MANAGER_SERVICE,
    QUEUE_SERVICE,
    DATABASE_SERVICE,
    MONITORING_SERVICE,
    sources
)
from .components.components_constants import (
    CLEAN_DB,
    SECURITY,
    PUBLIC_IP,
    PRIVATE_IP,
    ADMIN_PASSWORD,
    DB_STATUS_REPORTER,
    SERVICES_TO_INSTALL,
    UNCONFIGURED_INSTALL,
    BROKER_STATUS_REPORTER,
    MANAGER_STATUS_REPORTER,
    PREMIUM_EDITION
)
from .components.globals import set_globals
from cfy_manager.utils.common import output_table
from .components.service_names import (
    COMPOSER,
    MANAGER,
    POSTGRESQL_SERVER,
    SANITY
)
from .components.validations import validate, validate_dependencies
from .config import config
from .constants import (
    VERBOSE_HELP_MSG,
    INITIAL_INSTALL_FILE,
    STATUS_REPORTER_TOKEN,
    INITIAL_CONFIGURE_FILE,
)
from .encryption.encryption import update_encryption_key
from .exceptions import BootstrapError
from .logger import (
    get_file_handlers_level,
    get_logger,
    setup_console_logger,
    set_file_handlers_level,
)
from .networks.networks import add_networks
from .accounts import reset_admin_password
from .status_reporter import status_reporter
from .utils import CFY_UMASK
from .utils.certificates import (
    create_internal_certs,
    create_external_certs,
    generate_ca_cert,
    _generate_ssl_certificate,
)
from .utils.common import (
    run, sudo, can_lookup_hostname, allows_json_format, is_installed
)
from .utils.install import yum_install, yum_remove, is_package_installed
from .utils.files import (
    replace_in_file,
    remove as _remove,
    remove_temp_files,
    touch
)
from .utils.node import get_node_id

logger = get_logger('Main')

START_TIME = time.time()
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
DB_NODE_ADDRESS_HELP_MSG = (
    "Address of target DB cluster node."
)
DB_NODE_FORCE_HELP_MSG = (
    "Force removal of cluster node even if it is the master."
)
DB_NODE_ID_HELP_MSG = (
    "Cloudify's auto-generated id of target DB cluster node. "
    "Run `cfy_manager node get-id` on the DB cluster node to retrieve it."
)
DB_HOSTNAME_HELP_MSG = (
    "Hostname of target DB cluster node."
)


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

    setup_console_logger(verbose=kwargs['verbose'])
    config.load_config()
    rabbitmq = components.RabbitMQ()
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
    setup_console_logger(verbose=kwargs['verbose'])
    config.load_config()
    rabbitmq = components.RabbitMQ()
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
    setup_console_logger(verbose=kwargs['verbose'])
    config.load_config()
    rabbitmq = components.RabbitMQ()
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
    setup_console_logger(verbose=kwargs['verbose'])
    config.load_config()
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
    setup_console_logger(verbose=kwargs['verbose'])
    config.load_config()
    db = components.PostgresqlServer()
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
    setup_console_logger(verbose=kwargs['verbose'])
    config.load_config()
    db = components.PostgresqlServer()
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
    setup_console_logger(verbose=kwargs['verbose'])
    config.load_config()
    db = components.PostgresqlServer()
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
    """Switch the current DB master node."""
    _validate_components_prepared('db_node_set_master')
    setup_console_logger(verbose=kwargs['verbose'])
    config.load_config()
    db = components.PostgresqlServer()
    if config[POSTGRESQL_SERVER]['cluster']['nodes']:
        db.set_master(kwargs['address'])
    else:
        logger.info('There is no database cluster associated with this node.')


@allows_json_format()
def get_id(json_format=None):
    """Get Cloudify's auto-generated id for this node"""
    node_id = get_node_id()
    if json_format:
        print(json.dumps({'node_id': node_id}))
    else:
        print('The node id is: {0}'.format(node_id))


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


def _print_finish_message():
    if is_installed(MANAGER_SERVICE):
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
    db_status_reporter_token = config.get(
        DB_STATUS_REPORTER, {}).get(STATUS_REPORTER_TOKEN)
    broker_status_reporter_token = config.get(
        BROKER_STATUS_REPORTER, {}).get(STATUS_REPORTER_TOKEN)

    current_level = get_file_handlers_level()
    set_file_handlers_level(logging.ERROR)
    logger.notice('Admin password: %s', password)
    if db_status_reporter_token:
        logger.notice('Database Status Reported token: %s',
                      db_status_reporter_token)
    if broker_status_reporter_token:
        logger.notice('Queue Service Status Reported token: %s',
                      broker_status_reporter_token)
    for reporter in (MANAGER_STATUS_REPORTER,
                     DB_STATUS_REPORTER,
                     BROKER_STATUS_REPORTER):
        config.pop(reporter, None)
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


def _get_components(include_components=None):
    """Get the component objects based on the config.

    This looks at the config, and returns only the component objects
    that are supposed to be installed(/configured/started).

    All the "should we install this" config checks are done here.
    """
    _components = []

    if is_installed(DATABASE_SERVICE):
        _components += [components.PostgresqlServer()]
        if (config[SERVICES_TO_INSTALL] == [DATABASE_SERVICE] and
                config[POSTGRESQL_SERVER]['cluster']['nodes']):
            _components += [components.PostgresqlStatusReporter()]

    if is_installed(QUEUE_SERVICE):
        _components += [components.RabbitMQ()]
        if config[SERVICES_TO_INSTALL] == [QUEUE_SERVICE]:
            _components += [components.RabbitmqStatusReporter()]

    if is_installed(MANAGER_SERVICE):
        _components += [
            components.Manager(),
            components.PostgresqlClient(),
            components.RestService(),
            components.ManagerIpSetter(),
            components.Nginx(),
            components.Cli(),
            components.AmqpPostgres(),
            components.MgmtWorker(),
            components.Stage(),
        ]
        if not config[COMPOSER]['skip_installation']:
            _components += [
                components.Composer(),
            ]
        if is_package_installed('cloudify-status-reporter'):
            _components += [components.ManagerStatusReporter()]
        _components += [
            components.UsageCollector(),
        ]
        if not config[SANITY]['skip_sanity']:
            _components += [components.Sanity()]

    if is_installed(MONITORING_SERVICE):
        _components += [components.Prometheus()]
        if not is_installed(MANAGER_SERVICE):
            _components += [components.Nginx()]

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
    components = _get_components()
    validate(components=components)
    validate_dependencies(components=components)


@argh.arg('--private-ip', help=PRIVATE_IP_HELP_MSG)
def sanity_check(verbose=False, private_ip=None):
    """Run the Cloudify Manager sanity check"""
    _prepare_execution(verbose=verbose, private_ip=private_ip)
    sanity = components.Sanity()
    sanity.run_sanity_check()


def _get_packages():
    """Yum packages to install/uninstall, based on the current config"""
    premium = config[MANAGER][PREMIUM_EDITION] == 'premium'
    packages = []
    if is_installed(MANAGER_SERVICE):
        packages += sources.manager
        if premium:
            packages += sources.manager_cluster + sources.manager_premium

    if is_installed(DATABASE_SERVICE):
        packages += sources.db
        if premium:
            packages += sources.db_cluster

    if is_installed(QUEUE_SERVICE):
        packages += sources.queue
        if premium:
            packages += sources.queue_cluster

    if is_installed(MONITORING_SERVICE):
        packages += sources.prometheus
        if premium:
            packages += sources.prometheus_cluster

    return packages


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
    set_globals(only_install=only_install)
    yum_install(_get_packages())

    components = _get_components()
    validate(components=components, only_install=only_install)
    validate_dependencies(components=components)

    for component in components:
        component.install()

    if not only_install:
        for component in components:
            component.configure()
        for component in components:
            component.start()

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
    components = _get_components()
    validate(components=components)
    set_globals()

    if clean_db:
        for component in components:
            component.stop()

    for component in components:
        component.configure()

    config[UNCONFIGURED_INSTALL] = False
    logger.notice('Configuration finished successfully!')
    _finish_configuration()


def remove(verbose=False, force=False):
    """ Uninstall Cloudify Manager """

    _prepare_execution(verbose)
    if force:
        logger.warning('--force is deprecated, does nothing, and will be '
                       'removed in a future version')

    logger.notice('Removing Cloudify Manager...')

    should_stop = _are_components_configured()
    components = _get_components()
    for component in reversed(components):
        if should_stop:
            component.stop()
        component.remove()

    yum_remove(_get_packages())

    if _are_components_installed():
        _remove(INITIAL_INSTALL_FILE)

    if _are_components_configured():
        _remove(INITIAL_CONFIGURE_FILE)

    logger.notice('Cloudify Manager successfully removed!')
    _print_time()


@argh.arg('include_components', nargs='*')
@install_args
def start(include_components,
          verbose=False,
          private_ip=None,
          public_ip=None,
          admin_password=None,
          clean_db=False,
          only_install=None):
    """ Start Cloudify Manager services """
    _prepare_execution(
        verbose,
        private_ip,
        public_ip,
        admin_password,
        clean_db,
        config_write_required=True
    )
    _validate_components_prepared('start')
    set_globals()
    logger.notice('Starting Cloudify Manager services...')
    for component in _get_components(include_components):
        component.start()
    logger.notice('Cloudify Manager services successfully started!')
    _print_time()


@argh.arg('include_components', nargs='*')
def stop(include_components, verbose=False, force=False):
    """ Stop Cloudify Manager services """
    _prepare_execution(verbose)
    _validate_components_prepared('stop')
    if force:
        logger.warning('--force is deprecated, does nothing, and will be '
                       'removed in a future version')

    logger.notice('Stopping Cloudify Manager services...')
    for component in _get_components(include_components):
        component.stop()
    logger.notice('Cloudify Manager services successfully stopped!')
    _print_time()


@argh.arg('include_components', nargs='*')
def restart(include_components, verbose=False, force=False):
    """ Restart Cloudify Manager services """

    _prepare_execution(verbose)
    _validate_components_prepared('restart')
    if force:
        logger.warning('--force is deprecated, does nothing, and will be '
                       'removed in a future version')
    components = _get_components(include_components)
    for component in components:
        component.stop()
    for component in components:
        component.start()
    _print_time()


def _is_unit_finished(unit_name):
    unit_details = subprocess.check_output([
        '/bin/systemctl', 'show', unit_name]).splitlines()
    for line in unit_details:
        name, _, value = line.strip().partition(b'=')
        if name == b'ExecMainExitTimestampMonotonic':
            return int(value) > 0


@argh.decorators.named('wait-for-starter')
def wait_for_starter(verbose=False, timeout=180):
    _prepare_execution(verbose, config_write_required=False)
    deadline = time.time() + timeout
    journalctl = subprocess.Popen([
        '/bin/journalctl', '-fu', 'cloudify-starter.service'])
    while time.time() < deadline:
        if _is_unit_finished('cloudify-starter.service'):
            break
        else:
            time.sleep(1)
    else:
        raise BootstrapError('Timed out waiting for the starter service')
    journalctl.kill()


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
def image_starter(verbose=False):
    """Guess the IPs if needed and run cfy_manager configure + start

    This is to be used as a "starter service" for an image: with a
    preinstalled image, set this to run on boot, and it will start
    a configured manager.
    """
    _prepare_execution(verbose, config_write_required=False)
    config.load_config()
    command = [sys.executable, '-m', 'cfy_manager.main']
    args = []
    private_ip = config[MANAGER].get(PRIVATE_IP)
    if not private_ip:
        private_ip = _guess_private_ip()
        args += ['--private-ip', private_ip]
    if not config[MANAGER].get(PUBLIC_IP):
        # if public ip is not given, default it to the same as private
        args += ['--public-ip', private_ip]
    subprocess.check_call(command + ['configure'] + args)
    subprocess.check_call(command + ['start'] + args)


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
        generate_test_cert,
        reset_admin_password,
        image_starter,
        wait_for_starter
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
        status_reporter.show_configuration,
        status_reporter.start,
        status_reporter.stop,
        status_reporter.remove,
        status_reporter.configure,
        status_reporter.get_tokens
    ], namespace='status-reporter')

    parser.add_commands([
        get_id
    ], namespace='node',
        namespace_kwargs={'title': 'Handle node details'})
    parser.dispatch()

    os.umask(current_umask)


if __name__ == '__main__':
    main()
