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
import time
import subprocess
import pkg_resources
from traceback import format_exception

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
from .components.components_constants import (
    CLEAN_DB,
    SECURITY,
    PUBLIC_IP,
    PRIVATE_IP,
    ADMIN_PASSWORD,
    SERVICES_TO_INSTALL,
    UNCONFIGURED_INSTALL,
)
from .components.globals import set_globals
from cfy_manager.utils.common import output_table
from .components.service_names import (
    COMPOSER,
    MANAGER,
    POSTGRESQL_SERVER,
    SANITY,
    AMQP_POSTGRES,
    MGMTWORKER,
    STAGE
)
from .components.validations import validate, validate_dependencies
from .config import config
from .constants import (
    VERBOSE_HELP_MSG,
    SUPERVISORD_CONFIG_DIR,
    NEW_CERTS_TMP_DIR_PATH,
    CLOUDIFY_HOME_DIR,
    INITIAL_INSTALL_DIR,
    INITIAL_CONFIGURE_DIR
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
    create_internal_certs,
    create_external_certs,
    generate_ca_cert,
    _generate_ssl_certificate,
)
from .utils.common import (
    run,
    sudo,
    mkdir,
    copy,
    can_lookup_hostname,
    is_installed,
    is_dir_empty,
    get_installed_services_names,
)
from .utils.install import is_premium_installed, yum_install, yum_remove
from .utils.files import (
    remove as _remove,
    remove_temp_files,
    touch,
    read_yaml_file
)
from ._compat import xmlrpclib

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
DB_HOSTNAME_HELP_MSG = (
    "Hostname of target DB cluster node."
)
VALIDATE_HELP_MSG = (
    "Validate the provided certificates. If this flag is on, then the "
    "certificates will only be validated and not replaced."
)
INPUT_PATH_MSG = (
    "The replace-certificates yaml configuration file path."
)
CONFIG_FILE_HELP_MSG = (
    'Specify a configuration file to be used. File path is relative to the '
    '{0} (meaning only files in this location are considered valid). If '
    'more than one file is provided, these are merged in order from left '
    'to right.'.format(CLOUDIFY_HOME_DIR)
)

config_arg = argh.arg('-c', '--config-file', action='append', default=None,
                      help=CONFIG_FILE_HELP_MSG)


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


def _only_on_brokers():
    if QUEUE_SERVICE not in config[SERVICES_TO_INSTALL]:
        logger.error(
            'Broker management tasks must be performed on nodes with '
            'installed brokers.'
        )
        sys.exit(1)


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
    _validate_components_prepared('brokers_add')
    join_node = kwargs['join_node']
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
    _validate_components_prepared('brokers_remove')
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
@config_arg
@argh.decorators.arg('-v', '--verbose', help=VERBOSE_HELP_MSG,
                     default=False)
def brokers_list(**kwargs):
    """List brokers in the broker cluster.
    Use the cfy command to list brokers registered with the manager cluster.
    """
    setup_console_logger(verbose=kwargs['verbose'])
    config.load_config(kwargs.get('config_file'))
    _validate_components_prepared('brokers_list')
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
@config_arg
@argh.decorators.arg('-v', '--verbose', help=VERBOSE_HELP_MSG,
                     default=False)
def db_node_list(**kwargs):
    """List DB cluster members and DB cluster health."""
    setup_console_logger(verbose=kwargs['verbose'])
    config.load_config(kwargs.get('config_file'))
    _validate_components_prepared('db_cluster_list')
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
@argh.decorators.arg('-n', '--hostname', help=DB_HOSTNAME_HELP_MSG)
def db_node_add(**kwargs):
    """Add a DB cluster node."""
    setup_console_logger(verbose=kwargs['verbose'])
    config.load_config(kwargs.get('config_file'))
    _validate_components_prepared('db_node_add')
    db = components.PostgresqlServer()
    if config[POSTGRESQL_SERVER]['cluster']['nodes']:
        db.add_cluster_node(kwargs['address'], kwargs.get('hostname'))
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
    _validate_components_prepared('db_node_remove')
    db = components.PostgresqlServer()
    if config[POSTGRESQL_SERVER]['cluster']['nodes']:
        db.remove_cluster_node(kwargs['address'])
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
    _validate_components_prepared('db_node_reinit')
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
    _validate_components_prepared('db_node_set_master')
    db = components.PostgresqlServer()
    if config[POSTGRESQL_SERVER]['cluster']['nodes']:
        db.set_master(kwargs['address'])
    else:
        logger.info('There is no database cluster associated with this node.')


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
                       only_install=False,
                       config_file=None):
    setup_console_logger(verbose)

    config.load_config(config_file)
    if not only_install:
        # We don't validate anything that applies to the install anyway,
        # but we do populate things that are not relevant.
        _populate_and_validate_config_values(private_ip, public_ip,
                                             admin_password, clean_db)


def _print_finish_message(config_file=None):
    if is_installed(MANAGER_SERVICE):
        manager_config = config[MANAGER]
        protocol = \
            'https' if config[MANAGER][SECURITY]['ssl_enabled'] else 'http'
        logger.notice(
            'Manager is up at {protocol}://{ip}'.format(
                protocol=protocol,
                ip=manager_config[PUBLIC_IP])
        )
        # reload the config in case the admin password changed
        config.load_config(config_file)
        password = config[MANAGER][SECURITY][ADMIN_PASSWORD]
        print('Admin password: {0}'.format(password))
        print('#' * 50)
        print("To install the default plugins bundle run:")
        print("'cfy plugins bundle-upload'")
        print('#' * 50)


def _are_components_installed():
    return all(
        os.path.isfile(os.path.join(INITIAL_INSTALL_DIR, service_name))
        for service_name in get_installed_services_names())


def _are_components_configured():
    return all(
        os.path.isfile(os.path.join(INITIAL_CONFIGURE_DIR, service_name))
        for service_name in get_installed_services_names())


def is_supervisord_service():
    return service._get_service_type() == 'supervisord'


def _create_initial_install_file():
    """
    Create /etc/cloudify/.installed/<service_name> if the
    service installation finished successfully for the first time
    """
    if not _are_components_installed():
        mkdir(INITIAL_INSTALL_DIR)
        for service_name in get_installed_services_names():
            touch(os.path.join(INITIAL_INSTALL_DIR, service_name))


def _create_initial_configure_file():
    """
    Create /etc/cloudify/.configured/service_name if the configuration
    finished successfully for the first time
    """
    if not _are_components_configured():
        mkdir(INITIAL_CONFIGURE_DIR)
        for service_name in get_installed_services_names():
            touch(os.path.join(INITIAL_CONFIGURE_DIR, service_name))


def _finish_configuration(only_install=None):
    config.dump_config()
    remove_temp_files()
    _create_initial_install_file()
    if not only_install:
        _create_initial_configure_file()
    _print_time()


def _validate_components_prepared(cmd):
    error_message = (
        'Could not find {touched_files}.\nThis most likely means '
        'that you need to run `cfy_manager {fix_cmd}` before '
        'running `cfy_manager {cmd}`'
    )
    files_list = [os.path.join(INITIAL_INSTALL_DIR, installed_service) for
                  installed_service in get_installed_services_names()]
    if not _are_components_installed():
        raise BootstrapError(
            error_message.format(
                fix_cmd='install',
                touched_files=', '.join(files_list),
                cmd=cmd
            )
        )
    if not _are_components_configured() and cmd != 'configure':
        raise BootstrapError(
            error_message.format(
                fix_cmd='configure',
                touched_files=', '.join(files_list),
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

    if is_installed(QUEUE_SERVICE):
        _components += [components.RabbitMQ()]

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
        if (
            is_premium_installed()
            and not config[COMPOSER]['skip_installation']
        ):
            _components += [
                components.Composer(),
            ]
        _components += [
            components.UsageCollector(),
        ]
        if not config[SANITY]['skip_sanity']:
            _components += [components.Sanity()]

    if is_installed(MONITORING_SERVICE):
        _components += [components.Prometheus()]
        if not is_installed(MANAGER_SERVICE):
            _components += [components.Nginx()]

    if is_installed(ENTROPY_SERVICE):
        _components += [components.Haveged()]

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
        argh.arg('--clean-db', help=CLEAN_DB_HELP_MSG),
        argh.arg('--private-ip', help=PRIVATE_IP_HELP_MSG),
        argh.arg('--public-ip', help=PUBLIC_IP_HELP_MSG),
        argh.arg('-a', '--admin-password', help=ADMIN_PASSWORD_HELP_MSG),
        config_arg,
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
                     config_file=None,
                     clean_db=False):
    _prepare_execution(
        verbose,
        private_ip,
        public_ip,
        admin_password,
        clean_db,
        config_write_required=False,
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
    packages = []
    # Adding premium components on all, even if we're on community, because
    # yum will return 0 (success) if any packages install successfully even if
    # some of the specified packages don't exist.
    if is_installed(MANAGER_SERVICE):
        packages += sources.manager
        # Premium components
        packages += sources.manager_cluster + sources.manager_premium

    if is_installed(DATABASE_SERVICE):
        packages += sources.db
        # Premium components
        packages += sources.db_cluster

    if is_installed(QUEUE_SERVICE):
        packages += sources.queue
        # Premium components
        packages += sources.queue_cluster

    if is_installed(MONITORING_SERVICE):
        packages += sources.prometheus
        # Premium components
        packages += sources.prometheus_cluster

    if is_installed(ENTROPY_SERVICE):
        packages += sources.haveged

    return packages


def _configure_supervisord():
    mkdir(SUPERVISORD_CONFIG_DIR)
    # These services will be relevant for using supervisord on VM not on
    # containers
    sudo('systemctl enable supervisord.service', ignore_failures=True)
    sudo('systemctl restart supervisord', ignore_failures=True)


@argh.arg('--only-install', help=ONLY_INSTALL_HELP_MSG, default=False)
@install_args
def install(verbose=False,
            private_ip=None,
            public_ip=None,
            admin_password=None,
            clean_db=False,
            only_install=None,
            config_file=None):
    """ Install Cloudify Manager """

    _prepare_execution(
        verbose,
        private_ip,
        public_ip,
        admin_password,
        clean_db,
        config_write_required=True,
        config_file=config_file,
        only_install=only_install,
    )
    logger.notice('Installing desired components...')
    set_globals(only_install=only_install)
    yum_install(_get_packages())

    if is_supervisord_service():
        _configure_supervisord()

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
              clean_db=False):
    """ Configure Cloudify Manager """

    _prepare_execution(
        verbose,
        private_ip,
        public_ip,
        admin_password,
        clean_db,
        config_write_required=True,
        config_file=config_file,
    )

    _validate_components_prepared('configure')
    logger.notice('Configuring desired components...')
    components = _get_components()
    validate(components=components)
    set_globals()
    # This only relevant for restarting services on VM that use supervisord
    if is_supervisord_service():
        _configure_supervisord()
    if clean_db:
        for component in components:
            component.stop()

    for component in components:
        component.configure()

    config[UNCONFIGURED_INSTALL] = False
    logger.notice('Configuration finished successfully!')
    _finish_configuration()


@config_arg
def remove(verbose=False, force=False, config_file=None):
    """ Uninstall Cloudify Manager """

    _prepare_execution(verbose, config_file=config_file)
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

    installed_services = get_installed_services_names()
    if _are_components_installed():
        for installed_service in installed_services:
            _remove(os.path.join(INITIAL_INSTALL_DIR, installed_service))
        if is_dir_empty(INITIAL_INSTALL_DIR):
            _remove(INITIAL_INSTALL_DIR)
    if _are_components_configured():
        for installed_service in installed_services:
            _remove(os.path.join(INITIAL_CONFIGURE_DIR, installed_service))
        if is_dir_empty(INITIAL_CONFIGURE_DIR):
            _remove(INITIAL_CONFIGURE_DIR)

    if is_supervisord_service():
        _remove(SUPERVISORD_CONFIG_DIR)

    logger.notice('Cloudify Manager successfully removed!')
    _print_time()


@argh.arg('include_components', nargs='*')
@install_args
def start(include_components,
          verbose=False,
          private_ip=None,
          public_ip=None,
          admin_password=None,
          config_file=None,
          clean_db=False,
          only_install=None):
    """ Start Cloudify Manager services """
    _prepare_execution(
        verbose,
        private_ip,
        public_ip,
        admin_password,
        clean_db,
        config_write_required=True,
        config_file=config_file,
    )
    _validate_components_prepared('start')
    set_globals()
    logger.notice('Starting Cloudify Manager services...')
    for component in _get_components(include_components):
        component.start()
    logger.notice('Cloudify Manager services successfully started!')
    _print_time()


@argh.arg('include_components', nargs='*')
@config_arg
def stop(include_components, verbose=False, force=False, config_file=None):
    """ Stop Cloudify Manager services """
    _prepare_execution(verbose, config_file=config_file)
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
@config_arg
def restart(include_components, verbose=False, force=False, config_file=None):
    """ Restart Cloudify Manager services """

    _prepare_execution(verbose, config_file=config_file)
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


def _is_unit_finished(unit_name='cloudify-starter.service'):
    try:
        unit_details = subprocess.check_output(
            ['/bin/systemctl', 'show', unit_name],
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


def _get_starter_service_response():
    server = xmlrpclib.Server(
        'http://',
        transport=service.UnixSocketTransport("/tmp/supervisor.sock"))
    try:
        status_response = server.supervisor.getProcessInfo(STARTER_SERVICE)
    except xmlrpclib.Fault as e:
        raise BootstrapError(
            'Error {0} while trying to lookup {1}'.format(e, STARTER_SERVICE)
        )
    return status_response


def _is_supervisord_service_finished():
    if not os.path.exists('/tmp/supervisor.sock'):
        # supervisord did not start yet
        return False

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


@argh.decorators.named('wait-for-starter')
@config_arg
def wait_for_starter(timeout=300, config_file=None):
    config.load_config(config_file)

    _follow = _FileFollow('/var/log/cloudify/manager/cfy_manager.log')
    _follow.seek_to_end()

    is_started = _is_supervisord_service_finished \
        if is_supervisord_service() else _is_unit_finished
    deadline = time.time() + timeout
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
        config_write_required=False,
        config_file=config_file,
    )
    if _are_components_configured():
        logger.info('Components already configured - nothing to do')
        return
    config.load_config(config_file)
    command = [sys.executable, '-m', 'cfy_manager.main']
    args = []
    private_ip = config[MANAGER].get(PRIVATE_IP)
    if not private_ip:
        private_ip = _guess_private_ip()
        args += ['--private-ip', private_ip]
    if not config[MANAGER].get(PUBLIC_IP):
        # if public ip is not given, default it to the same as private
        args += ['--public-ip', private_ip]
    if not config[MANAGER].get(SECURITY, {}).get(ADMIN_PASSWORD):
        args += ['--admin-password', 'admin']
    try:
        subprocess.check_call(command + ['configure'] + args)
        subprocess.check_call(command + ['start'])
    except subprocess.CalledProcessError:
        sys.exit(1)


@argh.decorators.named('run-init')
@config_arg
def run_init(config_file=None):
    """Run the configured init system/service management system.

    Based on the configuration, run either systemd or supervisord.
    This is to be used for the docker image. Full OS images should run
    systemd on their own.
    """
    config.load_config(config_file)
    if is_supervisord_service():
        os.execv(
            "/usr/bin/supervisord",
            ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisord.conf"])
    else:
        os.execv(
            "/bin/bash",
            ["/bin/bash", "-c", "exec /sbin/init --log-target=journal 3>&1"])


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
    _handle_replace_certs_config_path(input_path)
    if only_validate:
        _only_validate()
    else:
        _replace_certificates()


def _replace_certificates():
    logger.info('Replacing certificates')
    for component in _get_components():
        component.replace_certificates()

    if MANAGER_SERVICE in config[SERVICES_TO_INSTALL]:
        # restart services that might not have been restarted
        for service_name in MGMTWORKER, AMQP_POSTGRES, STAGE, COMPOSER:
            service.restart(service_name)
            service.verify_alive(service_name)


def _handle_replace_certs_config_path(replace_certs_config_path):
    if not replace_certs_config_path:
        return
    replace_certs_config = read_yaml_file(replace_certs_config_path)
    for cert_name, cert_path in replace_certs_config.items():
        new_cert_local_path = NEW_CERTS_TMP_DIR_PATH + cert_name
        if cert_path != new_cert_local_path:
            copy(cert_path, new_cert_local_path)


def _only_validate():
    logger.info('Validating new certificates')
    for component in _get_components():
        component.validate_new_certs()


@argh.named('version')
def version():
    setup_console_logger()
    cfy_version = pkg_resources.require('cloudify-manager-install')[0].version
    logger.info('Cloudify {}'.format(cfy_version))


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
        wait_for_starter,
        run_init,
        version
    ])

    parser.add_commands([
        replace_certificates
    ], namespace='certificates')

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

    parser.dispatch()

    os.umask(current_umask)


if __name__ == '__main__':
    main()
