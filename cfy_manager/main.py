#!/usr/bin/env python
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
import sys
import argh
from time import time
from traceback import format_exception

from .components import (
    ComponentsFactory,
    SERVICE_COMPONENTS,
    MANAGER_SERVICE,
    QUEUE_SERVICE,
    SERVICE_INSTALLATION_ORDER
)
from .components.globals import set_globals, print_password_to_screen
from .components.validations import validate, validate_config_access
from .components.service_names import (
    MANAGER,
    CLUSTER,
    POSTGRESQL_CLIENT
)
from .components.components_constants import (
    SERVICES_TO_INSTALL,
    SECURITY,
    PRIVATE_IP,
    PUBLIC_IP,
    ADMIN_PASSWORD,
    CLEAN_DB,
    MASTER_IP
)
from .config import config
from .encryption.encryption import update_encryption_key
from .networks.networks import add_networks
from .exceptions import BootstrapError
from .constants import INITIAL_INSTALL_FILE
from .logger import get_logger, setup_console_logger
from .utils import CFY_UMASK
from .utils.files import remove as _remove, remove_temp_files, touch
from .utils.certificates import (
    create_internal_certs,
    create_external_certs,
    create_pkcs12,
)

logger = get_logger('Main')

START_TIME = time()


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
JOIN_CLUSTER_HELP_MSG = (
    "In case this machine will join an existing cluster with an external DB."
    "To join to a cluster, use the --join-cluster flag with the "
    "--admin-password flag supplying the master manager's password, the "
    "--database-ip supplying the external database's IP, and the"
    "--postgres-password supplying the external database's postgres user "
    "password."
)
DATABASE_IP_HELP_MSG = (
    "Used together with --join-cluster flag when joining to an existing "
    "cluster with an external database."
)
POSTGRES_PASSWORD_HELP_MSG = (
    "Used together with --join-cluster flag when joining to an existing "
    "cluster with an external database."
)

components = []


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


def _validate_config_values(private_ip, public_ip, admin_password, clean_db,
                            join_cluster=None, database_ip=None,
                            postgres_password=None):
    manager_config = config[MANAGER]

    # If the DB wasn't initiated even once yet, always set clean_db to True
    config[CLEAN_DB] = clean_db or not _is_manager_installed()

    if private_ip:
        manager_config[PRIVATE_IP] = private_ip
    if public_ip:
        manager_config[PUBLIC_IP] = public_ip
    if admin_password:
        if config[CLEAN_DB]:
            manager_config[SECURITY][ADMIN_PASSWORD] = admin_password
            if all([join_cluster, database_ip, postgres_password]):
                config[CLUSTER][MASTER_IP] = str(join_cluster)
                config[POSTGRESQL_CLIENT]['host'] = str(database_ip)
                config[POSTGRESQL_CLIENT]['postgres_password'] = \
                    str(postgres_password)
                config[POSTGRESQL_CLIENT]['ssl_enabled'] = True
                config[SERVICES_TO_INSTALL] = [
                    QUEUE_SERVICE,
                    MANAGER_SERVICE
                ]
            elif any([join_cluster, database_ip, postgres_password]):
                raise BootstrapError(
                    'The --join-cluster, --database-ip, --admin-password '
                    'and --postgres-password flags must be used together'
                )
        else:
            raise BootstrapError(
                'The --admin-password argument can only be used in '
                'conjunction with the --clean-db flag.'
            )
    elif any([join_cluster, database_ip]):
        raise BootstrapError(
            'The --join-cluster, --database-ip and --admin-password'
            'flags must be used together'
        )


def _prepare_execution(verbose=False,
                       private_ip=None,
                       public_ip=None,
                       admin_password=None,
                       clean_db=False,
                       config_write_required=False,
                       join_cluster=None,
                       database_ip=None,
                       postgres_password=None):
    setup_console_logger(verbose)

    validate_config_access(config_write_required)
    config.load_config()
    _validate_config_values(private_ip, public_ip, admin_password, clean_db,
                            join_cluster, database_ip, postgres_password)
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
        print_password_to_screen()
        logger.notice('#' * 50)
        logger.notice("To install the default plugins bundle run:")
        logger.notice("'cfy plugins bundle-upload'")
        logger.notice('#' * 50)


def _is_manager_installed():
    return os.path.isfile(INITIAL_INSTALL_FILE)


def _create_initial_install_file():
    """
    Create /etc/cloudify/.installed if install finished successfully
    for the first time
    """
    if not _is_manager_installed():
        touch(INITIAL_INSTALL_FILE)


def _finish_configuration():
    remove_temp_files()
    _print_finish_message()
    _print_time()
    config.dump_config()
    _create_initial_install_file()


def _validate_force(force, cmd):
    if not force:
        raise BootstrapError(
            'The --force flag must be passed to `cfy_manager {0}`'.format(cmd)
        )


def _validate_manager_installed(cmd):
    if not _is_manager_installed():
        raise BootstrapError(
            'Could not find {touched_file}.\nThis most likely means '
            'that you need to run `cfy_manager install` before '
            'running `cfy_manager {cmd}`'.format(
                touched_file=INITIAL_INSTALL_FILE,
                cmd=cmd
            )
        )
    if os.path.exists('/etc/cloudify/cluster'):
        raise BootstrapError(
            "Operation '{0}' is not allowed on a cluster node".format(cmd))


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


def install_args(f):
    """Apply all the args that are used by `cfy_manager install`"""
    args = [
        argh.arg('--clean-db', help=CLEAN_DB_HELP_MSG),
        argh.arg('--private-ip', help=PRIVATE_IP_HELP_MSG),
        argh.arg('--public-ip', help=PUBLIC_IP_HELP_MSG),
        argh.arg('-a', '--admin-password', help=ADMIN_PASSWORD_HELP_MSG),
        argh.arg('--join-cluster', help=JOIN_CLUSTER_HELP_MSG),
        argh.arg('--database-ip', help=DATABASE_IP_HELP_MSG),
        argh.arg('--postgres-password', help=POSTGRES_PASSWORD_HELP_MSG)
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
                     clean_db=False,
                     join_cluster=None,
                     database_ip=None,
                     postgres_password=None):
    _prepare_execution(
        verbose,
        private_ip,
        public_ip,
        admin_password,
        clean_db,
        join_cluster=join_cluster,
        database_ip=database_ip,
        postgres_password=postgres_password,
        config_write_required=False
    )
    validate(components=components)


@argh.arg('--private-ip', help=PRIVATE_IP_HELP_MSG)
def sanity_check(verbose=False, private_ip=None):
    """Run the Cloudify Manager sanity check"""
    _prepare_execution(verbose=verbose, private_ip=private_ip)
    sanity = ComponentsFactory.create_component('sanity')
    sanity.run_sanity_check()


@install_args
def install(verbose=False,
            private_ip=None,
            public_ip=None,
            admin_password=None,
            clean_db=False,
            join_cluster=None,
            database_ip=None,
            postgres_password=None):
    """ Install Cloudify Manager """

    _prepare_execution(
        verbose,
        private_ip,
        public_ip,
        admin_password,
        clean_db,
        join_cluster=join_cluster,
        database_ip=database_ip,
        postgres_password=postgres_password,
        config_write_required=True
    )
    logger.notice('Installing desired components...')
    validate(components=components)
    set_globals()

    for component in components:
        if not component.skip_installation:
            component.install()

    logger.notice('Installation finished successfully!')
    _finish_configuration()


@install_args
def configure(verbose=False,
              private_ip=None,
              public_ip=None,
              admin_password=None,
              clean_db=False,
              join_cluster=None,
              database_ip=None,
              postgres_password=None):
    """ Configure Cloudify Manager """

    _prepare_execution(
        verbose,
        private_ip,
        public_ip,
        admin_password,
        clean_db,
        config_write_required=True
    )

    logger.notice('Configuring desired components...')
    _validate_manager_installed('configure')
    validate(skip_validations=True, components=components)
    set_globals()

    if clean_db:
        for component in components:
            if not component.skip_installation:
                component.stop()

    for component in components:
        if not component.skip_installation:
            component.configure()

    logger.notice('Configuration finished successfully!')
    _finish_configuration()


def remove(verbose=False, force=False):
    """ Uninstall Cloudify Manager """

    _prepare_execution(verbose)
    _validate_force(force, 'remove')
    logger.notice('Removing Cloudify Manager...')

    should_stop = _is_manager_installed()

    for component in reversed(components):
        if should_stop and not component.skip_installation:
            component.stop()
        component.remove()

    if _is_manager_installed():
        _remove(INITIAL_INSTALL_FILE)

    logger.notice('Cloudify Manager successfully removed!')
    _print_time()


def start(verbose=False):
    """ Start Cloudify Manager services """

    _prepare_execution(verbose)
    _validate_manager_installed('start')
    logger.notice('Starting Cloudify Manager services...')
    for component in components:
        if not component.skip_installation:
            component.start()
    logger.notice('Cloudify Manager services successfully started!')
    _print_time()


def stop(verbose=False, force=False):
    """ Stop Cloudify Manager services """

    _prepare_execution(verbose)
    _validate_manager_installed('stop')
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
    _validate_manager_installed('restart')
    _validate_force(force, 'restart')

    stop(verbose, force)
    start(verbose)
    _print_time()


def main():
    # Set the umask to 0022; restore it later.
    current_umask = os.umask(CFY_UMASK)
    """Main entry point"""
    argh.dispatch_commands([
        validate_command,
        install,
        configure,
        remove,
        start,
        stop,
        restart,
        create_internal_certs,
        create_external_certs,
        create_pkcs12,
        sanity_check,
        add_networks,
        update_encryption_key,
    ])
    os.umask(current_umask)


if __name__ == '__main__':
    main()
