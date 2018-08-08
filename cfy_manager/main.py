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

from .components.globals import set_globals
from .components.validations import validate, validate_config_access
from .components.service_names import MANAGER
from .components.components_constants import (
    INSTALL_DATABASE_ONLY,
    SECURITY,
    PRIVATE_IP,
    PUBLIC_IP,
    ADMIN_PASSWORD,
    CLEAN_DB
)
from .config import config
from .networks.networks import add_networks
from .exceptions import BootstrapError
from .constants import INITIAL_INSTALL_FILE
from .logger import get_logger, setup_console_logger
from utils.components_factory import ComponentsFactory
from .utils.files import remove as _remove, remove_temp_files, touch
from .utils.certificates import (
    create_internal_certs,
    create_external_certs,
    create_pkcs12,
)

logger = get_logger('Main')

COMPONENTS = [
    "manager",
    "manager_ip_setter",
    "nginx",
    "python",
    "postgresql",
    "rabbitmq",
    "restservice",
    "influxdb",
    "amqpinflux",
    "java",
    "amqp_postgres",
    "stage",
    "composer",
    "mgmtworker",
    "riemann",
    "cluster",
    "cli",
    "usage_collector",
    "sanity"
]

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

components_objects = []


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


def _load_config_and_logger(verbose=False,
                            private_ip=None,
                            public_ip=None,
                            admin_password=None,
                            clean_db=False,
                            config_write_required=False):
    setup_console_logger(verbose)
    validate_config_access(config_write_required)
    config.load_config()
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
        else:
            raise BootstrapError(
                'The --admin-password argument can only be used in '
                'conjunction with the --clean-db flag.'
            )


def _print_finish_message():
    manager_config = config[MANAGER]
    protocol = 'https' if config[MANAGER][SECURITY]['ssl_enabled'] else 'http'
    logger.notice(
        'Manager is up at {protocol}://{ip}'.format(
            protocol=protocol,
            ip=manager_config[PUBLIC_IP])
    )
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


def _create_components_objects():
    for component_name in COMPONENTS:
        components_objects.append(
            ComponentsFactory.create_component(component_name))


def install_args(f):
    """Aply all the args that are used by `cfy_manager install`"""
    args = [
        argh.arg('--clean-db', help=CLEAN_DB_HELP_MSG),
        argh.arg('--private-ip', help=PRIVATE_IP_HELP_MSG),
        argh.arg('--public-ip', help=PUBLIC_IP_HELP_MSG),
        argh.arg('-a', '--admin-password', help=ADMIN_PASSWORD_HELP_MSG),
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
    _load_config_and_logger(
        verbose,
        private_ip,
        public_ip,
        admin_password,
        clean_db,
        config_write_required=False
    )
    validate(components=components_objects)


@argh.arg('--private-ip', help=PRIVATE_IP_HELP_MSG)
def sanity_check(verbose=False, private_ip=None):
    """Run the Cloudify Manager sanity check"""
    _load_config_and_logger(verbose=verbose, private_ip=private_ip)
    for component in components_objects:
        component.run_sanity_check()


@install_args
def install(verbose=False,
            private_ip=None,
            public_ip=None,
            admin_password=None,
            clean_db=False):
    """ Install Cloudify Manager """

    _load_config_and_logger(
        verbose,
        private_ip,
        public_ip,
        admin_password,
        clean_db,
        config_write_required=True
    )

    manager_config = config[MANAGER]
    if not manager_config[MANAGER][INSTALL_DATABASE_ONLY]:
        logger.notice('Installing Cloudify Manager...')
        validate(components=components_objects)
        set_globals()

    for component in components_objects:
        component.install()

    logger.notice('Cloudify Manager successfully installed!')
    _finish_configuration()


@install_args
def configure(verbose=False,
              private_ip=None,
              public_ip=None,
              admin_password=None,
              clean_db=False):
    """ Configure Cloudify Manager """

    _load_config_and_logger(
        verbose,
        private_ip,
        public_ip,
        admin_password,
        clean_db,
        config_write_required=True
    )

    logger.notice('Configuring Cloudify Manager...')
    _validate_manager_installed('configure')
    validate(skip_validations=True, components=components_objects)
    set_globals()

    for component in components_objects:
        component.configure()

    logger.notice('Cloudify Manager successfully configured!')
    _finish_configuration()


def remove(verbose=False, force=False):
    """ Uninstall Cloudify Manager """

    _load_config_and_logger(verbose)
    _validate_force(force, 'remove')
    logger.notice('Removing Cloudify Manager...')

    should_stop = _is_manager_installed()

    for component in reversed(components_objects):
        if should_stop:
            component.stop()
        component.remove()

    if _is_manager_installed():
        _remove(INITIAL_INSTALL_FILE)

    logger.notice('Cloudify Manager successfully removed!')
    _print_time()


def start(verbose=False):
    """ Start Cloudify Manager services """

    _load_config_and_logger(verbose)
    _validate_manager_installed('start')
    logger.notice('Starting Cloudify Manager services...')
    for component in components_objects:
        component.start()
    logger.notice('Cloudify Manager services successfully started!')
    _print_time()


def stop(verbose=False, force=False):
    """ Stop Cloudify Manager services """

    _load_config_and_logger(verbose)
    _validate_manager_installed('stop')
    _validate_force(force, 'stop')

    logger.notice('Stopping Cloudify Manager services...')
    for component in components_objects:
        component.stop()
    logger.notice('Cloudify Manager services successfully stopped!')
    _print_time()


def restart(verbose=False, force=False):
    """ Restart Cloudify Manager services """

    _load_config_and_logger(verbose)
    _validate_manager_installed('restart')
    _validate_force(force, 'restart')

    stop(verbose, force)
    start(verbose)
    _print_time()


def main():
    """Main entry point"""
    _create_components_objects()
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
        add_networks
    ])


if __name__ == '__main__':
    main()
