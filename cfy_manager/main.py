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
from .components.validations import validate

from .components.service_names import MANAGER
from .components import (
    SECURITY,
    PRIVATE_IP,
    PUBLIC_IP,
    ADMIN_PASSWORD,
    CLEAN_DB
)

from .config import config
from .exceptions import BootstrapError
from .constants import INITIAL_INSTALL_FILE
from .logger import get_logger, setup_console_logger

from .utils.files import remove_temp_files, touch
from .utils.certificates import (
    create_internal_certs,
    create_external_certs,
    create_pkcs12,
)
from .components import (
    handlers,
    services
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
SERVICE_NAME_HELP_MSG = 'The service to {op}'


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
                            clean_db=False):
    setup_console_logger(verbose)
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
    logger.notice('Manager is up at {0}'.format(manager_config[PUBLIC_IP]))
    logger.notice('#' * 50)
    logger.notice('Manager password is {0}'.format(
        manager_config[SECURITY][ADMIN_PASSWORD]))
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


@argh.arg('--clean-db', help=CLEAN_DB_HELP_MSG)
@argh.arg('-a', '--admin-password', help=ADMIN_PASSWORD_HELP_MSG)
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
        clean_db
    )

    logger.notice('Installing Cloudify Manager...')
    validate()
    set_globals()

    for component in handlers.COMPONENTS:
        component.install()

    logger.notice('Cloudify Manager successfully installed!')
    _finish_configuration()


@argh.arg('--clean-db', help=CLEAN_DB_HELP_MSG)
@argh.arg('-a', '--admin-password', help=ADMIN_PASSWORD_HELP_MSG)
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
        clean_db
    )

    logger.notice('Configuring Cloudify Manager...')
    if not _is_manager_installed():
        raise BootstrapError(
            'Could not find {touched_file}.\nThis most likely means '
            'that you need to run `cfy_manager install` before '
            'running `cfy_manager configure`'.format(
                touched_file=INITIAL_INSTALL_FILE
            )
        )
    validate(skip_validations=True)
    set_globals()

    for component in handlers.COMPONENTS:
        component.configure()

    logger.notice('Cloudify Manager successfully configured!')
    _finish_configuration()


def remove(verbose=False, force=False):
    """ Uninstall Cloudify Manager """

    _load_config_and_logger(verbose)
    if not force:
        raise BootstrapError(
            'The --force flag must be passed to `cfy_manager remove`'
        )

    logger.notice('Removing Cloudify Manager...')

    for component in handlers.COMPONENTS:
        component.remove()

    logger.notice('Cloudify Manager successfully removed!')
    _print_time()


@argh.arg('-s', '--service',
          action='append',
          help=SERVICE_NAME_HELP_MSG.format(op='start'))
def start_service(verbose=False, force=False, service=None):
    """Start a manager services"""
    import pydevd; pydevd.settrace('localhost', suspend=False, port=11223)
    logger.notice('Starting services')
    services.start(service)
    logger.notice('Services started')


@argh.arg('-s', '--service',
          action='append',
          help=SERVICE_NAME_HELP_MSG.format(op='stop'))
def stop_service(verbose=False, force=False, service='all'):
    """Stop a manager services"""
    logger.notice('Stopping services')
    services.stop(service)
    logger.notice('Services stopped')


def main():
    """Main entry point"""
    argh.dispatch_commands([
        install,
        configure,
        remove,
        start_service,
        stop_service,
        create_internal_certs,
        create_external_certs,
        create_pkcs12,
    ])


if __name__ == '__main__':
    main()
