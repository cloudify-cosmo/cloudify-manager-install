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

from .components import db
from .components import cli
from .components import java
from .components import nginx
from .components import stage
from .components import sanity
from .components import consul
from .components import python
from .components import manager
from .components import riemann
from .components import composer
from .components import logstash
from .components import rabbitmq
from .components import influxdb
from .components import syncthing
from .components import amqpinflux
from .components import mgmtworker
from .components import postgresql
from .components import restservice
from .components import manager_ip_setter

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
from .constants import INITIAL_DB_CREATION_FILE
from .logger import get_logger, setup_console_logger

from .utils.files import remove_temp_files
from .utils.certificates import (
    create_internal_certs,
    create_external_certs
)

logger = get_logger('Main')

COMPONENTS = [
    manager,
    manager_ip_setter,
    nginx,
    python,
    postgresql,
    rabbitmq,
    db,
    restservice,
    influxdb,
    amqpinflux,
    java,
    riemann,
    consul,
    syncthing,
    stage,
    composer,
    logstash,
    mgmtworker,
    cli,
    sanity
]

START_TIME = time()


CLEAN_DB_HELP_MSG = (
    'If set to "false", the DB will not be recreated when '
    'installing/configuring the Manager. Must be set to "true" on the first '
    'installation. If set to "false", the hash salt and admin password '
    'will not be generated'
)


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
    if private_ip:
        manager_config[PRIVATE_IP] = private_ip
    if public_ip:
        manager_config[PUBLIC_IP] = public_ip
    if admin_password:
        manager_config[SECURITY][ADMIN_PASSWORD] = admin_password

    # If the DB wasn't initiated even once yet, always set clean_db to True
    config[CLEAN_DB] = clean_db or not _is_db_initiated()


def _print_finish_message():
    manager_config = config[MANAGER]
    logger.notice('Manager is up at {0}'.format(manager_config[PUBLIC_IP]))
    logger.notice('#' * 50)
    logger.notice('Manager password is {0}'.format(
        manager_config[SECURITY][ADMIN_PASSWORD]))
    logger.notice('#' * 50)


def _is_db_initiated():
    return os.path.isfile(INITIAL_DB_CREATION_FILE)


def _update_initial_db_file():
    """
    Update /etc/cloudify/.db_created if the --clean-db flag was passed, and
    the install/configure process finished successfully
    :return:
    """
    # Only create if --clean-db was passed and the file doesn't exist
    if config[CLEAN_DB] and not _is_db_initiated():
        with open(INITIAL_DB_CREATION_FILE, 'w'):
            pass


def _finish_configuration():
    remove_temp_files()
    _print_finish_message()
    _print_time()
    config.dump_config()
    _update_initial_db_file()


@argh.arg('--clean-db', help=CLEAN_DB_HELP_MSG)
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

    for component in COMPONENTS:
        component.install()

    logger.notice('Cloudify Manager successfully installed!')
    _finish_configuration()


@argh.arg('--clean-db', help=CLEAN_DB_HELP_MSG)
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
    validate(skip_validations=True)
    set_globals()

    for component in COMPONENTS:
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

    for component in COMPONENTS:
        component.remove()

    logger.notice('Cloudify Manager successfully removed!')
    _print_time()


def main():
    """Main entry point"""
    argh.dispatch_commands([
        install,
        configure,
        remove,
        create_internal_certs,
        create_external_certs
    ])


if __name__ == '__main__':
    main()
