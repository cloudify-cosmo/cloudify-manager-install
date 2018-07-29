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
import subprocess
from os.path import join
from tempfile import gettempdir

from ..service_names import MANAGER

from .. import CONFIG
from ... import constants
from ...logger import get_logger

from ...utils import common
from ...utils.users import create_service_user
from ...utils.logrotate import setup_logrotate
from ...utils.sudoers import add_entry_to_sudoers
from ...utils.files import (replace_in_file,
                            remove_files,
                            deploy,
                            touch)

CONFIG_PATH = join(constants.COMPONENTS_DIR, MANAGER, CONFIG)
TMPFILES_FILE_NAME = 'cloudify.conf'
TMPFILES_FILE_PATH = join(constants.TMPFILES_INCLUDE_DIR, TMPFILES_FILE_NAME)

logger = get_logger(MANAGER)


def _get_exec_tempdir():
    return os.environ.get(constants.CFY_EXEC_TEMPDIR_ENVVAR) or gettempdir()


def _create_cloudify_user():
    create_service_user(
        user=constants.CLOUDIFY_USER,
        group=constants.CLOUDIFY_GROUP,
        home=constants.CLOUDIFY_HOME_DIR
    )
    common.mkdir(constants.CLOUDIFY_HOME_DIR)


def _create_run_dir():
    deploy(src=join(CONFIG_PATH, TMPFILES_FILE_NAME), dst=TMPFILES_FILE_PATH)
    common.run(['sudo', 'systemd-tmpfiles', '--create', '--prefix={}'.format(constants.COMMON_LOCK_DIR)])


def _delete_run_dir():
    remove_files([
        TMPFILES_FILE_PATH
    ])
    common.run(['sudo', 'systemd-tmpfiles', '--delete', '--prefix={}'.format(constants.COMMON_LOCK_DIR)])


def _create_sudoers_file_and_disable_sudo_requiretty():
    common.remove(constants.CLOUDIFY_SUDOERS_FILE, ignore_failure=True)
    touch(constants.CLOUDIFY_SUDOERS_FILE)
    common.chmod('440', constants.CLOUDIFY_SUDOERS_FILE)
    entry = 'Defaults:{user} !requiretty'.format(user=constants.CLOUDIFY_USER)
    description = 'Disable sudo requiretty for {0}'.format(
        constants.CLOUDIFY_USER
    )
    add_entry_to_sudoers(entry, description)


def _get_selinux_state():
    try:
        return subprocess.check_output(['/usr/sbin/getenforce']).rstrip('\n\r')
    except OSError as e:
        logger.warning('SELinux is not installed ({0})'.format(e))
        return None


def _set_selinux_permissive():
    """This sets SELinux to permissive mode both for the current session
    and systemwide.
    """
    selinux_state = _get_selinux_state()
    logger.debug('Checking whether SELinux in enforced...')
    if selinux_state == 'Enforcing':
        logger.info('SELinux is enforcing, setting permissive state...')
        common.sudo(['setenforce', 'permissive'])
        replace_in_file(
            'SELINUX=enforcing',
            'SELINUX=permissive',
            '/etc/selinux/config')
    else:
        logger.debug('SELinux is not enforced.')


def _create_manager_resources_dirs():
    resources_root = constants.MANAGER_RESOURCES_HOME
    common.mkdir(resources_root)
    common.mkdir(join(resources_root, 'cloudify_agent'))
    common.mkdir(join(resources_root, 'packages', 'scripts'))
    common.mkdir(join(resources_root, 'packages', 'templates'))


def _configure():
    _create_cloudify_user()
    _create_run_dir()
    _create_sudoers_file_and_disable_sudo_requiretty()
    _set_selinux_permissive()
    setup_logrotate()
    _create_manager_resources_dirs()


def install():
    logger.notice('Installing Cloudify Manager resources...')
    _configure()
    logger.notice('Cloudify Manager resources successfully installed')


def configure():
    logger.notice('Configuring Cloudify Manager resources...')
    _configure()
    logger.notice('Cloudify Manager resources successfully configured...')


def remove():
    logger.notice('Removing Cloudify Manager resources...')
    _delete_run_dir()
    remove_files([
        join(_get_exec_tempdir(), 'cloudify-ctx'),
    ])
    logger.notice('Cloudify Manager resources successfully removed')
