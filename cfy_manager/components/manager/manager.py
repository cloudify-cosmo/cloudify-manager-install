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

from ..base_component import BaseComponent
from ..service_names import MANAGER
from ..components_constants import CONFIG, SERVICES_TO_INSTALL
from ..service_components import QUEUE_SERVICE
from ..service_names import RABBITMQ
from ... import constants
from ...config import config
from ...logger import get_logger
from ...utils import common, service
from ...utils.certificates import use_supplied_certificates
from ...utils.files import (replace_in_file,
                            remove_files,
                            touch)
from ...utils.logrotate import setup_logrotate
from ...utils.sudoers import add_entry_to_sudoers
from ...utils.users import create_service_user

CONFIG_PATH = join(constants.COMPONENTS_DIR, MANAGER, CONFIG)

logger = get_logger(MANAGER)


class Manager(BaseComponent):
    def __init__(self, skip_installation):
        super(Manager, self).__init__(skip_installation)

    def _install(self):
        self._create_cloudify_user()
        self._create_sudoers_file_and_disable_sudo_requiretty()
        self._set_selinux_permissive()
        setup_logrotate()
        self._create_manager_resources_dirs()

    def _get_exec_tempdir(self):
        return os.environ.get(constants.CFY_EXEC_TEMPDIR_ENVVAR) or \
               gettempdir()

    def _create_cloudify_user(self):
        create_service_user(
            user=constants.CLOUDIFY_USER,
            group=constants.CLOUDIFY_GROUP,
            home=constants.CLOUDIFY_HOME_DIR
        )
        common.mkdir(constants.CLOUDIFY_HOME_DIR)
        common.chown(
            constants.CLOUDIFY_USER,
            constants.CLOUDIFY_GROUP,
            constants.CLOUDIFY_HOME_DIR,
        )

    def _create_sudoers_file_and_disable_sudo_requiretty(self):
        common.remove(constants.CLOUDIFY_SUDOERS_FILE, ignore_failure=True)
        touch(constants.CLOUDIFY_SUDOERS_FILE)
        common.chmod('440', constants.CLOUDIFY_SUDOERS_FILE)
        entry = 'Defaults:{user} !requiretty'\
            .format(user=constants.CLOUDIFY_USER)
        description = 'Disable sudo requiretty for {0}'.format(
            constants.CLOUDIFY_USER
        )
        add_entry_to_sudoers(entry, description)

    def _get_selinux_state(self):
        try:
            return subprocess.check_output(['/usr/sbin/getenforce'])\
                .rstrip('\n\r')
        except OSError as e:
            logger.warning('SELinux is not installed ({0})'.format(e))
            return None

    def _set_selinux_permissive(self):
        """This sets SELinux to permissive mode both for the current session
        and systemwide.
        """
        selinux_state = self._get_selinux_state()
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

    def _create_manager_resources_dirs(self):
        resources_root = constants.MANAGER_RESOURCES_HOME
        common.mkdir(resources_root)
        common.mkdir(join(resources_root, 'cloudify_agent'))
        common.mkdir(join(resources_root, 'packages', 'scripts'))
        common.mkdir(join(resources_root, 'packages', 'templates'))

    def _prepare_certificates(self):
        if not os.path.exists(constants.SSL_CERTS_TARGET_DIR):
            common.mkdir(constants.SSL_CERTS_TARGET_DIR)
        common.chown(
            constants.CLOUDIFY_USER,
            constants.CLOUDIFY_GROUP,
            constants.SSL_CERTS_TARGET_DIR,
        )
        # Move the broker certificate if we're not installing it locally
        if QUEUE_SERVICE not in config[SERVICES_TO_INSTALL]:
            # ...but only if one was provided.
            if config[RABBITMQ]['ca_path']:
                use_supplied_certificates(
                    component_name=RABBITMQ,
                    logger=logger,
                    ca_destination=constants.BROKER_CA_LOCATION,
                )

    def _configure(self):
        self._prepare_certificates()

    def install(self):
        logger.notice('Installing Cloudify Manager resources...')
        self._install()
        logger.notice('Cloudify Manager resources successfully installed!')

    def configure(self):
        logger.notice('Configuring Cloudify Manager resources...')
        self._configure()
        logger.notice('Cloudify Manager resources successfully configured!')

    def remove(self):
        logger.notice('Removing Cloudify Manager resources...')
        remove_files([
            join(self._get_exec_tempdir(), 'cloudify-ctx'),
        ])
        # Remove syncthing so a reinstall of a cluster node can work
        # TODO
        service.remove('syncthing')
        remove_files([
            '/opt/syncthing',
        ])
        logger.notice('Cloudify Manager resources successfully removed!')
