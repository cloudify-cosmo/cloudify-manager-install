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

from os.path import join

from ..components_constants import (
    CONFIG,
    HOME_DIR_KEY,
    LOG_DIR_KEY,
    SERVICE_USER,
    SERVICE_GROUP,
    HOSTNAME
)
from ..base_component import BaseComponent
from ..service_names import MGMTWORKER, MANAGER
from ...config import config
from ...logger import get_logger
from ... import constants as const
from ...utils import common, sudoers
from ...utils.files import deploy
from ...utils.systemd import systemd
from ...utils.install import is_premium_installed


HOME_DIR = '/opt/mgmtworker'
MGMTWORKER_VENV = join(HOME_DIR, 'env')
CLUSTER_SERVICE_QUEUE = 'cluster_service_queue'
LOG_DIR = join(const.BASE_LOG_DIR, MGMTWORKER)
CONFIG_PATH = join(const.COMPONENTS_DIR, MGMTWORKER, CONFIG)
HOOKS_CONFIG = join(HOME_DIR, 'config', 'hooks.conf')
logger = get_logger(MGMTWORKER)


class MgmtWorker(BaseComponent):
    def _add_snapshot_restore_sudo_commands(self):
        sudoers.allow_user_to_sudo_command(
            '/opt/nodejs/bin/npm',
            description='Allow web UI DB migrations during snapshot restore.',
            allow_as='stage_user',
        )

        sudoers.allow_user_to_sudo_command(
            '/usr/bin/cfy_manager status-reporter configure '
            '--token [a-zA-Z0-9]*',
            description='Allows status reporter configuration during '
                        'snapshort restore.',
            allow_as='root',
        )

        scripts = [
            (
                'allow-snapshot-ssl-client-cert-access',
                'Allow cfyuser to access ssl client certs for snapshots.'
            ),
            (
                'deny-snapshot-ssl-client-cert-access',
                'Restore ownership on ssl client certs after snapshot.'
            ),
        ]
        for script, description in scripts:
            sudoers.deploy_sudo_command_script(
                script,
                description,
                component=MGMTWORKER,
                allow_as='root',
            )
            script_path = join(const.BASE_RESOURCES_PATH, MGMTWORKER, script)
            common.chown('root', 'root', script_path)
            common.chmod('0500', script_path)

    def _deploy_mgmtworker_config(self):
        config[MGMTWORKER][HOME_DIR_KEY] = HOME_DIR
        config[MGMTWORKER][LOG_DIR_KEY] = LOG_DIR
        config[MGMTWORKER][SERVICE_USER] = const.CLOUDIFY_USER
        config[MGMTWORKER][SERVICE_GROUP] = const.CLOUDIFY_GROUP
        if is_premium_installed():
            config[MGMTWORKER][CLUSTER_SERVICE_QUEUE] = \
                'cluster_service_queue_{0}'.format(config[MANAGER][HOSTNAME])

        self._deploy_hooks_config()

    def _deploy_admin_token(self):
        script_name = 'create-admin-token.py'
        sudoers.deploy_sudo_command_script(
            script_name,
            'Create an admin token for mgmtworker',
            component=MGMTWORKER,
            allow_as='root',
        )
        script_path = join(const.BASE_RESOURCES_PATH, MGMTWORKER, script_name)
        common.chown('root', 'root', script_path)
        common.chmod('0500', script_path)
        common.run(['sudo', script_path])

    def _deploy_hooks_config(self):
        # If the hooks config file already exists, do nothing. This file
        # can be altered by users, so we shouldn't overwrite it once present.
        # Can't use os.path.exists because the file is owned by cfyuser
        r = common.sudo(
            'ls {0}'.format(HOOKS_CONFIG), ignore_failures=True
        )
        if r.returncode == 0:
            return

        deploy(
            src=join(CONFIG_PATH, 'hooks.conf'),
            dst=HOOKS_CONFIG
        )

        # The user should use root to edit the hooks config file
        common.chmod('440', HOOKS_CONFIG)
        common.chown(const.CLOUDIFY_USER,
                     const.CLOUDIFY_GROUP,
                     HOOKS_CONFIG)

    def _prepare_snapshot_permissions(self):
        self._add_snapshot_restore_sudo_commands()
        # TODO: See if these are necessary
        common.sudo(['chgrp', const.CLOUDIFY_GROUP, '/opt/manager'])
        common.sudo(['chmod', 'g+rw', '/opt/manager'])

    def configure(self):
        logger.notice('Configuring Management Worker...')
        self._deploy_mgmtworker_config()
        systemd.configure(MGMTWORKER)
        self._prepare_snapshot_permissions()
        logger.notice('Management Worker successfully configured')

    def remove(self):
        systemd.remove(MGMTWORKER, service_file=False)
        common.remove('/opt/mgmtworker')
        common.remove(join(const.BASE_RESOURCES_PATH, MGMTWORKER))

    def start(self):
        logger.notice('Starting Management Worker...')
        self._deploy_admin_token()
        systemd.start(MGMTWORKER)
        systemd.verify_alive(MGMTWORKER)
        logger.notice('Management Worker successfully started')

    def stop(self):
        logger.notice('Stopping Management Worker...')
        systemd.stop(MGMTWORKER)
        logger.notice('Management Worker successfully stopped')
