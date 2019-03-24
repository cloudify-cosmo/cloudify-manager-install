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

from os.path import join, dirname

from .cluster.cluster import ClusterComponent

from ..components_constants import (
    SOURCES,
    CONFIG,
    HOME_DIR_KEY,
    LOG_DIR_KEY,
    SERVICE_USER,
    SERVICE_GROUP,
    HOSTNAME
)
from ..base_component import BaseComponent
from ..service_names import MGMTWORKER, CLUSTER, MANAGER, PREMIUM
from ...config import config
from ...logger import get_logger
from ... import constants as const
from ...utils import common, sudoers
from ...utils.files import (
    deploy,
    get_local_source_path
)
from ...utils.systemd import systemd
from ...utils.install import yum_install, yum_remove
from ...exceptions import FileError


HOME_DIR = '/opt/mgmtworker'
MGMTWORKER_VENV = join(HOME_DIR, 'env')
CLUSTER_SERVICE_QUEUE = 'cluster_service_queue'
LOG_DIR = join(const.BASE_LOG_DIR, MGMTWORKER)
CONFIG_PATH = join(const.COMPONENTS_DIR, MGMTWORKER, CONFIG)

logger = get_logger(MGMTWORKER)


class MgmtWorkerComponent(BaseComponent):
    def __init__(self, skip_installation):
        super(MgmtWorkerComponent, self).__init__(skip_installation)

    def _install(self):
        source_url = config[MGMTWORKER][SOURCES]['mgmtworker_source_url']
        yum_install(source_url)

        premium_source_url = config[PREMIUM][SOURCES]['premium_source_url']
        try:
            get_local_source_path(premium_source_url)
        except FileError:
            logger.info(
                'premium package not found in manager resources package')
            logger.notice('premium will not be installed.')
        else:
            logger.notice('Installing Cloudify Premium...')
            cluster = ClusterComponent(skip_installation=False)
            cluster.install()

    def _deploy_mgmtworker_config(self):
        config[MGMTWORKER][HOME_DIR_KEY] = HOME_DIR
        config[MGMTWORKER][LOG_DIR_KEY] = LOG_DIR
        config[MGMTWORKER][SERVICE_USER] = const.CLOUDIFY_USER
        config[MGMTWORKER][SERVICE_GROUP] = const.CLOUDIFY_GROUP
        if config[CLUSTER]['enabled']:
            config[MGMTWORKER][CLUSTER_SERVICE_QUEUE] = \
                'cluster_service_queue_{0}'.format(config[MANAGER][HOSTNAME])

        self._deploy_broker_config()
        self._deploy_hooks_config()
        self._deploy_admin_token()

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

    def _deploy_broker_config(self):
        file_name = 'broker_config.json'
        work_dir = join(HOME_DIR, 'work')
        broker_config_dst = join(work_dir, file_name)
        deploy(
            src=join(CONFIG_PATH, file_name),
            dst=broker_config_dst
        )

        # The config contains credentials, do not let the world read it
        common.chmod('440', broker_config_dst)
        common.chown(const.CLOUDIFY_USER,
                     const.CLOUDIFY_GROUP,
                     broker_config_dst)

    def _deploy_hooks_config(self):
        file_name = 'hooks.conf'
        config_dir = join(HOME_DIR, 'config')
        hooks_config_dst = join(config_dir, file_name)

        # If the hooks config file already exists, do nothing. This file
        # can be altered by users, so we shouldn't overwrite it once present.
        # Can't use os.path.exists because the file is owned by cfyuser
        r = common.sudo(
            'ls {0}'.format(hooks_config_dst), ignore_failures=True
        )
        if r.returncode == 0:
            return

        deploy(
            src=join(CONFIG_PATH, file_name),
            dst=hooks_config_dst
        )

        # The user should use root to edit the hooks config file
        common.chmod('440', hooks_config_dst)
        common.chown(const.CLOUDIFY_USER,
                     const.CLOUDIFY_GROUP,
                     hooks_config_dst)

    def _prepare_snapshot_permissions(self):
        # TODO: See if all of this is necessary
        common.sudo(['chgrp', const.CLOUDIFY_GROUP, '/opt/manager'])
        common.sudo(['chmod', 'g+rw', '/opt/manager'])
        common.sudo(
            ['chgrp', '-R', const.CLOUDIFY_GROUP, const.SSL_CERTS_TARGET_DIR]
        )
        common.sudo(
            ['chgrp',
             const.CLOUDIFY_GROUP,
             dirname(const.SSL_CERTS_TARGET_DIR)]
        )
        common.sudo(['chmod', '-R', 'g+rw', const.SSL_CERTS_TARGET_DIR])
        common.sudo(['chmod', 'g+rw', dirname(const.SSL_CERTS_TARGET_DIR)])

    def _verify_mgmtworker_alive(self):
        systemd.verify_alive(MGMTWORKER)

    def _configure(self):
        cluster = ClusterComponent(skip_installation=False)
        cluster.configure()
        self._deploy_mgmtworker_config()
        systemd.configure(MGMTWORKER)
        self._prepare_snapshot_permissions()
        systemd.restart(MGMTWORKER)
        self._verify_mgmtworker_alive()

    def install(self):
        logger.notice('Installing Management Worker...')
        self._install()
        logger.notice('Management Worker successfully installed')

    def configure(self):
        logger.notice('Configuring Management Worker...')
        self._configure()
        logger.notice('Management Worker successfully configured')

    def remove(self):
        logger.notice('Removing Management Worker...')
        systemd.remove(MGMTWORKER, service_file=False)
        yum_remove('cloudify-management-worker')
        common.remove('/opt/mgmtworker')
        common.remove(join(const.BASE_RESOURCES_PATH, MGMTWORKER))
        logger.notice('Management Worker successfully removed')

    def start(self):
        logger.notice('Starting Management Worker...')
        systemd.start(MGMTWORKER)
        self._verify_mgmtworker_alive()
        logger.notice('Management Worker successfully started')

    def stop(self):
        logger.notice('Stopping Management Worker...')
        systemd.stop(MGMTWORKER)
        logger.notice('Management Worker successfully stopped')
