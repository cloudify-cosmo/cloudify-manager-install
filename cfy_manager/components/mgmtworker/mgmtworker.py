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

from cfy_manager.components import sources
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
from ..syncthing.syncthing import Syncthing

from ...config import config
from ...logger import get_logger
from ... import constants as const
from ...utils import common, service
from ...utils.files import deploy, get_local_source_path
from ...utils.install import (
    yum_install,
    yum_remove,
    is_premium_installed,
    RpmPackageHandler
)
from ...exceptions import FileError


HOME_DIR = '/opt/mgmtworker'
MGMTWORKER_VENV = join(HOME_DIR, 'env')
CLUSTER_SERVICE_QUEUE = 'cluster_service_queue'
LOG_DIR = join(const.BASE_LOG_DIR, MGMTWORKER)
CONFIG_PATH = join(const.COMPONENTS_DIR, MGMTWORKER, CONFIG)

logger = get_logger(MGMTWORKER)


class MgmtWorker(BaseComponent):
    def __init__(self, skip_installation):
        super(MgmtWorker, self).__init__(skip_installation)
        self._syncthing = Syncthing(skip_installation=skip_installation)

    @staticmethod
    def is_premium_installed():
        return RpmPackageHandler.is_package_installed('cloudify-premium')

    def _deploy_mgmtworker_config(self):
        config[MGMTWORKER][HOME_DIR_KEY] = HOME_DIR
        config[MGMTWORKER][LOG_DIR_KEY] = LOG_DIR
        config[MGMTWORKER][SERVICE_USER] = const.CLOUDIFY_USER
        config[MGMTWORKER][SERVICE_GROUP] = const.CLOUDIFY_GROUP
        if is_premium_installed():
            config[MGMTWORKER][CLUSTER_SERVICE_QUEUE] = \
                'cluster_service_queue_{0}'.format(config[MANAGER][HOSTNAME])

        self._deploy_hooks_config()

    def _deploy_admin_token_script(self):
        script_name = 'create-admin-token.py'
        script_src = join(const.COMPONENTS_DIR, MGMTWORKER, 'scripts',
                          script_name)
        target = join(const.BASE_RESOURCES_PATH, MGMTWORKER, script_name)
        deploy(script_src, target, render=True)
        common.chown(const.CLOUDIFY_USER, const.CLOUDIFY_GROUP, target)
        common.chmod('0500', target)

    def _deploy_admin_token(self):
        script_path = join(const.BASE_RESOURCES_PATH, MGMTWORKER,
                           'create-admin-token.py')
        common.run([script_path])

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

    def _verify_mgmtworker_alive(self):
        service.verify_alive(MGMTWORKER)

    def _configure(self):
        self._deploy_mgmtworker_config()
        service.configure(MGMTWORKER)

    def install(self):
        logger.notice('Installing Management Worker...')
        yum_install(sources.mgmtworker)
        self._deploy_admin_token_script()
        logger.notice('Management Worker successfully installed')
        try:
            get_local_source_path(sources.premium)
        except FileError:
            logger.info(
                'premium package not found in manager resources package')
            logger.notice('premium will not be installed.')
        else:
            logger.notice('Installing Cloudify Premium...')
            self._syncthing.install()

    def configure(self):
        logger.notice('Configuring Management Worker...')
        self._configure()
        logger.notice('Management Worker successfully configured')

    def remove(self):
        logger.notice('Removing Management Worker...')
        service.remove(MGMTWORKER, service_file=False)
        yum_remove('cloudify-management-worker')
        common.remove('/opt/mgmtworker')
        common.remove(join(const.BASE_RESOURCES_PATH, MGMTWORKER))
        logger.notice('Management Worker successfully removed')

    def start(self):
        logger.notice('Starting Management Worker...')
        try:
            self._deploy_admin_token()
        except Exception:
            pass
        service.start(MGMTWORKER)
        self._verify_mgmtworker_alive()
        logger.notice('Management Worker successfully started')

    def stop(self):
        logger.notice('Stopping Management Worker...')
        service.stop(MGMTWORKER)
        logger.notice('Management Worker successfully stopped')
