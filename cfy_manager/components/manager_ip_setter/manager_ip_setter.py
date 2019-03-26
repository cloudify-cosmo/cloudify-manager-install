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

from ..components_constants import SOURCES
from ..base_component import BaseComponent
from ..service_names import MANAGER, MANAGER_IP_SETTER
from ...config import config
from ...logger import get_logger
from ...utils import common
from ...utils.systemd import systemd
from ...utils.install import yum_install, yum_remove


MANAGER_IP_SETTER_DIR = join('/opt/cloudify', MANAGER_IP_SETTER)

logger = get_logger(MANAGER_IP_SETTER)


class ManagerIpSetterComponent(BaseComponent):
    def __init__(self, skip_installation):
        super(ManagerIpSetterComponent, self).__init__(skip_installation)

    def _install(self):
        sources = config[MANAGER_IP_SETTER][SOURCES]
        for source in sources.values():
            yum_install(source)

    def _configure(self):
        if config[MANAGER]['set_manager_ip_on_boot']:
            systemd.configure(MANAGER_IP_SETTER)
        else:
            logger.info('Set manager ip on boot is disabled.')

    def install(self):
        logger.notice('Installing Manager IP Setter...')
        self._install()
        logger.notice('Manager IP Setter successfully installed')

    def configure(self):
        logger.notice('Configuring Manager IP Setter...')
        self._configure()
        logger.notice('Manager IP Setter successfully configured')

    def remove(self):
        logger.notice('Removing Manager IP Setter...')
        systemd.remove(MANAGER_IP_SETTER, service_file=False)
        yum_remove('cloudify-manager-ip-setter')
        common.remove('/opt/cloudify/manager-ip-setter')
        logger.notice('Manager IP Setter successfully removed')
