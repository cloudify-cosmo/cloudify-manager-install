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

from ..base_component import BaseComponent
from ..service_names import MANAGER, MANAGER_IP_SETTER
from ...config import config
from ...logger import get_logger
from ...utils import (
    common,
    service,
    files
)
from ... import constants
from ..components_constants import SCRIPTS

MANAGER_IP_SETTER_DIR = join('/opt/cloudify', MANAGER_IP_SETTER)
MANAGER_IP_STARTER_SCRIPT = join(
    MANAGER_IP_SETTER_DIR,
    'manager_ip_starter.sh'
)
MANAGER_IP_STARTER = 'manager_ip_starter'
SCRIPTS_PATH = join(
    constants.COMPONENTS_DIR,
    'manager_ip_setter',
    SCRIPTS,
)

logger = get_logger(MANAGER_IP_SETTER)


class ManagerIpSetter(BaseComponent):
    def _configure_manager_ip_starter_wrapper_script(self):
        files.deploy(
            join(
                SCRIPTS_PATH,
                'manager_ip_starter.sh'
            ),
            MANAGER_IP_SETTER_DIR,
            render=False
        )
        common.chmod('755', MANAGER_IP_STARTER_SCRIPT)

    def configure(self):
        logger.notice('Configuring Manager IP Setter...')
        if config[MANAGER]['set_manager_ip_on_boot']:
            if self.service_type == 'supervisord':
                self._configure_manager_ip_starter_wrapper_script()
                service.configure(MANAGER_IP_STARTER)
            service.configure(MANAGER_IP_SETTER)
        else:
            logger.info('Set manager ip on boot is disabled.')
        logger.notice('Manager IP Setter successfully configured')

    def remove(self):
        service.remove(MANAGER_IP_SETTER, service_file=False)
        common.remove('/opt/cloudify/manager-ip-setter')
