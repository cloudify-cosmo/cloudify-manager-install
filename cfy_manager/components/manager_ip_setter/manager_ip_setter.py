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
from ...utils import common, service

MANAGER_IP_SETTER_DIR = join('/opt/cloudify', MANAGER_IP_SETTER)

logger = get_logger(MANAGER_IP_SETTER)


class ManagerIpSetter(BaseComponent):
    def configure(self):
        logger.notice('Configuring Manager IP Setter...')
        if config[MANAGER]['set_manager_ip_on_boot']:
            # Always use systemd as manager-ip-setter.sh invoked on booting
            # image
            # Only relevant for VMs
            service.SystemD().configure(
                MANAGER_IP_SETTER,
                ignore_failure=True,
                external_configure_params={
                    'service_type': self.service_type
                }
            )
        else:
            logger.info('Set manager ip on boot is disabled.')
        logger.notice('Manager IP Setter successfully configured')

    def remove(self):
        service.SystemD().remove(MANAGER_IP_SETTER, service_file=False)
        common.remove('/opt/cloudify/manager-ip-setter')
