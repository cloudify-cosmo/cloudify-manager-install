#########
# Copyright (c) 2019 Cloudify Platform Ltd. All rights reserved
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

import requests

from ...base_component import BaseComponent
from ...restservice.restservice import RestService
from cfy_manager.utils.common import is_manager_service_only_installed

from ....components import sources
from ....config import config
from ....logger import get_logger
from ....utils.systemd import systemd
from ....utils.install import yum_install
from ....constants import CA_CERT_PATH, INTERNAL_REST_PORT
from ....utils.network import get_auth_headers, wait_for_port
from ....components.components_constants import PRIVATE_IP, HOSTNAME
from ....components.service_names import (
    MANAGER,
    RESTSERVICE,
)

logger = get_logger('cluster')


class Cluster(BaseComponent):
    API_VERSION = 'v3.1'

    def _verify_local_rest_service_alive(self, verify_rest_call=False):
        # Restarting rest-service to read the new replicated rest-security.conf
        systemd.restart(RESTSERVICE)
        systemd.verify_alive(RESTSERVICE)
        rest_port = config[RESTSERVICE]['port']

        wait_for_port(rest_port)

        if verify_rest_call:
            rest_service_component = RestService()
            rest_service_component._verify_restservice_alive()

    def _remove_manager_from_cluster(self):
        logger.notice('Removing manager "{0}" from cluster'
                      .format(config[MANAGER][HOSTNAME]))
        url = 'https://{0}:{1}/api/{2}/managers/{3}'.format(
            config[PRIVATE_IP], INTERNAL_REST_PORT, self.API_VERSION,
            config[HOSTNAME])
        requests.delete(url, headers=get_auth_headers(), verify=CA_CERT_PATH)

    def install(self):
        yum_install(sources.premium)

    def configure(self):
        # Need to restart the RESTSERVICE so flask could import premium
        self._verify_local_rest_service_alive()
        if is_manager_service_only_installed():
            self._verify_local_rest_service_alive(verify_rest_call=True)
            logger.notice('Node has been added successfully!')
        else:
            logger.warn('Cluster must be instantiated with external DB '
                        'and Queue endpoints. Ignoring cluster configuration')

    def remove(self):
        try:
            self._remove_manager_from_cluster()
            logger.notice('Manager removed successfully')
        except Exception:
            logger.error('Manager was not able to be removed, make sure the'
                         'hostname in config.yaml is correct')
