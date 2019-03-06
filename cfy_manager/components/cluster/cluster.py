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

import json
import requests

from ...components.base_component import BaseComponent
from ...logger import get_logger
from ...exceptions import BootstrapError, NetworkError
from ...config import config
from ...components.service_names import (
    MANAGER,
    CLUSTER
)
from ...components.components_constants import (
    SERVICES_TO_INSTALL,
    PRIVATE_IP,
    PUBLIC_IP,
    PREMIUM_EDITION,
    HOSTNAME
)
from ...components.service_components import DATABASE_SERVICE
from ...utils.network import get_auth_headers

NODE_NAME_GENERATED_CHAR_SIZE = 6

logger = get_logger('cluster')


class ClusterComponent(BaseComponent):
    def __init__(self, skip_installation):
        super(ClusterComponent, self).__init__(skip_installation)

    @staticmethod
    def _generic_cloudify_rest_request(host, port, path,
                                       method, data=None):
        url = 'http://{0}:{1}/api/{2}'.format(host, port, path)
        try:
            if method == 'get':
                response = requests.get(url, headers=get_auth_headers())
            elif method == 'post':
                response = requests.post(url, json=data,
                                         headers=get_auth_headers())
            elif method == 'put':
                response = requests.put(url, json=data,
                                        headers=get_auth_headers())
            elif method == 'delete':
                response = requests.delete(url, json=data,
                                           headers=get_auth_headers())
            else:
                raise ValueError('Only GET/POST/PUT/DELETE requests are '
                                 'supported')
        # keep an erroneous HTTP response to examine its status code, but still
        # abort on fatal errors like being unable to connect at all
        except requests.HTTPError as e:
            response = e
        except requests.URLRequired as e:
            raise NetworkError(
                'REST service returned an invalid response: {0}'.format(e))
        if response.status_code == 401:
            raise NetworkError(
                'Could not connect to the REST service: '
                '401 unauthorized. Possible access control misconfiguration,'
                'Master and replica nodes must have the same admin password'
            )
        if response.status_code != 200:
            logger.debug(response.content)
            raise NetworkError(
                'REST service returned an unexpected response: '
                '{0}'.format(response.status_code)
            )

        try:
            return json.loads(response.content)
        except ValueError as e:
            logger.debug(response.content)
            raise BootstrapError(
                'REST service returned malformed JSON: {0}'.format(e))

    def _get_current_version(self):
        result = self._generic_cloudify_rest_request(
            PRIVATE_IP,
            80,
            'v3.1/version',
            'get'
        )
        return result

    def _join_to_cluster(self):
        """
        Used for either adding the first node to the cluster (can be
        single-node cluster), or adding a new manager to the cluster
        """
        logger.notice('Adding manager "{0}" to the cluster'
                           .format(config[MANAGER][HOSTNAME]))
        version_details = self._get_current_version()
        data = {
            'hostname': config[MANAGER][HOSTNAME],
            'private_ip': config[MANAGER][PRIVATE_IP],
            'public_ip': config[MANAGER][PUBLIC_IP],
            'version': version_details['version'],
            'edition': version_details['edition'],
            'distribution': version_details['distribution'],
            'distro_release': version_details['distro_release']
        }
        result = self._generic_cloudify_rest_request(
            PRIVATE_IP,
            80,
            'v3.1/managers',
            'post',
            data
        )
        return result

    def _remove_manager_from_cluster(self):
        logger.notice('Removing manager "{0}" from cluster'
                           .format(config[MANAGER][HOSTNAME]))
        data = {
            'hostname': config[MANAGER][HOSTNAME]
        }
        result = self._generic_cloudify_rest_request(
            PRIVATE_IP,
            80,
            'v3.1/managers',
            'delete',
            data
        )
        return result

    def install(self):
        pass

    def configure(self):
        if config[MANAGER][PREMIUM_EDITION]:
            logger.info('Premium version found')
            if DATABASE_SERVICE not in config[SERVICES_TO_INSTALL]:
                if config[CLUSTER]:
                    self._join_to_cluster()
                    logger.notice('Node has been added successfully!')
            else:
                logger.debug('All-in-one manager, ignoring cluster '
                             'configuration')

    def remove(self):
        try:
            self._remove_manager_from_cluster()
            logger.notice('Manager removed successfully')
        except Exception:
            logger.error('Manager was not able to be removed, make sure the'
                         'hostname in config.yaml is correct')
