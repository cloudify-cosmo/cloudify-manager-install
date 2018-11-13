#########
# Copyright (c) 2018 Cloudify Platform Ltd. All rights reserved
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
import json
import random
import string
import requests
import tempfile

from ...components.base_component import BaseComponent
from ...utils import common
from ...logger import get_logger
from ...exceptions import BootstrapError, NetworkError
from ...config import config
from ...components.service_names import (
    CLUSTER,
    MANAGER,
    POSTGRESQL_CLIENT
)
from ...components.components_constants import (
    SERVICES_TO_INSTALL,
    MASTER_IP,
    NODE_NAME,
    CLUSTER_HOST_IP,
    PRIVATE_IP,
    PREMIUM_EDITION
)
from ...constants import REST_HOME_DIR
from ...components.service_components import DATABASE_SERVICE
from ...utils.network import get_auth_headers

CLUSTER_REMOVE_SCRIPT = '/opt/manager/env/bin/teardown_cluster'
CLUSTER_SYSTEMD_UNIT_NAME = 'ha-cluster'
NODE_NAME_GENERATED_CHAR_SIZE = 6

logger = get_logger('cluster')


class ClusterComponent(BaseComponent):
    def __init__(self, skip_installation):
        super(ClusterComponent, self).__init__(skip_installation)

    def _generic_cloudify_rest_request(self, host, port, path,
                                       method, data=None):
        url = 'http://{0}:{1}/api/{2}'.format(host, port, path)
        try:
            if method == 'get':
                response = requests.get(url, headers=get_auth_headers())
            elif method == 'put':
                response = requests.put(url, json=data,
                                        headers=get_auth_headers())
            else:
                raise ValueError('Only GET/PUT requests supported')
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

    def _get_join_addresses(self, master_manager_ip):
        result = self._generic_cloudify_rest_request(
            master_manager_ip,
            80,
            'v3.1/cluster/nodes',
            'get')
        return [n['host_ip'] for n in result['items']]

    def _add_new_cluster_node_on_master(self, master_manager_ip,
                                        cluster_node_host_ip,
                                        cluster_node_name,
                                        cluster_node_database_ip):
        data = {
            'host_ip': cluster_node_host_ip,
            'node_name': cluster_node_name,
            'database_ip': cluster_node_database_ip
        }
        result = self._generic_cloudify_rest_request(
            master_manager_ip,
            80,
            'v3.1/cluster/nodes/{0}'.format(cluster_node_name),
            'put',
            data
        )
        return result

    def _get_cluster_status(self, master_manager_ip):
        result = self._generic_cloudify_rest_request(
            master_manager_ip,
            80,
            'v3.1/cluster',
            'get')
        return result

    def _generate_cluster_node_name(self):
        chars = string.ascii_uppercase + string.digits
        return 'cloudify_manager_' + ''.join(
            random.choice(chars) for _ in range(NODE_NAME_GENERATED_CHAR_SIZE))

    def _join_to_cluster(self, master_manager_ip):
        # Use the provided cluster_host_ip or the private_ip by default
        cluster_node_host_ip = config[MANAGER][CLUSTER_HOST_IP] or \
                               config[MANAGER][PRIVATE_IP]
        cluster_node_name = \
            config[CLUSTER][NODE_NAME] or self._generate_cluster_node_name()
        self.logger.notice('Adding cluster node "{0}" to the cluster'
                           .format(cluster_node_name))
        cluster_node_database_ip = \
            config[POSTGRESQL_CLIENT]['host'].split(':')[0]
        join_addrs = self._get_join_addresses(master_manager_ip)
        new_node = self._add_new_cluster_node_on_master(
            master_manager_ip, cluster_node_host_ip,
            cluster_node_name, cluster_node_database_ip)
        data = {
            'host_ip': cluster_node_host_ip,
            'node_name': cluster_node_name,
            'credentials': new_node['credentials'],
            'required': new_node['required'],
            'join_addrs': join_addrs,
            'ignore_database_validation': True,
            'bootstrap_cluster': False
        }
        manager_rest_python_path = os.path.join(REST_HOME_DIR, 'env', 'bin')
        start_cluster = os.path.join(manager_rest_python_path,
                                     'create_cluster_node')

        with tempfile.NamedTemporaryFile(delete=False) as f:
            json.dump(data, f)

        # Same as a regular all-in-one installation, we run the sub-process
        # instead of a rest call
        create_cluster_node = [start_cluster, '--config', f.name]
        common.sudo(create_cluster_node)

        return self._get_cluster_status(master_manager_ip)

    def configure(self):
        pass

    def install(self):
        if config[MANAGER][PREMIUM_EDITION]:
            self.logger.info('Premium version found')
            cluster_master_ip = config[CLUSTER][MASTER_IP]
            if cluster_master_ip and DATABASE_SERVICE \
                    not in config[SERVICES_TO_INSTALL]:
                self.logger.info('Master ip found, joining to cluster with '
                                 '{0} as master'.format(cluster_master_ip))
                cluster_status = self._join_to_cluster(cluster_master_ip)
                if cluster_status['error'] is not None:
                    self.logger.error(cluster_status['logs']['message'])
                else:
                    self.logger.notice('Node has been added to the cluster '
                                       'successfully!')

    def remove(self):
        try:
            common.sudo([CLUSTER_REMOVE_SCRIPT])
        except BootstrapError:
            logger.notice('Cluster remove script does not exist - skipping')
        else:
            logger.notice('Cluster components removed')
