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
from os.path import join

from ...base_component import BaseComponent
from ....utils.systemd import systemd
from ....constants import COMPONENTS_DIR
from ....utils.common import sudo
from ....logger import get_logger
from ....exceptions import BootstrapError, NetworkError
from ....config import config
from ....components.service_names import (
    MANAGER,
    CLUSTER,
    PREMIUM,
    RESTSERVICE,
    MGMTWORKER
)
from ....components.components_constants import (
    PRIVATE_IP,
    PUBLIC_IP,
    HOSTNAME,
    SOURCES,
    SCRIPTS
)
from ...validations import _services_coexistence_assertion
from ....components.service_components import (
    MANAGER_SERVICE,
    DATABASE_SERVICE,
    QUEUE_SERVICE
)
from ....utils.network import get_auth_headers
from ....utils.install import yum_install

REST_HOME_DIR = '/opt/manager'
REST_CONFIG_PATH = join(REST_HOME_DIR, 'cloudify-rest.conf')
REST_AUTHORIZATION_CONFIG_PATH = join(REST_HOME_DIR, 'authorization.conf')
REST_SECURITY_CONFIG_PATH = join(REST_HOME_DIR, 'rest-security.conf')

NODE_NAME_GENERATED_CHAR_SIZE = 6

logger = get_logger('cluster')
SCRIPTS_PATH = join(COMPONENTS_DIR, MGMTWORKER, CLUSTER, SCRIPTS)


class ClusterComponent(BaseComponent):
    def __init__(self, skip_installation):
        super(ClusterComponent, self).__init__(skip_installation)

    def _generic_cloudify_rest_request(self, host, port, path,
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
            config[MANAGER][PRIVATE_IP],
            80,
            'v3.1/version',
            'get'
        )
        return result

    def _log_results(self, result):
        """Log stdout/stderr output from the script
        """
        if result.aggr_stdout:
            output = result.aggr_stdout.split('\n')
            output = [line.strip() for line in output if line.strip()]
            for line in output[:-1]:
                logger.debug(line)
            logger.info(output[-1])
        if result.aggr_stderr:
            output = result.aggr_stderr.split('\n')
            output = [line.strip() for line in output if line.strip()]
            for line in output:
                logger.error(line)

    def _create_process_env(self):
        env = {}
        for value, envvar in [
            (REST_CONFIG_PATH, 'MANAGER_REST_CONFIG_PATH'),
            (REST_SECURITY_CONFIG_PATH, 'MANAGER_REST_SECURITY_CONFIG_PATH'),
            (REST_AUTHORIZATION_CONFIG_PATH,
             'MANAGER_REST_AUTHORIZATION_CONFIG_PATH'),
        ]:
            if value is not None:
                env[envvar] = value
        return env

    def _run_syncthing_configuration_script(self, hostname):
        env_dict = self._create_process_env()

        script_path = join(SCRIPTS_PATH, 'configure_syncthing_script.py')
        python_path = join(REST_HOME_DIR, 'env', 'bin', 'python')

        # Directly calling with this python bin, in order to make sure it's run
        # in the correct venv
        cmd = [python_path, script_path, hostname]
        result = sudo(cmd, env=env_dict)

        self._log_results(result)

    def _join_to_cluster(self):
        """
        Used for either adding the first node to the cluster (can be
        single-node cluster), or adding a new manager to the cluster

        The next step would be installing the mgmtworker which requires the
        rest-security.conf to be the same as in the rest of the managers in the
        cluster, as a result this operation may take a while until the config
        directories finish replicating
        """
        self._run_syncthing_configuration_script(config[MANAGER][HOSTNAME])
        logger.notice('Adding manager "{0}" to the cluster, this may take a '
                      'while until config files finish replicating'
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
        # During the below request, Syncthing will start FS replication and
        # wait for the config files to finish replicating
        result = self._generic_cloudify_rest_request(
            config[MANAGER][PRIVATE_IP],
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
            config[MANAGER][PRIVATE_IP],
            80,
            'v3.1/managers',
            'delete',
            data
        )
        return result

    def _install(self):
        yum_install(config[PREMIUM][SOURCES]['premium_source_url'])
        # Need to restart the RESTSERVICE so flask could import premium
        systemd.restart(RESTSERVICE)

    def install(self):
        self._install()

    def configure(self):
        if _services_coexistence_assertion(MANAGER_SERVICE,
                                           DATABASE_SERVICE) and \
            _services_coexistence_assertion(MANAGER_SERVICE,
                                            QUEUE_SERVICE):
            if config[CLUSTER]:
                self._join_to_cluster()
                logger.notice('Node has been added successfully!')
        else:
            logger.warn('Cluster must be instantiated with external DB'
                        'and Queue. Ignoring cluster configuration')

    def remove(self):
        try:
            self._remove_manager_from_cluster()
            logger.notice('Manager removed successfully')
        except Exception:
            logger.error('Manager was not able to be removed, make sure the'
                         'hostname in config.yaml is correct')
