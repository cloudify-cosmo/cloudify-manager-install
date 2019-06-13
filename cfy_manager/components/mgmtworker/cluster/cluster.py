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
from ...restservice.restservice import RestService
from ...validations import _is_installed
from ....config import config
from ....logger import get_logger
from ....constants import COMPONENTS_DIR, CA_CERT_PATH
from ....exceptions import BootstrapError, NetworkError
from ....components.components_constants import (
    PRIVATE_IP,
    PUBLIC_IP,
    HOSTNAME,
    SOURCES,
    SCRIPTS,
    ACTIVE_MANAGER_IP,
)
from ....components.service_components import (
    MANAGER_SERVICE,
    DATABASE_SERVICE,
    QUEUE_SERVICE
)
from ....components.service_names import (
    MANAGER,
    CLUSTER,
    PREMIUM,
    RESTSERVICE,
    MGMTWORKER
)
from ....utils.common import sudo
from ....utils.systemd import systemd
from ....utils.install import yum_install
from ....utils.files import write_to_tempfile
from ....utils.network import get_auth_headers, wait_for_port

REST_HOME_DIR = '/opt/manager'
REST_CONFIG_PATH = join(REST_HOME_DIR, 'cloudify-rest.conf')
REST_AUTHORIZATION_CONFIG_PATH = join(REST_HOME_DIR, 'authorization.conf')
REST_SECURITY_CONFIG_PATH = join(REST_HOME_DIR, 'rest-security.conf')

logger = get_logger('cluster')
SCRIPTS_PATH = join(COMPONENTS_DIR, MGMTWORKER, CLUSTER, SCRIPTS)


class Cluster(BaseComponent):
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
                '{0}: {1}'.format(response.status_code, response.content)
            )

        try:
            return json.loads(response.content)
        except ValueError as e:
            logger.debug(response.content)
            raise BootstrapError(
                'REST service returned malformed JSON: {0}'.format(e))

    def _get_current_version(self, active_manager_ip):
        result = self._generic_cloudify_rest_request(
            active_manager_ip,
            80,
            'v3.1/version',
            'get'
        )
        return result

    def _verify_local_rest_service_alive(self, verify_rest_call=False):
        # Restarting rest-service to read the new replicated rest-security.conf
        systemd.restart(RESTSERVICE)
        systemd.verify_alive(RESTSERVICE)
        rest_port = config[RESTSERVICE]['port']

        wait_for_port(rest_port)

        if verify_rest_call:
            rest_service_component = RestService()
            rest_service_component._verify_restservice_alive()

    def _log_results(self, result):
        """Log stdout/stderr output from the script"""
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

    def _run_syncthing_configuration_script(self, active_manager_ip):
        env_dict = self._create_process_env()

        script_path = join(SCRIPTS_PATH, 'configure_syncthing_script.py')
        python_path = join(REST_HOME_DIR, 'env', 'bin', 'python')

        # Directly calling with this python bin, in order to make sure it's run
        # in the correct venv

        cmd = [python_path, script_path]
        args_dict = {
            'hostname': config[MANAGER][HOSTNAME],
            'active_manager_ip': active_manager_ip,
            'rest_service_port': 80,
            'auth_headers': get_auth_headers()
        }

        args_json_path = write_to_tempfile(args_dict, json_dump=True)
        cmd.append(args_json_path)

        result = sudo(cmd, env=env_dict)

        self._log_results(result)

    def _join_to_cluster(self, active_manager_ip):
        """
        Used for either adding the first node to the cluster (can be
        single-node cluster), or adding a new manager to the cluster

        The next step would be installing the mgmtworker which requires the
        rest-security.conf to be the same as in the rest of the managers in the
        cluster, as a result this operation may take a while until the config
        directories finish replicating
        """
        logger.notice('Adding manager "{0}" to the cluster, this may take a '
                      'while until config files finish replicating'
                      .format(config[MANAGER][HOSTNAME]))
        version_details = self._get_current_version(active_manager_ip)
        data = {
            'hostname': config[MANAGER][HOSTNAME],
            'private_ip': config[MANAGER][PRIVATE_IP],
            'public_ip': config[MANAGER][PUBLIC_IP],
            'version': version_details['version'],
            'edition': version_details['edition'],
            'distribution': version_details['distribution'],
            'distro_release': version_details['distro_release']
        }
        if config['networks']:
            data['networks'] = config['networks']
        with open(CA_CERT_PATH) as f:
            data['ca_cert_content'] = f.read()

        # During the below request, Syncthing will start FS replication and
        # wait for the config files to finish replicating
        result = self._generic_cloudify_rest_request(
            active_manager_ip,
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

    def install(self):
        self._install()

    def configure(self):
        # Need to restart the RESTSERVICE so flask could import premium
        self._verify_local_rest_service_alive()
        if _is_installed(MANAGER_SERVICE) and not \
                _is_installed(DATABASE_SERVICE) and not\
                _is_installed(QUEUE_SERVICE):
            if config[CLUSTER]['enabled']:
                active_manager_ip = config[CLUSTER][ACTIVE_MANAGER_IP] or \
                                    config[MANAGER][PRIVATE_IP]
                # don't "join" on the first manager
                if config[CLUSTER][ACTIVE_MANAGER_IP]:
                    self._join_to_cluster(active_manager_ip)
                self._run_syncthing_configuration_script(active_manager_ip)
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
