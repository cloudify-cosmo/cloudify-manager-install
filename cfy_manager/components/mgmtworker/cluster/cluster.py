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
from os.path import join

from cfy_manager.components import sources
from ...base_component import BaseComponent
from ...restservice.restservice import RestService
from ...validations import _is_installed
from ....config import config
from ....logger import get_logger
from ....constants import COMPONENTS_DIR, CA_CERT_PATH, INTERNAL_REST_PORT
from ....components.components_constants import (
    PRIVATE_IP,
    HOSTNAME,
    SCRIPTS,
    CLUSTER_JOIN
)
from ....components.service_components import (
    MANAGER_SERVICE,
    DATABASE_SERVICE,
    QUEUE_SERVICE
)
from ....components.service_names import (
    MANAGER,
    CLUSTER,
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

    def _run_syncthing_configuration_script(self, bootstrap_cluster):
        args_dict = {
            'hostname': config[MANAGER][HOSTNAME],
            'bootstrap_cluster': bootstrap_cluster,
        }
        args_json_path = write_to_tempfile(args_dict, json_dump=True)
        cmd = [
            join(REST_HOME_DIR, 'env', 'bin', 'python'),
            join(SCRIPTS_PATH, 'configure_syncthing_script.py'),
            args_json_path
        ]
        result = sudo(cmd, env=self._create_process_env())
        self._log_results(result)

    def _remove_manager_from_cluster(self):
        logger.notice('Removing manager "{0}" from cluster'
                      .format(config[MANAGER][HOSTNAME]))
        url = 'https://{0}:{1}/api/{2}/managers/{4}'.format(
            config[PRIVATE_IP], INTERNAL_REST_PORT, self.API_VERSION,
            config[HOSTNAME])
        requests.delete(url, headers=get_auth_headers(), verify=CA_CERT_PATH)

    def install(self):
        yum_install(sources.premium)

    def configure(self):
        # Need to restart the RESTSERVICE so flask could import premium
        self._verify_local_rest_service_alive()
        if _is_installed(MANAGER_SERVICE) and not \
                _is_installed(DATABASE_SERVICE) and not\
                _is_installed(QUEUE_SERVICE):
            # this flag is set inside of restservice._configure_db
            join = config[CLUSTER_JOIN]
            if join:
                logger.notice(
                    'Adding manager "{0}" to the cluster, this may take a '
                    'while until config files finish replicating'
                    .format(config[MANAGER][HOSTNAME]))
            self._run_syncthing_configuration_script(not join)
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
