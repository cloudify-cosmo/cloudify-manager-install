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

from os.path import join
import requests

from cfy_manager.components import sources
from ..base_component import BaseComponent
from ...config import config
from ...logger import get_logger
from ...constants import COMPONENTS_DIR, CA_CERT_PATH, INTERNAL_REST_PORT
from ...components.components_constants import (
    PRIVATE_IP,
    HOSTNAME,
    SCRIPTS,
    CLUSTER_JOIN
)
from ...components.service_names import MANAGER
from ...utils import service
from ...utils.common import is_manager_service_only_installed
from ...utils.install import yum_install
from ...utils.network import get_auth_headers
from ...utils.scripts import run_script_on_manager_venv

REST_HOME_DIR = '/opt/manager'
REST_CONFIG_PATH = join(REST_HOME_DIR, 'cloudify-rest.conf')
REST_AUTHORIZATION_CONFIG_PATH = join(REST_HOME_DIR, 'authorization.conf')
REST_SECURITY_CONFIG_PATH = join(REST_HOME_DIR, 'rest-security.conf')

logger = get_logger('cluster')
SCRIPTS_PATH = join(COMPONENTS_DIR, 'syncthing', SCRIPTS)


class Syncthing(BaseComponent):
    API_VERSION = 'v3.1'

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
        return {'MANAGER_REST_CONFIG_PATH': REST_CONFIG_PATH}

    def _run_syncthing_configuration_script(self, command, bootstrap_cluster):
        args_dict = {
            'hostname': config[MANAGER][HOSTNAME],
            'bootstrap_cluster': bootstrap_cluster,
            'command': command
        }
        script_path = join(SCRIPTS_PATH, 'configure_syncthing_script.py')
        result = run_script_on_manager_venv(script_path,
                                            args_dict,
                                            envvars=self._create_process_env())
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
        if is_manager_service_only_installed():
            # this flag is set inside of restservice._configure_db
            join = config.get(CLUSTER_JOIN)
            if join:
                logger.notice(
                    'Adding manager "{0}" to the cluster, this may take a '
                    'while until config files finish replicating'
                    .format(config[MANAGER][HOSTNAME]))
            service.configure('syncthing')
            self._run_syncthing_configuration_script('configure', not join)
            logger.notice('Node has been added successfully!')
        else:
            logger.warn('Cluster must be instantiated with external DB '
                        'and Queue endpoints. Ignoring cluster configuration')

    def start(self):
        if is_manager_service_only_installed():
            service.start('syncthing')
            self._run_syncthing_configuration_script(
                'start', not config.get(CLUSTER_JOIN))
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
