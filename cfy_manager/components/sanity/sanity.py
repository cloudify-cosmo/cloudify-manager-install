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

import sys
import getpass
import time
from tempfile import mkdtemp
from os.path import join, isfile, expanduser, dirname

from .. import SOURCES, PRIVATE_IP

from ..service_names import SANITY, MANAGER

from ...config import config
from ...logger import get_logger
from ...constants import CLOUDIFY_HOME_DIR

from ...utils import common
from ...utils.network import wait_for_port
from ...utils.files import get_local_source_path

from ..base_component import BaseComponent


logger = get_logger(SANITY)

AUTHORIZED_KEYS_PATH = expanduser('~/.ssh/authorized_keys')
SANITY_WEB_SERVER_PORT = 12774


class SanityComponent(BaseComponent):
    def __init__(self):
        BaseComponent.__init__(self)

    def _create_ssh_key(self):
        logger.info('Creating SSH key for sanity...')
        key_path = join(mkdtemp(), 'ssh_key')
        common.run(['ssh-keygen', '-t', 'rsa', '-f', key_path, '-q', '-N', ''])
        new_path = join(CLOUDIFY_HOME_DIR, 'ssh_key')
        common.move(key_path, new_path)
        common.chmod('600', new_path)
        common.chown('cfyuser', 'cfyuser', new_path)
        logger.debug('Created SSH key: {0}'.format(new_path))
        self._add_ssh_key_to_authorized(key_path)
        return new_path

    def _add_ssh_key_to_authorized(self, ssh_key_path):
        public_ssh = '{0}.pub'.format(ssh_key_path)
        if isfile(AUTHORIZED_KEYS_PATH):
            logger.debug('Adding sanity SSH key to current authorized_keys...')
            # Add a newline to the SSH file
            common.run(['echo >> {0}'.format(AUTHORIZED_KEYS_PATH)], shell=True)
            common.run(
                ['cat {0} >> {1}'.format(public_ssh, AUTHORIZED_KEYS_PATH)],
                shell=True
            )
            common.remove(public_ssh)
        else:
            logger.debug('Setting sanity SSH key as authorized_keys...')
            common.move(public_ssh, AUTHORIZED_KEYS_PATH)
        common.remove(dirname(ssh_key_path))

    def _remove_sanity_ssh(self, ssh_key_path):
        # This removes the last line from the file
        common.run(["sed -i '$ d' {0}".format(AUTHORIZED_KEYS_PATH)], shell=True)
        common.remove(ssh_key_path)

    def _upload_blueprint(self):
        logger.info('Uploading sanity blueprint...')
        sanity_source_url = config[SANITY][SOURCES]['sanity_source_url']
        sanity_blueprint = get_local_source_path(sanity_source_url)
        common.run(['cfy', 'blueprints', 'upload', sanity_blueprint, '-n',
                    'no-monitoring-singlehost-blueprint.yaml', '-b', SANITY],
                   stdout=sys.stdout)

    def _deploy_app(self, ssh_key_path):
        logger.info('Deploying sanity app...')
        manager_ip = config[MANAGER][PRIVATE_IP]
        ssh_user = getpass.getuser()
        common.run(['cfy', 'deployments', 'create', '-b', SANITY, SANITY,
                    '-i', 'server_ip={0}'.format(manager_ip),
                    '-i', 'agent_user={0}'.format(ssh_user),
                    '-i', 'agent_private_key_path={0}'.format(ssh_key_path),
                    '-i', 'webserver_port={0}'.format(SANITY_WEB_SERVER_PORT)],
                   stdout=sys.stdout)

    def _install_sanity(self):
        logger.info('Installing sanity app...')
        common.run(['cfy', 'executions', 'start', 'install', '-d', SANITY],
                   stdout=sys.stdout)

    def _verify_sanity(self):
        wait_for_port(SANITY_WEB_SERVER_PORT)

    def _clean_old_sanity(self):
        logger.debug('Removing remnants of old sanity installation if exists...')
        common.remove('/opt/mgmtworker/work/deployments/default_tenant/sanity')

    def _run_sanity(self, ssh_key_path):
        self._clean_old_sanity()
        self._upload_blueprint()
        self._deploy_app(ssh_key_path)
        self._install_sanity()

    # @retrying.retry(stop_max_attempt_number=3, wait_fixed=1000)
    def _clean_sanity(self):
        logger.info('Removing sanity...')
        common.run(['cfy', 'executions', 'start', 'uninstall', '-d', SANITY],
                   stdout=sys.stdout)
        common.run(['cfy', 'deployments', 'delete', SANITY],
                   stdout=sys.stdout)
        time.sleep(3)
        common.run(['cfy', 'blueprints', 'delete', SANITY],
                   stdout=sys.stdout)

    def run_sanity_check(self):
        logger.notice('Running Sanity...')
        ssh_key_path = self._create_ssh_key()
        self._run_sanity(ssh_key_path)
        self._verify_sanity()
        self._clean_sanity()
        self._remove_sanity_ssh(ssh_key_path)
        logger.notice('Sanity completed successfully')

    def install(self):
        if config[SANITY]['skip_sanity']:
            logger.info('Skipping sanity check...')
            return
        self.run_sanity_check()

    def configure(self):
        pass

    def remove(self):
        pass
