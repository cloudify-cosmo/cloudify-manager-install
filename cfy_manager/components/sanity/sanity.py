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
import time
import uuid
import pkg_resources
from contextlib import contextmanager
from tempfile import mkdtemp
from os.path import join, isfile, expanduser, dirname

from ..components_constants import CLUSTER_JOIN
from ..base_component import BaseComponent
from ..service_names import SANITY
from ...config import config
from ...logger import get_logger
from ...constants import CLOUDIFY_HOME_DIR, CLOUDIFY_USER, CLOUDIFY_GROUP
from ...utils import common
from ...utils.files import write_to_file, remove_files


logger = get_logger(SANITY)
AUTHORIZED_KEYS_PATH = expanduser('~/.ssh/authorized_keys')
SANITY_WEB_SERVER_PORT = 12774


class Sanity(BaseComponent):
    def __init__(self):
        super(Sanity, self).__init__()
        random_postfix = str(uuid.uuid4())
        self.blueprint_name = '{0}_blueprint_{1}'.format(SANITY,
                                                         random_postfix)
        self.deployment_name = '{0}_deployment_{1}'.format(SANITY,
                                                           random_postfix)

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

    @staticmethod
    def _add_ssh_key_to_authorized(ssh_key_path):
        public_ssh = '{0}.pub'.format(ssh_key_path)
        if isfile(AUTHORIZED_KEYS_PATH):
            logger.debug('Adding sanity SSH key to current authorized_keys...')
            # Add a newline to the SSH file
            common.run(['echo >> {0}'.format(AUTHORIZED_KEYS_PATH)],
                       shell=True)
            common.run(
                ['cat {0} >> {1}'.format(public_ssh, AUTHORIZED_KEYS_PATH)],
                shell=True
            )
            common.remove(public_ssh)
        else:
            logger.debug('Setting sanity SSH key as authorized_keys...')
            common.move(public_ssh, AUTHORIZED_KEYS_PATH)
        common.remove(dirname(ssh_key_path))

    @staticmethod
    def _remove_sanity_ssh(ssh_key_path):
        # This removes the last line from the file
        common.run(["sed -i '$ d' {0}".format(AUTHORIZED_KEYS_PATH)],
                   shell=True)
        common.remove(ssh_key_path)

    def _upload_blueprint(self):
        logger.info('Uploading sanity blueprint...')
        blueprint_path = pkg_resources.resource_filename(
            'cfy_manager',
            'components/sanity/blueprint/bp.yaml'
        )
        common.run(['cfy', 'blueprints', 'upload', blueprint_path,
                    '-b', self.blueprint_name],
                   stdout=sys.stdout,
                   env={'LC_ALL': 'en_US.UTF-8'})

    def _deploy_app(self):
        logger.info('Deploying sanity app...')
        common.run(['cfy', 'deployments', 'create', '-b', self.blueprint_name,
                    self.deployment_name,
                    '--skip-plugins-validation'],
                   stdout=sys.stdout,
                   env={'LC_ALL': 'en_US.UTF-8'})

    def _install_sanity(self):
        logger.info('Installing sanity app...')
        common.run(['cfy', 'executions', 'start', 'install', '-d',
                    self.deployment_name],
                   stdout=sys.stdout,
                   env={'LC_ALL': 'en_US.UTF-8'})

    @staticmethod
    def _clean_old_sanity():
        logger.debug('Removing remnants of old sanity '
                     'installation if exists...')
        common.remove('/opt/mgmtworker/work/deployments/default_tenant/sanity')

    def _run_sanity(self):
        self._clean_old_sanity()
        self._upload_blueprint()
        self._deploy_app()
        self._install_sanity()

    def _clean_sanity(self):
        logger.info('Removing sanity...')
        common.run(['cfy', 'executions', 'start', 'uninstall', '-d',
                    self.deployment_name],
                   stdout=sys.stdout,
                   env={'LC_ALL': 'en_US.UTF-8'})
        common.run(['cfy', 'deployments', 'delete', self.deployment_name],
                   stdout=sys.stdout,
                   env={'LC_ALL': 'en_US.UTF-8'})
        time.sleep(3)
        common.run(['cfy', 'blueprints', 'delete', self.blueprint_name],
                   stdout=sys.stdout,
                   env={'LC_ALL': 'en_US.UTF-8'})

    def run_sanity_check(self):
        logger.notice('Running Sanity...')
        self._run_sanity()
        self._clean_sanity()
        logger.notice('Sanity completed successfully')

    def start(self):
        if config.get(CLUSTER_JOIN):
            logger.notice('Not running the sanity check: joined a cluster')
            return
        with self._sanity_check_mode():
            self.run_sanity_check()

    @contextmanager
    def _sanity_check_mode(self):
        marker_file = '/opt/manager/sanity_mode'
        try:
            write_to_file('sanity: True', marker_file)
            common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, marker_file)
            yield
        finally:
            remove_files([marker_file])
