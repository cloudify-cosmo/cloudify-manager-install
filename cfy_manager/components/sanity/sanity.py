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

from ..restservice.db import get_manager_count
from ..base_component import BaseComponent
from ..service_names import SANITY
from ...logger import get_logger
from ...constants import CLOUDIFY_USER, CLOUDIFY_GROUP
from ...utils import common
from ...utils.files import write_to_file, remove_files


logger = get_logger(SANITY)


class Sanity(BaseComponent):
    def __init__(self):
        super(Sanity, self).__init__()
        random_postfix = str(uuid.uuid4())
        self.blueprint_name = '{0}_blueprint_{1}'.format(SANITY,
                                                         random_postfix)
        self.deployment_name = '{0}_deployment_{1}'.format(SANITY,
                                                           random_postfix)

    def _upload_blueprint(self):
        logger.info('Uploading sanity blueprint...')
        blueprint_path = pkg_resources.resource_filename(
            'cfy_manager',
            'components/sanity/blueprint/bp.yaml'
        )
        common.cfy('blueprints', 'upload', blueprint_path,
                   '-b', self.blueprint_name,
                   stdout=sys.stdout)

    def _deploy_app(self):
        logger.info('Deploying sanity app...')
        common.cfy('deployments', 'create', '-b', self.blueprint_name,
                   self.deployment_name,
                   '--skip-plugins-validation',
                   stdout=sys.stdout)

    def _install_sanity(self):
        logger.info('Installing sanity app...')
        common.cfy('executions', 'start', 'install', '-d',
                   self.deployment_name,
                   stdout=sys.stdout)

    def _clean_sanity(self):
        logger.info('Removing sanity...')
        common.cfy('executions', 'start', 'uninstall', '-d',
                   self.deployment_name,
                   stdout=sys.stdout)
        common.cfy('deployments', 'delete', self.deployment_name,
                   stdout=sys.stdout)
        time.sleep(3)
        common.cfy('blueprints', 'delete', self.blueprint_name,
                   stdout=sys.stdout)

    def run_sanity_check(self):
        logger.notice('Running Sanity...')
        self._upload_blueprint()
        self._deploy_app()
        self._install_sanity()
        self._clean_sanity()
        logger.notice('Sanity completed successfully')

    def start(self):
        if get_manager_count() > 1:
            logger.notice('Not running the sanity check: part of a cluster')
            return
        with self.sanity_check_mode():
            self.run_sanity_check()

    @contextmanager
    def sanity_check_mode(self):
        marker_file = '/opt/manager/sanity_mode'
        try:
            write_to_file('sanity: True', marker_file)
            common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, marker_file)
            yield
        finally:
            remove_files([marker_file])
