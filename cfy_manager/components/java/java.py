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

from os.path import join, isfile

from ..components_constants import SOURCES
from ..base_component import BaseComponent
from ..service_names import JAVA
from ... import constants
from ...config import config
from ...logger import get_logger
from ...exceptions import ValidationError
from ...utils.common import move, mkdir, sudo
from ...utils.install import yum_install, yum_remove
from ...utils.files import remove_files, copy_notice, remove_notice

logger = get_logger(JAVA)
HOME_DIR = join('/opt', JAVA)
LOG_DIR = join(constants.BASE_LOG_DIR, JAVA)


class JavaComponent(BaseComponent):
    def __init__(self, skip_installation):
        super(JavaComponent, self).__init__(skip_installation)

    def _install(self):
        java_source_url = config[JAVA][SOURCES]['java_source_url']
        yum_install(java_source_url)

    def _move_java_log(self):
        mkdir(LOG_DIR)

        # Java install log is dropped in /var/log.
        # Move it to live with the rest of the cloudify logs
        java_install_log = '/var/log/java_install.log'
        if isfile(java_install_log):
            move(java_install_log, join(LOG_DIR, 'java_install.log'))

    def _validate_java_installed(self):
        java_result = sudo(['java', '-version'], ignore_failures=True)
        if java_result.returncode != 0:
            raise ValidationError('Java runtime error: java was not installed')

    def _configure(self):
        copy_notice(JAVA)
        self._move_java_log()
        self._validate_java_installed()

    def install(self):
        logger.notice('Installing Java...')
        self._install()
        self._configure()
        logger.notice('Java successfully installed')

    def configure(self):
        logger.info('Configuring Java...')
        self._configure()
        logger.info('Java successfully configured')

    def remove(self):
        logger.notice('Removing Java...')
        remove_notice(JAVA)
        remove_files([LOG_DIR])
        yum_remove(JAVA)
        logger.notice('Java successfully removed')
