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

from ..service_names import PYTHON

from ...config import config
from ...logger import get_logger

from ...utils.install import yum_install, yum_remove
from ...utils.files import copy_notice, remove_notice

from ..base_component import BaseComponent


logger = get_logger(PYTHON)


class PythonComponent(BaseComponent):
    def __init__(self):
        BaseComponent.__init__(self)

    def _install(self):
        if config[PYTHON]['install_python_compilers']:
            logger.info('Installing Compilers...')
            yum_install('python-devel', disable_all_repos=False)
            yum_install('gcc', disable_all_repos=False)
            yum_install('gcc-c++', disable_all_repos=False)

    def _configure(self):
        copy_notice(PYTHON)

    def install(self):
        logger.notice('Installing Python dependencies...')
        self._install()
        self._configure()
        logger.notice('Python dependencies successfully installed')

    def configure(self):
        logger.notice('Configuring Python dependencies...')
        self._configure()
        logger.notice('Python dependencies successfully configured')

    def remove(self):
        remove_notice(PYTHON)
        if config[PYTHON]['remove_on_teardown']:
            logger.notice('Removing Python dependencies...')
            if config[PYTHON]['install_python_compilers']:
                yum_remove('python-devel')
                yum_remove('gcc')
                yum_remove('gcc-c++')
            logger.notice('Python dependencies successfully removed')
