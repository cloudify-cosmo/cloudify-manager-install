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

from cfy_manager.components.sources import patch
from ...logger import get_logger
from ..base_component import BaseComponent
from ...utils.install import yum_install, yum_remove

logger = get_logger('patch')


class Patch(BaseComponent):
    def __init__(self, skip_installation):
        super(Patch, self).__init__(skip_installation)

    def install(self):
        logger.notice('Installing Patch...')
        yum_install(patch)
        logger.notice('Patch successfully installed')

    def remove(self):
        yum_remove('patch')
