#########
# Copyright (c) 2018 Cloudify Platform Ltd. All rights reserved
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

from ..utils import common
from ..logger import get_logger
from ..exceptions import BootstrapError

from base_component import BaseComponent

CLUSTER_REMOVE_SCRIPT = '/opt/manager/env/bin/teardown_cluster'
logger = get_logger('cluster')


class ClusterComponent(BaseComponent):
    def __init__(self):
        BaseComponent.__init__(self)

    def configure(self):
        pass

    def install(self):
        pass

    def remove(self):
        try:
            common.sudo([CLUSTER_REMOVE_SCRIPT])
        except BootstrapError:
            logger.notice('Cluster remove script does not exist - skipping')
        else:
            logger.notice('Cluster components removed')