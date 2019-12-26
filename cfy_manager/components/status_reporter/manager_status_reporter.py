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

from ...config import config
from .status_reporter import StatusReporter
from ...utils.node import update_status_reporter_config
from ..components_constants import MANAGER_STATUS_REPORTER, CONSTANTS


class ManagerStatusReporter(StatusReporter):

    def __init__(self, skip_installation):
        super(ManagerStatusReporter, self).__init__(skip_installation,
                                                    'manager_reporter',
                                                    MANAGER_STATUS_REPORTER)

    def configure(self):
        super(ManagerStatusReporter, self).configure()
        update_status_reporter_config({'ca_path':
                                       config[CONSTANTS]['ca_cert_path']})
