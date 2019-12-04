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
from ...utils.files import update_yaml_file
from ...constants import STATUS_REPORTER_CONFIGURATION_PATH

from ..service_components import QUEUE_SERVICE
from ..components_constants import SERVICES_TO_INSTALL, BROKER_STATUS_REPORTER

from .status_reporter import StatusReporter


class RabbitmqStatusReporter(StatusReporter):
    @staticmethod
    def _should_install():
        return config[SERVICES_TO_INSTALL] == [QUEUE_SERVICE]

    def __init__(self, skip_installation):
        skip_installation = skip_installation or not self._should_install()
        super(RabbitmqStatusReporter, self).__init__(skip_installation,
                                                     'rabbitmq_reporter',
                                                     BROKER_STATUS_REPORTER)

    def configure(self):
        super(RabbitmqStatusReporter, self).configure()
        update_yaml_file(STATUS_REPORTER_CONFIGURATION_PATH,
                         'cfyreporter',
                         'cfyreporter',
                         {'extra_config': self._get_extra_config()})

    @staticmethod
    def _get_extra_config():
        extra_config = {'use_long_name': config['rabbitmq']['use_long_name'],
                        'rabbitmq_username': config['rabbitmq']['username'],
                        'rabbitmq_password': config['rabbitmq']['password'],
                        'rabbitmq_nodename': config['rabbitmq']['nodename']}
        return extra_config
