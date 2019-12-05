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
from ..service_components import DATABASE_SERVICE
from ...constants import STATUS_REPORTER_CONFIG_KEY
from ..service_names import POSTGRESQL_SERVER, MANAGER
from ...utils.node import update_status_reporter_config
from ..components_constants import (PRIVATE_IP,
                                    DB_STATUS_REPORTER,
                                    SERVICES_TO_INSTALL)

from .status_reporter import StatusReporter


class PostgresqlStatusReporter(StatusReporter):
    @staticmethod
    def _should_install():
        # Only installing when in clustered setup
        return (config[SERVICES_TO_INSTALL] == [DATABASE_SERVICE] and
                config[POSTGRESQL_SERVER]['cluster']['nodes'])

    def __init__(self, skip_installation):
        skip_installation = skip_installation or not self._should_install()
        super(PostgresqlStatusReporter, self).__init__(skip_installation,
                                                       'postgresql_reporter',
                                                       DB_STATUS_REPORTER)

    def configure(self):
        super(PostgresqlStatusReporter, self).configure()
        private_ip = config[MANAGER][PRIVATE_IP]
        extra_config = {STATUS_REPORTER_CONFIG_KEY: {'private_ip': private_ip}}
        update_status_reporter_config(extra_config)
