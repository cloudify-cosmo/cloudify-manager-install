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

from ..base_component import BaseComponent
from ...service_names import AMQP_POSTGRES
from ...logger import get_logger
from ...utils import service


logger = get_logger(AMQP_POSTGRES)


class AmqpPostgres(BaseComponent):
    services = {'cloudify-amqp-postgres': {'is_group': False}}

    def configure(self, config_file=None):
        logger.notice('Configuring AMQP-Postgres...')
        service.configure('cloudify-amqp-postgres')
        logger.notice('AMQP-Postgres successfully configured')
        self.start()

    def remove(self):
        logger.notice('Removing AMQP-Postgres...')
        service.remove('cloudify-amqp-postgres')
        logger.notice('AMQP-Postgres successfully removed')
