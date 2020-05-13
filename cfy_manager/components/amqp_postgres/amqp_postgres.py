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

from os.path import join

from ..components_constants import LOG_DIR_KEY
from ..base_component import BaseComponent
from ..service_names import AMQP_POSTGRES
from ...config import config
from ...logger import get_logger
from ...utils.systemd import systemd
from ...constants import BASE_LOG_DIR


logger = get_logger(AMQP_POSTGRES)


class AmqpPostgres(BaseComponent):

    def __init__(self, skip_installation):
        super(AmqpPostgres, self).__init__(skip_installation)

    def _setup_log_dir(self):
        # Can't use AMQP_POSTGRES here because Jinja doesn't play nice
        # with `-`s
        conf = config.setdefault('amqp_postgres', {})
        conf[LOG_DIR_KEY] = join(BASE_LOG_DIR, AMQP_POSTGRES)

    def configure(self):
        logger.notice('Configuring AMQP-Postgres...')
        self._setup_log_dir()
        systemd.configure(AMQP_POSTGRES)
        logger.notice('AMQP-Postgres successfully configured')

    def start(self):
        logger.notice('Starting AMQP-Postgres...')
        systemd.start(AMQP_POSTGRES)
        systemd.verify_alive(AMQP_POSTGRES)
        logger.notice('AMQP-Postgres successfully started')

    def stop(self):
        logger.notice('Stopping AMQP-Postgres...')
        systemd.stop(AMQP_POSTGRES)
        logger.notice('AMQP-Postgres successfully stopped')

    def remove(self):
        logger.notice('Removing AMQP-Postgres...')
        systemd.remove(AMQP_POSTGRES, service_file=False)
        logger.notice('AMQP-Postgres successfully removed')
