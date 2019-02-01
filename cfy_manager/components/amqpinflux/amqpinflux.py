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

from ..components_constants import SOURCES
from ..base_component import BaseComponent
from ..service_names import AMQPINFLUX
from ...config import config
from ...logger import get_logger
from ...utils.systemd import systemd
from ...utils.install import yum_install, yum_remove

logger = get_logger(AMQPINFLUX)

HOME_DIR = join('/opt', AMQPINFLUX)


class AmqpInfluxComponent(BaseComponent):

    def __init__(self, skip_installation):
        super(AmqpInfluxComponent, self).__init__(skip_installation)

    def _install(self):
        source_url = config[AMQPINFLUX][SOURCES]['amqpinflux_source_url']
        yum_install(source_url)

    def _configure(self):
        logger.info('Starting AMQP-Influx Broker Service...')
        systemd.configure(AMQPINFLUX,
                          user='amqpinflux', group='amqpinflux')
        systemd.restart(AMQPINFLUX)
        systemd.verify_alive(AMQPINFLUX)

    def install(self):
        logger.notice('Installing AMQP-Influx...')
        self._install()
        self._configure()
        logger.notice('AMQP-Influx successfully installed')

    def configure(self):
        logger.notice('Configuring AMQP-Influx...')
        self._configure()
        logger.notice('AMQP-Influx successfully configured')

    def start(self):
        logger.notice('Starting AMQP-Influx...')
        systemd.start(AMQPINFLUX)
        systemd.verify_alive(AMQPINFLUX)
        logger.notice('AMQP-Influx successfully started')

    def stop(self):
        logger.notice('Stopping AMQP-Influx...')
        systemd.stop(AMQPINFLUX)
        logger.notice('AMQP-Influx successfully stopped')

    def remove(self):
        logger.notice('Removing AMQP-Influx...')
        systemd.remove(AMQPINFLUX, service_file=False)
        yum_remove('cloudify-amqp-influx')
        logger.notice('AMQP-Influx successfully removed')
