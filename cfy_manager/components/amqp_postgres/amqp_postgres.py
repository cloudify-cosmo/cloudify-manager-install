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

from ..service_names import AMQP_POSTGRES

from ...logger import get_logger
from ...utils.systemd import systemd


logger = get_logger(AMQP_POSTGRES)


def _configure():
    logger.info('Starting AMQP-PostgreSQL Broker Service...')
    systemd.configure(AMQP_POSTGRES)
    systemd.restart(AMQP_POSTGRES)
    systemd.verify_alive(AMQP_POSTGRES)


def install():
    pass


def configure():
    logger.notice('Configuring AMQP-Postgres...')
    _configure()
    logger.notice('AMQP-Postgres successfully configured')


def start():
    logger.notice('Starting AMQP-Postgres...')
    systemd.start(AMQP_POSTGRES)
    systemd.verify_alive(AMQP_POSTGRES)
    logger.notice('AMQP-Postgres successfully started')


def stop():
    logger.notice('Stopping AMQP-Postgres...')
    systemd.stop(AMQP_POSTGRES)
    logger.notice('AMQP-Postgres successfully stopped')


def remove():
    logger.notice('Removing AMQP-Postgres...')
    systemd.remove(AMQP_POSTGRES, service_file=False)
    logger.notice('AMQP-Postgres successfully removed')
