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

from .. import SOURCES

from ..service_names import AMQPINFLUX

from ...config import config
from ...logger import get_logger

from ...utils.systemd import systemd
from ...utils.install import yum_install, yum_remove


logger = get_logger(AMQPINFLUX)

HOME_DIR = join('/opt', AMQPINFLUX)


def _install():
    source_url = config[AMQPINFLUX][SOURCES]['amqpinflux_source_url']
    yum_install(source_url)


def _configure():
    logger.info('Starting AMQP-Influx Broker Service...')
    systemd.configure(AMQPINFLUX)
    systemd.restart(AMQPINFLUX)
    systemd.verify_alive(AMQPINFLUX)


def install():
    logger.notice('Installing AMQP-Influx...')
    _install()
    _configure()
    logger.notice('AMQP-Influx successfully installed')


def configure():
    logger.notice('Configuring AMQP-Influx...')
    _configure()
    logger.notice('AMQP-Influx successfully configured')


def remove():
    logger.notice('Removing AMQP-Influx...')
    systemd.remove(AMQPINFLUX, service_file=False)
    yum_remove('cloudify-amqp-influx')
    logger.notice('AMQP-Influx successfully removed')
