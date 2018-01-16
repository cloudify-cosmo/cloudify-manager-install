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

from .. import SCRIPTS, SOURCES

from ..service_names import RIEMANN

from ... import constants
from ...config import config
from ...logger import get_logger

from ...utils.systemd import systemd
from ...utils.install import yum_install, yum_remove


logger = get_logger(RIEMANN)

HOME_DIR = join('/opt', RIEMANN)
CONFIG_PATH = join('/etc', RIEMANN)
SCRIPTS_PATH = join(constants.COMPONENTS_DIR, RIEMANN, SCRIPTS)
LOG_DIR = join(constants.BASE_LOG_DIR, RIEMANN)


def _install():
    sources = config[RIEMANN][SOURCES]

    yum_install(sources['daemonize_source_url'])
    yum_install(sources['riemann_source_url'])
    yum_install(sources['cloudify_riemann_url'])


def start_and_verify():
    logger.info('Starting Riemann service...')
    systemd.configure(RIEMANN)
    systemd.restart(RIEMANN)
    systemd.verify_alive(RIEMANN)


def _configure():
    start_and_verify()


def install():
    logger.notice('Installing Riemann...')
    _install()
    _configure()
    logger.notice('Riemann successfully installed')


def configure():
    logger.notice('Configuring Riemann...')
    _configure()
    logger.notice('Riemann successfully configured')


def remove():
    logger.notice('Removing Riemann...')
    systemd.remove(RIEMANN, service_file=False)
    yum_remove(RIEMANN)
    logger.notice('Riemann successfully removed')
