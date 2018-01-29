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

from .. import SOURCES, CONFIG, LOG_DIR_KEY

from ..service_names import LOGSTASH

from ... import constants
from ...config import config
from ...logger import get_logger

from ...utils import common
from ...utils.systemd import systemd
from ...utils.install import yum_install, yum_remove
from ...utils.files import deploy

LOGSTASH_CONF_DIR = join('/etc', LOGSTASH)
REMOTE_CONFIG_PATH = join(LOGSTASH_CONF_DIR, 'conf.d')
INIT_D_FILE = '/etc/init.d/logstash'
LOG_DIR = join(constants.BASE_LOG_DIR, LOGSTASH)

CONFIG_PATH = join(constants.COMPONENTS_DIR, LOGSTASH, CONFIG)

logger = get_logger(LOGSTASH)


def _install():
    """Install logstash as a systemd service."""
    sources = config[LOGSTASH][SOURCES]

    for source in sources:
        yum_install(sources[source])


def _deploy_logstash_config():
    logger.info('Deploying Logstash configuration...')
    config[LOGSTASH][LOG_DIR_KEY] = LOG_DIR  # Used in config files

    deploy(
        join(CONFIG_PATH, 'logstash.conf'),
        join(REMOTE_CONFIG_PATH, 'logstash.conf')
    )
    common.chown(LOGSTASH, LOGSTASH, REMOTE_CONFIG_PATH)


def _start_and_validate_logstash():
    logger.debug('Checking logstash config...')
    common.sudo(['/sbin/chkconfig', 'logstash', 'on'])
    logger.info('Starting Logstash service...')
    systemd.restart(LOGSTASH, append_prefix=False)
    systemd.verify_alive(LOGSTASH, append_prefix=False)


def _configure():
    _deploy_logstash_config()
    _start_and_validate_logstash()


def install():
    logger.notice('Installing Logstash...')
    _install()
    _configure()
    logger.notice('Logstash successfully installed')


def configure():
    logger.notice('Configuring Logstash...')
    _configure()
    logger.notice('Logstash successfully configured')


def remove():
    logger.notice('Removing Logstash...')
    systemd.remove(LOGSTASH, service_file=False)
    yum_remove('postgresql94-jdbc')
    common.remove('/etc/logstash')
    logger.notice('Logstash successfully removed')
