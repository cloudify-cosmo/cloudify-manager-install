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

from ..service_names import MANAGER, MANAGER_IP_SETTER

from ...config import config
from ...logger import get_logger

from ...utils import common
from ...utils.systemd import systemd
from ...utils.install import yum_install, yum_remove


MANAGER_IP_SETTER_DIR = join('/opt/cloudify', MANAGER_IP_SETTER)

logger = get_logger(MANAGER_IP_SETTER)


def _install():
    yum_install(config[MANAGER_IP_SETTER]['sources']['manager_ip_setter_rpm'])


def _configure():
    if config[MANAGER]['set_manager_ip_on_boot']:
        systemd.configure(MANAGER_IP_SETTER)
    else:
        logger.info('Set manager ip on boot is disabled.')


def install():
    logger.notice('Installing Manager IP Setter...')
    _install()
    _configure()
    logger.notice('Manager IP Setter successfully installed')


def configure():
    logger.notice('Configuring Manager IP Setter...')
    _configure()
    logger.notice('Manager IP Setter successfully configured')


def remove():
    logger.notice('Removing Manager IP Setter...')
    systemd.remove(MANAGER_IP_SETTER, service_file=False)
    yum_remove('cloudify-manager-ip-setter')
    common.remove('/opt/cloudify/manager-ip-setter')
    logger.notice('Manager IP Setter successfully removed')
