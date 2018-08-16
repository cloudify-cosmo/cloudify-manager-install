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

from os.path import join, dirname

from .. import (
    SOURCES,
    CONFIG,
    HOME_DIR_KEY,
    LOG_DIR_KEY,
    SERVICE_USER,
    SERVICE_GROUP
)

from ..service_names import MGMTWORKER

from ...config import config
from ...logger import get_logger
from ... import constants as const

from ...utils import common
from ...utils.files import deploy
from ...utils.systemd import systemd
from ...utils.install import yum_install, yum_remove

HOME_DIR = '/opt/mgmtworker'
MGMTWORKER_VENV = join(HOME_DIR, 'env')
LOG_DIR = join(const.BASE_LOG_DIR, MGMTWORKER)
CONFIG_PATH = join(const.COMPONENTS_DIR, MGMTWORKER, CONFIG)

logger = get_logger(MGMTWORKER)


def _install():
    source_url = config[MGMTWORKER][SOURCES]['mgmtworker_source_url']
    yum_install(source_url)

    # TODO: Take care of this
    # Prepare riemann dir. We will change the owner to riemann later, but the
    # management worker will still need access to it
    # common.mkdir('/opt/riemann')
    # utils.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, riemann_dir)
    # utils.chmod('770', riemann_dir)


def _deploy_mgmtworker_config():
    config[MGMTWORKER][HOME_DIR_KEY] = HOME_DIR
    config[MGMTWORKER][LOG_DIR_KEY] = LOG_DIR
    config[MGMTWORKER][SERVICE_USER] = const.CLOUDIFY_USER
    config[MGMTWORKER][SERVICE_GROUP] = const.CLOUDIFY_GROUP

    _deploy_broker_config()
    _deploy_hooks_config()


def _deploy_broker_config():
    file_name = 'broker_config.json'
    work_dir = join(HOME_DIR, 'work')
    broker_config_dst = join(work_dir, file_name)
    deploy(
        src=join(CONFIG_PATH, file_name),
        dst=broker_config_dst
    )

    # The config contains credentials, do not let the world read it
    common.chmod('440', broker_config_dst)
    common.chown(const.CLOUDIFY_USER, const.CLOUDIFY_GROUP, broker_config_dst)


def _deploy_hooks_config():
    file_name = 'hooks.conf'
    config_dir = join(HOME_DIR, 'config')
    hooks_config_dst = join(config_dir, file_name)
    deploy(
        src=join(CONFIG_PATH, file_name),
        dst=hooks_config_dst
    )

    # The user should use root to edit the hooks config file
    common.chmod('440', hooks_config_dst)
    common.chown(const.CLOUDIFY_USER, const.CLOUDIFY_GROUP, hooks_config_dst)


def _prepare_snapshot_permissions():
    # TODO: See if all of this is necessary
    common.sudo(['chgrp', const.CLOUDIFY_GROUP, '/opt/manager'])
    common.sudo(['chmod', 'g+rw', '/opt/manager'])
    common.sudo(
        ['chgrp', '-R', const.CLOUDIFY_GROUP, const.SSL_CERTS_TARGET_DIR]
    )
    common.sudo(
        ['chgrp', const.CLOUDIFY_GROUP, dirname(const.SSL_CERTS_TARGET_DIR)]
    )
    common.sudo(['chmod', '-R', 'g+rw', const.SSL_CERTS_TARGET_DIR])
    common.sudo(['chmod', 'g+rw', dirname(const.SSL_CERTS_TARGET_DIR)])


def _verify_mgmtworker_alive():
    systemd.verify_alive(MGMTWORKER)


def _configure():
    _deploy_mgmtworker_config()
    systemd.configure(MGMTWORKER)
    _prepare_snapshot_permissions()
    systemd.restart(MGMTWORKER)
    _verify_mgmtworker_alive()


def install():
    logger.notice('Installing Management Worker...')
    _install()
    _configure()
    logger.notice('Management Worker successfully installed')


def configure():
    logger.notice('Configuring Management Worker...')
    _configure()
    logger.notice('Management Worker successfully configured')


def remove():
    logger.notice('Removing Management Worker...')
    systemd.remove(MGMTWORKER, service_file=False)
    yum_remove('cloudify-management-worker')
    common.remove('/opt/mgmtworker')
    logger.notice('Management Worker successfully removed')


def start():
    logger.notice('Starting Management Worker...')
    systemd.start(MGMTWORKER)
    _verify_mgmtworker_alive()
    logger.notice('Management Worker successfully started')


def stop():
    logger.notice('Stopping Management Worker...')
    systemd.stop(MGMTWORKER)
    logger.notice('Management Worker successfully stopped')
