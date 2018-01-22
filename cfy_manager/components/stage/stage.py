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

from .. import (
    SOURCES,
    SERVICE_USER,
    SERVICE_GROUP,
    VENV
)

from ..service_names import STAGE, MANAGER, RESTSERVICE

from ...config import config
from ...logger import get_logger

from ...utils import common
from ...utils.install import yum_install, yum_remove
from ...utils.systemd import systemd
from ...utils.network import wait_for_port


logger = get_logger(STAGE)

STAGE_USER = '{0}_user'.format(STAGE)
STAGE_GROUP = '{0}_group'.format(STAGE)

HOME_DIR = join('/opt', 'cloudify-{0}'.format(STAGE))
NODEJS_DIR = join('/opt', 'nodejs')
MAKE_AUTH_TOKEN_SCRIPT = '/opt/manager/scripts/make-auth-token.py'


def _set_community_mode():
    premium_edition = config[MANAGER]['premium_edition']
    community_mode = '' if premium_edition else '-mode community'

    # This is used in the stage systemd service file
    config[STAGE]['community_mode'] = community_mode


def _install():
    sources = config[STAGE][SOURCES]
    for source in sources.values():
        yum_install(source)


def _create_auth_token(rest_service_python):
    common.run([
        'sudo', '-u', STAGE_USER, rest_service_python, MAKE_AUTH_TOKEN_SCRIPT
    ])


def _run_db_migrate():
    common.run('npm run db-migrate', cwd=join(HOME_DIR, 'backend'))


def _start_and_validate_stage():
    _set_community_mode()
    # Used in the service template
    config[STAGE][SERVICE_USER] = STAGE_USER
    config[STAGE][SERVICE_GROUP] = STAGE_GROUP
    systemd.configure(STAGE)

    logger.info('Starting Stage service...')
    systemd.restart(STAGE)
    wait_for_port(8088)


def _configure():
    rest_service_python = join(config[RESTSERVICE][VENV], 'bin', 'python')
    _create_auth_token(rest_service_python)
    _run_db_migrate()
    _start_and_validate_stage()


def install():
    logger.notice('Installing Stage...')
    _install()
    _configure()
    logger.notice('Stage successfully installed')


def configure():
    logger.notice('Configuring Stage...')
    _configure()
    logger.notice('Stage successfully configured')


def remove():
    logger.notice('Removing Stage...')
    yum_remove('nodejs')
    systemd.remove(STAGE, service_file=False)
    logger.notice('Stage successfully removed')
