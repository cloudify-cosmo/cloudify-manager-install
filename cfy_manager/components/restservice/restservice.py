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

import json
import urllib2
import subprocess
from os.path import join

from . import db

from .. import (
    SOURCES,
    CONFIG,
    SCRIPTS,
    HOME_DIR_KEY,
    LOG_DIR_KEY,
    VENV,
    FLASK_SECURITY,
    CLEAN_DB
)

from ..service_names import RESTSERVICE

from ... import constants
from ...config import config
from ...logger import get_logger
from ...exceptions import BootstrapError, FileError, NetworkError

from ...utils import common
from ...utils.systemd import systemd
from ...utils.install import yum_install, yum_remove
from ...utils.network import get_auth_headers, wait_for_port
from ...utils.files import deploy, get_local_source_path, write_to_file
from ...utils.logrotate import set_logrotate, remove_logrotate


HOME_DIR = '/opt/manager'
REST_VENV = join(HOME_DIR, 'env')
LOG_DIR = join(constants.BASE_LOG_DIR, 'rest')
CONFIG_PATH = join(constants.COMPONENTS_DIR, RESTSERVICE, CONFIG)
SCRIPTS_PATH = join(constants.COMPONENTS_DIR, RESTSERVICE, SCRIPTS)
RESTSERVICE_RESOURCES = join(constants.BASE_RESOURCES_PATH, RESTSERVICE)
REST_CONFIG_PATH = join(HOME_DIR, 'cloudify-rest.conf')
REST_AUTHORIZATION_CONFIG_PATH = join(HOME_DIR, 'authorization.conf')
REST_SECURITY_CONFIG_PATH = join(HOME_DIR, 'rest-security.conf')
logger = get_logger(RESTSERVICE)


def _make_paths():
    # Used in the service templates
    config[RESTSERVICE][HOME_DIR_KEY] = HOME_DIR
    config[RESTSERVICE][LOG_DIR_KEY] = LOG_DIR
    config[RESTSERVICE][VENV] = REST_VENV


def _deploy_rest_configuration():
    logger.info('Deploying REST Service Configuration file...')
    deploy(join(CONFIG_PATH, 'cloudify-rest.conf'), REST_CONFIG_PATH)
    common.chown(constants.CLOUDIFY_USER, constants.CLOUDIFY_GROUP,
                 REST_CONFIG_PATH)


def _deploy_authorization_configuration():
    logger.info('Deploying REST authorization configuration file...')
    deploy(join(CONFIG_PATH, 'authorization.conf'),
           REST_AUTHORIZATION_CONFIG_PATH)
    common.chown(constants.CLOUDIFY_USER, constants.CLOUDIFY_GROUP,
                 REST_AUTHORIZATION_CONFIG_PATH)


def _pre_create_snapshot_paths():
    for resource_dir in (
            'blueprints',
            'deployments',
            'uploaded-blueprints',
            'snapshots',
            'plugins'
    ):
        path = join(constants.MANAGER_RESOURCES_HOME, resource_dir)
        common.mkdir(path)


def _deploy_security_configuration():
    # Pre-creating paths so permissions fix can work correctly in mgmtworker
    _pre_create_snapshot_paths()
    common.chown(
        constants.CLOUDIFY_USER,
        constants.CLOUDIFY_GROUP,
        constants.MANAGER_RESOURCES_HOME
    )

    logger.info('Deploying REST Security configuration file...')

    write_to_file(config[FLASK_SECURITY], REST_SECURITY_CONFIG_PATH,
                  json_dump=True)
    common.chown(
        constants.CLOUDIFY_USER,
        constants.CLOUDIFY_GROUP,
        REST_SECURITY_CONFIG_PATH
    )
    common.chmod('g+r', REST_SECURITY_CONFIG_PATH)


def _calculate_worker_count():
    gunicorn_config = config[RESTSERVICE]['gunicorn']
    worker_count = gunicorn_config['worker_count']
    max_worker_count = gunicorn_config['max_worker_count']
    if not worker_count:
        # Calculate number of processors
        nproc = int(subprocess.check_output('nproc'))
        worker_count = nproc * 2 + 1

    if worker_count > max_worker_count:
        worker_count = max_worker_count

    gunicorn_config['worker_count'] = worker_count


def _configure_restservice():
    _calculate_worker_count()
    _deploy_rest_configuration()
    _deploy_security_configuration()
    _deploy_authorization_configuration()


def _verify_restservice():
    """To verify that the REST service is working, GET the blueprints list.

    There's nothing special about the blueprints endpoint, it's simply one
    that also requires the storage backend to be up, so if it works, there's
    a good chance everything is configured correctly.
    """
    auth_headers = get_auth_headers()
    validation_cmd = ['curl', '--unix-socket',
                      constants.REST_SERVICE_SOCKET_PATH, '-f',
                      '-k',  # TODO: replace with REST service's cert
                      'http://localhost/api/v2.1/blueprints']
    for name, value in auth_headers.items():
        validation_cmd.extend(['-H', '{}: {}'.format(name, value)])

    proc = common.run(validation_cmd, retries=24, retry_interval=3)

    try:
        json.loads(proc.aggr_stdout)
    except ValueError as e:
        raise BootstrapError(
            'REST service returned malformed JSON: {0}'.format(e))


def _verify_restservice_alive():
    systemd.verify_alive(RESTSERVICE)

    logger.info('Verifying Rest service is working as expected...')
    _verify_restservice()


def _configure_db():
    configs = {
        'rest_config': REST_CONFIG_PATH,
        'authorization_config': REST_AUTHORIZATION_CONFIG_PATH,
        'security_config': REST_SECURITY_CONFIG_PATH
    }
    if config[CLEAN_DB]:
        db.prepare_db()
        db.populate_db(configs)
    else:
        db.create_amqp_resources(configs)


def _configure():
    _make_paths()
    _configure_restservice()
    _configure_db()
    set_logrotate(RESTSERVICE)
    systemd.configure(RESTSERVICE)
    systemd.restart(RESTSERVICE)
    _verify_restservice_alive()


def _remove_files():
    """
    Remove all files related to the REST service and uninstall the RPM,
    """
    yum_remove('cloudify-rest-service')
    yum_remove('cloudify-agents')

    common.remove('/opt/manager')


def install():
    logger.notice('Installing Rest Service...')
    yum_install(config[RESTSERVICE][SOURCES]['restservice_source_url'])
    yum_install(config[RESTSERVICE][SOURCES]['agents_source_url'])

    premium_source_url = config[RESTSERVICE][SOURCES]['premium_source_url']
    try:
        get_local_source_path(premium_source_url)
    except FileError:
        logger.info('premium package not found in manager resources package')
        logger.notice('premium will not be installed.')
    else:
        logger.notice('Installing Cloudify Premium...')
        yum_install(config[RESTSERVICE][SOURCES]['premium_source_url'])

    _configure()
    logger.notice('Rest Service successfully installed')


def configure():
    logger.notice('Configuring Rest Service...')
    _configure()
    logger.notice('Rest Service successfully configured')


def remove():
    logger.notice('Removing Restservice...')
    systemd.remove(RESTSERVICE, service_file=False)
    remove_logrotate(RESTSERVICE)
    _remove_files()
    logger.notice('Rest Service successfully removed')


def start():
    logger.notice('Starting Restservice...')
    systemd.start(RESTSERVICE)
    _verify_restservice_alive()
    logger.notice('Restservice successfully started')


def stop():
    logger.notice('Stopping Restservice...')
    systemd.stop(RESTSERVICE)
    logger.notice('Restservice successfully stopped')
