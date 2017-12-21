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
from tempfile import mkdtemp

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
from ...exceptions import BootstrapError, NetworkError

from ...utils import common, sudoers
from ...utils.systemd import systemd
from ...utils.install import yum_install, yum_remove
from ...utils.network import get_auth_headers, wait_for_port
from ...utils.files import deploy
from ...utils.files import write_to_file


HOME_DIR = '/opt/manager'
REST_VENV = join(HOME_DIR, 'env')
LOG_DIR = join(constants.BASE_LOG_DIR, 'rest')
CONFIG_PATH = join(constants.COMPONENTS_DIR, RESTSERVICE, CONFIG)
SCRIPTS_PATH = join(constants.COMPONENTS_DIR, RESTSERVICE, SCRIPTS)
RESTSERVICE_RESOURCES = join(constants.BASE_RESOURCES_PATH, RESTSERVICE)

logger = get_logger(RESTSERVICE)


def _make_paths():
    # Used in the service templates
    config[RESTSERVICE][HOME_DIR_KEY] = HOME_DIR
    config[RESTSERVICE][LOG_DIR_KEY] = LOG_DIR
    config[RESTSERVICE][VENV] = REST_VENV


def _deploy_rest_configuration():
    logger.info('Deploying REST Service Configuration file...')
    conf_path = join(HOME_DIR, 'cloudify-rest.conf')
    deploy(join(CONFIG_PATH, 'cloudify-rest.conf'), conf_path)
    common.chown(constants.CLOUDIFY_USER, constants.CLOUDIFY_GROUP, conf_path)


def _deploy_authorization_configuration():
    logger.info('Deploying REST authorization configuration file...')
    conf_path = join(HOME_DIR, 'authorization.conf')
    deploy(join(CONFIG_PATH, 'authorization.conf'), conf_path)
    common.chown(constants.CLOUDIFY_USER, constants.CLOUDIFY_GROUP, conf_path)


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

    rest_security_path = join(HOME_DIR, 'rest-security.conf')
    write_to_file(config[FLASK_SECURITY], rest_security_path, json_dump=True)
    common.chown(
        constants.CLOUDIFY_USER,
        constants.CLOUDIFY_GROUP,
        rest_security_path
    )
    common.chmod('g+r', rest_security_path)


def _allow_creating_cluster():
    systemd_run = '/usr/bin/systemd-run'
    journalctl = '/usr/bin/journalctl'

    create_cluster_node = join(HOME_DIR, 'env', 'bin', 'create_cluster_node')
    cluster_unit_name = 'cloudify-ha-cluster'

    cmd = '{0} --unit {1} {2} --config *'.format(
        systemd_run,
        cluster_unit_name,
        create_cluster_node
    )
    sudoers.allow_user_to_sudo_command(cmd, description='Start a cluster')

    cmd = '{0} --unit {1}*'.format(journalctl, cluster_unit_name)
    sudoers.allow_user_to_sudo_command(cmd, description='Read cluster logs')


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
    _allow_creating_cluster()


def _verify_restservice():
    """To verify that the REST service is working, GET the blueprints list.

    There's nothing special about the blueprints endpoint, it's simply one
    that also requires the storage backend to be up, so if it works, there's
    a good chance everything is configured correctly.
    """
    rest_port = config[RESTSERVICE]['port']
    url = 'http://{0}:{1}/api/v2.1/blueprints'.format('127.0.0.1', rest_port)

    wait_for_port(rest_port)
    req = urllib2.Request(url, headers=get_auth_headers())

    try:
        response = urllib2.urlopen(req)
    # keep an erroneous HTTP response to examine its status code, but still
    # abort on fatal errors like being unable to connect at all
    except urllib2.HTTPError as e:
        response = e
    except urllib2.URLError as e:
        raise NetworkError(
            'REST service returned an invalid response: {0}'.format(e))
    if response.code == 401:
        raise NetworkError(
            'Could not connect to the REST service: '
            '401 unauthorized. Possible access control misconfiguration'
        )
    if response.code != 200:
        raise NetworkError(
            'REST service returned an unexpected response: '
            '{0}'.format(response.code)
        )

    try:
        json.load(response)
    except ValueError as e:
        raise BootstrapError(
            'REST service returned malformed JSON: {0}'.format(e))


def _start_restservice():
    systemd.restart(RESTSERVICE)
    systemd.verify_alive(RESTSERVICE)

    logger.info('Verifying Rest service is working as expected...')
    _verify_restservice()


def _configure_db():
    if config[CLEAN_DB]:
        db.prepare_db()
        db.populate_db()
    else:
        db.create_amqp_resources()


def _configure():
    _make_paths()
    _configure_restservice()
    _configure_db()
    systemd.configure(RESTSERVICE)
    _start_restservice()


def _remove_files():
    """
    Remove all files related to the REST service and uninstall the RPM,
    but don't remove the spec files which are handled by the installation RPM
    """
    tmp_dir = mkdtemp()
    # Keep the spec files in a temp location
    common.move(join(constants.MANAGER_RESOURCES_HOME, 'spec'), tmp_dir)

    # Removing the RPM before recreating /opt/manager/resources, because
    # yum remove will delete this folder
    yum_remove('cloudify-rest-service')

    # Recreate /opt/manager/resources and move the spec files back in
    common.mkdir(constants.MANAGER_RESOURCES_HOME)
    common.move(join(tmp_dir, 'spec'), constants.MANAGER_RESOURCES_HOME)

    common.remove(tmp_dir)


def install():
    logger.notice('Installing Rest Service...')
    yum_install(config[RESTSERVICE][SOURCES]['restservice_source_url'])
    _configure()
    logger.notice('Rest Service successfully installed')


def configure():
    logger.notice('Configuring Rest Service...')
    _configure()
    logger.notice('Rest Service successfully configured')


def remove():
    logger.notice('Removing Restservice...')
    systemd.remove(RESTSERVICE, service_file=False)
    _remove_files()
    logger.notice('Rest Service successfully removed')
