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
from os.path import join

from ..components_constants import (
    SOURCES,
    SERVICE_USER,
    SERVICE_GROUP,
    CONFIG,
    ENDPOINT_IP,
)
from ..base_component import BaseComponent
from ..service_names import INFLUXDB
from ... import constants
from ...config import config
from ...logger import get_logger
from ...exceptions import ValidationError, BootstrapError
from ...utils import common
from ...utils.systemd import systemd
from ...utils.install import yum_install, yum_remove
from ...utils.network import wait_for_port, check_http_response
from ...utils.files import copy_notice, remove_notice, remove_files, temp_copy

logger = get_logger(INFLUXDB)

# Currently, cannot be changed due to webui not allowing to configure it.
INFLUXDB_ENDPOINT_PORT = 8086

HOME_DIR = join('/opt', INFLUXDB)
LOG_DIR = join(constants.BASE_LOG_DIR, INFLUXDB)
INIT_D_PATH = join('/etc', 'init.d', INFLUXDB)
CONFIG_PATH = join(constants.COMPONENTS_DIR, INFLUXDB, CONFIG)


class InfluxDBComponent(BaseComponent):

    def __init__(self, skip_installation):
        super(InfluxDBComponent, self).__init__(skip_installation)

    def _configure_database(self, host, port):
        db_user = "root"
        db_pass = "root"
        db_name = "cloudify"

        logger.info('Creating InfluxDB Database...')

        # the below request is equivalent to running:
        # curl -S -s "http://localhost:8086/db?u=root&p=root" '-d "{\"name\": \"cloudify\"}"  # NOQA
        import urllib
        import urllib2
        import ast

        endpoint_for_list = 'http://{0}:{1}/db'.format(host, port)
        endpoint_for_creation = ('http://{0}:{1}/cluster/database_configs/'
                                 '{2}'.format(host, port, db_name))
        params = urllib.urlencode(dict(u=db_user, p=db_pass))
        url_for_list = endpoint_for_list + '?' + params
        url_for_creation = endpoint_for_creation + '?' + params

        # check if db already exists
        db_list = eval(urllib2.urlopen(urllib2.Request(url_for_list)).read())
        try:
            assert not any(d.get('name') == db_name for d in db_list)
        except AssertionError:
            logger.info('Database {0} already exists!'.format(db_name))
            return

        try:
            tmp_path = temp_copy(join(CONFIG_PATH, 'retention.json'))

            with open(tmp_path) as policy_file:
                retention_policy = policy_file.read()
            logger.debug(
                'Using retention policy: \n{0}'.format(retention_policy))
            data = json.dumps(ast.literal_eval(retention_policy))
            logger.debug('Using retention policy: \n{0}'.format(data))
            content_length = len(data)
            request = urllib2.Request(url_for_creation, data, {
                'Content-Type': 'application/json',
                'Content-Length': content_length})
            logger.debug('Request is: {0}'.format(request))
            request_reader = urllib2.urlopen(request)
            response = request_reader.read()
            logger.debug('Response: {0}'.format(response))
            request_reader.close()
            common.remove('/tmp/retention.json')

        except Exception as ex:
            raise BootstrapError(
                'Failed to create: {0} ({1}).'.format(db_name, ex)
            )

        logger.debug('Verifying database created successfully...')
        db_list = eval(urllib2.urlopen(urllib2.Request(url_for_list)).read())
        try:
            assert any(d.get('name') == db_name for d in db_list)
        except AssertionError:
            raise ValidationError('Verification failed!')
        logger.info('Databased {0} successfully created'.format(db_name))

    def _install_influxdb(self):
        source_url = config[INFLUXDB][SOURCES]['influxdb_source_url']
        yum_install(source_url)

    def _install(self):
        if config[INFLUXDB]['is_internal']:
            self._install_influxdb()

    def _create_paths(self):
        common.mkdir(HOME_DIR)
        common.mkdir(LOG_DIR)

        self._deploy_config_file()

        common.chown(INFLUXDB, INFLUXDB, HOME_DIR)
        common.chown(INFLUXDB, INFLUXDB, LOG_DIR)

    def _deploy_config_file(self):
        logger.info('Deploying InfluxDB configuration...')
        common.copy(
            source=join(CONFIG_PATH, 'config.toml'),
            destination=join(HOME_DIR, 'shared', 'config.toml')
        )

    def _configure_local_influxdb(self):
        config[INFLUXDB][SERVICE_USER] = INFLUXDB
        config[INFLUXDB][SERVICE_GROUP] = INFLUXDB

        self._create_paths()
        copy_notice(INFLUXDB)

        systemd.configure(INFLUXDB)
        # Provided with InfluxDB's package. Will be removed if it exists.
        common.remove(INIT_D_PATH)

    def _check_response(self):
        influxdb_endpoint_ip = config[INFLUXDB][ENDPOINT_IP]
        influxdb_url = 'http://{0}:{1}'.format(
            influxdb_endpoint_ip,
            INFLUXDB_ENDPOINT_PORT
        )
        response = check_http_response(influxdb_url)

        # InfluxDB normally responds with a 404 on GET to /, but also allow other
        # non-server-error response codes to allow for that behaviour to change.
        if response.code >= 500:
            raise ValidationError('Could not validate InfluxDB')

    def _verify_influxdb_alive(self):
        systemd.verify_alive(INFLUXDB)
        wait_for_port(INFLUXDB_ENDPOINT_PORT)
        self._check_response()

    def _configure(self):
        influxdb_endpoint_ip = config[INFLUXDB][ENDPOINT_IP]
        is_internal = config[INFLUXDB]['is_internal']
        if is_internal:
            self._configure_local_influxdb()
            systemd.restart(INFLUXDB)

        wait_for_port(INFLUXDB_ENDPOINT_PORT, influxdb_endpoint_ip)
        self._configure_database(influxdb_endpoint_ip, INFLUXDB_ENDPOINT_PORT)

        if is_internal:
            logger.info('Starting InfluxDB Service...')
            systemd.restart(INFLUXDB)
            self._verify_influxdb_alive()

    def install(self):
        logger.notice('Installing InfluxDB...')
        self._install()
        self._configure()
        logger.notice('InfluxDB successfully installed')

    def configure(self):
        logger.notice('Configuring InfluxDB...')
        self._configure()
        logger.notice('InfluxDB successfully configured')

    def remove(self):
        logger.notice('Removing Influxdb...')
        remove_notice(INFLUXDB)
        systemd.remove(INFLUXDB)
        remove_files([HOME_DIR, LOG_DIR, INIT_D_PATH])
        yum_remove(INFLUXDB)
        logger.notice('InfluxDB successfully removed')

    def start(self):
        is_internal = config[INFLUXDB]['is_internal']
        if is_internal:
            logger.notice('Starting Influxdb...')
            systemd.start(INFLUXDB)
            self._verify_influxdb_alive()
            logger.notice('Influxdb successfully started')

    def stop(self):
        is_internal = config[INFLUXDB]['is_internal']
        if is_internal:
            logger.notice('Stopping Influxdb...')
            systemd.stop(INFLUXDB)
            logger.notice('Influxdb successfully stopped')
