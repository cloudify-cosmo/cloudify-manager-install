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

import csv
import os
import json
import base64
import random
import string
import time
import urllib2
import subprocess
from os.path import join, exists
from collections import namedtuple

import requests

from . import db
from ..components_constants import (
    ADMIN_PASSWORD,
    CLEAN_DB,
    CONFIG,
    FLASK_SECURITY,
    HOME_DIR_KEY,
    LOG_DIR_KEY,
    SCRIPTS,
    SECURITY,
    SERVICES_TO_INSTALL,
    SOURCES,
    VENV,
    CLUSTER_JOIN,
    SERVER_PASSWORD
)
from ..base_component import BaseComponent
from ..service_components import DATABASE_SERVICE
from ..service_names import (
    MANAGER,
    RESTSERVICE,
    POSTGRESQL_CLIENT
)
from ... import constants
from ...config import config
from ...logger import (
    get_logger,
)
from ...exceptions import BootstrapError, NetworkError, InputError
from ...utils import certificates, common
from ...utils.systemd import systemd
from ...utils.install import yum_install, yum_remove
from ...utils.network import get_auth_headers, wait_for_port
from ...utils.files import (
    deploy,
    remove_files,
    sudo_read,
    write_to_file,
)
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
CLOUDIFY_LICENSE_PUBLIC_KEY_PATH = join(HOME_DIR, 'license_key.pem.pub')
REST_URL = 'http://127.0.0.1:{port}/api/v3.1/{endpoint}'


class RestService(BaseComponent):
    def __init__(self, skip_installation=False):
        super(RestService, self).__init__(skip_installation)

    def _make_paths(self):
        # Used in the service templates
        config[RESTSERVICE][HOME_DIR_KEY] = HOME_DIR
        config[RESTSERVICE][LOG_DIR_KEY] = LOG_DIR
        config[RESTSERVICE][VENV] = REST_VENV

    def _deploy_restservice_files(self):
        logger.info('Deploying REST authorization, REST Service configuration'
                    ' and Cloudify licenses public key...')
        resource = namedtuple('Resource', 'src dst')
        resources = [
            resource(
                src=join(CONFIG_PATH, 'cloudify-rest.conf'),
                dst=REST_CONFIG_PATH
            ),
            resource(
                src=join(CONFIG_PATH, 'authorization.conf'),
                dst=REST_AUTHORIZATION_CONFIG_PATH
            ),
            resource(
                src=join(CONFIG_PATH, 'license_key.pem.pub'),
                dst=CLOUDIFY_LICENSE_PUBLIC_KEY_PATH
            )]
        for resource in resources:
            deploy(resource.src, resource.dst)
            common.chown(constants.CLOUDIFY_USER, constants.CLOUDIFY_GROUP,
                         resource.dst)

    def _generate_flask_security_config(self):
        logger.info('Generating random hash salt and secret key...')
        config[FLASK_SECURITY] = {
            'hash_salt': base64.b64encode(os.urandom(32)),
            'secret_key': base64.b64encode(os.urandom(32)),
            'encoding_alphabet': self._random_alphanumeric(),
            'encoding_block_size': 24,
            'encoding_min_length': 5,
            'encryption_key': base64.urlsafe_b64encode(os.urandom(64))
        }

    def _pre_create_snapshot_paths(self):
        for resource_dir in (
                'blueprints',
                'deployments',
                'uploaded-blueprints',
                'snapshots',
                'plugins'
        ):
            path = join(constants.MANAGER_RESOURCES_HOME, resource_dir)
            common.mkdir(path)

    def _get_flask_security(self):
        # If we're recreating the DB, or if there's no previous security
        # config file, just use the config that was generated
        if config[CLEAN_DB] or not exists(REST_SECURITY_CONFIG_PATH):
            return config[FLASK_SECURITY]

        security_config = config[FLASK_SECURITY]

        current_config = json.loads(sudo_read(REST_SECURITY_CONFIG_PATH))

        # We want the existing config values to take precedence, but for any
        # new values to also be in the final config dict
        security_config.update(current_config)

        return security_config

    def _deploy_security_configuration(self):
        logger.info('Deploying REST Security configuration file...')

        flask_security = self._get_flask_security()
        write_to_file(flask_security, REST_SECURITY_CONFIG_PATH,
                      json_dump=True)
        common.chown(
            constants.CLOUDIFY_USER,
            constants.CLOUDIFY_GROUP,
            REST_SECURITY_CONFIG_PATH
        )
        common.chmod('660', REST_SECURITY_CONFIG_PATH)

    def _calculate_worker_count(self):
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

    def _chown_resources_dir(self):
        # Pre-creating paths so permissions fix can
        # work correctly in mgmtworker
        self._pre_create_snapshot_paths()
        common.chown(
            constants.CLOUDIFY_USER,
            constants.CLOUDIFY_GROUP,
            constants.MANAGER_RESOURCES_HOME
        )

    def _configure_restservice(self):
        self._calculate_worker_count()
        self._deploy_restservice_files()
        self._deploy_security_configuration()

    def _verify_restservice(self):
        """To verify that the REST service is working, check the status

        Not everything will be green on the status, because not all
        services are set up yet, but we are just checking that the REST
        service responds.
        """
        rest_port = config[RESTSERVICE]['port']
        url = REST_URL.format(port=rest_port, endpoint='status')
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

    def _verify_restservice_alive(self):
        systemd.verify_alive(RESTSERVICE)

        logger.info('Verifying Rest service is working as expected...')
        self._verify_restservice()

    def _configure_db(self):
        configs = {
            'rest_config': REST_CONFIG_PATH,
            'authorization_config': REST_AUTHORIZATION_CONFIG_PATH,
            'security_config': REST_SECURITY_CONFIG_PATH
        }
        config[CLUSTER_JOIN] = False
        result = db.check_manager_in_table()
        if result == constants.MANAGER_NOT_IN_DB:
            # Adding a manager to the cluster - external RabbitMQ already
            # configured
            logger.info('Manager not in DB, will join the cluster...')
            config[CLUSTER_JOIN] = True
            certificates.handle_ca_cert(generate_if_missing=False)
            db.insert_manager(configs)
        elif result == constants.DB_NOT_INITIALIZED or config[CLEAN_DB]:
            logger.info('DB not initialized, creating DB...')
            certificates.handle_ca_cert()
            db.prepare_db()
            db.populate_db(configs)
            db.insert_manager(configs)
        elif not config[CLEAN_DB]:
            # Reinstalling the manager with the old DB
            db.create_amqp_resources(configs)

    def _generate_password(self, length=12):
        chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
        password = ''.join(random.choice(chars) for _ in range(length))
        return password

    def _set_admin_password(self):
        if not config[MANAGER][SECURITY][ADMIN_PASSWORD]:
            config[MANAGER][SECURITY][ADMIN_PASSWORD] = \
                self._generate_password()

    def _random_alphanumeric(self, result_len=31):
        """
        :return: random string of unique alphanumeric characters
        """
        ascii_alphanumeric = string.ascii_letters + string.digits
        return ''.join(
            random.SystemRandom().sample(ascii_alphanumeric, result_len)
        )

    def _validate_admin_password_and_security_config(self):
        if not config[MANAGER][SECURITY][ADMIN_PASSWORD]:
            raise InputError(
                'Admin password not found in {config_path} and '
                'was not provided as an argument.\n'
                'The password was not generated because the `--clean-db` flag '
                'was not passed cfy_manager install/configure'.format(
                    config_path=constants.USER_CONFIG_PATH
                )
            )
        if not config[FLASK_SECURITY]:
            raise InputError(
                'Flask security configuration not found in {config_path}.\n'
                'The Flask security configuration was not generated because '
                'the `--clean-db` flag was not passed cfy_manager '
                'install/configure'.format(
                    config_path=constants.USER_CONFIG_PATH
                )
            )

    def _wait_for_haproxy_startup(self):
        logger.info('Waiting for DB proxy startup to complete...')
        healthy = False
        for attempt in range(60):
            # Get the haproxy status data
            try:
                haproxy_csv = requests.get(
                    'http://localhost:7000/admin?stats;csv;norefresh'
                ).text
            except requests.ConnectionError as err:
                logger.info(
                    'Could not connect to DB proxy ({err}), '
                    'retrying...'.format(err=err)
                )
                time.sleep(1)
                continue

            # Example output (# noqas are not part of actual output):
            # # pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,sid,throttle,lbtot,tracked,type,rate,rate_lim,rate_max,check_status,check_code,check_duration,hrsp_1xx,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other,hanafail,req_rate,req_rate_max,req_tot,cli_abrt,srv_abrt,comp_in,comp_out,comp_byp,comp_rsp,lastsess,last_chk,last_agt,qtime,ctime,rtime,ttime,  # noqa
            # stats,FRONTEND,,,1,1,2000,7,553,83778,0,0,0,,,,,OPEN,,,,,,,,,1,1,0,,,,0,1,0,1,,,,0,6,0,0,0,0,,1,1,7,,,0,0,0,0,,,,,,,,  # noqa
            # stats,BACKEND,0,0,0,0,200,0,553,83778,0,0,,0,0,0,0,UP,0,0,0,,0,89,0,,1,1,0,,0,,1,0,,0,,,,0,0,0,0,0,0,,,,,0,0,0,0,0,0,0,,,0,0,0,0,  # noqa
            # postgres,FRONTEND,,,0,0,2000,0,0,0,0,0,0,,,,,OPEN,,,,,,,,,1,2,0,,,,0,0,0,0,,,,,,,,,,,0,0,0,,,0,0,0,0,,,,,,,,  # noqa
            # postgres,postgresql_192.0.2.46_5432,0,0,0,0,100,0,0,0,,0,,0,0,0,0,DOWN,1,1,0,1,1,89,89,,1,2,1,,0,,2,0,,0,L7STS,503,3,,,,,,,0,,,,0,0,,,,,-1,HTTP status check returned code <503>,,0,0,0,0,  # noqa
            # postgres,postgresql_192.0.2.47_5432,0,0,0,0,100,0,0,0,,0,,0,0,0,0,UP,1,1,0,0,0,89,0,,1,2,2,,0,,2,0,,0,L7OK,200,3,,,,,,,0,,,,0,0,,,,,-1,HTTP status check returned code <200>,,0,0,0,0,  # noqa
            # postgres,postgresql_192.0.2.48_5432,0,0,0,0,100,0,0,0,,0,,0,0,0,0,DOWN,1,1,0,1,1,87,87,,1,2,3,,0,,2,0,,0,L7STS,503,2,,,,,,,0,,,,0,0,,,,,-1,HTTP status check returned code <503>,,0,0,0,0,  # noqa
            # postgres,BACKEND,0,0,0,0,200,0,0,0,0,0,,0,0,0,0,UP,1,1,0,,0,89,0,,1,2,0,,0,,1,0,,0,,,,,,,,,,,,,,0,0,0,0,0,0,-1,,,0,0,0,0,  # noqa
            haproxy_status = list(csv.DictReader(
                haproxy_csv.lstrip('# ').splitlines()
            ))

            servers = [
                row for row in haproxy_status
                if row['svname'] not in ('BACKEND', 'FRONTEND')
            ]

            for server in servers:
                logger.debug(
                    'Server: {name}: {status} ({why}) - {detail}'.format(
                        name=server['svname'],
                        status=server['status'],
                        why=server['check_status'],
                        detail=server['last_chk'],
                    )
                )

            if any(server['check_status'] == 'INI' for server in servers):
                logger.info('DB healthchecks still initialising...')
                time.sleep(1)
                continue

            if not any(server['status'] == 'UP' for server in servers):
                logger.info('DB proxy has not yet selected a backend DB...')
                time.sleep(1)
                continue

            healthy = True
            # If we got here, haproxy is happy!
            break

        if not healthy:
            raise RuntimeError(
                'DB proxy startup failed.'
            )

        logger.info('DB proxy startup complete.')

    def _set_haproxy_connect_any(self, enable):
        """Make SELinux allow/disallow haproxy listening on any ports.
        This is required so that it can listen on port 5432 for postgres.
        The alternatives to make it only able to do that have much greater
        complexity, so this approach was selected.
        """
        value = '--on' if enable else '--off'
        common.sudo(
            ['semanage', 'boolean', '-m', value, 'haproxy_connect_any'],
            ignore_failures=True
        )

    def _configure_db_proxy(self):
        self._set_haproxy_connect_any(True)

        certificates.use_supplied_certificates(
            component_name='postgresql_server',
            logger=self.logger,
            ca_destination='/etc/haproxy/ca.crt',
            owner='haproxy',
            group='haproxy',
        )

        deploy(os.path.join(CONFIG_PATH, 'haproxy.cfg'),
               '/etc/haproxy/haproxy.cfg')

        systemd.enable('haproxy', append_prefix=False)
        systemd.restart('haproxy', append_prefix=False)
        self._wait_for_haproxy_startup()

    @staticmethod
    def _upload_cloudify_license():
        """
        Upload a Cloudify license to the Manager (only when a path to a
        license is provided in config.yaml).
        """
        license_path = config[MANAGER]['cloudify_license_path']
        if license_path:
            try:
                logger.info('Uploading Cloudify license `{0}` to the'
                            ' Manager...'.format(license_path))
                rest_port = config[RESTSERVICE]['port']
                wait_for_port(rest_port)
                url = REST_URL.format(port=rest_port, endpoint='license')
                response = requests.put(url=url, headers=get_auth_headers(),
                                        data=open(license_path, 'rb'))
                if response.status_code != 200:
                    raise BootstrapError(
                        'Failed to upload Cloudify license: {0} {1}'
                        .format(response.status_code, response.content))
            except IOError as e:
                logger.warning('Failed to upload Cloudify license `{0}` due'
                               ' to IOError: {1}'.format(license_path,
                                                         e.message))

    def install(self):
        logger.notice('Installing Rest Service...')
        yum_install(config[RESTSERVICE][SOURCES]['restservice_source_url'])
        yum_install(config[RESTSERVICE][SOURCES]['agents_source_url'])

        self._chown_resources_dir()

        set_logrotate(RESTSERVICE)

        if DATABASE_SERVICE not in config[SERVICES_TO_INSTALL]:
            yum_install(config[RESTSERVICE][SOURCES]['haproxy_rpm_url'])
        logger.notice('Rest Service successfully installed')

    def configure(self):
        logger.notice('Configuring Rest Service...')
        if common.manager_using_db_cluster():
            self._configure_db_proxy()

        if config[CLEAN_DB]:
            self._set_admin_password()
            self._generate_flask_security_config()
        else:
            self._validate_admin_password_and_security_config()
        self._make_paths()
        self._configure_restservice()
        self._configure_db()
        if config[POSTGRESQL_CLIENT][SERVER_PASSWORD]:
            logger.info('Removing postgres password from config.yaml')
            config[POSTGRESQL_CLIENT][SERVER_PASSWORD] = '<removed>'
        systemd.configure(RESTSERVICE)
        systemd.restart(RESTSERVICE)
        if config[CLUSTER_JOIN]:
            logger.info('Extra node in cluster, will verify rest-service '
                        'after clustering configured')
        else:
            self._verify_restservice_alive()
            self._upload_cloudify_license()

        logger.notice('Rest Service successfully configured')

    def remove(self):
        logger.notice('Removing Restservice...')
        systemd.remove(RESTSERVICE, service_file=False)
        remove_logrotate(RESTSERVICE)

        yum_remove('cloudify-rest-service')
        yum_remove('cloudify-agents')

        common.remove('/opt/manager')

        if common.manager_using_db_cluster():
            self._set_haproxy_connect_any(False)
            common.remove('/etc/haproxy')

        if DATABASE_SERVICE not in config[SERVICES_TO_INSTALL]:
            yum_remove('haproxy')
            remove_files(['/etc/haproxy'])
        logger.notice('Rest Service successfully removed')

    def start(self):
        logger.notice('Starting Restservice...')
        systemd.start(RESTSERVICE)
        self._verify_restservice_alive()
        logger.notice('Restservice successfully started')

    def stop(self):
        logger.notice('Stopping Restservice...')
        systemd.stop(RESTSERVICE)
        logger.notice('Restservice successfully stopped')
