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

import os
import json
import time
import base64
import random
import string
import urllib2
import subprocess
from os.path import join, exists
from collections import namedtuple

import requests

from . import db
from ...components import sources
from ...utils.db import run_psql_command
from ...status_reporter import status_reporter
from ...utils.scripts import get_encoded_user_ids
from ...constants import (
    REST_HOME_DIR,
    REST_CONFIG_PATH,
    SELECT_USER_TOKENS_QUERY,
    REST_SECURITY_CONFIG_PATH,
    REST_AUTHORIZATION_CONFIG_PATH,
    CA_CERT_PATH
)
from ..components_constants import (
    VENV,
    CONFIG,
    SCRIPTS,
    PASSWORD,
    CLEAN_DB,
    SECURITY,
    SSL_INPUTS,
    LOG_DIR_KEY,
    HOME_DIR_KEY,
    CLUSTER_JOIN,
    ADMIN_PASSWORD,
    FLASK_SECURITY,
    SERVER_PASSWORD,
    DB_STATUS_REPORTER,
    SERVICES_TO_INSTALL,
    BROKER_STATUS_REPORTER,
    MANAGER_STATUS_REPORTER,
)
from ..base_component import BaseComponent
from ..syncthing.syncthing import Syncthing
from ..service_components import DATABASE_SERVICE, MANAGER_SERVICE
from ..service_names import (
    MANAGER,
    RESTSERVICE,
    POSTGRESQL_CLIENT
)
from ... import constants
from ...config import config

from ...utils import certificates, common
from ...logger import get_logger
from ...exceptions import BootstrapError, NetworkError
from ...utils import service
from ...utils.install import yum_install, yum_remove
from ...utils.network import get_auth_headers, wait_for_port
from ...utils.install import is_premium_installed
from ...utils.files import (
    check_rpms_are_present,
    deploy,
    remove_files,
    sudo_read,
    write_to_file,
)
from ...utils.logrotate import set_logrotate, remove_logrotate

REST_VENV = join(REST_HOME_DIR, 'env')
LOG_DIR = join(constants.BASE_LOG_DIR, 'rest')
CONFIG_PATH = join(constants.COMPONENTS_DIR, RESTSERVICE, CONFIG)
SCRIPTS_PATH = join(constants.COMPONENTS_DIR, RESTSERVICE, SCRIPTS)
RESTSERVICE_RESOURCES = join(constants.BASE_RESOURCES_PATH, RESTSERVICE)
logger = get_logger(RESTSERVICE)
CLOUDIFY_LICENSE_PUBLIC_KEY_PATH = join(REST_HOME_DIR, 'license_key.pem.pub')
REST_URL = 'http://127.0.0.1:{port}/api/v3.1/{endpoint}'
LDAP_CA_CERT_PATH = '/etc/cloudify/ssl/ldap_ca.crt'


class RestService(BaseComponent):
    def __init__(self, skip_installation=False):
        super(RestService, self).__init__(skip_installation)
        self._syncthing = Syncthing(skip_installation=skip_installation)

    def _make_paths(self):
        # Used in the service templates
        config[RESTSERVICE][HOME_DIR_KEY] = REST_HOME_DIR
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
        security_config = config.get(FLASK_SECURITY, {})
        config[FLASK_SECURITY] = {
            'hash_salt': base64.b64encode(os.urandom(32)),
            'secret_key': base64.b64encode(os.urandom(32)),
            'encoding_alphabet': self._random_alphanumeric(),
            'encoding_block_size': 24,
            'encoding_min_length': 5,
            'encryption_key': base64.urlsafe_b64encode(os.urandom(64))
        }

        # We want the config values to take precedence and generate the
        # missing values
        config[FLASK_SECURITY].update(security_config)

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
        self._generate_flask_security_config()
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
        service.verify_alive(RESTSERVICE)

        # logger.info('Verifying Rest service is working as expected...')
        # self._verify_restservice()

    def _configure_db(self):
        configs = {
            'rest_config': REST_CONFIG_PATH,
            'authorization_config': REST_AUTHORIZATION_CONFIG_PATH,
            'security_config': REST_SECURITY_CONFIG_PATH
        }
        config[CLUSTER_JOIN] = False
        logger.info('_configure_db')
        if config[CLEAN_DB]:
            db.drop_db()

        if not db.check_db_exists():
            self._initialize_db(configs)
        else:
            if db.manager_is_in_db():
                logger.warn(
                    'Manager found in DB. Skipping DB configuration.'
                )
                db.create_amqp_resources(configs)
            else:
                db.validate_schema_version(configs)
                self._join_cluster(configs)

    @staticmethod
    def _fetch_manager_reporter_token():
        sql_stmnt = "{0} = '{1}'".format(
            SELECT_USER_TOKENS_QUERY,
            MANAGER_STATUS_REPORTER
        )
        query_result = run_psql_command(
            command=['-c', sql_stmnt],
            db_key='cloudify_db_name',
        )
        manager_reporter = json.loads(query_result)
        reporters_tokens = get_encoded_user_ids([manager_reporter])
        config.setdefault(
            MANAGER_STATUS_REPORTER,
            {})[constants.STATUS_REPORTER_TOKEN] = \
            reporters_tokens[MANAGER_STATUS_REPORTER]

    def _initialize_db(self, configs):
        logger.info('DB not initialized, creating DB...')
        self._generate_passwords()
        certificates.handle_ca_cert(self.logger)
        db.prepare_db()
        db.populate_db(configs)
        db.insert_manager(configs)

    def _validate_cluster_join(self):
        issues = []

        certs = config[SSL_INPUTS]
        internal_certs_provided = (
            certs['internal_cert_path'] and certs['internal_key_path']
        )
        ca_certs_provided = (
            certs['ca_key_path'] and certs['ca_cert_path']
        )
        if not internal_certs_provided and not ca_certs_provided:
            issues.append(
                'Internal cert and key or CA cert and key must be provided '
                'to join an existing cluster. '
                'These should be set in either ssl_inputs.internal_cert_path '
                'and ssl_inputs.internal_key_path; or '
                'ssl_inputs.ca_cert_path and ssl_inputs.ca_key_path.'
            )

        if not config[MANAGER][SECURITY]['admin_password']:
            issues.append(
                'manager.security.admin_password must be set to the current '
                'admin password for the cluster.'
            )

        if issues:
            raise BootstrapError(
                'Existing cluster could not be joined due to configuration '
                'issues. Please run cfy_manager remove --force, then fix the '
                'configuration issues before reinstalling. Issues were:\n'
                '{issues}'.format(
                    issues='\n'.join(issues),
                )
            )

    def _join_cluster(self, configs):
        logger.info('Manager not in DB, will join the cluster...')
        self._validate_cluster_join()
        config[CLUSTER_JOIN] = True
        certificates.handle_ca_cert(self.logger, generate_if_missing=False)
        db.insert_manager(configs)

    def _generate_password(self, length=12):
        chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
        password = ''.join(random.choice(chars) for _ in range(length))
        return password

    def _generate_admin_password_if_empty(self):
        if not config[MANAGER][SECURITY][ADMIN_PASSWORD]:
            config[MANAGER][SECURITY][ADMIN_PASSWORD] = \
                self._generate_password()

    @staticmethod
    def _is_in_cluster_mode():
        return config[SERVICES_TO_INSTALL] == [MANAGER_SERVICE]

    def _generate_status_reporter_passwords(self):
        if not is_premium_installed():
            return
        if self._is_in_cluster_mode():
            config.setdefault(DB_STATUS_REPORTER, {})[PASSWORD] = \
                self._generate_password()
            config.setdefault(BROKER_STATUS_REPORTER, {})[PASSWORD] = \
                self._generate_password()
        config.setdefault(MANAGER_STATUS_REPORTER, {})[PASSWORD] = \
            self._generate_password()

    def _generate_passwords(self):
        self._generate_status_reporter_passwords()
        self._generate_admin_password_if_empty()

    def _random_alphanumeric(self, result_len=31):
        """
        :return: random string of unique alphanumeric characters
        """
        ascii_alphanumeric = string.ascii_letters + string.digits
        return ''.join(
            random.SystemRandom().sample(ascii_alphanumeric, result_len)
        )

    def _wait_for_haproxy_startup(self):
        logger.info('Waiting for DB proxy startup to complete...')
        healthy = False
        for attempt in range(60):
            servers = common.get_haproxy_servers(logger)

            if not servers:
                # No results yet
                logger.info('Haproxy not responding, retrying...')
                time.sleep(1)
                continue

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
            component_name='postgresql_client',
            logger=self.logger,
            ca_destination='/etc/haproxy/ca.crt',
            owner='haproxy',
            group='haproxy',
        )

        deploy(os.path.join(CONFIG_PATH, 'haproxy.cfg'),
               '/etc/haproxy/haproxy.cfg')

        service.enable('haproxy', append_prefix=False)
        service.restart('haproxy', append_prefix=False)
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
        yum_install(sources.restservice)
        yum_install(sources.agents)

        self._chown_resources_dir()

        set_logrotate(RESTSERVICE)

        if DATABASE_SERVICE not in config[SERVICES_TO_INSTALL]:
            rpm = sources.haproxy
            if check_rpms_are_present([rpm]):
                yum_install(rpm)
            else:
                logger.info(
                    'DB proxy RPM not available, skipping.'
                )
        logger.notice('Rest Service successfully installed')

    def _create_process_env(self):
        env = {}
        for value, envvar in [
            (REST_CONFIG_PATH, 'MANAGER_REST_CONFIG_PATH'),
            (REST_SECURITY_CONFIG_PATH, 'MANAGER_REST_SECURITY_CONFIG_PATH'),
            (REST_AUTHORIZATION_CONFIG_PATH,
             'MANAGER_REST_AUTHORIZATION_CONFIG_PATH'),
        ]:
            if value is not None:
                env[envvar] = value
        return env

    def configure(self):
        logger.notice('Configuring Rest Service...')

        logger.info('Checking for ldaps CA cert to deploy.')
        certificates.use_supplied_certificates(
            RESTSERVICE,
            logger,
            sub_component='ldap',
            just_ca_cert=True,
            ca_destination=LDAP_CA_CERT_PATH,
        )

        if common.manager_using_db_cluster():
            self._configure_db_proxy()

        self._make_paths()
        self._configure_restservice()
        service.configure(RESTSERVICE)
        self._configure_db()
        if is_premium_installed():
            self._join_cluster_setup()
        if config[POSTGRESQL_CLIENT][SERVER_PASSWORD]:
            logger.info('Removing postgres password from config.yaml')
            config[POSTGRESQL_CLIENT][SERVER_PASSWORD] = '<removed>'

        logger.notice('Rest Service successfully configured')

    def _join_cluster_setup(self):
        if not common.is_manager_service_only_installed():
            return
        self._syncthing.configure()

    @staticmethod
    def _configure_status_reporter():
        conf = {
            'token':
                config[
                    MANAGER_STATUS_REPORTER][constants.STATUS_REPORTER_TOKEN],
            'managers_ips': ['localhost'],
            'ca_path': CA_CERT_PATH
        }
        status_reporter.configure(**conf)

    def remove(self):
        logger.notice('Removing Restservice...')
        service.remove(RESTSERVICE, service_file=False)
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
        service.start(RESTSERVICE)
        if config.get(CLUSTER_JOIN):
            logger.info('Extra node in cluster, will verify rest-service '
                        'after clustering configured')
        else:
            self._verify_restservice_alive()
            self._upload_cloudify_license()
        if is_premium_installed():
            self._syncthing.start()
            self._fetch_manager_reporter_token()
            self._configure_status_reporter()
        logger.notice('Restservice successfully started')

    def stop(self):
        logger.notice('Stopping Restservice...')
        service.stop(RESTSERVICE)
        logger.notice('Restservice successfully stopped')
