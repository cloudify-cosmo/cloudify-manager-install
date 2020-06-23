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
import subprocess
from os.path import join, exists
from collections import namedtuple

import requests

from . import db
from ..validations import validate_certificates
from ...utils.db import run_psql_command
from ...utils.scripts import get_encoded_user_ids
from ...constants import (
    REST_HOME_DIR,
    REST_CONFIG_PATH,
    REST_SECURITY_CONFIG_PATH,
    REST_AUTHORIZATION_CONFIG_PATH
)
from ..components_constants import (
    VENV,
    CONFIG,
    SCRIPTS,
    CLEAN_DB,
    SECURITY,
    SSL_INPUTS,
    LOG_DIR_KEY,
    HOME_DIR_KEY,
    CLUSTER_JOIN,
    ADMIN_PASSWORD,
    FLASK_SECURITY,
    SERVER_PASSWORD,
    SERVICES_TO_INSTALL,
    HOSTNAME
)
from ..base_component import BaseComponent
from ..service_names import (
    MANAGER,
    RESTSERVICE,
    POSTGRESQL_CLIENT,
    DATABASE_SERVICE,
    MANAGER_SERVICE,
    MONITORING_SERVICE
)
from ... import constants
from ...config import config
from ...logger import get_logger
from ...utils import (
    certificates,
    common,
    files,
    service
)
from ...exceptions import BootstrapError
from ...utils.network import get_auth_headers, wait_for_port
from ...utils.install import is_premium_installed
from ...utils.scripts import (run_script_on_manager_venv,
                              log_script_run_results)
from ...utils.files import (
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
CLUSTER_DETAILS_PATH = '/tmp/cluster_details.json'
RABBITMQ_CA_CERT_PATH = '/etc/cloudify/ssl/rabbitmq-ca.pem'


class RestService(BaseComponent):
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
            'hash_salt': base64.b64encode(os.urandom(32)).decode('ascii'),
            'secret_key': base64.b64encode(os.urandom(32)).decode('ascii'),
            'encoding_alphabet': self._random_alphanumeric(),
            'encoding_block_size': 24,
            'encoding_min_length': 5,
            'encryption_key':
                base64.urlsafe_b64encode(os.urandom(64)).decode('ascii')
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

    def _configure_restservice_wrapper_script(self):
        if self.service_type == 'supervisord':
            deploy(
                join(
                    SCRIPTS_PATH,
                    'restservice-wrapper-script.sh'
                ),
                '/etc/cloudify',
                render=False
            )
            common.chmod('755', '/etc/cloudify/restservice-wrapper-script.sh')

    def _configure_restservice(self):
        self._generate_flask_security_config()
        self._calculate_worker_count()
        self._deploy_restservice_files()
        self._deploy_security_configuration()
        self._configure_restservice_wrapper_script()

    def _verify_restservice_alive(self):
        logger.info('Verifying Rest service is up...')
        service.verify_alive(RESTSERVICE)
        wait_for_port(config[RESTSERVICE]['port'])

    def _configure_db(self):
        configs = {
            'rest_config': REST_CONFIG_PATH,
            'authorization_config': REST_AUTHORIZATION_CONFIG_PATH,
            'security_config': REST_SECURITY_CONFIG_PATH
        }
        config[CLUSTER_JOIN] = False

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
                cluster_cfg_fn, rabbitmq_ca_fn = self._join_cluster(configs)
                if MONITORING_SERVICE in config.get(SERVICES_TO_INSTALL):
                    self._prepare_cluster_config_update(cluster_cfg_fn,
                                                        rabbitmq_ca_fn)

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
        return db.insert_manager(configs)

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
        return (config[SERVICES_TO_INSTALL] == [MANAGER_SERVICE] or
                config[SERVICES_TO_INSTALL] == [MANAGER_SERVICE,
                                                MONITORING_SERVICE])

    def _generate_passwords(self):
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
        self.handle_haproxy_certificate(installing=True)

        deploy(os.path.join(CONFIG_PATH, 'haproxy.cfg'),
               '/etc/haproxy/haproxy.cfg')

        # Configure the haproxy service for supervisord
        if self.service_type == 'supervisord':
            service.configure(
                'haproxy',
                user='haproxy',
                group='haproxy',
                src_dir='restservice',
                append_prefix=False
            )
        else:
            service.enable('haproxy', append_prefix=False)
        service.restart('haproxy', append_prefix=False)
        self._wait_for_haproxy_startup()

    def handle_haproxy_certificate(self, installing):
        base_cert_config = {
            'logger': self.logger,
            'ca_destination': '/etc/haproxy/ca.crt',
            'owner': 'haproxy',
            'group': 'haproxy'
        }

        install_cert_config = {'component_name': 'postgresql_client'}

        replace_cert_config = {
            'ca_src': constants.NEW_POSTGRESQL_CA_CERT_FILE_PATH
        }

        certificates.handle_cert_config(installing,
                                        base_cert_config,
                                        install_cert_config,
                                        replace_cert_config)

    @staticmethod
    def handle_ldap_certificate(installing):
        base_cert_config = {
            'logger': logger,
            'ca_destination': LDAP_CA_CERT_PATH
        }

        install_cert_config = {
                'component_name': RESTSERVICE,
                'sub_component': 'ldap',
                'just_ca_cert': True
            }

        replace_cert_config = {
            'ca_src': constants.NEW_LDAP_CA_CERT_PATH
        }

        certificates.handle_cert_config(installing,
                                        base_cert_config,
                                        install_cert_config,
                                        replace_cert_config)

    def replace_certificates(self):
        if common.manager_using_db_cluster():
            self._replace_haproxy_cert()
        self._replace_ldap_cert()

    def _replace_ca_certs_on_db(self):
        if os.path.exists(constants.NEW_INTERNAL_CA_CERT_FILE_PATH):
            self._replace_manager_ca_on_db()
        if os.path.exists(constants.NEW_BROKER_CA_CERT_FILE_PATH):
            self._replace_rabbitmq_ca_on_db()

    def _replace_manager_ca_on_db(self):
        cert_name = '{0}-ca'.format(config[MANAGER][HOSTNAME])
        self._log_replacing_certs_on_db(cert_name)
        script_input = {
            'cert_path': constants.NEW_INTERNAL_CA_CERT_FILE_PATH,
            'name': cert_name
        }
        db.run_script('replace_certs_on_db', script_input)

    def _replace_rabbitmq_ca_on_db(self):
        self._log_replacing_certs_on_db('rabbitmq-ca')
        script_input = {
            'cert_path': constants.NEW_BROKER_CA_CERT_FILE_PATH,
            'name': 'rabbitmq-ca'
        }
        db.run_script('replace_certs_on_db', script_input)

    def _log_replacing_certs_on_db(self, cert_type):
        self.logger.info(
            'Replacing {0} in Certificate table'.format(cert_type))

    def _replace_ldap_cert(self):
        if os.path.exists(constants.NEW_LDAP_CA_CERT_PATH):
            validate_certificates(ca_filename=constants.NEW_LDAP_CA_CERT_PATH)
            logger.info('Replacing ldap CA cert on the restservice component')
            self.handle_ldap_certificate(installing=False)

    def _replace_haproxy_cert(self):
        if os.path.exists(constants.NEW_POSTGRESQL_CA_CERT_FILE_PATH):
            # The certificate was validated in the PostgresqlClient component
            self.logger.info(
                'Replacing haproxy cert on the restservice component')
            self.handle_haproxy_certificate(installing=False)
            service.reload('haproxy', append_prefix=False)
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
                               ' to IOError: {1}'.format(license_path, e))

    def install(self):
        logger.notice('Installing Rest Service...')
        self._chown_resources_dir()
        set_logrotate(RESTSERVICE)
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

    def _run_syncthing_configuration_script(self, bootstrap_cluster):
        args_dict = {
            'hostname': config[MANAGER][HOSTNAME],
            'bootstrap_cluster': bootstrap_cluster,
            'service_management': self.service_type
        }
        script_path = join(SCRIPTS_PATH, 'configure_syncthing_script.py')
        result = run_script_on_manager_venv(script_path,
                                            args_dict,
                                            envvars=self._create_process_env())
        log_script_run_results(result)

    def _prepare_cluster_config_update(self, cluster_cfg_filename,
                                       rabbitmq_ca_cert_filename):
        logger.notice('Updating cluster configuration for monitoring service')
        with open(cluster_cfg_filename, 'r') as fp:
            cfg = json.load(fp)
        if (rabbitmq_ca_cert_filename and
                not os.path.isfile(RABBITMQ_CA_CERT_PATH)):
            files.move(rabbitmq_ca_cert_filename, RABBITMQ_CA_CERT_PATH)
            files.chown(constants.CLOUDIFY_USER, constants.CLOUDIFY_GROUP,
                        RABBITMQ_CA_CERT_PATH)
            cfg['rabbitmq']['ca_path'] = RABBITMQ_CA_CERT_PATH
        with open(CLUSTER_DETAILS_PATH, 'w') as fp:
            json.dump(cfg, fp)
        files.chown(constants.CLOUDIFY_USER, constants.CLOUDIFY_GROUP,
                    CLUSTER_DETAILS_PATH)
        files.remove(cluster_cfg_filename, ignore_failure=True)

    def configure(self):
        logger.notice('Configuring Rest Service...')

        logger.info('Checking for ldaps CA cert to deploy.')
        self.handle_ldap_certificate(installing=True)
        if common.manager_using_db_cluster():
            self._configure_db_proxy()

        self._make_paths()
        self._configure_restservice()
        service.configure(RESTSERVICE)
        logger.notice('Rest Service successfully configured')

    def _join_cluster_setup(self):
        if not common.is_manager_service_only_installed():
            return

        # this flag is set inside of restservice._configure_db
        to_join = config[CLUSTER_JOIN]
        if to_join:
            logger.notice(
                'Adding manager "{0}" to the cluster, this may take a '
                'while until config files finish replicating'.format(
                    config[MANAGER][HOSTNAME]))
        self._run_syncthing_configuration_script(not to_join)

    def remove(self):
        service.remove(RESTSERVICE, service_file=False)
        remove_logrotate(RESTSERVICE)

        common.remove('/opt/manager')

        if common.manager_using_db_cluster():
            self._set_haproxy_connect_any(False)
            common.remove('/etc/haproxy')

        if DATABASE_SERVICE not in config[SERVICES_TO_INSTALL]:
            remove_files(['/etc/haproxy'])

    def start(self):
        logger.notice('Starting Restservice...')
        self._make_paths()
        self._configure_db()
        if is_premium_installed():
            self._join_cluster_setup()
        if config[POSTGRESQL_CLIENT][SERVER_PASSWORD]:
            logger.info('Removing postgres password from config.yaml')
            config[POSTGRESQL_CLIENT][SERVER_PASSWORD] = '<removed>'
        service.restart(RESTSERVICE)
        if config[CLUSTER_JOIN]:
            logger.info('Extra node in cluster, will verify rest-service '
                        'after clustering configured')
        else:
            self._verify_restservice_alive()
            self._upload_cloudify_license()
        logger.notice('Restservice successfully started')

    def stop(self):
        logger.notice('Stopping Restservice...')
        service.stop(RESTSERVICE)
        logger.notice('Restservice successfully stopped')
