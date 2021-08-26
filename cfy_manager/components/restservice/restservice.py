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
import base64
import random
import string
import subprocess
from os.path import join, exists, dirname
from collections import namedtuple

import requests

from . import db
from ..validations import validate_certificates
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
    SERVICES_TO_INSTALL,
    HOSTNAME
)
from ..base_component import BaseComponent
from ..service_names import (
    MANAGER,
    RESTSERVICE,
    POSTGRESQL_CLIENT,
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
from cfy_manager.utils.db import get_postgres_host
from ...exceptions import BootstrapError
from ...utils.network import get_auth_headers, wait_for_port
from ...utils.install import is_premium_installed
from ...utils.scripts import (run_script_on_manager_venv,
                              log_script_run_results)
from ...utils.files import (
    deploy,
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
    services = ['cloudify-restservice']

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
        self._deploy_rest_conf()

    def _deploy_rest_conf(self):
        client_conf = config[POSTGRESQL_CLIENT]
        const = config['constants']
        rest_conf = {
            'postgresql_bin_path': '/usr/pgsql-9.5/bin/',
            'postgresql_db_name': client_conf['cloudify_db_name'],
            'postgresql_host': get_postgres_host(),
            'postgresql_username': client_conf['cloudify_username'],
            'postgresql_password': client_conf['cloudify_password'],
            'postgresql_ssl_enabled': client_conf['ssl_enabled'],
            'postgresql_ssl_client_verification':
                client_conf['ssl_client_verification'],
            'postgresql_ssl_cert_path':
                const.get('postgresql_client_cert_path'),
            'postgresql_ssl_key_path':
                const.get('postgresql_client_key_path'),
            'postgresql_ca_cert_path': const.get('postgresql_ca_cert_path'),
            'ca_cert_path': const['ca_cert_path'],
            'manager_hostname': config[MANAGER][HOSTNAME],
        }
        files.write_to_file(rest_conf, REST_CONFIG_PATH, json_dump=True)
        common.chown(constants.CLOUDIFY_USER, constants.CLOUDIFY_GROUP,
                     REST_CONFIG_PATH)

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
        for server_name in ['gunicorn', 'uvicorn']:
            server_config = config[RESTSERVICE][server_name]
            worker_count = server_config['worker_count']
            cpu_ratio = server_config['cpu_ratio']
            max_worker_count = server_config['max_worker_count']

            if not worker_count:
                number_of_cpus = int(subprocess.check_output('nproc'))
                worker_count = int(number_of_cpus * cpu_ratio) + 1

            server_config['worker_count'] = min(worker_count, max_worker_count)

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

    def verify_started(self):
        if config.get(CLUSTER_JOIN):
            logger.info('Extra node in cluster, will verify rest-service '
                        'after clustering configured')
        logger.info('Verifying Rest service is up...')
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

        if db.check_db_exists():
            db.validate_schema_version(configs)
        else:
            self._initialize_db(configs)

        managers = db.get_managers()
        if config[MANAGER][HOSTNAME] in managers:
            db.update_stored_manager(configs)
        else:
            db.insert_manager(configs)
            if len(managers) > 0:
                self._join_cluster(configs)

    def _initialize_db(self, configs):
        logger.info('DB not initialized, creating DB...')
        self._generate_passwords()
        db.prepare_db()
        db.populate_db(configs)
        run_script_on_manager_venv(
            '/opt/manager/scripts/create_system_filters.py')

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
        certificates.handle_ca_cert(logger, generate_if_missing=False)

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

    @staticmethod
    def _ensure_ldap_cert_path_writable():
        """This can be set later by the restservice so it must be able to
        write the relevant directory.
        """
        common.chown(constants.CLOUDIFY_USER, constants.CLOUDIFY_GROUP,
                     dirname(LDAP_CA_CERT_PATH))

    @staticmethod
    def handle_ldap_certificate():
        certificates.use_supplied_certificates(
            logger=logger,
            ca_destination=LDAP_CA_CERT_PATH,
            component_name=RESTSERVICE,
            sub_component='ldap',
            just_ca_cert=True
        )

    def replace_certificates(self):
        self.stop()
        self._replace_ldap_cert()
        self._replace_ca_certs_on_db()
        self.start()

    def validate_new_certs(self):
        # All other certs are validated in other components
        if os.path.exists(constants.NEW_LDAP_CA_CERT_PATH):
            validate_certificates(ca_filename=constants.NEW_LDAP_CA_CERT_PATH)

    def _replace_ca_certs_on_db(self):
        if os.path.exists(constants.NEW_INTERNAL_CA_CERT_FILE_PATH):
            self._replace_manager_ca_on_db()
            if common.is_all_in_one_manager():
                self._replace_rabbitmq_ca_on_db()
                return
        if os.path.exists(constants.NEW_BROKER_CA_CERT_FILE_PATH):
            self._replace_rabbitmq_ca_on_db()

    def _replace_manager_ca_on_db(self):
        cert_name = '{0}-ca'.format(config[MANAGER][HOSTNAME])
        self._log_replacing_certs_on_db(cert_name)
        script_input = {
            'cert_path': constants.NEW_INTERNAL_CA_CERT_FILE_PATH,
            'name': cert_name
        }
        self._run_replace_certs_on_db_script(script_input)

    def _replace_rabbitmq_ca_on_db(self):
        self._log_replacing_certs_on_db('rabbitmq-ca')
        cert_path = (constants.NEW_INTERNAL_CA_CERT_FILE_PATH
                     if common.is_all_in_one_manager()
                     else constants.NEW_BROKER_CA_CERT_FILE_PATH)
        script_input = {
            'cert_path': cert_path,
            'name': 'rabbitmq-ca'
        }
        self._run_replace_certs_on_db_script(script_input)

    @staticmethod
    def _run_replace_certs_on_db_script(script_input):
        configs = {
            'rest_config': REST_CONFIG_PATH,
            'authorization_config': REST_AUTHORIZATION_CONFIG_PATH,
            'security_config': REST_SECURITY_CONFIG_PATH
        }
        output = db.run_script('replace_certs_on_db.py', script_input, configs)
        logger.info(output)

    @staticmethod
    def _log_replacing_certs_on_db(cert_type):
        logger.info('Replacing %s in Certificate table', cert_type)

    def _replace_ldap_cert(self):
        if os.path.exists(constants.NEW_LDAP_CA_CERT_PATH):
            validate_certificates(ca_filename=constants.NEW_LDAP_CA_CERT_PATH)
            logger.info('Replacing ldap CA cert on the restservice component')
            config['restservice']['ldap']['ca_cert'] = \
                constants.NEW_LDAP_CA_CERT_PATH
            self.handle_ldap_certificate()

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

    def _run_cluster_configuration_script(self, bootstrap_syncthing):
        args_dict = {
            'hostname': config[MANAGER][HOSTNAME],
            'bootstrap_syncthing': bootstrap_syncthing,
            'service_management': self.service_type
        }
        script_path = join(SCRIPTS_PATH, 'configure_cluster_script.py')
        result = run_script_on_manager_venv(script_path,
                                            args_dict,
                                            envvars=self._create_process_env())
        log_script_run_results(result)

    def _prepare_cluster_config_update(self, cluster_cfg_filename,
                                       rabbitmq_ca_cert_filename):
        logger.notice('Updating cluster configuration for monitoring service')
        common.chmod('644', cluster_cfg_filename)
        with open(cluster_cfg_filename, 'r') as fp:
            cfg = json.load(fp)
        if (rabbitmq_ca_cert_filename and
                not os.path.isfile(RABBITMQ_CA_CERT_PATH)):
            files.move(rabbitmq_ca_cert_filename, RABBITMQ_CA_CERT_PATH)
            cfg['rabbitmq']['ca_path'] = RABBITMQ_CA_CERT_PATH
        with open(CLUSTER_DETAILS_PATH, 'w') as fp:
            json.dump(cfg, fp)
        files.chown(constants.CLOUDIFY_USER, constants.CLOUDIFY_GROUP,
                    CLUSTER_DETAILS_PATH)
        files.remove(cluster_cfg_filename, ignore_failure=True)

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
        self._run_cluster_configuration_script(not to_join)

    def configure(self):
        logger.notice('Configuring Rest Service...')

        logger.info('Checking for ldaps CA cert to deploy.')
        self.handle_ldap_certificate()
        self._ensure_ldap_cert_path_writable()

        self._make_paths()
        self._configure_restservice()
        service.configure('cloudify-restservice')
        certificates.handle_ca_cert(logger)
        self._configure_db()
        if is_premium_installed():
            self._join_cluster_setup()
        self.start()
        if not config[CLUSTER_JOIN]:
            self._upload_cloudify_license()
        logger.notice('Rest Service successfully configured')

    def remove(self):
        service.remove('cloudify-restservice', service_file=False)
        remove_logrotate(RESTSERVICE)
        common.remove('/opt/manager')

    def upgrade(self):
        logger.notice('Upgrading Rest Service...')
        self._deploy_restservice_files()
        run_script_on_manager_venv('/opt/manager/scripts/load_permissions.py')
        run_script_on_manager_venv(
            '/opt/manager/scripts/create_system_filters.py')
        self._ensure_ldap_cert_path_writable()
        logger.notice('Rest Service successfully upgraded')
