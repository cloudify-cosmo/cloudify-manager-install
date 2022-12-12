import os
import json
import base64
import random
import string
import subprocess
from os.path import join, exists
from collections import namedtuple

import requests

from . import db
from ...constants import (
    REST_HOME_DIR,
    REST_CONFIG_PATH,
    REST_SECURITY_CONFIG_PATH,
    REST_AUTHORIZATION_CONFIG_PATH
)
from ...components_constants import (
    ADMIN_PASSWORD,
    CLUSTER_JOIN,
    CONFIG,
    FLASK_SECURITY,
    HOSTNAME,
    PROVIDER_CONTEXT,
    SCRIPTS,
    SECURITY,
    SERVICES_TO_INSTALL,
    SSL_INPUTS,
)
from ..base_component import BaseComponent
from ...service_names import (
    MANAGER,
    RESTSERVICE,
    POSTGRESQL_CLIENT,
    MANAGER_SERVICE,
    MONITORING_SERVICE,
    RABBITMQ,
)
from ... import constants
from ...config import config
from ...logger import get_logger
from ...utils import (
    certificates,
    common,
    service,
)
from cfy_manager.utils.db import get_postgres_host
from ...exceptions import BootstrapError
from ...utils.network import get_auth_headers, wait_for_port
from ...utils.install import is_premium_installed
from ...utils.scripts import (run_script_on_manager_venv,
                              run_snapshot_script,
                              log_script_run_results)
from ...utils.files import (
    chown,
    deploy,
    read,
    remove,
    write,
    write_to_tempfile,
)
from ...utils.logrotate import set_logrotate, remove_logrotate

CONFIG_PATH = join(constants.COMPONENTS_DIR, RESTSERVICE, CONFIG)
SCRIPTS_PATH = join(constants.COMPONENTS_DIR, RESTSERVICE, SCRIPTS)
RESTSERVICE_RESOURCES = join(constants.BASE_RESOURCES_PATH, RESTSERVICE)
logger = get_logger(RESTSERVICE)
CLOUDIFY_LICENSE_PUBLIC_KEY_PATH = join(REST_HOME_DIR, 'license_key.pem.pub')
REST_URL = 'http://127.0.0.1:{port}/api/v3.1/{endpoint}'
CLUSTER_DETAILS_PATH = '/tmp/cluster_details.json'
RABBITMQ_CA_CERT_PATH = '/etc/cloudify/ssl/rabbitmq-ca.pem'


class RestService(BaseComponent):
    services = {'cloudify-restservice': {'is_group': False},
                'cloudify-api': {'is_group': True}}

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
        rest_conf = {
            'postgresql_bin_path': '/usr/pgsql-14/bin/',
            'postgresql_db_name': client_conf['cloudify_db_name'],
            'postgresql_host': get_postgres_host(),
            'postgresql_username': client_conf['cloudify_username'],
            'postgresql_password': client_conf['cloudify_password'],
            'postgresql_ssl_enabled': client_conf['ssl_enabled'],
            'postgresql_ssl_client_verification':
                client_conf['ssl_client_verification'],
            'postgresql_ssl_cert_path':
                constants.POSTGRESQL_CLIENT_CERT_PATH,
            'postgresql_ssl_key_path':
                constants.POSTGRESQL_CLIENT_KEY_PATH,
            'postgresql_ca_cert_path':
                constants.POSTGRESQL_CA_CERT_PATH,
            'ca_cert_path':
                constants.CA_CERT_PATH,
            'manager_hostname': config[MANAGER][HOSTNAME],
        }
        write(rest_conf, REST_CONFIG_PATH, json_dump=True,
              owner=constants.CLOUDIFY_USER,
              group=constants.CLOUDIFY_GROUP)

    def _generate_flask_security_config(self):
        logger.info('Generating random hash salt and secret key...')
        security_config = config.get(FLASK_SECURITY, {})
        new_flask_security = {
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
        new_flask_security.update(security_config)
        return new_flask_security

    def _pre_create_resources_paths(self):
        for resource_dir in (
                'blueprints',
                'deployments',
                'uploaded-blueprints',
                'snapshots',
                'plugins',
                'log_bundles',
        ):
            path = join(constants.MANAGER_RESOURCES_HOME, resource_dir)
            common.mkdir(path)

    def _get_flask_security(self, flask_security_config):
        # If we're recreating the DB, or if there's no previous security
        # config file, just use the config that was generated
        if not exists(REST_SECURITY_CONFIG_PATH):
            return flask_security_config

        security_config = flask_security_config

        current_config = json.loads(read(REST_SECURITY_CONFIG_PATH))

        # We want the existing config values to take precedence, but for any
        # new values to also be in the final config dict
        security_config.update(current_config)

        return security_config

    def _deploy_security_configuration(self, flask_security_config):
        logger.info('Deploying REST Security configuration file...')

        flask_security = self._get_flask_security(flask_security_config)
        write(flask_security, REST_SECURITY_CONFIG_PATH, json_dump=True,
              owner=constants.CLOUDIFY_USER, group=constants.CLOUDIFY_GROUP,
              mode=0o660)

    def _calculate_worker_count(self, component_name):
        server_config = config[component_name]['gunicorn']
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
        self._pre_create_resources_paths()
        common.chown(
            constants.CLOUDIFY_USER,
            constants.CLOUDIFY_GROUP,
            constants.MANAGER_RESOURCES_HOME
        )

    def _configure_restservice_wrapper_script(self):
        deploy(
            join(
                SCRIPTS_PATH,
                'restservice-wrapper-script.sh'
            ),
            '/etc/cloudify',
            render=False
        )
        common.chmod('755', '/etc/cloudify/restservice-wrapper-script.sh')

    def _configure_api_wrapper_script(self):
        deploy(
            join(
                SCRIPTS_PATH,
                'api-wrapper-script.sh'
            ),
            '/etc/cloudify',
            render=False
        )
        common.chmod('755', '/etc/cloudify/api-wrapper-script.sh')

    def _configure_restservice(self):
        flask_security_config = self._generate_flask_security_config()
        self._calculate_worker_count('restservice')
        self._deploy_restservice_files()
        self._deploy_security_configuration(flask_security_config)
        self._configure_restservice_wrapper_script()

    def _configure_api(self):
        self._calculate_worker_count('api')
        self._configure_api_wrapper_script()

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

        if not db.check_db_exists():
            db.prepare_db()
            self._initialize_db(configs)
            return

        # the db did exist beforehand, so we're either joining a cluster,
        # or re-configuring a single manager
        db.validate_schema_version(configs)
        managers = db.get_managers()
        if config[MANAGER][HOSTNAME] in managers:
            # we're already in this db! we're just reconfiguring.
            db.update_stored_manager(configs)
        else:
            db.insert_manager(configs)
            if len(managers) > 0:
                config[CLUSTER_JOIN] = True
                self._join_cluster(configs)

    def _initialize_db(self, configs):
        logger.info('DB not initialized, creating DB...')

        self._generate_admin_password_if_empty()
        # values passed through to manager_rest.configure_manager:
        configure_manager_settings = {
            PROVIDER_CONTEXT: db.get_provider_context(),
            MANAGER: db.get_manager(),
            # pass through rabbitmq config separately too, because we might
            # have defaulted all kinds of things about rabbitmq
            # (eg. the default localhost broker)
            RABBITMQ: config[RABBITMQ],
        }

        additional_config = [
            write_to_tempfile(configure_manager_settings, json_dump=True)
        ]

        db.populate_db(configs, additional_config_files=additional_config)
        if additional_config:
            for filepath in additional_config:
                remove(filepath)

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
                'issues. Please run cfy_manager remove, then fix the '
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
                     constants.SSL_CERTS_TARGET_DIR)

    def replace_certificates(self):
        self.stop()
        self._replace_ca_certs_on_db()
        self.start()

    def validate_new_certs(self):
        # All other certs are validated in other components
        if os.path.exists(constants.NEW_LDAP_CA_CERT_PATH):
            certificates.validate_certificates(
                ca_filename=constants.NEW_LDAP_CA_CERT_PATH)

    def _replace_ca_certs_on_db(self):
        if os.path.exists(constants.NEW_INTERNAL_CA_CERT_FILE_PATH):
            self._replace_manager_ca_on_db()
            if os.path.exists(constants.NEW_INTERNAL_CA_KEY_FILE_PATH):
                self._replace_manager_ca_key_on_db()
            if common.is_all_in_one_manager():
                self._replace_rabbitmq_ca_on_db()
                if os.path.exists(constants.NEW_INTERNAL_CA_KEY_FILE_PATH):
                    self._replace_rabbitmq_ca_key_on_db()
                return
        if os.path.exists(constants.NEW_BROKER_CA_CERT_FILE_PATH):
            self._replace_rabbitmq_ca_on_db()
            if os.path.exists(constants.NEW_BROKER_CA_KEY_FILE_PATH):
                self._replace_rabbitmq_ca_key_on_db()

    def _replace_manager_ca_on_db(self):
        cert_name = '{0}-ca'.format(config[MANAGER][HOSTNAME])
        self._log_replacing_certs_on_db(cert_name)
        script_input = {
            'cert_path': constants.NEW_INTERNAL_CA_CERT_FILE_PATH,
            'name': cert_name
        }
        self._run_replace_certs_on_db_script(script_input)

    def _replace_manager_ca_key_on_db(self):
        key_path = '{0}-ca-key'.format(config[MANAGER][HOSTNAME])
        self._log_replacing_certs_on_db(key_path)
        script_input = {
            'cert_path': constants.NEW_INTERNAL_CA_KEY_FILE_PATH,
            'name': key_path
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

    def _replace_rabbitmq_ca_key_on_db(self):
        self._log_replacing_certs_on_db('rabbitmq-ca-key')
        key_path = (constants.NEW_INTERNAL_CA_KEY_FILE_PATH
                    if common.is_all_in_one_manager()
                    else constants.NEW_BROKER_CA_KEY_FILE_PATH)
        script_input = {
            'cert_path': key_path,
            'name': 'rabbitmq-ca-key'
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

    @staticmethod
    def _upload_cloudify_license():
        """
        Upload a Cloudify license to the Manager (only when a path to a
        license is provided in config.yaml).
        """
        license_path = config[MANAGER]['cloudify_license_path']
        if license_path:
            try:
                logger.info('Uploading Cloudify license `%s` to the'
                            ' Manager...', license_path)
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
                logger.warning('Failed to upload Cloudify license `%s` due'
                               ' to IOError: %s', license_path, e)

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
            common.move(rabbitmq_ca_cert_filename, RABBITMQ_CA_CERT_PATH)
            cfg['rabbitmq']['ca_path'] = RABBITMQ_CA_CERT_PATH
        with open(CLUSTER_DETAILS_PATH, 'w') as fp:
            json.dump(cfg, fp)
        chown(constants.CLOUDIFY_USER, constants.CLOUDIFY_GROUP,
              CLUSTER_DETAILS_PATH)
        remove(cluster_cfg_filename, ignore_failure=True)

    def _join_cluster_setup(self):
        if not common.is_only_manager_service_in_config():
            return

        if not common.filesystem_replication_enabled():
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

        self.configure_service('cloudify-restservice')
        self.configure_service('cloudify-api')
        certificates.handle_ca_cert(logger)
        self._configure_db()
        self._ensure_ldap_cert_path_writable()
        if is_premium_installed():
            self._join_cluster_setup()
        self.start()
        if not config[CLUSTER_JOIN]:
            self._upload_cloudify_license()
        logger.notice('Rest Service successfully configured')

    def configure_service(self, service_name, service_config=None):
        if service_name == 'cloudify-restservice':
            self._configure_restservice()
            service.configure('cloudify-restservice')
        if service_name == 'cloudify-api':
            self._configure_api()
            service.configure('cloudify-api', src_dir=RESTSERVICE)

    def remove(self):
        service.remove('cloudify-restservice')
        service.remove('cloudify-api')
        remove_logrotate(RESTSERVICE)
        remove('/opt/manager')

    def _validate_config_defaults(self):
        """Validate that config defaults exist."""
        if not config.get('api', {}):
            logger.info('Setting default values for `api` configuration')
            config['api'] = {
                'gunicorn': {
                    'worker_count': 0,
                    'cpu_ratio': 0.2,
                    'max_worker_count': 4,
                    'max_requests': 1000,
                },
                'port': 8101,
            }
        if not config['restservice']['gunicorn'].get('cpu_ratio'):
            config['restservice']['gunicorn']['cpu_ratio'] = 2.0

    def upgrade(self):
        logger.notice('Upgrading Rest Service...')
        self._validate_config_defaults()
        super().upgrade()
        self._deploy_restservice_files()
        run_script_on_manager_venv('/opt/manager/scripts/load_permissions.py')
        run_script_on_manager_venv(
            '/opt/manager/scripts/create_system_filters.py')
        run_snapshot_script('populate_deployment_statuses')
        run_snapshot_script('migrate_pickle_to_json')
        logger.notice('Rest Service successfully upgraded')
