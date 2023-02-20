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

BASE_DIR = dirname(__file__)
COMPONENTS_DIR = join(BASE_DIR, 'components')
NETWORKS_DIR = join(BASE_DIR, 'networks')
UTILS_DIR = join(BASE_DIR, 'utils')
BASE_LOG_DIR = '/var/log/cloudify'


REST_HOME_DIR = '/opt/manager'
REST_CONFIG_PATH = join(REST_HOME_DIR, 'cloudify-rest.conf')
REST_SECURITY_CONFIG_PATH = join(REST_HOME_DIR, 'rest-security.conf')
REST_AUTHORIZATION_CONFIG_PATH = join(REST_HOME_DIR, 'authorization.conf')
REST_LOG_DIR = join(BASE_LOG_DIR, 'rest')

MGMWORKER_HOME_DIR = '/opt/mgmtworker'
MGMWORKER_HOOKS_CONFIG = join(MGMWORKER_HOME_DIR, 'config', 'hooks.conf')
MGMWORKER_LOG_DIR = join(BASE_LOG_DIR, 'mgmtworker')

AMQP_POSTGRES_LOG_DIR = join(BASE_LOG_DIR, 'amqp-postgres')

EXECUTION_SCHEDULER_LOG_DIR = join(BASE_LOG_DIR, 'execution-scheduler')

CLOUDIFY_USER = 'cfyuser'
CLOUDIFY_GROUP = 'cfyuser'
CLOUDIFY_HOME_DIR = '/etc/cloudify'
SUDOERS_INCLUDE_DIR = '/etc/sudoers.d'
CLOUDIFY_SUDOERS_FILE = join(SUDOERS_INCLUDE_DIR, CLOUDIFY_USER)
INITIAL_INSTALL_DIR = join(CLOUDIFY_HOME_DIR, '.installed')
INSTALLED_COMPONENTS = join(INITIAL_INSTALL_DIR, 'components.yaml')
INSTALLED_PACKAGES = join(INITIAL_INSTALL_DIR, 'packages.yaml')
INITIAL_CONFIGURE_DIR = join(CLOUDIFY_HOME_DIR, '.configured')
SUPERVISORD_CONFIG_DIR = '/etc/supervisord.d'

BASE_RESOURCES_PATH = '/opt/cloudify'
CLOUDIFY_SOURCES_PATH = join(BASE_RESOURCES_PATH, 'sources')
MANAGER_RESOURCES_HOME = join(REST_HOME_DIR, 'resources')
AGENT_ARCHIVES_PATH = '{0}/packages/agents'.format(MANAGER_RESOURCES_HOME)

DEFAULT_CONFIG_FILE_NAME = 'config.yaml'
USER_CONFIG_PATH = join(CLOUDIFY_HOME_DIR, DEFAULT_CONFIG_FILE_NAME)
# For defaults, use the version supplied in the package
DEFAULT_CONFIG_PATH = join(dirname(BASE_DIR), DEFAULT_CONFIG_FILE_NAME)

MONITORING_PORT = 8009

SSL_CERTS_TARGET_DIR = join(CLOUDIFY_HOME_DIR, 'ssl')

INTERNAL_CERT_FILENAME = 'cloudify_internal_cert.pem'
INTERNAL_KEY_FILENAME = 'cloudify_internal_key.pem'
CA_CERT_FILENAME = 'cloudify_internal_ca_cert.pem'
CA_KEY_FILENAME = 'cloudify_internal_ca_key.pem'
EXTERNAL_CA_CERT_FILENAME = 'cloudify_external_ca_cert.pem'
EXTERNAL_CA_KEY_FILENAME = 'cloudify_external_ca_key.pem'
EXTERNAL_CERT_FILENAME = 'cloudify_external_cert.pem'
EXTERNAL_KEY_FILENAME = 'cloudify_external_key.pem'
POSTGRESQL_CLIENT_CERT_FILENAME = 'postgresql.crt'
POSTGRESQL_CLIENT_KEY_FILENAME = 'postgresql.key'
POSTGRESQL_CLIENT_SU_CERT_FILENAME = 'postgresql_su.crt'
POSTGRESQL_CLIENT_SU_KEY_FILENAME = 'postgresql_su.key'
POSTGRESQL_CA_CERT_FILENAME = 'postgresql_ca.crt'
POSTGRESQL_CA_KEY_FILENAME = 'postgresql_ca.key'
MONITORING_CA_CERT_FILENAME = 'monitoring_ca_cert.pem'
MONITORING_CA_KEY_FILENAME = 'monitoring_ca_key.pem'
MONITORING_CERT_FILENAME = 'monitoring_cert.pem'
MONITORING_KEY_FILENAME = 'monitoring_key.pem'
BROKER_CERT_LOCATION = '/etc/cloudify/ssl/rabbitmq-cert.pem'
BROKER_KEY_LOCATION = '/etc/cloudify/ssl/rabbitmq-key.pem'
BROKER_CA_LOCATION = '/etc/cloudify/ssl/rabbitmq-ca.pem'
BROKER_CA_KEY_LOCATION = '/etc/cloudify/ssl/rabbitmq-ca-key.pem'

INTERNAL_CERT_PATH = join(SSL_CERTS_TARGET_DIR, INTERNAL_CERT_FILENAME)
INTERNAL_KEY_PATH = join(SSL_CERTS_TARGET_DIR, INTERNAL_KEY_FILENAME)
CA_CERT_PATH = join(SSL_CERTS_TARGET_DIR, CA_CERT_FILENAME)
CA_KEY_PATH = join(SSL_CERTS_TARGET_DIR, CA_KEY_FILENAME)
EXTERNAL_CA_CERT_PATH = join(SSL_CERTS_TARGET_DIR, EXTERNAL_CA_CERT_FILENAME)
EXTERNAL_CA_KEY_PATH = join(SSL_CERTS_TARGET_DIR, EXTERNAL_CA_KEY_FILENAME)
EXTERNAL_CERT_PATH = join(SSL_CERTS_TARGET_DIR, EXTERNAL_CERT_FILENAME)
EXTERNAL_KEY_PATH = join(SSL_CERTS_TARGET_DIR, EXTERNAL_KEY_FILENAME)
POSTGRESQL_CLIENT_CERT_PATH = \
    join(SSL_CERTS_TARGET_DIR, POSTGRESQL_CLIENT_CERT_FILENAME)
POSTGRESQL_CLIENT_KEY_PATH = \
    join(SSL_CERTS_TARGET_DIR, POSTGRESQL_CLIENT_KEY_FILENAME)
POSTGRESQL_CLIENT_SU_CERT_PATH = \
    join(SSL_CERTS_TARGET_DIR, POSTGRESQL_CLIENT_SU_CERT_FILENAME)
POSTGRESQL_CLIENT_SU_KEY_PATH = \
    join(SSL_CERTS_TARGET_DIR, POSTGRESQL_CLIENT_SU_KEY_FILENAME)
POSTGRESQL_CA_CERT_PATH = \
    join(SSL_CERTS_TARGET_DIR, POSTGRESQL_CA_CERT_FILENAME)
POSTGRESQL_CA_KEY_PATH = \
    join(SSL_CERTS_TARGET_DIR, POSTGRESQL_CA_KEY_FILENAME)
MONITORING_CA_CERT_PATH = \
    join(SSL_CERTS_TARGET_DIR, MONITORING_CA_CERT_FILENAME)
MONITORING_CA_KEY_PATH = \
    join(SSL_CERTS_TARGET_DIR, MONITORING_CA_KEY_FILENAME)
MONITORING_CERT_PATH = \
    join(SSL_CERTS_TARGET_DIR, MONITORING_CERT_FILENAME)
MONITORING_KEY_PATH = \
    join(SSL_CERTS_TARGET_DIR, MONITORING_KEY_FILENAME)
CERT_METADATA_FILE_PATH = join(SSL_CERTS_TARGET_DIR, 'certificate_metadata')
EXTERNAL_CERT_METADATA_FILE_PATH = join(
    SSL_CERTS_TARGET_DIR, 'external_certificate_metadata')

CFY_EXEC_TEMPDIR_ENVVAR = 'CFY_EXEC_TEMP'

SCRIPTS = 'scripts'

SELECT_USER_TOKENS_QUERY = """
SELECT
    json_build_object(
        'id', id,
        'username', username,
        'api_token_key', api_token_key
    )
FROM users
WHERE username
"""

VERBOSE_HELP_MSG = (
    "Used to give more verbose output."
)

NEW_CERTS_TMP_DIR_PATH = '/tmp/new_cloudify_certs/'

NEW_LDAP_CA_CERT_PATH = (NEW_CERTS_TMP_DIR_PATH + 'new_ldap_ca_cert.pem')

NEW_BROKER_CERT_FILE_PATH = NEW_CERTS_TMP_DIR_PATH + 'new_rabbitmq_cert.pem'
NEW_BROKER_KEY_FILE_PATH = NEW_CERTS_TMP_DIR_PATH + 'new_rabbitmq_key.pem'
NEW_BROKER_CA_CERT_FILE_PATH = (NEW_CERTS_TMP_DIR_PATH +
                                'new_rabbitmq_ca_cert.pem')
NEW_BROKER_CA_KEY_FILE_PATH = (NEW_CERTS_TMP_DIR_PATH +
                               'new_rabbitmq_ca_key.pem')

NEW_POSTGRESQL_CERT_FILE_PATH = (NEW_CERTS_TMP_DIR_PATH +
                                 'new_postgresql_server_cert.pem')
NEW_POSTGRESQL_KEY_FILE_PATH = (NEW_CERTS_TMP_DIR_PATH +
                                'new_postgresql_server_key.pem')
NEW_POSTGRESQL_CLIENT_CERT_FILE_PATH = (NEW_CERTS_TMP_DIR_PATH +
                                        'new_postgresql_client_cert.pem')
NEW_POSTGRESQL_CLIENT_KEY_FILE_PATH = (NEW_CERTS_TMP_DIR_PATH +
                                       'new_postgresql_client_key.pem')
NEW_POSTGRESQL_CA_CERT_FILE_PATH = (NEW_CERTS_TMP_DIR_PATH +
                                    'new_postgresql_server_ca_cert.pem')
NEW_POSTGRESQL_CA_KEY_FILE_PATH = (NEW_CERTS_TMP_DIR_PATH +
                                   'new_postgresql_server_ca_key.pem')

NEW_INTERNAL_CERT_FILE_PATH = NEW_CERTS_TMP_DIR_PATH + 'new_internal_cert.pem'
NEW_INTERNAL_KEY_FILE_PATH = NEW_CERTS_TMP_DIR_PATH + 'new_internal_key.pem'
NEW_INTERNAL_CA_CERT_FILE_PATH = (NEW_CERTS_TMP_DIR_PATH + 'new_ca_cert.pem')
NEW_INTERNAL_CA_KEY_FILE_PATH = (NEW_CERTS_TMP_DIR_PATH + 'new_ca_key.pem')

NEW_EXTERNAL_CERT_FILE_PATH = NEW_CERTS_TMP_DIR_PATH + 'new_external_cert.pem'
NEW_EXTERNAL_KEY_FILE_PATH = NEW_CERTS_TMP_DIR_PATH + 'new_external_key.pem'
NEW_EXTERNAL_CA_CERT_FILE_PATH = (NEW_CERTS_TMP_DIR_PATH +
                                  'new_external_ca_cert.pem')
NEW_EXTERNAL_CA_KEY_FILE_PATH = (NEW_CERTS_TMP_DIR_PATH +
                                 'new_external_ca_key.pem')

NEW_PROMETHEUS_CERT_FILE_PATH = (NEW_CERTS_TMP_DIR_PATH +
                                 'new_prometheus_cert.pem')
NEW_PROMETHEUS_KEY_FILE_PATH = (NEW_CERTS_TMP_DIR_PATH +
                                'new_prometheus_key.pem')
NEW_PROMETHEUS_CA_CERT_FILE_PATH = (NEW_CERTS_TMP_DIR_PATH +
                                    'new_prometheus_ca_cert.pem')
NEW_PROMETHEUS_CA_KEY_FILE_PATH = (NEW_CERTS_TMP_DIR_PATH +
                                   'new_prometheus_ca_key.pem')

CONFIG_FILE_HELP_MSG = (
    'Specify a configuration file to be used. File path is relative to the '
    '{0} (meaning only files in this location are considered valid). If '
    'more than one file is provided, these are merged in order from left '
    'to right.'.format(CLOUDIFY_HOME_DIR)
)

UPGRADE_IN_PROGRESS = 'upgrade_in_progress'
