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

# region Common Strings

SERVICES_TO_INSTALL = 'services_to_install'

SERVICE_USER = 'service_user'
SERVICE_GROUP = 'service_group'

SCRIPTS = 'scripts'
CONFIG = 'config'

HOSTNAME = 'hostname'
PRIVATE_IP = 'private_ip'
PUBLIC_IP = 'public_ip'
SECURITY = 'security'
ADMIN_PASSWORD = 'admin_password'
ADMIN_USERNAME = 'admin_username'

ENABLE_REMOTE_CONNECTIONS = 'enable_remote_connections'
POSTGRES_PASSWORD = 'postgres_password'
SERVER_PASSWORD = 'server_password'

SSL_ENABLED = 'ssl_enabled'
SSL_CLIENT_VERIFICATION = 'ssl_client_verification'
# endregion

# region Config Keys

AGENT = 'agent'
CONSTANTS = 'constants'
SSL_INPUTS = 'ssl_inputs'
VALIDATIONS = 'validations'
SKIP_VALIDATIONS = 'skip_validations'
PROVIDER_CONTEXT = 'provider_context'
FLASK_SECURITY = 'flask_security'
UNCONFIGURED_INSTALL = 'unconfigured_install'

# this key is set if the current install is joining a manager to a cluster.
# It is set in db.py, and used when running the syncthing config script.
CLUSTER_JOIN = 'join'

# endregion

ETCD_CA_PATH = '/etc/etcd/ca.crt'
ETCD_CA_KEY_PATH = '/etc/etcd/ca.key'
PATRONI_DB_CA_PATH = '/var/lib/patroni/ca.crt'
PATRONI_DB_CA_KEY_PATH = '/var/lib/patroni/ca.key'
LISTENERS = 'listeners'
