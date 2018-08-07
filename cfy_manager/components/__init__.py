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

from ..components.amqpinflux import AmqpInfluxComponent
from ..components.cli import CliComponent
from ..components.composer import ComposerComponent
from ..components.influxdb import InfluxDBComponent
from ..components.java import JavaComponent
from ..components.amqp_postgres import AmqpPostgresComponent
from ..components.manager import ManagerComponent
from ..components.manager_ip_setter import ManagerIpSetterComponent
from ..components.mgmtworker import MgmtWorker
from ..components.nginx import NginxComponent
from ..components.postgresql import PostgresqlComponent
from ..components.python import PythonComponent
from ..components.rabbitmq import RabbitMQComponent
from ..components.restservice import RestServiceComponent
from ..components.riemann import RiemannComponent
from ..components.sanity import SanityComponent
from ..components.stage import StageComponent
from ..components.usage_collector import UsageCollectorComponent
from ..components.cluster import ClusterComponent

# region Common Strings
DATABASE_ONLY = 'database_only'

SOURCES = 'sources'

SERVICE_USER = 'service_user'
SERVICE_GROUP = 'service_group'

SCRIPTS = 'scripts'
CONFIG = 'config'

HOME_DIR_KEY = 'home_dir'
LOG_DIR_KEY = 'log_dir'

VENV = 'venv'

PRIVATE_IP = 'private_ip'
PUBLIC_IP = 'public_ip'
ENDPOINT_IP = 'endpoint_ip'
SECURITY = 'security'
ADMIN_PASSWORD = 'admin_password'
ADMIN_USERNAME = 'admin_username'

# endregion

# region Config Keys

AGENT = 'agent'
CONSTANTS = 'constants'
SSL_INPUTS = 'ssl_inputs'
VALIDATIONS = 'validations'
SKIP_VALIDATIONS = 'skip_validations'
PROVIDER_CONTEXT = 'provider_context'
CLEAN_DB = 'clean_db'
FLASK_SECURITY = 'flask_security'

# endregion
