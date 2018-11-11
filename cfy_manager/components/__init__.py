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

from .amqp_postgres import AmqpPostgresComponent  # NOQA
from .amqpinflux import AmqpInfluxComponent  # NOQA
from .cli import CliComponent  # NOQA
from .composer import ComposerComponent  # NOQA
from .influxdb import InfluxDBComponent  # NOQA
from .java import JavaComponent  # NOQA
from .manager import ManagerComponent  # NOQA
from .manager_ip_setter import ManagerIpSetterComponent  # NOQA
from .mgmtworker import MgmtWorkerComponent  # NOQA
from .nginx import NginxComponent  # NOQA
from .postgresql_server import PostgresqlServerComponent  # NOQA
from .postgresql_client import PostgresqlClientComponent # NOQA
from .python import PythonComponent  # NOQA
from .rabbitmq import RabbitMQComponent  # NOQA
from .restservice import RestServiceComponent  # NOQA
from .riemann import RiemannComponent  # NOQA
from .sanity import SanityComponent  # NOQA
from .stage import StageComponent  # NOQA
from .usage_collector import UsageCollectorComponent  # NOQA
from .cluster.cluster import ClusterComponent  # NOQA

from components_factory import ComponentsFactory  # NOQA
from service_components import SERVICE_COMPONENTS  # NOQA
from service_components import MANAGER_SERVICE  # NOQA
from service_components import QUEUE_SERVICE  # NOQA
from service_components import COMPOSER_SERVICE  # NOQA
from service_components import SERVICE_INSTALLATION_ORDER  # NOQA
