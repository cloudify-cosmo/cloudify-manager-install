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

from .amqpinflux import amqpinflux
from .logstash import logstash
from .mgmtworker import mgmtworker
from .influxdb import influxdb
from .nginx import nginx
from .postgresql import postgresql
from .rabbitmq import rabbitmq
from .restservice import restservice
from .riemann import riemann
from .stage import stage
from .composer import composer
from .cli import cli
from .manager import manager
from .manager_ip_setter import manager_ip_setter
from .python import python
from .sanity import sanity
from .java import java

from . import service_names

SERVICES_BY_NAME = {
    service_names.AMQPINFLUX: amqpinflux,
    service_names.INFLUXDB: influxdb,
    service_names.LOGSTASH: logstash,
    service_names.MGMTWORKER: mgmtworker,
    service_names.NGINX: nginx,
    service_names.POSTGRESQL: postgresql,
    service_names.RABBITMQ: rabbitmq,
    service_names.RESTSERVICE: restservice,
    service_names.RIEMANN: riemann,
    service_names.STAGE: stage,
    service_names.COMPOSER: composer,
    service_names.CLI: cli,
    service_names.MANAGER: manager,

    service_names.MANAGER_IP_SETTER: manager_ip_setter,
    service_names.PYTHON: python,
    service_names.SANITY: sanity,
    service_names.JAVA: java
}


COMPONENTS_BY_NAME = dict(
    SERVICES_BY_NAME,
    **{
        service_names.MANAGER_IP_SETTER: manager_ip_setter,
        service_names.PYTHON: python,
        service_names.SANITY: sanity,
        service_names.JAVA: java
    }
)

COMPONENTS_ORDER = (
    service_names.MANAGER,
    service_names.MANAGER_IP_SETTER,
    service_names.NGINX,
    service_names.PYTHON,
    service_names.POSTGRESQL,
    service_names.RABBITMQ,
    service_names.RESTSERVICE,
    service_names.INFLUXDB,
    service_names.AMQPINFLUX,
    service_names.JAVA,
    service_names.STAGE,
    service_names.COMPOSER,
    service_names.LOGSTASH,
    service_names.MGMTWORKER,
    service_names.RIEMANN,
    service_names.CLI,
    service_names.SANITY
)

SERVICES = [SERVICES_BY_NAME[s]
            for s in COMPONENTS_ORDER if s in SERVICES_BY_NAME]
COMPONENTS = [COMPONENTS_BY_NAME[c]
              for c in COMPONENTS_ORDER if c in COMPONENTS_BY_NAME]
