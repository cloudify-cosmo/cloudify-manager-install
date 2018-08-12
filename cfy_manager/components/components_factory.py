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


from . import (
    AmqpPostgresComponent,
    AmqpInfluxComponent,
    ManagerComponent,
    ManagerIpSetterComponent,
    NginxComponent,
    PythonComponent,
    PostgresqlComponent,
    PostgresqlClientComponent,
    RabbitMQComponent,
    RestServiceComponent,
    InfluxDBComponent,
    JavaComponent,
    StageComponent,
    ComposerComponent,
    MgmtWorkerComponent,
    RiemannComponent,
    ClusterComponent,
    CliComponent,
    UsageCollectorComponent,
    SanityComponent
)


class ComponentsFactory:
    def __init__(self):
        pass

    @staticmethod
    def create_component(component_name):
        return {
            "manager": ManagerComponent(),
            "manager_ip_setter": ManagerIpSetterComponent(),
            "nginx": NginxComponent(),
            "python": PythonComponent(),
            "postgresql": PostgresqlComponent(),
            "postgresql_client": PostgresqlClientComponent(),
            "rabbitmq": RabbitMQComponent(),
            "restservice": RestServiceComponent(),
            "influxdb": InfluxDBComponent(),
            "amqpinflux": AmqpInfluxComponent(),
            "java": JavaComponent(),
            "amqp_postgres": AmqpPostgresComponent(),
            "stage": StageComponent(),
            "composer": ComposerComponent(),
            "mgmtworker": MgmtWorkerComponent(),
            "riemann": RiemannComponent(),
            "cluster": ClusterComponent(),
            "cli": CliComponent(),
            "usage_collector": UsageCollectorComponent(),
            "sanity": SanityComponent()
        }[component_name]
