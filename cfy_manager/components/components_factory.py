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
    ManagerComponent,
    ManagerIpSetterComponent,
    NginxComponent,
    PythonComponent,
    PostgresqlServerComponent,
    PostgresqlClientComponent,
    RabbitMQComponent,
    RestServiceComponent,
    StageComponent,
    ComposerComponent,
    MgmtWorkerComponent,
    ClusterComponent,
    CliComponent,
    UsageCollectorComponent,
    SanityComponent
)


class ComponentsFactory:
    def __init__(self):
        pass

    @staticmethod
    def create_component(component_name, skip_installation=False):
        return {
            "manager": ManagerComponent(skip_installation),
            "manager_ip_setter": ManagerIpSetterComponent(skip_installation),
            "nginx": NginxComponent(skip_installation),
            "python": PythonComponent(skip_installation),
            "postgresql_server": PostgresqlServerComponent(skip_installation),
            "postgresql_client": PostgresqlClientComponent(skip_installation),
            "rabbitmq": RabbitMQComponent(skip_installation),
            "restservice": RestServiceComponent(skip_installation),
            "amqp_postgres": AmqpPostgresComponent(skip_installation),
            "stage": StageComponent(skip_installation),
            "composer": ComposerComponent(skip_installation),
            "mgmtworker": MgmtWorkerComponent(skip_installation),
            "cluster": ClusterComponent(skip_installation),
            "cli": CliComponent(skip_installation),
            "usage_collector": UsageCollectorComponent(skip_installation),
            "sanity": SanityComponent(skip_installation)
        }[component_name]
