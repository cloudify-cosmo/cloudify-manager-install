#########
# Copyright (c) 2019 Cloudify Platform Ltd. All rights reserved
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
    AmqpPostgres,
    Manager,
    ManagerIpSetter,
    Nginx,
    Python,
    PostgresqlServer,
    PostgresqlClient,
    RabbitMQ,
    RestService,
    Stage,
    Composer,
    MgmtWorker,
    Cli,
    UsageCollector,
    Patch,
    Sanity,
    RabbitmqStatusReporter,
    PostgresqlStatusReporter,
    ManagerStatusReporter
)


class ComponentsFactory:
    def __init__(self):
        pass

    @staticmethod
    def create_component(component_name, skip_installation=False):
        return {
            "manager": Manager(skip_installation),
            "manager_ip_setter": ManagerIpSetter(skip_installation),
            "nginx": Nginx(skip_installation),
            "python": Python(skip_installation),
            "postgresql_server": PostgresqlServer(skip_installation),
            "postgresql_client": PostgresqlClient(skip_installation),
            "rabbitmq": RabbitMQ(skip_installation),
            "restservice": RestService(skip_installation),
            "amqp_postgres": AmqpPostgres(skip_installation),
            "stage": Stage(skip_installation),
            "composer": Composer(skip_installation),
            "mgmtworker": MgmtWorker(skip_installation),
            "cli": Cli(skip_installation),
            "usage_collector": UsageCollector(skip_installation),
            "patch": Patch(skip_installation),
            "sanity": Sanity(skip_installation),
            "manager_status_reporter":
                ManagerStatusReporter(skip_installation),
            "rabbitmq_status_reporter":
                RabbitmqStatusReporter(skip_installation),
            "postgresql_status_reporter":
                PostgresqlStatusReporter(skip_installation)
        }[component_name]
