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
            "manager": Manager,
            "manager_ip_setter": ManagerIpSetter,
            "nginx": Nginx,
            "python": Python,
            "postgresql_server": PostgresqlServer,
            "postgresql_client": PostgresqlClient,
            "rabbitmq": RabbitMQ,
            "restservice": RestService,
            "amqp_postgres": AmqpPostgres,
            "stage": Stage,
            "composer": Composer,
            "mgmtworker": MgmtWorker,
            "cli": Cli,
            "usage_collector": UsageCollector,
            "patch": Patch,
            "sanity": Sanity,
            "manager_status_reporter": ManagerStatusReporter,
            "rabbitmq_status_reporter": RabbitmqStatusReporter,
            "postgresql_status_reporter": PostgresqlStatusReporter
        }[component_name](skip_installation)
