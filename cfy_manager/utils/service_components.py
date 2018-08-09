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

# region Service components

SERVICE_COMPONENTS = {
    "manager_service": [
        "amqp_postgres",
        "manager",
        "manager_ip_setter",
        "nginx",
        "python",
        "rabbitmq",
        "restservice",
        "influxdb",
        "amqpinflux",
        "java",
        "stage",
        "composer",
        "mgmtworker",
        "riemann",
        "cluster",
        "cli",
        "usage_collector",
        "sanity"
    ],
    "database_service": [
        "postgresql"
    ],
    "queue_service": [],
    "composer_service": []
}

# endregion
