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
    # The ordering in each service is required as some components depend on
    # the previously installed ones
    # Please do not change the order in which the components of each service
    # will be installed
    "database_service": [
        "postgresql_server"
    ],
    "queue_service": [],
    "composer_service": [],
    "manager_service": [
        "manager",
        "manager_ip_setter",
        "nginx",
        "python",
        "postgresql_client",
        "rabbitmq",
        "restservice",
        "influxdb",
        "amqpinflux",
        "java",
        "amqp_postgres",
        "stage",
        "composer",
        "mgmtworker",
        "riemann",
        "cluster",
        "cli",
        "usage_collector",
        "sanity",
        "cluster"
    ]
}

# endregion

# region Service package names

# Service names constants
DATABASE_SERVICE = 'database_service'
QUEUE_SERVICE = 'queue_service'
COMPOSER_SERVICE = 'composer_service'
MANAGER_SERVICE = 'manager_service'

# endregion

# region Service installation order

# This is to ensure that database is installed first in any kind of
# separated installation
SERVICE_INSTALLATION_ORDER = [
    DATABASE_SERVICE,
    QUEUE_SERVICE,
    COMPOSER_SERVICE,
    MANAGER_SERVICE
]

# endregion
