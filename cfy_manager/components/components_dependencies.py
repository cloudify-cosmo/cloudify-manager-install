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

# region Dependencies with error messages

DEPENDENCIES_ERROR_MESSAGES = {
    'sudo': 'necessary to run commands with root privileges',
    'openssl-1.0.2k': 'necessary for creating certificates',
    'logrotate': 'used in Cloudify logs',
    'systemd-sysv': 'required to create Cloudify services',
    'initscripts': 'required by the RabbitMQ server',
    'sed': 'required by the CLI',
    'tar': 'required to untar packages',
    'yum': 'used to install Cloudify\'s required packages',
    'python-setuptools': 'required by python',
    'python-backports': 'required by python',
    'python-backports-ssl_match_hostname': 'required by python',
    'openssh-server': 'required by the sanity check'
}

# endregion

# region Components dependencies

COMPONENTS_DEPENDENCIES = {
    'default': ['sudo', 'logrotate', 'yum', 'python-setuptools',
                'python-backports', 'python-backports-ssl_match_hostname'],
    'CliComponent': ['sed'],
    'ComposerComponent': ['systemd-sysv', 'tar'],
    'AmqpPostgresComponent': ['systemd-sysv'],
    'ManagerComponent': [],
    'ManagerIpSetterComponent': ['systemd-sysv'],
    'MgmtWorkerComponent': ['systemd-sysv'],
    'NginxComponent': ['systemd-sysv', 'openssl-1.0.2k'],
    'PostgresqlServerComponent': ['systemd-sysv'],
    'PostgresqlClientComponent': [],
    'PythonComponent': [],
    'RabbitMQComponent': ['initscripts', 'systemd-sysv'],
    'RestServiceComponent': ['systemd-sysv'],
    'SanityComponent': ['openssh-server'],
    'StageComponent': ['systemd-sysv'],
    'UsageCollectorComponent': [],
    'PatchComponent': []
}

# endregion
