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

manager = [
    'cloudify-management-worker', 'cloudify-rest-service',
    'cloudify-cli', 'nginx', 'postgresql14', 'cloudify-agents',
    'nodejs', 'cloudify-stage',
    'git'  # required for installing some Terraform modules
]
manager_premium = [
    'cloudify-premium', 'cloudify-composer'
]
manager_cluster = []
db = [
    'postgresql14', 'postgresql14-server',
    'libxslt', 'libicu',
]
db_cluster = [
    'libestr', 'libfastjson', 'etcd', 'patroni'
]
queue_rh8_x86 = ['erlang']
queue_other = ['esl-erlang']
queue = ['libtool-ltdl', 'unixODBC',
         'rabbitmq-server', 'cloudify-rabbitmq']
queue_cluster = []
prometheus = [
    'prometheus', 'node_exporter', 'blackbox_exporter', 'postgres_exporter',
]
prometheus_cluster = [
    'nginx',
]
haveged = [
    'haveged',
]
