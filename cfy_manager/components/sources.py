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

composer = 'cloudify-blueprint-composer-*.tgz'
sanity = 'cloudify-hello-world-example-*.tar.gz'

manager = [
    'cloudify-management-worker', 'cloudify-rest-service',
    'cloudify-cli', 'cloudify-manager-ip-setter', 'nginx',
    'python-psycopg2', 'postgresql95', 'cloudify-agents',
    'patch', 'nodejs', 'cloudify-stage'
]
manager_premium = ['cloudify-premium', 'cloudify-status-reporter']
manager_cluster = ['haproxy']
db = ['postgresql95', 'postgresql95-server', 'postgresql95-contrib', 'libxslt']
db_cluster = [
    'libestr', 'libfastjson', 'rsyslog', 'etcd',
    'cloudify-status-reporter', 'patroni'
]
queue = ['rabbitmq-server-3.7.7', 'cloudify-rabbitmq']
queue_cluster = ['cloudify-status-reporter']
