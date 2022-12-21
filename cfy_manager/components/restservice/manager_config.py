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

from ...config import config
from ... import constants


def make_manager_config():
    prometheus_config = config.get('prometheus', {})
    rest_config = {
        'rest_service_log_path':
            constants.REST_LOG_DIR + '/cloudify-rest-service.log',
        'rest_service_log_level': config['restservice']['log']['level'],
        'file_server_root': config['manager']['file_server_root'],
        'file_server_url': config['manager']['file_server_url'],
        'insecure_endpoints_disabled':
            config['restservice']['insecure_endpoints_disabled'],
        'maintenance_folder':
            constants.REST_HOME_DIR + '/maintenance',
        'min_available_memory_mb':
            config['restservice']['min_available_memory_mb'],
        'failed_logins_before_account_lock':
            config['restservice']['failed_logins_before_account_lock'],
        'account_lock_period': config['restservice']['account_lock_period'],
        'public_ip': config['manager']['public_ip'],
        'default_page_size': config['restservice']['default_page_size'],
        'monitoring_timeout': prometheus_config.get('request_timeout', 4),
        'log_fetch_username': prometheus_config.get('credentials', {}).get(
            'username'),
        'log_fetch_password': prometheus_config.get('credentials', {}).get(
            'password'),
    }
    mgmtworker_config = {
        'max_workers': config['mgmtworker']['max_workers'],
        'min_workers': config['mgmtworker']['min_workers'],
    }
    agent_config = {
        'min_workers': config['agent']['min_workers'],
        'max_workers': config['agent']['max_workers'],
        'broker_port': config['agent']['broker_port'],
        'heartbeat': config['agent']['heartbeat'],
        'log_level': config['agent']['log_level']
    }
    workflow_config = config['mgmtworker']['workflows']
    return [  # (scope, {name: value})
        ('mgmtworker', mgmtworker_config),
        ('workflow', workflow_config),
        ('agent', agent_config),
        ('rest', rest_config)
    ]
