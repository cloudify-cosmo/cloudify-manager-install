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


def make_manager_config():
    rest_config = {
        'rest_service_log_path':
            config['restservice']['log_dir'] + '/cloudify-rest-service.log',
        'rest_service_log_level': config['restservice']['log']['level'],
        'ldap_server': config['restservice']['ldap']['server'],
        'ldap_username': config['restservice']['ldap']['username'],
        'ldap_password': config['restservice']['ldap']['password'],
        'ldap_domain': config['restservice']['ldap']['domain'],
        'ldap_is_active_directory':
            config['restservice']['ldap']['is_active_directory'],
        'ldap_dn_extra': config['restservice']['ldap']['dn_extra'],
        'ldap_timeout': 5.0,
        'file_server_root': config['manager']['file_server_root'],
        'file_server_url': config['manager']['file_server_url'],
        'insecure_endpoints_disabled':
            config['restservice']['insecure_endpoints_disabled'],
        'maintenance_folder':
            config['restservice']['home_dir'] + '/maintenance',
        'min_available_memory_mb':
            config['restservice']['min_available_memory_mb'],
        'failed_logins_before_account_lock':
            config['restservice']['failed_logins_before_account_lock'],
        'account_lock_period': config['restservice']['account_lock_period'],
        'public_ip': config['manager']['public_ip'],
        'default_page_size': config['restservice']['default_page_size']
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
