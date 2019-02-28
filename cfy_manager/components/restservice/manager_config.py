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

from collections import namedtuple

from ...config import config
from ...constants import REST_SCOPE, MGMTWORKER_SCOPE

ConfigItem = namedtuple('ConfigItem', [
    'name', 'value', 'scope', 'schema', 'is_editable'
])


def make_manager_config():
    return [
        ConfigItem(
            'rest_service_log_path',
            config['restservice']['log_dir'] + '/cloudify-rest-service.log',
            REST_SCOPE,
            None,
            False
        ),
        ConfigItem(
            'rest_service_log_level',
            config['restservice']['log']['level'],
            REST_SCOPE,
            {'type': 'string', 'enum': ['DEBUG', 'INFO', 'WARNING',
                                        'ERROR', 'CRITICAL']},
            True
        ),
        ConfigItem(
            'ldap_server',
            config['restservice']['ldap']['server'],
            REST_SCOPE,
            {'type': 'string'},
            True
        ),
        ConfigItem(
            'ldap_username',
            config['restservice']['ldap']['username'],
            REST_SCOPE,
            {'type': 'string'},
            True
        ),
        ConfigItem(
            'ldap_password',
            config['restservice']['ldap']['password'],
            REST_SCOPE,
            {'type': 'string'},
            True
        ),
        ConfigItem(
            'ldap_domain',
            config['restservice']['ldap']['domain'],
            REST_SCOPE,
            {'type': 'string'},
            True
        ),
        ConfigItem(
            'ldap_is_active_directory',
            config['restservice']['ldap']['is_active_directory'],
            REST_SCOPE,
            {'type': 'boolean'},
            True
        ),
        ConfigItem(
            'ldap_dn_extra',
            config['restservice']['ldap']['dn_extra'],
            REST_SCOPE,
            None,
            True
        ),
        ConfigItem(
            'ldap_timeout',
            5.0,
            REST_SCOPE,
            {'type': 'number'},
            True
        ),
        ConfigItem(
            'file_server_root',
            config['manager']['file_server_root'],
            REST_SCOPE,
            None,
            False
        ),
        ConfigItem(
            'file_server_url',
            config['manager']['file_server_url'],
            REST_SCOPE,
            None,
            False
        ),
        ConfigItem(
            'insecure_endpoints_disabled',
            config['restservice']['insecure_endpoints_disabled'],
            REST_SCOPE,
            {'type': 'boolean'},
            False
        ),
        ConfigItem(
            'maintenance_folder',
            config['restservice']['home_dir'] + '/maintenance',
            REST_SCOPE,
            None,
            False
        ),
        ConfigItem(
            'min_available_memory_mb',
            config['restservice']['min_available_memory_mb'],
            REST_SCOPE,
            {'type': 'number', 'minimum': 0},
            True
        ),
        ConfigItem(
            'failed_logins_before_account_lock',
            config['restservice']['failed_logins_before_account_lock'],
            REST_SCOPE,
            {'type': 'number', 'minimum': 1},
            True
        ),
        ConfigItem(
            'account_lock_period',
            config['restservice']['account_lock_period'],
            REST_SCOPE,
            {'type': 'number', 'minimum': -1},
            True
        ),
        ConfigItem(
            'public_ip',
            config['manager']['public_ip'],
            REST_SCOPE,
            None,
            False
        ),
        ConfigItem(
            'default_page_size',
            config['restservice']['default_page_size'],
            REST_SCOPE,
            {'type': 'number', 'minimum': 1},
            True
        ),

        ConfigItem(
            'mgmtworker_max_workers',
            config['mgmtworker']['max_workers'],
            MGMTWORKER_SCOPE,
            {'type': 'number', 'minimum': 1},
            True
        ),
        ConfigItem(
            'mgmtworker_max_workers',
            config['mgmtworker']['min_workers'],
            MGMTWORKER_SCOPE,
            {'type': 'number', 'minimum': 1},
            True
        )
    ]
