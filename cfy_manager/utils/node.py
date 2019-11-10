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

from os import path

import yaml

from .files import sudo_read
from .install import is_premium_installed
from ..exceptions import InitializationError
from ..constants import STATUS_REPORTER_CONFIGURATION_PATH


def get_node_id():
    if not path.exists(STATUS_REPORTER_CONFIGURATION_PATH):
        if is_premium_installed():
            raise InitializationError(
                'Status reporter is not installed, path does not exist: {0}'
                .format(STATUS_REPORTER_CONFIGURATION_PATH)
            )
        else:
            # Status reporter is not installed in community edition
            return 'COMMUNITY'
    try:
        reporter_config = yaml.safe_load(
            sudo_read(STATUS_REPORTER_CONFIGURATION_PATH)
        )
    except yaml.YAMLError as e:
        raise InitializationError('Failed loading status reporter\'s '
                                  'configuration with the following: '
                                  '{0}'.format(e))
    return reporter_config['node_id']
