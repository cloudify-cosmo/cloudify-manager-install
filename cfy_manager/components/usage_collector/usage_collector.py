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

import os
from uuid import uuid4

from ... import constants
from ...logger import get_logger
from ...utils import common, files
from ..service_names import USAGE_COLLECTOR


MANAGER_ID_PATH = '/etc/cloudify/.id'
logger = get_logger(USAGE_COLLECTOR)


def _create_manager_id_file():
    logger.info('Creating manager id file...')
    if os.path.exists(MANAGER_ID_PATH):
        with open(MANAGER_ID_PATH) as f:
            existing_manager_id = f.read().strip()
            if existing_manager_id:
                return
    files.write_to_file(uuid4().hex, MANAGER_ID_PATH)
    common.chown(constants.CLOUDIFY_USER,
                 constants.CLOUDIFY_GROUP,
                 MANAGER_ID_PATH)
    logger.info('Manager id file successfully created')


def install():
    _create_manager_id_file()


def configure():
    return


def remove():
    if os.path.exists(MANAGER_ID_PATH):
        common.remove(MANAGER_ID_PATH)
