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

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from .common import move, mkdir, chown
from .install import is_premium_installed
from .files import sudo_read, update_yaml_file, is_file, is_dir

from ..logger import get_logger
from ..exceptions import InitializationError
from ..constants import (CLOUDIFY_USER,
                         CLOUDIFY_GROUP,
                         STATUS_REPORTER_OS_USER,
                         STATUS_REPORTER_CONFIGURATION_PATH)


ARCHIVE_DIR = 'archive'
logger = get_logger('SystemNode')
CLUSTER_STATUS_PATH = '/opt/manager/cluster_statuses'


def get_node_id():
    if not is_file(STATUS_REPORTER_CONFIGURATION_PATH):
        if is_premium_installed():
            raise InitializationError(
                'Status reporter is not installed, path does not exist: {0}'
                .format(STATUS_REPORTER_CONFIGURATION_PATH)
            )
        else:
            # Status reporter is not installed in community edition
            return 'COMMUNITY'
    try:
        yaml = YAML(typ='safe')
        yaml.default_flow_style = False
        reporter_config = yaml.load(
            sudo_read(STATUS_REPORTER_CONFIGURATION_PATH)
        )
    except YAMLError as e:
        raise InitializationError('Failed loading status reporter\'s '
                                  'configuration with the following: '
                                  '{0}'.format(e))
    return reporter_config['node_id']


def archive_status_report(node_type, node_id):
    file_name = '{node_type}_{node_id}.json'.format(node_type=node_type,
                                                    node_id=node_id)
    report_path = '{status_path}/{file_name}'.format(
        status_path=CLUSTER_STATUS_PATH, file_name=file_name
    )
    if not is_file(report_path):
        return

    try:
        destination_path = '{status_path}/{archive}'.format(
            status_path=CLUSTER_STATUS_PATH, archive=ARCHIVE_DIR
        )
        if not is_dir(destination_path):
            mkdir(destination_path, use_sudo=True)
            chown(CLOUDIFY_USER, CLOUDIFY_GROUP, destination_path)
        move(report_path, destination_path)
        archived_report_path = '{archive_path}/{file_name}'.format(
            archive_path=destination_path, file_name=file_name
        )
        chown(CLOUDIFY_USER, CLOUDIFY_GROUP, archived_report_path)
    except Exception as e:
        logger.warn('Error had occurred while trying to archive status report '
                    'file {0}: {1}'.format(file_name, e))


def update_status_reporter_config(updated_content):
    """
    :param updated_content: The content to update in the config file
    :type updated_content: dict
    """
    update_yaml_file(STATUS_REPORTER_CONFIGURATION_PATH,
                     STATUS_REPORTER_OS_USER,
                     STATUS_REPORTER_OS_USER,
                     updated_content)
