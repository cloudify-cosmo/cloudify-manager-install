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

import uuid

import yaml

from ..base_component import BaseComponent

from ...logger import get_logger
from ...components import sources
from ...exceptions import InitializationError
from ...utils.common import remove, move, chown
from ...utils.files import write_to_tempfile
from ...utils.systemd import systemd
from ...utils.files import check_rpms_are_present
from ...utils.install import yum_install, yum_remove
from ...constants import STATUS_REPORTER, STATUS_REPORTER_CONFIGURATION_PATH

logger = get_logger(STATUS_REPORTER)


class StatusReporter(BaseComponent):
    def __init__(self, skip_installation, reporter_type):
        skip_installation = (skip_installation or
                             not check_rpms_are_present(
                                 sources.status_reporter))
        super(StatusReporter, self).__init__(skip_installation)
        self.reporter_type = reporter_type

    def _build_extra_config_flags(self):
        return ''

    def install(self):
        logger.notice('Installing Status Reporter {0}...'.format(
            self.reporter_type))
        yum_install(sources.status_reporter)
        logger.notice('Status Reporter {0} successfully installed'.format(
            self.reporter_type))

    def configure(self):
        logger.notice('Configuring status reporter {0}...'.format(
            self.reporter_type))
        reporter_settings = {'reporter_type': self.reporter_type,
                             'extra_config_flags':
                                 self._build_extra_config_flags()}
        systemd.configure(STATUS_REPORTER,
                          external_configure_params=reporter_settings)
        logger.notice('Generating node id...')
        node_id = self._generate_node_id()
        logger.notice('Generated "{0}" node id.'.format(node_id))
        logger.notice('Status reporter {0} successfully configured'.format(
            self.reporter_type))

    @staticmethod
    def _generate_node_id():
        try:
            with open(STATUS_REPORTER_CONFIGURATION_PATH) as f:
                reporter_config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise InitializationError('Failed loading status reporter\'s '
                                      'configuration with the following: '
                                      '{0}'.format(e))
        reporter_config['node_id'] = str(uuid.uuid4())
        updated_conf = yaml.safe_dump(reporter_config,
                                      default_flow_style=False)
        updated_conf_path = write_to_tempfile(updated_conf)
        remove(STATUS_REPORTER_CONFIGURATION_PATH)
        move(updated_conf_path, STATUS_REPORTER_CONFIGURATION_PATH)
        chown('cfyreporter',
              'cfyreporter',
              STATUS_REPORTER_CONFIGURATION_PATH)
        return reporter_config['node_id']

    def remove(self):
        logger.notice('Removing status reporter {0}...'.format(
            self.reporter_type))
        systemd.remove(STATUS_REPORTER, service_file=False)
        yum_remove('cloudify_status_reporter')
        logger.info('Removing Status Reporter logs...')
        remove('/var/log/status-reporter')
        logger.notice('Status reporter {0} successfully removed'.format(
            self.reporter_type))
