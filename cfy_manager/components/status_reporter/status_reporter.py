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

from ..base_component import BaseComponent

from ...logger import get_logger
from ...utils import service
from ...utils.install import is_package_available
from ...utils.node import update_status_reporter_config
from ...utils.files import (remove_files,
                            read_yaml_file)
from ...constants import (STATUS_REPORTER,
                          STATUS_REPORTER_PATH,
                          STATUS_REPORTER_CONFIGURATION_PATH,
                          STATUS_REPORTER_TOKEN,
                          STATUS_REPORTER_MANAGERS_IPS)

logger = get_logger(STATUS_REPORTER)


class StatusReporter(BaseComponent):
    def __init__(self, skip_installation, reporter_type, user_name):
        skip_installation = (
            skip_installation or
            not is_package_available('cloudify-status-reporter')
        )
        super(StatusReporter, self).__init__(skip_installation)
        self._user_name = user_name

        # The reporter type correlates to the name of the reporter script
        # defined on it's package.
        self.reporter_type = reporter_type

    def _build_extra_config_flags(self):
        return ''

    def configure(self):
        logger.notice('Configuring status reporter {0}...'.format(
            self.reporter_type))
        reporter_settings = {'reporter_type': self.reporter_type,
                             'extra_config_flags':
                                 self._build_extra_config_flags()}
        service.configure(
            STATUS_REPORTER,
            external_configure_params=reporter_settings
        )
        logger.notice('Generating node id...')
        node_id = self._generate_basic_reporter_settings(self._user_name)
        logger.notice('Generated "{0}" node id.'.format(node_id))
        logger.notice('Status reporter {0} successfully configured'.format(
            self.reporter_type))

    @staticmethod
    def _generate_basic_reporter_settings(user_name):
        node_id = str(uuid.uuid4())
        update_status_reporter_config({'node_id': node_id,
                                       'user_name': user_name})
        return node_id

    def remove(self):
        service.remove(STATUS_REPORTER)
        remove_files([STATUS_REPORTER_PATH])

    @staticmethod
    def _is_status_reporter_configured():
        status_reporter_configuration = read_yaml_file(
            STATUS_REPORTER_CONFIGURATION_PATH)
        return (status_reporter_configuration.get(
            STATUS_REPORTER_MANAGERS_IPS) and
            status_reporter_configuration.get(STATUS_REPORTER_TOKEN))

    def start(self):
        if not (self._is_status_reporter_configured()):
            logger.warning('Not starting status reporter service, please '
                           'configure first the mandatory settings: '
                           'Cloudify\'s managers ips and authentication '
                           'token')
            return
        logger.notice('Starting Status Reporter service...')
        service.start(STATUS_REPORTER)
        logger.notice('Started Status Reporter service')

    def stop(self):
        if not (self._is_status_reporter_configured()):
            logger.warning('There is no status reporter service up')
            return
        logger.notice('Stopping Status Reporter service...')
        service.stop(STATUS_REPORTER)
        logger.notice('Status Reporter service stopped')
