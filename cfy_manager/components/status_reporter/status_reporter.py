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

from ..base_component import BaseComponent

from ...logger import get_logger
from ...components import sources
from ...utils.common import remove
from ...utils.systemd import systemd
from ...utils.install import yum_install, yum_remove

STATUS_REPORTER = 'status-reporter'

logger = get_logger(STATUS_REPORTER)


class StatusReporter(BaseComponent):
    def __init__(self, skip_installation, reporter_type):
        super(StatusReporter, self).__init__(skip_installation)
        self.reporter_type = reporter_type
        self.skip_installation = skip_installation

    def _build_extra_config_flags(self):
        return ''

    def install(self):
        if self.skip_installation:
            logger.notice('Not installing status reporter {0} due'
                          ' to current setup...'.format(self.reporter_type))
            return
        logger.notice('Installing Status Reporter {0}...'.format(
            self.reporter_type))
        yum_install(sources.status_reporter)
        logger.notice('Status Reporter {0} successfully installed'.format(
            self.reporter_type))

    def configure(self):
        if self.skip_installation:
            logger.notice('Nothing to configure for status reporter {0} due'
                          ' to current setup...'.format(self.reporter_type))
            return
        logger.notice('Configuring status reporter {0}...'.format(
            self.reporter_type))
        reporter_settings = {'reporter_type': self.reporter_type,
                             'extra_config_flags':
                                 self._build_extra_config_flags()}
        systemd.configure(STATUS_REPORTER,
                          external_configure_params=reporter_settings)
        logger.notice('Status reporter {0} successfully configured'.format(
            self.reporter_type))

    def remove(self):
        if self.skip_installation:
            logger.notice('Status Reporter was not installed,'
                          ' so nothing to remove...')
            return
        logger.notice('Removing status reporter {0}...'.format(
            self.reporter_type))
        systemd.remove(STATUS_REPORTER, service_file=False)
        yum_remove('cloudify_status_reporter')
        logger.info('Removing Status Reporter logs...')
        remove('/var/log/status-reporter')
        logger.notice('Status reporter {0} successfully removed'.format(
            self.reporter_type))
