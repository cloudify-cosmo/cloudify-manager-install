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

from ..utils.systemd import systemd
from ..constants import STATUS_REPORTER
from ..logger import get_logger, setup_console_logger

logger = get_logger(STATUS_REPORTER)
setup_console_logger()


def configure():
    logger.notice('Configuring component status reporting service with...')
    systemd.restart(STATUS_REPORTER)
    logger.notice('Component status reporting service Configured')


def start():
    logger.notice('Starting component status reporting service...')
    systemd.start(STATUS_REPORTER)
    logger.notice('Started status reporting service')


def stop():
    logger.notice('Stopping component status reporting service...')
    systemd.stop(STATUS_REPORTER)
    logger.notice('Component status reporting service stopped')


def remove():
    logger.notice('Removing component status reporting service...')
    systemd.remove(STATUS_REPORTER)
    logger.notice('Component status reporting service removed')
