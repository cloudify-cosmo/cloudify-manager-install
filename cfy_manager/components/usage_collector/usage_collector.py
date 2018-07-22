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

from os.path import join
from random import randint

from .. import SCRIPTS
from ... import constants
from ...config import config
from ...logger import get_logger
from ...utils import common, files
from ...exceptions import InputError
from ..service_names import USAGE_COLLECTOR
from ...utils.install import RpmPackageHandler


HOURS_INTERVAL = 'interval_in_hours'
DAYS_INTERVAL = 'interval_in_days'
MANAGER_ID_PATH = '/etc/cloudify/.id'
COLLECT_UPTIME = 'collect_cloudify_uptime'
MANAGER_PYTHON = '/opt/manager/env/bin/python'
COLLECTOR_SCRIPTS = [('collect_cloudify_uptime', HOURS_INTERVAL),
                     ('collect_cloudify_usage', DAYS_INTERVAL)]
SCRIPTS_DESTINATION_PATH = join('/opt/cloudify', USAGE_COLLECTOR)
logger = get_logger(USAGE_COLLECTOR)


def install():
    logger.notice('Installing Usage Collector...')
    _deploy_collector_scripts()
    _configure()
    logger.notice('Usage Collector successfully installed')


def configure():
    logger.notice('Configuring Usage Collector...')
    if _configure():
        logger.notice('Usage Collector successfully configured')


def remove():
    logger.notice('Removing Usage Collector...')
    if _validate_cronie_installed():
        _remove_cron_jobs()
    common.remove(SCRIPTS_DESTINATION_PATH)
    common.remove(MANAGER_ID_PATH)
    logger.notice('Usage Collector successfully removed')


def _configure():
    if not _validate_cronie_installed():
        return False
    _remove_cron_jobs()
    _create_cron_jobs()
    return True


def _validate_cronie_installed():
    if not RpmPackageHandler.is_package_installed('cronie'):
        logger.warning('Package cronie is not installed, unable to install '
                       'Usage Collector')
        return False
    return True


def _deploy_collector_scripts():
    logger.info('Deploying Usage Collector scripts...')
    common.mkdir(SCRIPTS_DESTINATION_PATH)

    for collector, interval_type in COLLECTOR_SCRIPTS:
        script_name = '{}.py'.format(collector)
        source_path = join(constants.COMPONENTS_DIR,
                           USAGE_COLLECTOR,
                           SCRIPTS,
                           script_name)
        destination_path = join(SCRIPTS_DESTINATION_PATH, script_name)
        files.deploy(source_path, destination_path)
        common.chmod('+x', destination_path)
        common.chown(constants.CLOUDIFY_USER,
                     constants.CLOUDIFY_GROUP,
                     destination_path)
    logger.info('Usage Collector scripts successfully deployed')


def _create_cron_jobs():
    logger.info('Creating cron jobs for Usage Collector...')

    for collector, interval_type in COLLECTOR_SCRIPTS:
        active = config[USAGE_COLLECTOR][collector]['active']
        if active:
            interval = config[USAGE_COLLECTOR][collector][interval_type]
            _add_cron_job(collector, interval_type, interval)
        else:
            logger.notice('Deactivated {} cron job'.format(collector))

    logger.info('Usage Collector cron jobs successfully created')


def _add_cron_job(script_name, interval_type, interval):
    script_path = join(SCRIPTS_DESTINATION_PATH, '{}.py'.format(script_name))
    time_string = _get_cron_time_string(interval_type, interval)

    # crontab job command
    job = '{0} {1} {2} # {3}'.format(time_string,
                                     MANAGER_PYTHON,
                                     script_path,
                                     script_name)

    # Adding a new job to crontab.
    # Adding sudo manually, because common.sudo doesn't support parenthesis.
    cmd = '(sudo crontab -u {0} -l 2>/dev/null; echo "{1}") | ' \
          'sudo crontab -u {0} -'.format(constants.CLOUDIFY_USER, job)
    common.run([cmd], shell=True)


def _get_cron_time_string(interval_type, interval):
    if not isinstance(interval, int):
        raise InputError(
            'The interval between collector runs ({}) must be integer'
            .format(interval_type)
        )

    random_minute = randint(0, 59)
    if interval_type == HOURS_INTERVAL:
        return '{0} */{1} * * *'.format(random_minute, interval)
    if interval_type == DAYS_INTERVAL:
        random_hour = randint(0, 23)
        return '{0} {1} */{2} * *'.format(random_minute, random_hour, interval)


def _remove_cron_jobs():
    logger.info('Removing cron jobs of Usage Collector...')
    for collector, _ in COLLECTOR_SCRIPTS:
        _delete_cron_job(collector)
    logger.info('Usage Collector cron jobs successfully removed')


def _delete_cron_job(job_comment):
    cmd = "sudo crontab -u {0} -l | grep -v '# {1}' | sudo crontab -u {0} -" \
          .format(constants.CLOUDIFY_USER, job_comment)
    common.run([cmd], shell=True)
