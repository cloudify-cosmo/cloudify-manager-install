from os.path import join
from random import randint

from ... import constants
from ...config import config
from ...logger import get_logger
from ...utils import common, files
from ...exceptions import InputError
from ...components_constants import SCRIPTS
from ..base_component import BaseComponent
from ...service_names import USAGE_COLLECTOR
from ...utils.install import is_package_installed
from ...utils.logrotate import set_logrotate, remove_logrotate


HOURS_INTERVAL = 'interval_in_hours'
DAYS_INTERVAL = 'interval_in_days'
MANAGER_ID_PATH = '/etc/cloudify/.id'
MANAGER_PYTHON = '/opt/manager/env/bin/python'
COLLECTOR_SCRIPTS = [('collect_cloudify_uptime', HOURS_INTERVAL),
                     ('collect_cloudify_usage', DAYS_INTERVAL)]
SCRIPTS_DESTINATION_PATH = join('/opt/cloudify', USAGE_COLLECTOR)
LOG_DIR = join(constants.BASE_LOG_DIR, USAGE_COLLECTOR)
logger = get_logger(USAGE_COLLECTOR)


class UsageCollector(BaseComponent):
    def install(self):
        logger.notice('Installing Usage Collector...')
        self._deploy_collector_scripts()
        logger.notice('Usage Collector successfully installed')

    def configure(self):
        if self._validate_crontab_accessible():
            logger.notice('Configuring Usage Collector...')
            common.mkdir(LOG_DIR)
            common.chown(constants.CLOUDIFY_USER,
                         constants.CLOUDIFY_GROUP,
                         LOG_DIR)
            set_logrotate(USAGE_COLLECTOR)
            logger.notice('Usage Collector successfully configured')
            self.start()

    def start(self):
        if self._validate_crontab_accessible():
            logger.notice('Enabling usage collector')
            self._remove_cron_jobs()
            self._create_cron_jobs()
            logger.notice('Usage collector enabled')

    def stop(self, force=True):
        if self._validate_crontab_accessible():
            logger.notice('Disabling usage collector')
            self._remove_cron_jobs()
            logger.notice('Usage collector disabled')

    def remove(self):
        logger.notice('Removing Usage Collector...')
        if self._validate_crontab_accessible():
            self._remove_cron_jobs()
        remove_logrotate(USAGE_COLLECTOR)
        files.remove([SCRIPTS_DESTINATION_PATH, MANAGER_ID_PATH])
        logger.notice('Usage Collector successfully removed')

    def _validate_crontab_accessible(self):
        if not is_package_installed('cronie'):
            logger.warning('Package cronie is not installed,'
                           'Usage Collector cannot be used')
            return False

        try:
            common.run(['crontab', '-u', constants.CLOUDIFY_USER, '-l'])
        except common.ProcessExecutionError as ex:
            logger.warning(
                'Usage Collector cannot be used, unable to use crontab: {0}.'
                .format(ex.aggr_stderr.strip().replace("\n", "\t"))
            )

        return True

    def _deploy_collector_scripts(self):
        logger.info('Deploying Usage Collector scripts...')
        common.mkdir(SCRIPTS_DESTINATION_PATH)
        script_names = ['{}.py'.format(item[0]) for item in COLLECTOR_SCRIPTS]
        script_names.append('script_utils.py')

        for script_name in script_names:
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

    def _create_cron_jobs(self):
        logger.info('Creating cron jobs for Usage Collector...')

        for collector, interval_type in COLLECTOR_SCRIPTS:
            active = config[USAGE_COLLECTOR][collector]['active']
            if active:
                interval = config[USAGE_COLLECTOR][collector][interval_type]
                self._add_cron_job(collector, interval_type, interval)
            else:
                logger.notice('Deactivated {} cron job'.format(collector))

        logger.info('Usage Collector cron jobs successfully created')

    def _add_cron_job(self, script_name, interval_type, interval):
        script_path = join(SCRIPTS_DESTINATION_PATH,
                           '{}.py'.format(script_name))
        time_string = self._get_cron_time_string(interval_type, interval)
        command = f'{MANAGER_PYTHON} {script_path}'
        common.add_cron_job(time_string, command, script_name,
                            constants.CLOUDIFY_USER)

    def _get_cron_time_string(self, interval_type, interval):
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
            return '{0} {1} */{2} * *'.format(random_minute,
                                              random_hour,
                                              interval)

    def _remove_cron_jobs(self):
        logger.info('Removing cron jobs of Usage Collector...')
        for collector, _ in COLLECTOR_SCRIPTS:
            self._delete_cron_job(collector)
        logger.info('Usage Collector cron jobs successfully removed')

    def _delete_cron_job(self, job_comment):
        cmd = "crontab -u {0} -l | " \
              "grep -v '# {1}' | " \
              "crontab -u {0} -" \
              .format(constants.CLOUDIFY_USER, job_comment)
        common.run([cmd], shell=True)
