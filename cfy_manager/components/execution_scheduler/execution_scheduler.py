from os.path import join

from ..components_constants import LOG_DIR_KEY, HOME_DIR_KEY
from ..base_component import BaseComponent
from ..service_names import EXECUTION_SCHEDULER
from ...config import config
from ...logger import get_logger
from ...utils import service
from ...constants import BASE_LOG_DIR, REST_HOME_DIR


logger = get_logger(EXECUTION_SCHEDULER)


class ExecutionScheduler(BaseComponent):
    services = {'cloudify-execution-scheduler': {'is_group': False}}

    @staticmethod
    def _setup_log_dir():
        conf = config.setdefault('execution_scheduler', {})
        conf[LOG_DIR_KEY] = join(BASE_LOG_DIR, EXECUTION_SCHEDULER)

    @staticmethod
    def _setup_rest_config_dir():
        conf = config.setdefault('restservice', {})
        conf[HOME_DIR_KEY] = REST_HOME_DIR

    def configure(self, upgrade=False):
        logger.notice('Configuring execution scheduler...')
        if upgrade:
            self._setup_rest_config_dir()
        self._setup_log_dir()
        service.configure('cloudify-execution-scheduler')
        logger.notice('Execution scheduler successfully configured')
        self.start()

    def upgrade(self):
        self.configure(upgrade=True)

    def remove(self):
        logger.notice('Removing execution scheduler...')
        service.remove('cloudify-execution-scheduler', service_file=False)
        logger.notice('Execution scheduler successfully removed')
