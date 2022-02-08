from ..base_component import BaseComponent
from ..service_names import EXECUTION_SCHEDULER
from ...logger import get_logger
from ...utils import service


logger = get_logger(EXECUTION_SCHEDULER)


class ExecutionScheduler(BaseComponent):
    services = {'cloudify-execution-scheduler': {'is_group': False}}

    def configure(self, upgrade=False):
        logger.notice('Configuring execution scheduler...')
        service.configure('cloudify-execution-scheduler')
        logger.notice('Execution scheduler successfully configured')
        self.start()

    def upgrade(self):
        self.configure(upgrade=True)

    def remove(self):
        logger.notice('Removing execution scheduler...')
        service.remove('cloudify-execution-scheduler')
        logger.notice('Execution scheduler successfully removed')
