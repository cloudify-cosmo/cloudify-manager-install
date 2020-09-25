from ..base_component import BaseComponent
from ..service_names import HAVEGED
from ...logger import get_logger
from ...utils import service


logger = get_logger(HAVEGED)


class Haveged(BaseComponent):
    component_name = HAVEGED

    def configure(self):
        logger.info('Configuring haveged for entropy generation.')
        service.enable(HAVEGED, append_prefix=False)
        logger.info('Successfully configured haveged.')

    def remove(self):
        pass

    def start(self):
        logger.info('Starting haveged for entropy generation.')
        service.start(HAVEGED, append_prefix=False)
        logger.info('Successfully started haveged.')

    def stop(self):
        logger.info('Stopping haveged entropy generation')
        service.stop(HAVEGED, append_prefix=False)
        logger.info('Successfully stopped haveged.')
