from ..base_component import BaseComponent
from ..service_names import HAVEGED
from ...logger import get_logger
from ...utils import service


logger = get_logger(HAVEGED)


class Haveged(BaseComponent):
    component_name = HAVEGED
    services = ['haveged']

    def configure(self):
        logger.info('Configuring haveged for entropy generation.')
        if self.service_type == 'supervisord':
            service.configure(HAVEGED)
        service.enable(HAVEGED)
        logger.info('Successfully configured haveged.')
        self.start()
