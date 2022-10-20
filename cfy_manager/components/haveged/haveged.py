import subprocess

from ..base_component import BaseComponent
from ...service_names import HAVEGED
from ...logger import get_logger
from ...utils import service


logger = get_logger(HAVEGED)


class Haveged(BaseComponent):
    component_name = HAVEGED
    services = {'haveged': {'is_group': False}}

    def configure(self):
        if using_systemd_haveged():
            return

        logger.info('Configuring haveged for entropy generation.')
        service.configure(HAVEGED)
        service.enable(HAVEGED)
        logger.info('Successfully configured haveged.')
        self.start()

    def remove(self):
        if using_systemd_haveged():
            # We don't manage this
            return
        super().remove()

    def start(self):
        if using_systemd_haveged():
            # We don't manage this
            return
        super().start()
