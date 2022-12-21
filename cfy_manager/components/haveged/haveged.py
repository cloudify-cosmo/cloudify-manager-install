from ..base_component import BaseComponent
from ...service_names import HAVEGED
from ...logger import get_logger
from ...utils import service


logger = get_logger(HAVEGED)


class Haveged(BaseComponent):
    component_name = HAVEGED
    services = {'haveged': {'is_group': False}}

    def __init__(self, *args, **kwargs):
        self._systemd_check = None
        super().__init__(*args, **kwargs)

    def _using_systemd_haveged(self):
        if self._systemd_check is None:
            self._systemd_check = service.using_systemd_service(HAVEGED)
        return self._systemd_check

    def configure(self):
        if self._using_systemd_haveged():
            return

        logger.info('Configuring haveged for entropy generation.')
        service.configure(HAVEGED)
        service.enable(HAVEGED)
        logger.info('Successfully configured haveged.')
        self.start()

    def remove(self):
        if self._using_systemd_haveged():
            # We don't manage this
            return
        super().remove()

    def start(self):
        if self._using_systemd_haveged():
            # We don't manage this
            return
        super().start()
