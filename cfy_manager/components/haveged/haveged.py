from ..base_component import BaseComponent
from ...service_names import HAVEGED
from ...logger import get_logger
from ...utils import service


logger = get_logger(HAVEGED)


class Haveged(BaseComponent):
    component_name = HAVEGED
    services = {'haveged': {'is_group': False}}

    def configure(self, config_file=None):
        if using_systemd_haveged():
            return

        logger.info('Configuring haveged for entropy generation.')
        if self.service_type == 'supervisord':
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


def using_systemd_haveged():
    # On more complete installs of RHEL/Centos, haveged may already be running
    if service.SystemD().is_installed(HAVEGED):
        logger.notice('Using system haveged')
        return True
    if service.SystemD().is_active(HAVEGED):
        logger.notice('System haveged active but disabled. Stopping it... ')
        service.SystemD().stop(HAVEGED)
    return False
