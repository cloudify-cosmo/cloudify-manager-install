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


def using_systemd_haveged():
    """On RHEL/Centos installs, haveged might already be present"""
    try:
        if subprocess.check_output([
            'systemctl', 'is-system-running',
        ]).strip().lower() != 'running':
            logger.debug('Systemd system is not running, assuming no '
                         'services are installed.')
            return False

        if subprocess.check_output([
            'systemctl', 'is-enabled', HAVEGED,
        ]).strip().lower() == 'enabled':
            logger.notice('Using system haveged')
            return True

        if subprocess.check_output([
            'systemctl', 'is-active', HAVEGED
        ]).strip().lower() in ['running', 'active', 'activating']:
            logger.notice('System haveged active but disabled. Stopping it...')
            subprocess.run(['systemctl', 'stop', HAVEGED])

    except subprocess.CalledProcessError as e:
        logger.debug('Error checking if rsyslog is installed: %s', e)
    return False
