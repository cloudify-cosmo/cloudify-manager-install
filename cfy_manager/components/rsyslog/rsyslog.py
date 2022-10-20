import os

from cfy_manager.constants import COMPONENTS_DIR
from cfy_manager.components.base_component import BaseComponent
from cfy_manager.logger import get_logger
from cfy_manager.utils import files, service

SYSLOG_WRAPPER_PATH = '/opt/cloudify/syslog_wrapper_script.sh'

logger = get_logger('rsyslog')


class Rsyslog(BaseComponent):
    component_name = 'rsyslog'

    def __init__(self, *args, **kwargs):
        self._systemd_check = None
        super().__init__(*args, **kwargs)

    def _using_systemd_rsyslog(self):
        if self._systemd_check is None:
            self._systemd_check = service.using_systemd_service('rsyslog')
        return self._systemd_check

    def configure(self):
        if self._using_systemd_rsyslog():
            logger.notice('Using system rsyslog')
            return
        logger.notice('Configuring Rsyslog...')
        syslog_wrapper = '''#!/bin/bash
set -e

rm -f /var/run/syslogd.pid

exec /usr/sbin/rsyslogd -n'''
        files.write(syslog_wrapper, SYSLOG_WRAPPER_PATH,
                    owner='root', group='root', mode=0o750)
        service.configure(
            'rsyslog',
            config_path='config/supervisord',
        )

        if not os.path.exists('/dev/log'):
            logger.info('Configuring rsyslog for non-journald system')
            files.deploy(
                src=os.path.join(COMPONENTS_DIR, 'rsyslog', 'nojournald.conf'),
                dst='/etc/rsyslog.conf',
            )
            service.restart('rsyslog')

    def remove(self):
        if self._using_systemd_rsyslog():
            # We don't manage this
            return
        logger.notice('Removing Rsyslog...')
        files.remove([SYSLOG_WRAPPER_PATH])
        service.remove('rsyslog')

    # Logic to stop the logger is deliberately not included
    def start(self):
        if self._using_systemd_rsyslog():
            # We don't manage this
            return
        logger.notice('Ensuring Rsyslog is running')
        service.start('rsyslog')
