from cfy_manager.components.base_component import BaseComponent
from cfy_manager.logger import get_logger
from cfy_manager.utils import files, service, syslog

SYSLOG_WRAPPER_PATH = '/opt/cloudify/syslog_wrapper_script.sh'

logger = get_logger('rsyslog')


class Rsyslog(BaseComponent):
    component_name = 'rsyslog'

    def configure(self):
        if syslog.using_systemd_rsyslog():
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

    def remove(self):
        if syslog.using_systemd_rsyslog():
            # We don't manage this
            return
        logger.notice('Removing Rsyslog...')
        files.remove_files([SYSLOG_WRAPPER_PATH])
        service.remove('rsyslog')

    # Logic to stop the logger is deliberately not included
    def start(self):
        if syslog.using_systemd_rsyslog():
            # We don't manage this
            return
        logger.notice('Ensuring Rsyslog is running')
        service.start('rsyslog')
