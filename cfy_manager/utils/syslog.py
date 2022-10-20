import subprocess

from cfy_manager.utils import files, service
from cfy_manager.exceptions import ProcessExecutionError


def deploy_rsyslog_filters(group, services, logger):
    template = '''template(name="{svc}-sup" type="list") {{
  property(name="msg" position.from="{trim}" droplastlf="on" )
  constant(value="\n")
  }}
template(name="{svc}-supdock" type="list") {{
  property(name="msg" position.from="{spacetrim}" droplastlf="on" )
  constant(value="\n")
  }}
if $syslogtag == '/supervisord:' and $rawmsg startswith '{svc}' then /var/log/cloudify/{group}/{svc}.log;{svc}-sup
& stop
if $syslogtag == '/supervisord:' and $msg startswith ' {svc}' then /var/log/cloudify/{group}/{svc}.log;{svc}-supdock
& stop
if $programname == '{svc}' then /var/log/cloudify/{group}/{svc}.log
& stop'''  # noqa
    path_template = '/etc/rsyslog.d/40-{svc}.conf'
    for svc in services:
        trim = len(svc) + 2
        files.write(template.format(svc=svc, trim=trim, spacetrim=trim+1,
                    group=group), path_template.format(svc=svc))

    if using_systemd_rsyslog(logger):
        try:
            service.SystemD().restart('rsyslog')
        except ProcessExecutionError as err:
            # Some container setups can detect rsyslog being used with systemd
            # but not be able to restart it.
            logger.warning('Failed to restart rsyslog: %s', err)
    else:
        service.restart('rsyslog')


def using_systemd_rsyslog(logger):
    """On RHEL/Centos installs, rsyslog might already be present"""
    try:
        if subprocess.check_output([
            'systemctl', 'is-system-running',
        ]).strip().lower() != 'running':
            logger.debug('Systemd system is not running, assuming no '
                         'services are installed.')
            return False
        return subprocess.check_output([
            'systemctl', 'is-enabled', 'rsyslog',
        ]).strip() == 'enabled'
    except subprocess.CalledProcessError as e:
        logger.debug('Error checking if rsyslog is installed: %s', e)
    return False
