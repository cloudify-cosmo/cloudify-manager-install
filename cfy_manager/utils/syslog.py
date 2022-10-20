import subprocess

from cfy_manager.utils import files, service


# cache the result of the systemd check globally; this is only based on the
# machine state prior to running this program, and will never change during
# its runtime
_using_systemd_rsyslog = None


def deploy_rsyslog_filters(group, services, logger):
    global _using_systemd_rsyslog

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

    if _using_systemd_rsyslog is None:
        _using_systemd_rsyslog = service.using_systemd_service('rsyslog')

    if _using_systemd_rsyslog:
        try:
            subprocess.check_call(['/bin/systemctl', 'restart', 'rsyslog'])
        except subprocess.CalledProcessError as err:
            # Some container setups can detect rsyslog being used with systemd
            # but not be able to restart it.
            logger.warning('Failed to restart rsyslog: %s', err)
    else:
        service.restart('rsyslog')
