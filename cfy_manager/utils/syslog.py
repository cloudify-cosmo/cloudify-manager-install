from cfy_manager.utils import common, files, service


def deploy_rsyslog_filters(group, services, service_type):
    template = '''template(name="{svc}-sup" type="list") {{
  property(name="msg" position.from="{trim}" droplastlf="on" )
  constant(value="\n")
  }}
if $syslogtag == '/supervisord:' and $rawmsg startswith '{svc}' then /var/log/cloudify/{group}/{svc}.log;{svc}-sup
& stop
if $programname == '{svc}' then /var/log/cloudify/{group}/{svc}.log
& stop'''  # noqa
    path_template = '/etc/rsyslog.d/40-{svc}.conf'
    for svc in services:
        trim = len(svc) + 2
        files.write_to_file(template.format(svc=svc, trim=trim, group=group),
                            path_template.format(svc=svc))

    if service_type == 'supervisord':
        _configure_syslog()

    service.restart('rsyslog')


def _configure_syslog():
    if service.is_alive('rsyslog'):
        # We already configured syslog
        return
    syslog_wrapper = '''#!/bin/bash
set -e

rm -f /var/run/syslogd.pid

exec /usr/sbin/rsyslogd -n'''
    syslog_wrapper_path = '/opt/cloudify/syslog_wrapper_script.sh'
    files.write_to_file(syslog_wrapper, syslog_wrapper_path)
    common.chmod('755', syslog_wrapper_path)
    service.configure(
        'rsyslog',
        config_path='config/supervisord',
    )
