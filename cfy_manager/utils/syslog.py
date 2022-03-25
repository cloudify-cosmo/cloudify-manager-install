from cfy_manager.utils import files, service


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
        files.write(template.format(svc=svc, trim=trim, group=group),
                    path_template.format(svc=svc))

    if using_systemd_rsyslog():
        service.SystemD().restart('rsyslog')
    else:
        service.restart('rsyslog')


def using_systemd_rsyslog():
    # On more complete installs of RHEL/Centos, rsyslog may already be running
    return service.SystemD().is_installed('rsyslog')
