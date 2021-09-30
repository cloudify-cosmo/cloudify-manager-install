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
    if files.is_file('/opt/cloudify/syslog_wrapper_script.sh'):
        # We already configured syslog
        return
    files.deploy(
        join(
            SCRIPTS_PATH,
            'syslog_wrapper_script.sh'
        ),
        '/opt/cloudify',
        render=False
    )
    common.chmod(
        '755',
        '/opt/cloudify/syslog_wrapper_script.sh'
    )
    service.configure(
        'rsyslog',
        src_dir='postgresql_server',
        config_path='config/supervisord',
    )
