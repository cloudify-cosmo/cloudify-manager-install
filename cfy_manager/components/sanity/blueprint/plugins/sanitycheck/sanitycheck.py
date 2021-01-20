import subprocess
import tempfile
import shutil
from os.path import expanduser, join

from cloudify.decorators import operation


@operation
def install_agent(ctx, **_):
    install_agent_script = ctx.agent.init_script({
        'user': 'cfyuser',
        'basedir': '/etc/cloudify'
    })
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write(install_agent_script)
    subprocess.check_call(['bash', f.name])


@operation
def store_envdir(ctx, **_):
    envdir = ctx.instance.runtime_properties['cloudify_agent']['envdir']
    ctx.instance.runtime_properties['envdir'] = envdir


@operation
def uninstall_agent(ctx, **_):
    envdir = ctx.instance.runtime_properties['envdir']
    daemon_delete_cmd = [
        join(envdir, 'bin', 'cfy-agent'),
        'daemons', 'delete', '--name', ctx.instance.id
    ]
    subprocess.check_call(daemon_delete_cmd,
                          env={'CLOUDIFY_DAEMON_STORAGE_DIRECTORY':
                               expanduser('~cfyuser/.cfy-agent/')})

    shutil.rmtree(expanduser('~cfyuser/{0}'.format(ctx.instance.id)))
