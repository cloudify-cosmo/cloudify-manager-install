import subprocess
import tempfile
import shutil
from os.path import expanduser

from cloudify.decorators import operation


@operation
def install_agent(ctx, **_):
    install_agent_script = ctx.agent.init_script({'user': 'cfyuser'})
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write(install_agent_script)
    subprocess.check_call(['bash', f.name])


@operation
def uninstall_agent(ctx, **_):
    daemon_delete_cmd = [
        expanduser('~cfyuser/{0}/env/bin/cfy-agent'.format(ctx.instance.id)),
        'daemons', 'delete', '--name', ctx.instance.id
    ]
    subprocess.check_call(daemon_delete_cmd,
                          env={'CLOUDIFY_DAEMON_STORAGE_DIRECTORY':
                               expanduser('~cfyuser/.cfy-agent/')})

    shutil.rmtree(expanduser('~cfyuser/{0}'.format(ctx.instance.id)))
