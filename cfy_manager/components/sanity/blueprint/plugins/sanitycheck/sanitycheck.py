import subprocess
import tempfile

from cloudify.decorators import operation


@operation
def install_agent(ctx, **_):
    install_agent_script = ctx.agent.init_script({'user': 'cfyuser'})
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write(install_agent_script)
    subprocess.check_call(['bash', f.name])
