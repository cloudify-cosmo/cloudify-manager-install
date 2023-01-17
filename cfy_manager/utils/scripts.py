from os.path import join, dirname, isfile

from ..utils import common
from ..logger import get_logger
from ..utils.files import write_to_tempfile
from cfy_manager.exceptions import FileError
from ..constants import REST_HOME_DIR, SCRIPTS

logger = get_logger(SCRIPTS)

UTIL_DIR = dirname(__file__)
SCRIPTS_PATH = join(UTIL_DIR, 'scripts')


def run_snapshot_script(script_name, **kwargs):
    snapshot_script = (
        '/opt/mgmtworker/env/lib/python3.11/site-packages/'
        f'cloudify_system_workflows/snapshots/{script_name}.py')
    return run_script_on_manager_venv(snapshot_script,
                                      **kwargs)


def run_script_on_manager_venv(script_path,
                               script_input=None,
                               script_input_arg='--input',
                               envvars=None,
                               script_args=None,
                               json_dump=True):
    """Runs a script in a separate process inside the Cloudify Manager's venv.

    :param script_path: script absolute path (or -m to run a module)
    :param script_input: script configuration to pass to the script. The path
     will be passed with the script_conf_arg param as an argument of the
     script - unless not provided.
    :param script_input_arg: named argument to pass the script conf with.
    :param envvars: env vars to run the script with.
    :param script_args: script arguments.
    :param json_dump: if to json.dump the script_input.
    :return: process result of the run script.
    """
    if script_path != '-m' and not isfile(script_path):
        raise FileError('Provided script path "{0}" isn\'t a file or doesn\'t '
                        'exist.'.format(script_path))
    python_path = join(REST_HOME_DIR, 'env', 'bin', 'python')
    cmd = [python_path, script_path]
    cmd.extend(script_args or [])

    if script_input:
        args_json_path = write_to_tempfile(script_input, json_dump)
        cmd.extend([script_input_arg, args_json_path])

    return common.run(cmd, env=envvars)


def log_script_run_results(script_result):
    """Log stdout/stderr output from the script"""
    if script_result.aggr_stdout:
        output = script_result.aggr_stdout.split('\n')
        output = [line.strip() for line in output if line.strip()]
        for line in output[:-1]:
            logger.debug(line)
        logger.info(output[-1])
    if script_result.aggr_stderr:
        output = script_result.aggr_stderr.split('\n')
        output = [line.strip() for line in output if line.strip()]
        for line in output:
            logger.error(line)
