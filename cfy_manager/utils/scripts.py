#########
# Copyright (c) 2019 Cloudify Platform Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.

import json
from os.path import join, dirname, isfile

from ..utils import common
from ..logger import get_logger
from ..utils.files import write_to_tempfile
from cfy_manager.exceptions import FileError
from ..constants import REST_HOME_DIR, SCRIPTS, REST_SECURITY_CONFIG_PATH

logger = get_logger(SCRIPTS)

UTIL_DIR = dirname(__file__)
SCRIPTS_PATH = join(UTIL_DIR, 'scripts')


def run_script_on_manager_venv(script_path,
                               script_input=None,
                               script_input_arg='--input',
                               envvars=None,
                               script_args=None,
                               json_dump=True):
    """Runs a script in a separate process inside the Cloudify Manager's venv.

    :param script_path: script absolute path.
    :param script_input: script configuration to pass to the script. The path
     will be passed with the script_conf_arg param as an argument of the
     script - unless not provided.
    :param script_input_arg: named argument to pass the script conf with.
    :param envvars: env vars to run the script with.
    :param script_args: script arguments.
    :param json_dump: if to json.dump the script_input.
    :return: process result of the run script.
    """
    if not isfile(script_path):
        raise FileError('Provided script path "{0}" isn\'t a file or doesn\'t '
                        'exist.'.format(script_path))
    python_path = join(REST_HOME_DIR, 'env', 'bin', 'python')
    cmd = [python_path, script_path]
    cmd.extend(script_args or [])

    if script_input:
        args_json_path = write_to_tempfile(script_input, json_dump)
        cmd.extend([script_input_arg, args_json_path])

    return common.sudo(cmd, env=envvars)


def get_encoded_user_ids(users):
    script_path = join(SCRIPTS_PATH, 'get_encoded_user_ids.py')
    envvars = {'MANAGER_REST_SECURITY_CONFIG_PATH': REST_SECURITY_CONFIG_PATH}
    result = run_script_on_manager_venv(script_path, users, envvars=envvars)
    if not result:
        return None
    users = json.loads(result.aggr_stdout)
    tokens = {
        user['username']:
            '{0}{1}'.format(user['encoded_id'], user['api_token_key'])
        for user in users}
    return tokens
