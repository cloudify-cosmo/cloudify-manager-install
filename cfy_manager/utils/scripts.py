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

from os.path import join

from ..utils import common
from ..logger import get_logger
from ..constants import REST_HOME_DIR, SCRIPTS
from ..utils.files import write_to_tempfile

logger = get_logger(SCRIPTS)


def run_script_on_manager_venv(script_path,
                               script_input=None,
                               script_input_arg='--input',
                               envvars=None,
                               script_args=None):
    """Runs a script in a separate process.

    :param script_path: script absolute path.
    :param script_input: script configuration to pass to the script. The path
     will be passed with the script_conf_arg param as an argument of the
     script - unless not provided.
    :param script_input_arg: named argument to pass the script conf with.
    :param envvars: env vars to run the script with.
    :param script_args: script arguments.
    :return: process result of the run script.
    """

    python_path = join(REST_HOME_DIR, 'env', 'bin', 'python')
    cmd = [python_path, script_path]
    cmd.extend(script_args or [])

    if script_input:
        args_json_path = write_to_tempfile(script_input, json_dump=True)
        cmd.extend([script_input_arg, args_json_path])

    return common.sudo(cmd, env=envvars)
