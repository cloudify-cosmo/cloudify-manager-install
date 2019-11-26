#!/usr/bin/env python
#########
# Copyright (c) 2018 GigaSpaces Technologies Ltd. All rights reserved
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

from __future__ import print_function
from os.path import join

import argh

from ..utils.scripts import run_script_on_manager_venv

SCRIPT_DIR = '/opt/cloudify/encryption'


def _run_update_encryption_key_script(commit):
    script_path = join(SCRIPT_DIR, 'update-encryption-key')
    script_args = ['--commit'] if commit else None

    return run_script_on_manager_venv(script_path, script_args=script_args)


@argh.arg('-c', '--commit',
          help='Whether to commit the updated encryption key. Without this '
               'argument, a dry-run will be performed to confirm the change '
               'will work.',
          default=False,
          action='store_true')
def update_encryption_key(commit=False):
    """
        Update encryption key for secrets and credentials
    """
    print(_run_update_encryption_key_script(commit).aggr_stdout, end='')
