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

from __future__ import print_function

import os
import glob
import time
import shlex
import socket
import logging
import tempfile
import subprocess
from functools import wraps
from datetime import datetime

import argh

from .._compat import text_type
from ..config import config
from ..logger import get_logger
from ..exceptions import ProcessExecutionError

from cfy_manager.components.components_constants import SERVICES_TO_INSTALL
from cfy_manager.components.service_names import (
    POSTGRESQL_SERVER,
    QUEUE_SERVICE,
    MANAGER_SERVICE,
    DATABASE_SERVICE,
    MAIN_SERVICES_NAMES,
)
from . import subprocess_preexec

logger = get_logger('utils')


def run(command, retries=0, stdin=u'', ignore_failures=False,
        globx=False, shell=False, env=None, stdout=None, stderr=None):
    # TODO: add ability to *log* output, instead of just printing to stdout
    if isinstance(command, str) and not shell:
        command = shlex.split(command)
    stderr = stderr or subprocess.PIPE
    stdout = stdout or subprocess.PIPE
    if isinstance(stdin, text_type):
        stdin = stdin.encode('utf-8')
    if env:
        env = {k.encode('utf-8'): v.encode('utf-8') for k, v in env.items()}
    if globx:
        glob_command = []
        for arg in command:
            glob_command.append(glob.glob(arg))
        command = glob_command
    logger.debug('Running: {0}'.format(command))
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=stdout,
                            stderr=stderr, shell=shell, env=env,
                            preexec_fn=subprocess_preexec)
    proc.aggr_stdout, proc.aggr_stderr = proc.communicate(input=stdin)
    if proc.aggr_stdout is not None:
        proc.aggr_stdout = proc.aggr_stdout.decode('utf-8')
    if proc.aggr_stderr is not None:
        proc.aggr_stderr = proc.aggr_stderr.decode('utf-8')
    if proc.returncode != 0:
        if retries:
            logger.warn('Failed running command: %s. Retrying. '
                        '(%s left)', command, retries)
            proc = run(command, retries - 1)
        elif not ignore_failures:
            msg = 'Failed running command: {0} ({1}).'.format(
                command, proc.aggr_stderr)
            err = ProcessExecutionError(msg, proc.returncode)
            err.aggr_stdout = proc.aggr_stdout
            err.aggr_stderr = proc.aggr_stderr
            raise err
    return proc


def sudo(command, *args, **kwargs):
    if isinstance(command, str):
        command = shlex.split(command)
    if 'env' in kwargs:
        command = ['sudo', '-E'] + command
    else:
        command.insert(0, 'sudo')
    return run(command=command, *args, **kwargs)


def cfy(*command, **kwargs):
    # all `cfy` run calls have LC_ALL explicitly provided because
    # click on py3.6 absolutely requires some locale to be set
    env = {'LC_ALL': 'en_US.UTF-8'}
    base = ['sudo', 'cfy'] if kwargs.pop('sudo', False) else ['cfy']
    return run(base + list(command), env=env, **kwargs)


def mkdir(folder, use_sudo=True):
    if os.path.isdir(folder):
        return
    logger.debug('Creating Directory: {0}'.format(folder))
    cmd = ['mkdir', '-p', folder]
    if use_sudo:
        sudo(cmd)
    else:
        run(cmd)


def chmod(mode, path, recursive=False):
    logger.debug('chmoding {0}: {1}'.format(path, mode))
    command = ['chmod']
    if recursive:
        command.append('-R')
    command += [mode, path]
    sudo(command)


def chown(user, group, path):
    logger.debug('chowning {0} by {1}:{2}...'.format(
        path, user, group))
    sudo(['chown', '-R', '{0}:{1}'.format(user, group), path])


def remove(path, ignore_failure=False):
    logger.debug('Removing {0}...'.format(path))
    sudo(['rm', '-rf', path], ignore_failures=ignore_failure)


def untar(source,
          destination=None,
          skip_old_files=False,
          unique_tmp_dir=False):
    if not destination:
        destination = tempfile.mkdtemp() if unique_tmp_dir else '/tmp'
        config.add_temp_path_to_clean(destination)
    logger.debug('Extracting {0} to {1}...'.format(
        source, destination))
    tar_command = ['tar', '-xvf', source, '-C', destination, '--strip=1']
    if skip_old_files:
        tar_command.append('--skip-old-files')
    sudo(tar_command)

    return destination


def ensure_destination_dir_exists(destination):
    destination_dir = os.path.dirname(destination)
    if not os.path.exists(destination_dir):
        logger.debug(
            'Path does not exist: {0}. Creating it...'.format(
                destination_dir))
        sudo(['mkdir', '-p', destination_dir])


def copy(source, destination, backup=False):
    if os.path.exists(destination):
        if backup:
            modified_name = time.strftime('%Y%m%d-%H%M%S_') + \
                            os.path.basename(destination)
            new_dest = os.path.join(os.path.dirname(destination),
                                    modified_name)
            sudo(['cp', '-rp', destination, new_dest])
    else:
        ensure_destination_dir_exists(destination)
    sudo(['cp', '-rp', source, destination])


def move(source, destination, rename_only=False):
    ensure_destination_dir_exists(destination)
    sudo(['cp', source, destination])
    sudo(['rm', source])


def can_lookup_hostname(hostname):
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.gaierror:
        return False


def manager_using_db_cluster():
    """Is this manager using a clustered DB backend?"""
    return (
        DATABASE_SERVICE not in config[SERVICES_TO_INSTALL]
        and config[POSTGRESQL_SERVER]['cluster']['nodes']
    )


def is_all_in_one_manager():
    return (
        MANAGER_SERVICE in config[SERVICES_TO_INSTALL] and
        DATABASE_SERVICE in config[SERVICES_TO_INSTALL] and
        QUEUE_SERVICE in config[SERVICES_TO_INSTALL]
    )


def is_installed(service):
    return service in config[SERVICES_TO_INSTALL]


def get_main_services_from_config():
    return [service_name for service_name in config[SERVICES_TO_INSTALL]
            if service_name in MAIN_SERVICES_NAMES]


def is_manager_service_only_installed():
    return (is_installed(MANAGER_SERVICE) and
            not is_installed(DATABASE_SERVICE) and
            not is_installed(QUEUE_SERVICE))


def allows_json_format():
    """Decorator for Argparse commands that allow a JSON format. This silences
    the given logger and outputs only at least at the ERROR level. Any inner
    calls that build a new logger will also have a silenced logger.
    """
    dest = 'json_format'

    def decorator(f):
        @argh.arg('--json',
                  help='Print in a JSON format instead of using logs.',
                  dest=dest,
                  default=False)
        @wraps(f)
        def wrapper(*args, **kwargs):
            if kwargs[dest]:
                logging.getLogger().setLevel(logging.ERROR)
            return f(*args, **kwargs)

        return wrapper

    return decorator


def output_table(data, fields):
    field_lengths = []
    for field in fields:
        for entry in data:
            if isinstance(entry[field], list):
                entry[field] = ', '.join(entry[field])
        if data:
            field_length = max(
                2 + len(str(entry[field])) for entry in data
            )
        else:
            field_length = 2
        field_length = max(
            field_length,
            2 + len(field)
        )
        field_lengths.append(field_length)

    output_table_divider(field_lengths)
    # Column headings
    output_table_row(field_lengths, fields)
    output_table_divider(field_lengths)

    for entry in data:
        row = [
            entry[field] for field in fields
        ]
        output_table_row(field_lengths, row)
    output_table_divider(field_lengths)


def output_table_divider(lengths):
    output = '+'
    for length in lengths:
        output += '-' * length
        output += '+'
    print(output)


def output_table_row(lengths, entries):
    output = '|'
    for i in range(len(lengths)):
        output += str(entries[i]).center(lengths[i])
        output += '|'
    print(output)


def get_formatted_timestamp():
    # Adding 'Z' to match ISO format
    return '{0}Z'.format(datetime.utcnow().isoformat()[:-3])
