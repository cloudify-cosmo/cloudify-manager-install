from __future__ import print_function

import os
import glob
import time
import shlex
import shutil
import socket
import sys
import logging
import subprocess
from functools import wraps
from datetime import datetime

import argh

from ..config import config
from ..logger import get_logger
from ..exceptions import ProcessExecutionError

from cfy_manager.components_constants import SERVICES_TO_INSTALL
from cfy_manager.service_names import (
    POSTGRESQL_SERVER,
    QUEUE_SERVICE,
    MANAGER_SERVICE,
    DATABASE_SERVICE,
    MAIN_SERVICES_NAMES,
    MANAGER,
    PROMETHEUS,
    RABBITMQ,
)
from cfy_manager.utils.install_state import get_configured_services
from . import subprocess_preexec

logger = get_logger('utils')


def run(command, retries=0, stdin=u'', ignore_failures=False,
        globx=False, shell=False, env=None, stdout=None, stderr=None,
        cwd=None):
    # TODO: add ability to *log* output, instead of just printing to stdout
    if isinstance(command, str) and not shell:
        command = shlex.split(command)
    stderr = stderr or subprocess.PIPE
    stdout = stdout or subprocess.PIPE
    if isinstance(stdin, str):
        stdin = stdin.encode('utf-8')

    if not env:
        env = {}
        env.update(os.environ)
    # Use actual python interpreter to install
    # any deps that require python (like nodejs)
    python_bin_path = sys.executable.removesuffix('/python')
    if env.get('PATH'):
        env['PATH'] = f"{python_bin_path}:{env.get('PATH')}"
    else:
        env['PATH'] = python_bin_path
    env = {k.encode('utf-8'): v.encode('utf-8') for k, v in env.items()}
    if 'LANG' not in env:
        env['LANG'] = 'en_US.utf-8'
    if 'LC_ALL' not in env:
        env['LC_ALL'] = 'C'

    if globx:
        glob_command = []
        for arg in command:
            glob_command.append(glob.glob(arg))
        command = glob_command
    logger.debug('Running: {0}'.format(command))
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=stdout,
                            stderr=stderr, shell=shell, env=env,
                            preexec_fn=subprocess_preexec, cwd=cwd)
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


def cfy(*command, **kwargs):
    as_user = kwargs.pop('as_user', None)
    # all `cfy` run calls have LC_ALL explicitly provided because
    # click on py3.6 absolutely requires some locale to be set
    env = {'LC_ALL': 'en_US.UTF-8'}

    base = []
    if as_user:
        base = ['sudo', '-E', '-u', as_user]

    base.append('/usr/bin/cfy')
    try:
        return run(base + list(command), env=env, **kwargs)
    except ProcessExecutionError as e:
        logger.error('CLI call failed, stdout: %s, stderr: %s',
                     e.aggr_stdout, e.aggr_stderr)
        raise


def mkdir(folder):
    if os.path.isdir(folder):
        return
    logger.debug('Creating Directory: {0}'.format(folder))
    cmd = ['mkdir', '-p', folder]
    run(cmd)


def chmod(mode, path, recursive=False):
    logger.debug('chmoding {0}: {1}'.format(path, mode))
    command = ['chmod']
    if recursive:
        command.append('-R')
    command += [mode, path]
    run(command)


def chown(user, group, path):
    logger.debug('chowning {0} by {1}:{2}...'.format(
        path, user, group))
    run(['chown', '-R', '{0}:{1}'.format(user, group), path])


def ensure_destination_dir_exists(destination):
    destination_dir = os.path.dirname(destination)
    if not os.path.exists(destination_dir):
        logger.debug(
            'Path does not exist: {0}. Creating it...'.format(
                destination_dir))
        run(['mkdir', '-p', destination_dir])


def copy(source, destination, backup=False):
    if os.path.exists(destination):
        if backup:
            modified_name = time.strftime('%Y%m%d-%H%M%S_') + \
                            os.path.basename(destination)
            new_dest = os.path.join(os.path.dirname(destination),
                                    modified_name)
            run(['cp', '-rp', destination, new_dest])
    else:
        ensure_destination_dir_exists(destination)
    run(['cp', '-rp', source, destination])


def move(source, destination):
    ensure_destination_dir_exists(destination)
    shutil.move(source, destination)


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


def service_is_configured(service):
    return service in get_configured_services()


def service_is_in_config(service):
    return service in config[SERVICES_TO_INSTALL]


def get_main_services_from_config():
    return [service_name for service_name in config[SERVICES_TO_INSTALL]
            if service_name in MAIN_SERVICES_NAMES]


def is_only_manager_service_in_config():
    return (service_is_in_config(MANAGER_SERVICE) and
            not service_is_in_config(DATABASE_SERVICE) and
            not service_is_in_config(QUEUE_SERVICE))


def filesystem_replication_enabled():
    return config[MANAGER].get('cluster_filesystem_replication')


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


def get_prometheus_credentials():
    creds = config.get(PROMETHEUS, {}).get('credentials', {})
    if creds.get('username') and creds.get('password'):
        return creds
    if MANAGER_SERVICE in config[SERVICES_TO_INSTALL]:
        manager_security_cfg = config.get(MANAGER).get('security', {})
        creds['username'] = manager_security_cfg.get('admin_username')
        creds['password'] = manager_security_cfg.get('admin_password')
    elif DATABASE_SERVICE in config[SERVICES_TO_INSTALL]:
        creds['username'] = 'postgres'
        creds['password'] = \
            config.get(POSTGRESQL_SERVER).get('postgres_password')
    elif QUEUE_SERVICE in config[SERVICES_TO_INSTALL]:
        rabbitmq_cfg = config.get(RABBITMQ)
        creds['username'] = rabbitmq_cfg.get('username')
        creds['password'] = rabbitmq_cfg.get('password')
    return creds


def add_cron_job(time_string, command, comment, user):
    job = f'{time_string} {command} # {comment}'

    cmd = (
        # Only add the job if it doesn't already exist
        f'(crontab -u {user} -l 2>/dev/null | grep -F "{job}" || '
        f'(crontab -u {user} -l 2>/dev/null; '
        f'echo "{job}") | crontab -u {user} - )'
    )
    run([cmd], shell=True)
