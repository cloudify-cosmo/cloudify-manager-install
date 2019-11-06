#########
# Copyright (c) 2017 GigaSpaces Technologies Ltd. All rights reserved
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

import csv
import glob
import os
import shlex
import socket
import subprocess
import tempfile

import requests

from ..config import config
from ..logger import get_logger
from ..exceptions import ProcessExecutionError

from cfy_manager.components.components_constants import SERVICES_TO_INSTALL
from cfy_manager.components.service_components import (QUEUE_SERVICE,
                                                       MANAGER_SERVICE,
                                                       DATABASE_SERVICE)
from cfy_manager.components.service_names import (
    POSTGRESQL_CLIENT,
    POSTGRESQL_SERVER,
)

from . import subprocess_preexec

logger = get_logger('utils')


def run(command, retries=0, stdin=b'', ignore_failures=False,
        globx=False, shell=False, env=None, stdout=None):
    # TODO: add ability to *log* output, instead of just printing to stdout
    if isinstance(command, str) and not shell:
        command = shlex.split(command)
    stderr = subprocess.PIPE
    stdout = stdout or subprocess.PIPE
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
    if proc.returncode != 0:
        command_str = ' '.join(command)
        if retries:
            logger.warn('Failed running command: {0}. Retrying. '
                        '({1} left)'.format(command_str, retries))
            proc = run(command, retries - 1)
        elif not ignore_failures:
            msg = 'Failed running command: {0} ({1}).'.format(
                command_str, proc.aggr_stderr)
            raise ProcessExecutionError(msg, proc.returncode)
    return proc


def sudo(command, *args, **kwargs):
    if isinstance(command, str):
        command = shlex.split(command)
    if 'env' in kwargs:
        command = ['sudo', '-E'] + command
    else:
        command.insert(0, 'sudo')
    return run(command=command, *args, **kwargs)


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


def copy(source, destination):
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
        and config[POSTGRESQL_CLIENT]['host'] in (
            '127.0.0.1', 'localhost',
        )
        and config[POSTGRESQL_SERVER]['cluster']['nodes']
    )


def get_haproxy_servers(logger):
    # Get the haproxy status data
    try:
        haproxy_csv = requests.get(
            'http://localhost:7000/admin?stats;csv;norefresh'
        ).text
    except requests.ConnectionError as err:
        logger.info(
            'Could not connect to DB proxy ({err}), '.format(err=err)
        )
        return None

    # Example output (# noqas are not part of actual output):
    # # pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,sid,throttle,lbtot,tracked,type,rate,rate_lim,rate_max,check_status,check_code,check_duration,hrsp_1xx,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other,hanafail,req_rate,req_rate_max,req_tot,cli_abrt,srv_abrt,comp_in,comp_out,comp_byp,comp_rsp,lastsess,last_chk,last_agt,qtime,ctime,rtime,ttime,  # noqa
    # stats,FRONTEND,,,1,1,2000,7,553,83778,0,0,0,,,,,OPEN,,,,,,,,,1,1,0,,,,0,1,0,1,,,,0,6,0,0,0,0,,1,1,7,,,0,0,0,0,,,,,,,,  # noqa
    # stats,BACKEND,0,0,0,0,200,0,553,83778,0,0,,0,0,0,0,UP,0,0,0,,0,89,0,,1,1,0,,0,,1,0,,0,,,,0,0,0,0,0,0,,,,,0,0,0,0,0,0,0,,,0,0,0,0,  # noqa
    # postgres,FRONTEND,,,0,0,2000,0,0,0,0,0,0,,,,,OPEN,,,,,,,,,1,2,0,,,,0,0,0,0,,,,,,,,,,,0,0,0,,,0,0,0,0,,,,,,,,  # noqa
    # postgres,postgresql_192.0.2.46_5432,0,0,0,0,100,0,0,0,,0,,0,0,0,0,DOWN,1,1,0,1,1,89,89,,1,2,1,,0,,2,0,,0,L7STS,503,3,,,,,,,0,,,,0,0,,,,,-1,HTTP status check returned code <503>,,0,0,0,0,  # noqa
    # postgres,postgresql_192.0.2.47_5432,0,0,0,0,100,0,0,0,,0,,0,0,0,0,UP,1,1,0,0,0,89,0,,1,2,2,,0,,2,0,,0,L7OK,200,3,,,,,,,0,,,,0,0,,,,,-1,HTTP status check returned code <200>,,0,0,0,0,  # noqa
    # postgres,postgresql_192.0.2.48_5432,0,0,0,0,100,0,0,0,,0,,0,0,0,0,DOWN,1,1,0,1,1,87,87,,1,2,3,,0,,2,0,,0,L7STS,503,2,,,,,,,0,,,,0,0,,,,,-1,HTTP status check returned code <503>,,0,0,0,0,  # noqa
    # postgres,BACKEND,0,0,0,0,200,0,0,0,0,0,,0,0,0,0,UP,1,1,0,,0,89,0,,1,2,0,,0,,1,0,,0,,,,,,,,,,,,,,0,0,0,0,0,0,-1,,,0,0,0,0,  # noqa
    haproxy_status = list(csv.DictReader(
        haproxy_csv.lstrip('# ').splitlines()
    ))

    servers = [
        row for row in haproxy_status
        if row['svname'] not in ('BACKEND', 'FRONTEND')
    ]

    for server in servers:
        logger.debug(
            'Server: {name}: {status} ({why}) - {detail}'.format(
                name=server['svname'],
                status=server['status'],
                why=server['check_status'],
                detail=server['last_chk'],
            )
        )

    return servers


def is_all_in_one_manager():
    return (
        MANAGER_SERVICE in config[SERVICES_TO_INSTALL] and
        DATABASE_SERVICE in config[SERVICES_TO_INSTALL] and
        QUEUE_SERVICE in config[SERVICES_TO_INSTALL]
    )
