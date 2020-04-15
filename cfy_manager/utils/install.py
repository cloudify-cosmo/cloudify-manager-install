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
import re

from ..logger import get_logger

from .common import run, sudo
from ..exceptions import RPMNotFound, YumError, ProcessExecutionError

logger = get_logger('yum')


class RpmPackageHandler(object):

    def __init__(self, source_path):
        self.source_path = source_path
        self.package_name = self.get_rpm_package_name()

    def remove_existing_rpm_package(self):
        """Removes any version that satisfies the package name of the given
        source path.
        """
        if self.is_package_installed(self.package_name):
            logger.debug(
                'Removing existing package sources for package '
                'with name: {0}'.format(self.package_name))
            sudo(['rpm', '--noscripts', '-e', self.package_name])

    @staticmethod
    def is_package_installed(name):
        installed = run(['rpm', '-q', name], ignore_failures=True)
        if installed.returncode == 0:
            return True
        return False

    def is_rpm_installed(self):
        """Returns true if provided rpm is already installed.
        """
        src_query = run(['rpm', '-qp', self.source_path])
        source_name = src_query.aggr_stdout.rstrip('\n\r')

        return self.is_package_installed(source_name)

    def get_rpm_package_name(self):
        """Returns the package name according to the info provided in the
        source file.
        """
        split_index = ' : '
        package_details = {}
        package_details_query = run(['rpm', '-qpi', self.source_path])
        rows = package_details_query.aggr_stdout.split('\n')
        # split raw data according to the ' : ' index
        for row in rows:
            if split_index in row:
                first_columb_index = row.index(split_index)
                key = row[:first_columb_index].strip()
                value = row[first_columb_index + len(split_index):].strip()
                package_details[key] = value
        return package_details['Name']


def _yum_install(packages, disable_all_repos=True):
    logger.info('Installing {0}...'.format(', '.join(packages)))
    install_cmd = [
        'yum', 'install', '-y', '--disablerepo=*', '--enablerepo=cloudify'
    ] + packages
    if not disable_all_repos:
        install_cmd.remove('--disablerepo=*')
    sudo(install_cmd)


def is_package_available(package, disable_all_repos=True):
    command = ['yum', '-q', 'list', '--disablerepo=*',
               '--enablerepo=cloudify', package]
    if not disable_all_repos:
        command.remove('--disablerepo=*')
    try:
        sudo(command)
    except ProcessExecutionError as e:
        if re.search('^Error: No matching', e.aggr_stderr, re.MULTILINE):
            return False
        raise YumError(package, e.aggr_stdout)
    else:
        return True


def yum_install(packages, disable_all_repos=True):
    """Installs a package using yum.

    :param packages: list of package names to install
    :param disable_all_repos: whether to disable all rpm repos, but keep
           the local repo enabled anyway
    """
    try:
        _yum_install(packages, disable_all_repos=disable_all_repos)
    except ProcessExecutionError as e:
        if re.search('^No package', e.aggr_stdout, re.MULTILINE):
            raise RPMNotFound(', '.join(packages))
        logger.error(e.aggr_stdout)
        raise YumError(', '.join(packages), e.aggr_stdout)


def yum_remove(packages, ignore_failures=False):
    logger.info('yum removing {0}...'.format(', '.join(packages)))
    try:
        sudo(['yum', 'remove', '-y'] + packages)
    except ProcessExecutionError as e:
        msg = 'Packages `{0}` may not been removed successfully'.format(
            ', '.join(packages))
        if not ignore_failures:
            logger.error(msg)
            raise YumError(packages, e.aggr_stdout)
        logger.warn(msg)


def pip_install(source, venv='', constraints_file=None):
    log_message = 'Installing {0}'.format(source)

    pip_cmd = '{0}/bin/pip'.format(venv) if venv else 'pip'
    cmdline = [pip_cmd, 'install', source, '--upgrade']

    if venv:
        log_message += ' in virtualenv {0}'.format(venv)
    if constraints_file:
        cmdline.extend(['-c', constraints_file])
        log_message += ' using constraints file {0}'.format(constraints_file)

    logger.info(log_message)
    sudo(cmdline)


def is_premium_installed():
    return RpmPackageHandler.is_package_installed('cloudify-premium')
