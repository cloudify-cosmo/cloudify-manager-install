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

import sys
import platform
import subprocess
import netifaces
import os
from getpass import getuser
from collections import namedtuple
from distutils.version import LooseVersion

from . import PRIVATE_IP, PUBLIC_IP, VALIDATIONS, SKIP_VALIDATIONS, SSL_INPUTS

from .service_names import MANAGER

from ..config import config
from ..logger import get_logger
from ..constants import USER_CONFIG_PATH
from ..exceptions import ValidationError

from ..utils.common import run, sudo
from ..utils.install import RpmPackageHandler

logger = get_logger(VALIDATIONS)

_errors = []


def _get_os_distro():
    distro, version, _ = \
        platform.linux_distribution(full_distribution_name=False)
    return distro.lower(), version.split('.')[0]


def _get_host_total_memory():
    """
    MemTotal:        7854400 kB
    MemFree:         1811840 kB
    MemAvailable:    3250176 kB
    Buffers:          171164 kB
    Cached:          1558216 kB
    SwapCached:       119180 kB
    """
    with open('/proc/meminfo') as memfile:
        memory = memfile.read()
    for attribute in memory.splitlines():
        if attribute.lower().startswith('memtotal'):
            return int(attribute.split(':')[1].strip().split(' ')[0]) / 1024


def _get_available_host_disk_space():
    """
    Filesystem                 Type 1G-blocks  Used Available Use% Mounted on
    /dev/mapper/my_file_system ext4      213G   63G      139G  32% /
    """
    df = subprocess.Popen(["df", "-BG", "/etc/issue"], stdout=subprocess.PIPE)
    output = df.communicate()[0]
    available_disk_space_in_gb = output.split("\n")[1].split()[3].rstrip('G')
    return int(available_disk_space_in_gb)


def _validate_supported_distros():
    logger.info('Validating supported distributions...')
    distro, version = _get_os_distro()
    supported_distros = config[VALIDATIONS]['supported_distros']
    supported_distro_versions = \
        config[VALIDATIONS]['supported_distro_versions']
    if distro not in supported_distros:
        _errors.append(
            'Cloudify manager does not support the current distro (`{0}`),'
            'supported distros are: {1}'.format(distro, supported_distros)
        )
    if version not in supported_distro_versions:
        _errors.append(
            'Cloudify manager does not support the current distro version '
            '(`{0}`), supported versions are: {1}'.format(
                version, supported_distro_versions
            )
        )


def _validate_private_ip():
    logger.info('Validating private IP address...')
    private_ip = config[MANAGER][PRIVATE_IP]
    all_addresses = set()
    found = False
    for interface in netifaces.interfaces():
        int_addresses = netifaces.ifaddresses(interface)
        if not int_addresses:
            logger.debug(
                'Could not find any addresses for interface {0}'.format(
                    interface))
            continue
        inet_addresses = int_addresses.get(netifaces.AF_INET)
        if not inet_addresses:
            logger.debug('No AF_INET addresses found for interface {0}'.format(
                interface))
            continue
        for inet_addr in inet_addresses:
            addr = inet_addr.get('addr')
            if not addr:
                logger.debug('No addr found for {0}'.format(inet_addr))
                continue
            if addr == private_ip:
                found = True
                break
            all_addresses.add(addr)
        if found:
            break

    if not found:
        _errors.append(
            "The provided private IP ({ip}) is not associated with any INET-"
            "type address available on this machine (available INET-type "
            "addresses: {addresses}). This will cause installation to fail. "
            "If you are certain that this IP address should be used, please "
            "set the '{param}' parameter to 'false'".format(
                ip=private_ip,
                addresses=', '.join(all_addresses),
                param=SKIP_VALIDATIONS))


def _validate_python_version():
    logger.info('Validating Python version...')
    major_version, minor_version = sys.version_info[0], sys.version_info[1]
    python_version = '{0}.{1}'.format(major_version, minor_version)
    expected_version = config[VALIDATIONS]['expected_python_version']
    if python_version != expected_version:
        error = 'Local python version (`{0}`) does not match expected ' \
                'version (`{1}`)'.format(python_version, expected_version)
        _errors.append(error)


def _validate_sufficient_memory():
    logger.info('Validating memory requirement...')
    current_memory = _get_host_total_memory()
    required_memory = \
        config[VALIDATIONS]['minimum_required_total_physical_memory_in_mb']
    if current_memory < required_memory:
        _errors.append(
            'The provided host does not have enough memory to run '
            'Cloudify Manager (Current: {0}MB, Required: {1}MB).'.format(
                current_memory, required_memory)
        )


def _validate_sufficient_disk_space():
    logger.info('Validating disk space requirement...')
    available_disk_space_in_gb = _get_available_host_disk_space()
    required_disk_space = \
        config[VALIDATIONS]['minimum_required_available_disk_space_in_gb']

    if available_disk_space_in_gb < required_disk_space:
        _errors.append(
            'The provided host does not have enough disk space to run '
            'Cloudify Manager (Current: {0}GB, Required: {1}GB).'.format(
                available_disk_space_in_gb, required_disk_space)
        )


def _validate_openssl_version():
    logger.info('Validating OpenSSL version...')
    required_version = '1.0.2'

    try:
        output = run(['openssl', 'version']).aggr_stdout
    except OSError as e:
        _errors.append(
            'Cloudify Manager requires OpenSSL {0}, Error: {1}'.format(
                required_version, e
            )
        )
        return

    # The output should look like: "LibreSSL 2.2.7" or "OpenSSL 1.0.2k-fips"
    version = output.split()[1]
    if LooseVersion(version) < LooseVersion(required_version):
        _errors.append(
            'Cloudify Manager requires OpenSSL {0}, current version: {1}'
            ''.format(required_version, version)
        )


def _validate_inputs():
    Input = namedtuple('Input', 'key string flag')
    required_inputs = [
        Input(key=PRIVATE_IP, flag='--private-ip', string='Private IP'),
        Input(key=PUBLIC_IP, flag='--public-ip', string='Public IP')
    ]
    for inp in required_inputs:
        input_value = config[MANAGER].get(inp.key)
        if not input_value:
            raise ValidationError(
                '{string} not set in the config.\n'
                'Possible solutions are:\n'
                '1. Set the `{key}` key in {config_path}\n'
                '2. Use the `{flag}` flag when running '
                '`cfy_manager install/configure`'.format(
                    string=inp.string,
                    key=inp.key,
                    config_path=USER_CONFIG_PATH,
                    flag=inp.flag
                )
            )


def _validate_user_has_sudo_permissions():
    current_user = getuser()
    logger.info('Validating user `{0}` has sudo permissions...'.format(
        current_user
    ))
    result = run(['sudo', '-n', 'true'])
    if result.returncode != 0:
        _errors.append(
            "Failed executing 'sudo'. Please ensure that the "
            "current user ({0}) is allowed to execute 'sudo' commands "
            "and impersonate other users using "
            "'sudo -u'. (Error: {1})".format(current_user, result.aggr_stderr)
        )


def _validate_dependencies():
    logger.info('Validating Cloudify Manager dependencies...')
    dependencies = {
        'sudo': 'necessary to run commands with root privileges',
        'openssl-1.0.2k': 'necessary for creating certificates',
        'logrotate': 'used in Cloudify logs',
        'systemd-sysv': 'required by the PostgreSQL DB',
        'initscripts': 'required by the RabbitMQ server',
        'which': 'used when installing Logstash plugins',
        'python-setuptools': 'required by python',
        'python-backports': 'required by python',
        'python-backports-ssl_match_hostname': 'required by python',
        'openssh-server': 'required by the sanity check'
    }

    missing_packages = {}
    for dep, reason in dependencies.items():
        logger.debug('Validating that `{dep}` is installed'.format(dep=dep))
        if not RpmPackageHandler.is_package_installed(dep):
            missing_packages[dep] = reason

    if missing_packages:
        error_msg = '\n'.join(
            '`{package}` - {reason}'.format(package=package, reason=reason)
            for package, reason in missing_packages.items()
        )
        packages = ' '.join(missing_packages.keys())
        raise ValidationError(
            'Prerequisite packages missing: \n{error_msg}.\n'
            'Please ensure these packages are installed and try again.\n'
            'Possible solution is to run - sudo yum install {packages}'
            .format(error_msg=error_msg, packages=packages)
        )


def _check_ssl_file(input_name, kind='Key', password=None):
    filename = config[SSL_INPUTS][input_name]
    if not os.path.isfile(filename):
        raise ValidationError(
            '{0} file {1} (input name: {2}) does not exist'
            .format(kind, filename, input_name))
    if kind == 'Key':
        check_command = ['openssl', 'rsa', '-in', filename, '-check', '-noout']
        if password:
            check_command += ['-passin', 'pass:{0}'.format(password)]
    elif kind == 'Cert':
        check_command = ['openssl', 'x509', '-in', filename, '-noout']
    else:
        raise ValueError('Unknown kind: {0}'.format(kind))
    proc = sudo(check_command, ignore_failures=True)
    if proc.returncode != 0:
        password_err = ''
        if password:
            password_err = '(or the provided password is incorrect)'
        raise ValidationError('{0} file {1} (input name: {2}) is invalid {3}'
                              .format(kind, filename, input_name,
                                      password_err))


def _check_key_and_cert(prefix):
    cert_input = '{0}_cert_path'.format(prefix)
    key_input = '{0}_key_path'.format(prefix)
    if [
        not config[SSL_INPUTS][cert_input],
        not config[SSL_INPUTS][key_input]
    ].count(True) == 1:
        raise ValidationError('Either both {0} and {1} must be provided, '
                              'or neither.'.format(cert_input, key_input))


def _validate_cert_inputs():
    ssl_inputs = config[SSL_INPUTS]
    if ssl_inputs['ca_key_path'] and ssl_inputs['ca_cert_path']:
        _check_ssl_file('ca_key_path', password=ssl_inputs['ca_key_password'])
        _check_ssl_file('ca_cert_path', kind='Cert')
    elif ssl_inputs['ca_key_path'] and not ssl_inputs['ca_cert_path']:
        raise ValidationError('Internal CA key provided, but the internal '
                              'CA cert was not')
    elif ssl_inputs['ca_cert_path'] and not ssl_inputs['ca_key_path']:
        if not ssl_inputs['internal_cert_path'] \
                or not ssl_inputs['internal_key_path']:
            raise ValidationError('If ca_cert_path was provided, but '
                                  'ca_key_path was not provided, both '
                                  'internal_cert_path and internal_key_path '
                                  'must be provided.')
    elif ssl_inputs['ca_key_password']:
        raise ValidationError('If ca_key_password was provided, both '
                              ' ca_cert_path and ca_key_path must be '
                              'provided.')

    _check_key_and_cert('internal')
    _check_key_and_cert('external')
    _check_key_and_cert('external_ca')


def validate_config_access(write_required):
    # It's OK if file doesn't exist.
    if os.path.isfile(USER_CONFIG_PATH):
        if write_required:
            mode = os.R_OK | os.W_OK
            label = 'readable and writable'
        else:
            mode = os.R_OK
            label = 'readable'

        if not os.access(USER_CONFIG_PATH, mode):
            raise ValidationError(
                'Configuration file ({0}) must be {1} '
                'by the current user'.format(
                    USER_CONFIG_PATH, label))


def validate(skip_validations=False):
    # Inputs always need to be validated, otherwise the install won't work
    _validate_inputs()

    # These dependencies also need to always be validated
    _validate_dependencies()

    if config[VALIDATIONS][SKIP_VALIDATIONS] or skip_validations:
        logger.info('Skipping validations')
        return

    logger.notice('Validating local machine...')
    _validate_private_ip()
    _validate_python_version()
    _validate_supported_distros()
    _validate_sufficient_memory()
    _validate_sufficient_disk_space()
    _validate_openssl_version()
    _validate_user_has_sudo_permissions()
    _validate_cert_inputs()

    if _errors:
        printable_error = 'Validation error(s):\n' \
                          '{0}'.format('\n'.join(_errors))
        raise ValidationError(printable_error)
    logger.notice('All validations passed successfully!')
