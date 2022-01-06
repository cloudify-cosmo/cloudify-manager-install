import re
import subprocess

from ..logger import get_logger

from .common import run
from ..exceptions import RPMNotFound, YumError, ProcessExecutionError

logger = get_logger('yum')


def is_package_installed(name):
    installed = run(['rpm', '-q', name], ignore_failures=True)
    if installed.returncode == 0:
        return True
    return False


def _yum_install(packages, disable_all_repos=True):
    logger.info('Installing {0}...'.format(', '.join(packages)))
    install_cmd = [
        'yum', 'install', '-y', '--disablerepo=*', '--enablerepo=cloudify'
    ] + packages
    if not disable_all_repos:
        install_cmd.remove('--disablerepo=*')
    run(install_cmd, stderr=subprocess.STDOUT)


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
        run(['yum', 'remove', '-y',
             '--setopt=clean_requirements_on_remove=1'] + packages)
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
    run(cmdline)


def is_premium_installed():
    return is_package_installed('cloudify-premium')
