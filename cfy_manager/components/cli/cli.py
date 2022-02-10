import errno
import logging
import os
import pwd
from contextlib import contextmanager
from os.path import join, exists, expanduser

from ...components_constants import SECURITY, SSL_INPUTS
from ..base_component import BaseComponent
from ...service_names import CLI, MANAGER
from ...config import config
from ...logger import (get_logger,
                       set_file_handlers_level,
                       get_file_handlers_level)
from ...utils import common, certificates
from ...constants import (CA_CERT_PATH,
                          EXTERNAL_CA_CERT_PATH)

logger = get_logger(CLI)
PROFILE_NAME = 'manager-local'


@contextmanager
def _hide_logs():
    """Increase the logging level, so that the password isn't in the logfile"""
    current_level = get_file_handlers_level()
    set_file_handlers_level(logging.ERROR)
    try:
        yield
    finally:
        set_file_handlers_level(current_level)


def getuser():
    # Given that this will be under sudo, getpass.getuser will be unhelpful
    # Also, when using the sudo trampoline in main, os.getuid is returning 0
    return pwd.getpwuid(int(os.environ.get('SUDO_UID', 0))).pw_name


class Cli(BaseComponent):
    def _set_colors(self, is_root):
        """
        Makes sure colors are enabled by default in cloudify logs via CLI
        """

        home_dir = expanduser('~root') if is_root else expanduser('~')
        sed_cmd = 's/colors: false/colors: true/g'
        config_path = join(home_dir, '.cloudify', 'config.yaml')
        cmd = "/usr/bin/sed -i -e '{0}' {1}".format(sed_cmd, config_path)

        common.run([cmd], shell=True)

    def configure(self):
        logger.notice('Configuring Cloudify CLI...')
        username = config[MANAGER][SECURITY]['admin_username']
        password = config[MANAGER][SECURITY]['admin_password']

        current_user = getuser()

        manager = config[MANAGER]['cli_local_profile_host_name']
        if not manager:
            manager = config[MANAGER]['public_ip']

        use_cmd = ['profiles', 'use', PROFILE_NAME,
                   '--skip-credentials-validation']
        set_cmd = ['profiles', 'set', '-m', manager, '-t', 'default_tenant']
        if username:
            set_cmd += ['-u', username]
        if password:
            set_cmd += ['-p', password]
        if config[MANAGER][SECURITY]['ssl_enabled']:
            cert_path = self._deploy_external_cert()
            set_cmd += ['-c', cert_path, '--ssl', 'on']
        else:
            set_cmd += ['--ssl', 'off']
        if config['nginx']['port']:
            set_cmd += ['--rest-port', '{0}'.format(config['nginx']['port'])]

        logger.info('Setting CLI for the root user...')
        with _hide_logs():
            common.cfy(*use_cmd)
            common.cfy(*set_cmd)
        self._set_colors(is_root=True)

        if current_user != 'root':
            logger.info('Setting CLI for the current user (%s)...',
                        current_user)

            with _hide_logs():
                common.cfy(*use_cmd, as_user=current_user)
                common.cfy(*set_cmd, as_user=current_user)
            self._set_colors(is_root=False)

        logger.notice('Cloudify CLI successfully configured')

    def _remove_profile(self, profile, silent=False, as_user=None):
        proc = common.cfy('profiles', 'delete', profile,
                          ignore_failures=True, as_user=as_user)
        if silent:
            return
        if proc.returncode == 0:
            logger.notice('CLI profile removed')
        else:
            logger.warning('Failed removing CLI profile (rc=%s)',
                           proc.returncode)

    def remove(self, silent=False):
        profile_name = config[MANAGER]['cli_local_profile_host_name']
        try:
            logger.notice('Removing CLI profile for root user...')
            self._remove_profile(profile_name)

            current_user = getuser()
            if current_user != 'root':
                logger.notice('Removing CLI profile for %s user...',
                              current_user)
                self._remove_profile(profile_name, as_user=current_user)
        except OSError as ex:
            if ex.errno == errno.ENOENT:
                logger.warning('Could not find the `cfy` executable; it has '
                               'most likely been removed already or never '
                               'installed due to an error; skipping')
            else:
                raise

    def _deploy_external_cert(self):
        """Return the path of the external cert to use with the CLI.

        If provided, copy the external CA cert and return that.
        Otherwise, just return the external cert path.
        """
        if exists(config[SSL_INPUTS]['external_ca_cert_path']):
            certificates.use_supplied_certificates(
                SSL_INPUTS,
                logger,
                ca_destination=EXTERNAL_CA_CERT_PATH,
                prefix='external_ca_',
                just_ca_cert=True,
            )
            return EXTERNAL_CA_CERT_PATH
        else:
            return CA_CERT_PATH
