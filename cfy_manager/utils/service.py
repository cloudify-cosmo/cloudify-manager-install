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

from os.path import exists, join

from retrying import retry

from .files import deploy
from .common import run, sudo, remove as remove_file, chown

from ..config import config
from ..logger import get_logger
from ..constants import COMPONENTS_DIR, CLOUDIFY_USER, CLOUDIFY_GROUP
from ..exceptions import ValidationError

logger = get_logger('SystemD')


class SystemD(object):
    @staticmethod
    def systemctl(action, service='', retries=0, ignore_failure=False):
        systemctl_cmd = ['systemctl', action]
        if service:
            systemctl_cmd.append(service)
        return sudo(systemctl_cmd, retries=retries,
                    ignore_failures=ignore_failure)

    def configure(self, service_name,
                  user=CLOUDIFY_USER, group=CLOUDIFY_GROUP,
                  external_configure_params=None):
        """This configures systemd for a specific service.

        It requires that two files are present for each service one containing
        the environment variables and one containing the systemd config.
        All env files will be named "cloudify-SERVICENAME".
        All systemd config files will be named "cloudify-SERVICENAME.service".

        """
        sid = _get_full_service_name(service_name, append_prefix=True)
        env_dst = "/etc/sysconfig/{0}".format(sid)
        srv_dst = "/usr/lib/systemd/system/{0}.service".format(sid)

        service_dir_name = service_name.replace('-', '_')
        src_dir = join(COMPONENTS_DIR, service_dir_name, 'systemd')
        env_src = join(src_dir, sid)
        srv_src = join(src_dir, '{0}.service'.format(sid))

        if exists(env_src):
            logger.debug('Deploying systemd EnvironmentFile...')
            deploy(env_src, env_dst, render=True,
                   additional_render_context=external_configure_params)
            chown(user, group, env_dst)

        # components that have had their service file moved to a RPM, won't
        # have the file here.
        # TODO: after this is done to all components, this can be removed
        if exists(srv_src):
            logger.debug('Deploying systemd .service file...')
            deploy(srv_src, srv_dst, render=True)

        logger.debug('Enabling systemd .service...')
        self.systemctl('enable', '{0}.service'.format(sid))

    def remove(self, service_name, service_file=True, append_prefix=True):
        """Stop and disable the service, and then delete its data
        """
        self.stop(service_name,
                  ignore_failure=True, append_prefix=append_prefix)
        self.disable(service_name,
                     ignore_failure=True, append_prefix=append_prefix)

        # components that have had their unit file moved to the RPM, will
        # also remove it during RPM uninstall
        # TODO: remove this after all components have been changed to use RPMs
        if service_file:
            remove_file(self.get_service_file_path(
                service_name, append_prefix=append_prefix))

        remove_file(self.get_vars_file_path(
            service_name, append_prefix=append_prefix))

    @staticmethod
    def get_vars_file_path(service_name, append_prefix=True):
        """Returns the path to a systemd environment variables file
        for a given service_name. (e.g. /etc/sysconfig/cloudify-rabbitmq)
        """
        if append_prefix:
            sid = 'cloudify-{0}'.format(service_name)
        else:
            sid = service_name
        return '/etc/sysconfig/{0}'.format(sid)

    @staticmethod
    def get_service_file_path(service_name, append_prefix=True):
        """Returns the path to a systemd service file
        for a given service_name.
        (e.g. /usr/lib/systemd/system/cloudify-rabbitmq.service)
        """
        if append_prefix:
            sid = 'cloudify-{0}'.format(service_name)
        else:
            sid = service_name
        return "/usr/lib/systemd/system/{0}.service".format(sid)

    def enable(self, service_name):
        self.systemctl('enable', service_name)

    def disable(self, service_name, ignore_failure=False):
        self.systemctl('disable', service_name,
                       ignore_failure=ignore_failure)

    def start(self, service_name, ignore_failure=False):
        self.systemctl('start', service_name, ignore_failure=ignore_failure)

    def stop(self, service_name):
        self.systemctl('stop', service_name)

    def restart(self, service_name):
        self.systemctl('restart', service_name)

    def reload(self, service_name, append_prefix=True):
        full_service_name = self._get_full_service_name(service_name,
                                                        append_prefix)
        self.systemctl('reload', full_service_name)

    def is_alive(self, service_name):
        result = self.systemctl('status', service_name, ignore_failure=True)
        return result.returncode == 0


def _get_full_service_name(service_name, append_prefix):
    if append_prefix:
        return 'cloudify-{0}'.format(service_name)
    return service_name


class Supervisord(object):
    def supervisorctl(self, action, service='', ignore_failure=False):
        cmd = [
            'supervisorctl', '-c', '/etc/supervisord.conf', action
        ]
        if service:
            cmd += [service]
        return run(cmd, ignore_failures=ignore_failure)

    def enable(self, service_name):
        self.supervisorctl('update', service_name)

    def disable(self, service_name):
        self.supervisorctl('remove', service_name)

    def start(self, service_name, ignore_failure=False):
        self.supervisorctl(
            'start', service_name, ignore_failure=ignore_failure)

    def stop(self, service_name):
        self.supervisorctl('stop', service_name)

    def restart(self, service_name):
        self.supervisorctl('restart', service_name)

    def is_alive(self, service_name):
        result = self.supervisorctl(
            'status', service_name, ignore_failure=True)
        return result.returncode == 0

    def configure(self, service_name,
                  user=CLOUDIFY_USER, group=CLOUDIFY_GROUP,
                  external_configure_params=None,
                  src_dir=None):
        """This configures systemd for a specific service.

        It requires that two files are present for each service one containing
        the environment variables and one containing the systemd config.
        All env files will be named "cloudify-SERVICENAME".
        All systemd config files will be named "cloudify-SERVICENAME.service".

        """
        sid = _get_full_service_name(service_name, append_prefix=True)
        dst = '/etc/supervisord.d/{0}.cloudify.conf'.format(service_name)

        if src_dir is None:
            src_dir = service_name
        src_dir = src_dir.replace('-', '_')
        srv_src = join(COMPONENTS_DIR, src_dir, 'supervisord.conf')
        logger.info('srv %s', srv_src)
        if exists(srv_src):
            logger.debug('Deploying supervisord service file...')
            deploy(srv_src, dst, render=True,
                   additional_render_context=external_configure_params)

        self.enable(sid)


def _get_backend():
    if config.get('service_management', 'supervisord') == 'supervisord':
        return Supervisord()
    else:
        return SystemD()


def enable(service_name, append_prefix=True):
    full_service_name = _get_full_service_name(service_name, append_prefix)
    logger.debug('Enabling service {0}...'.format(full_service_name))
    return _get_backend().enable(full_service_name)


def disable(service_name, append_prefix=True):
    full_service_name = _get_full_service_name(service_name, append_prefix)
    logger.debug('Disabling service {0}...'.format(full_service_name))
    return _get_backend().disable(full_service_name)


def start(service_name, append_prefix=True, ignore_failure=False):
    full_service_name = _get_full_service_name(service_name, append_prefix)
    logger.debug('Starting service {0}...'.format(full_service_name))
    return _get_backend().start(
        full_service_name, ignore_failure=ignore_failure)


def stop(service_name, append_prefix=True):
    full_service_name = _get_full_service_name(service_name, append_prefix)
    logger.debug('Stopping service {0}...'.format(full_service_name))
    return _get_backend().stop(full_service_name)


def restart(service_name, append_prefix=True):
    full_service_name = _get_full_service_name(service_name, append_prefix)
    logger.debug('Restarting service {0}...'.format(full_service_name))
    return _get_backend().restart(full_service_name)


def remove(service_name, append_prefix=True, service_file=True):
    raise NotImplementedError()


@retry(stop_max_attempt_number=3, wait_fixed=1000)
def verify_alive(service_name, append_prefix=True):
    full_service_name = _get_full_service_name(service_name, append_prefix)
    if _get_backend().is_alive(full_service_name):
        logger.debug('{0} is running'.format(full_service_name))
    else:
        raise ValidationError('{0} is not running'.format(full_service_name))


def is_alive(service_name, append_prefix=True):
    full_service_name = _get_full_service_name(service_name, append_prefix)
    return _get_backend().is_alive(full_service_name)


def configure(service_name, user=CLOUDIFY_USER, group=CLOUDIFY_GROUP,
              external_configure_params=None, src_dir=None):
    return _get_backend().configure(
        service_name, user, group, external_configure_params,
        src_dir=src_dir)
