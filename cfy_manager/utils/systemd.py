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
from .common import sudo, remove, chown

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

    def configure(self, service_name, render=True,
                  user=CLOUDIFY_USER, group=CLOUDIFY_GROUP,
                  external_configure_params=None):
        """This configures systemd for a specific service.

        It requires that two files are present for each service one containing
        the environment variables and one containing the systemd config.
        All env files will be named "cloudify-SERVICENAME".
        All systemd config files will be named "cloudify-SERVICENAME.service".

        """
        sid = 'cloudify-{0}'.format(service_name)
        env_dst = "/etc/sysconfig/{0}".format(sid)
        srv_dst = "/usr/lib/systemd/system/{0}.service".format(sid)

        service_dir_name = service_name.replace('-', '_')
        src_dir = join(COMPONENTS_DIR, service_dir_name, 'config')
        env_src = join(src_dir, sid)
        srv_src = join(src_dir, '{0}.service'.format(sid))

        if exists(env_src):
            logger.debug('Deploying systemd EnvironmentFile...')
            deploy(env_src, env_dst, render=render,
                   additional_render_context=external_configure_params)
            chown(user, group, env_dst)

        # components that have had their service file moved to a RPM, won't
        # have the file here.
        # TODO: after this is done to all components, this can be removed
        if exists(srv_src):
            logger.debug('Deploying systemd .service file...')
            deploy(srv_src, srv_dst, render=render,
                   additional_render_context=external_configure_params)

        logger.debug('Enabling systemd .service...')
        self.systemctl('enable', '{0}.service'.format(sid))

        self.systemctl('daemon-reload')

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
            remove(self.get_service_file_path(service_name,
                                              append_prefix=append_prefix))

        remove(self.get_vars_file_path(service_name,
                                       append_prefix=append_prefix))

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

    def enable(self, service_name, retries=0, append_prefix=True):
        full_service_name = self._get_full_service_name(service_name,
                                                        append_prefix)
        logger.debug('Enabling systemd service {0}...'.format(
            full_service_name))
        self.systemctl('enable', full_service_name, retries)

    def disable(self, service_name, retries=0, append_prefix=True,
                ignore_failure=False):
        full_service_name = self._get_full_service_name(service_name,
                                                        append_prefix)
        logger.debug('Disabling systemd service {0}...'.format(
            full_service_name))
        self.systemctl('disable', full_service_name, retries,
                       ignore_failure=ignore_failure)

    def start(self, service_name, retries=0, append_prefix=True):
        full_service_name = self._get_full_service_name(service_name,
                                                        append_prefix)
        logger.debug('Starting systemd service {0}...'.format(
            full_service_name))
        self.systemctl('start', full_service_name, retries)

    def stop(self, service_name, retries=0, append_prefix=True,
             ignore_failure=False):
        full_service_name = self._get_full_service_name(service_name,
                                                        append_prefix)
        logger.debug('Stopping systemd service {0}...'.format(
            full_service_name))
        self.systemctl('stop', full_service_name, retries,
                       ignore_failure=ignore_failure)

    def restart(self,
                service_name,
                retries=0,
                ignore_failure=False,
                append_prefix=True):
        full_service_name = self._get_full_service_name(service_name,
                                                        append_prefix)
        self.systemctl('restart', full_service_name, retries,
                       ignore_failure=ignore_failure)

    def is_alive(self, service_name, append_prefix=True):
        service_name = self._get_full_service_name(service_name, append_prefix)
        result = self.systemctl('status', service_name, ignore_failure=True)
        return result.returncode == 0

    @retry(stop_max_attempt_number=3, wait_fixed=1000)
    def verify_alive(self, service_name, append_prefix=True):
        if self.is_alive(service_name, append_prefix):
            logger.debug('{0} is running'.format(service_name))
        else:
            raise ValidationError('{0} is not running'.format(service_name))

    @staticmethod
    def _get_full_service_name(service_name, append_prefix):
        if append_prefix:
            return 'cloudify-{0}'.format(service_name)
        return service_name


systemd = SystemD()
