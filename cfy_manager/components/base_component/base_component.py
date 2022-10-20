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

from ..components_dependencies import (
    DEPENDENCIES_ERROR_MESSAGES,
    COMPONENTS_DEPENDENCIES,
    COMPONENTS_DEPENDENCIES_RH8)
from ...exceptions import ValidationError
from ...utils.install import is_package_installed
from ...utils import service
from ...logger import get_logger
from ..validations import _get_os_distro


class BaseComponent(object):
    services = {}

    def __init__(self):
        self.logger = get_logger(self.__class__.__name__)

    def install(self):
        pass

    def configure(self):
        pass

    def configure_service(self, service_name, service_config=None):
        pass

    def start(self):
        self.logger.info('Starting component')
        for name, conf in self.services.items():
            is_group = conf.get('is_group', False)
            service.restart(name, is_group)
            service.verify_alive(name, is_group)
        self.verify_started()
        self.logger.info('Component started')

    def stop(self, force=True):
        self.logger.info('Stopping component')
        for name, conf in self.services.items():
            if force or service.is_installed(name):
                service.stop(name, conf.get('is_group', False))
        self.logger.info('Component stopped')

    def remove(self):
        pass

    def upgrade(self):
        for service_name, service_config in self.services.items():
            if not service.is_installed(service_name):
                self.configure_service(service_name, service_config)

    def verify_started(self):
        pass

    def _get_dependencies(self):
        dependencies_dict = {}
        dependencies_list = \
            COMPONENTS_DEPENDENCIES['default'] + \
            COMPONENTS_DEPENDENCIES[self.__class__.__name__]
        _, rh_version = _get_os_distro()
        if rh_version == "8":
            dependencies_list = \
                COMPONENTS_DEPENDENCIES_RH8['default'] + \
                COMPONENTS_DEPENDENCIES_RH8[self.__class__.__name__]
        for dependency in dependencies_list:
            dependencies_dict.update({
                dependency: DEPENDENCIES_ERROR_MESSAGES[dependency]})
        return dependencies_dict

    def validate_dependencies(self):
        missing_packages = {}
        for dep, reason in self._get_dependencies().items():
            self.logger.debug(
                'Validating that `{dep}` is installed for '
                '{class_name}'.format(dep=dep,
                                      class_name=self.__class__.__name__))
            if not is_package_installed(dep):
                missing_packages[dep] = reason

        if missing_packages:
            error_msg = '\n'.join(
                '`{package}` - {reason}'.format(package=package,
                                                reason=reason)
                for package, reason in missing_packages.items()
            )
            packages = ' '.join(missing_packages.keys())
            raise ValidationError(
                # TODO: update class_name to show service/component
                'Prerequisite packages for {class_name} missing: \n'
                '{error_msg}.\n Please ensure these packages are installed '
                'and try again.\n Possible solution is to run - sudo yum '
                'install {packages}'.format(
                    class_name=self.__class__.__name__,
                    error_msg=error_msg,
                    packages=packages)
            )
        else:
            self.logger.debug(
                'All prerequisites for {class_name} are met'.format(
                    class_name=self.__class__.__name__))

    def replace_certificates(self):
        pass

    def validate_new_certs(self):
        pass
