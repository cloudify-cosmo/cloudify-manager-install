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
    DEPENDENCIES_ERROR_MESSAGES, COMPONENTS_DEPENDENCIES)
from ...constants import CLOUDIFY_USER, CLOUDIFY_GROUP
from ...exceptions import ValidationError
from ...utils.install import is_package_installed
from ...utils.certificates import use_supplied_certificates
from ...utils import service
from ...logger import get_logger


class BaseComponent(object):
    def __init__(self):
        self.logger = get_logger(self.__class__.__name__)
        self.service_type = service._get_service_type()

    def install(self):
        pass

    def configure(self):
        pass

    def start(self):
        pass

    def stop(self):
        pass

    def remove(self):
        pass

    def _get_dependencies(self):
        dependencies_dict = {}
        dependencies_list = \
            COMPONENTS_DEPENDENCIES['default'] + \
            COMPONENTS_DEPENDENCIES[self.__class__.__name__]
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

    def use_supplied_certificates(self,
                                  cert_destination=None,
                                  key_destination=None,
                                  ca_destination=None,
                                  owner=CLOUDIFY_USER,
                                  group=CLOUDIFY_GROUP,
                                  key_perms='440',
                                  cert_perms='444'):
        return use_supplied_certificates(
            component_name=self.component_name,
            logger=self.logger,
            cert_destination=cert_destination,
            key_destination=key_destination,
            ca_destination=ca_destination,
            owner=owner,
            group=group,
            key_perms=key_perms,
            cert_perms=cert_perms,
        )
