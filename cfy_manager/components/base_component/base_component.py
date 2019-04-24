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

from ..validations import check_certificates
from ..components_dependencies import (
    DEPENDENCIES_ERROR_MESSAGES, COMPONENTS_DEPENDENCIES)
from ...config import config
from ...constants import CLOUDIFY_USER, CLOUDIFY_GROUP
from ...exceptions import ValidationError
from ...utils.certificates import remove_key_encryption
from ...utils.install import RpmPackageHandler
from ...utils.common import sudo, move, copy
from ...logger import get_logger
from ...utils.common import chown
from ...utils.files import (
    write_to_file,
    remove_files
)

SANITY_MODE_FILE_PATH = '/opt/manager/sanity_mode'


class BaseComponent(object):

    def __init__(self, skip_installation=False):
        self.logger = get_logger(self.__class__.__name__)
        self.skip_installation = skip_installation

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
            if not RpmPackageHandler.is_package_installed(dep):
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

    def use_supplied_certificates(self, cert_destination, key_destination,
                                  ca_destination,
                                  owner=CLOUDIFY_USER, group=CLOUDIFY_GROUP):
        """Use user-supplied certificates, checking they're not broken."""
        cert_src, key_src, ca_src, key_pass = check_certificates(
            self.component_name,
        )

        if not any([cert_src, key_src, ca_src, key_pass]):
            # No certificates supplied, so not using them
            self.logger.debug('No user-supplied certificates were present.')
            return False

        # Put the files in the correct place
        self.logger.info('Ensuring files are in correct locations.')

        if cert_src != cert_destination:
            move(cert_src, cert_destination)
        if key_src != key_destination:
            move(key_src, key_destination)
        if ca_src != ca_destination:
            if ca_src:
                move(ca_src, ca_destination)
            else:
                copy(cert_destination, ca_destination)

        if key_pass:
            remove_key_encryption(
                ca_destination, ca_destination, key_pass
            )

        self.logger.info('Setting certificate ownership and permissions.')
        sudo(['chown', '{owner}.{group}'.format(owner=owner, group=group),
              cert_destination, key_destination, ca_destination])
        # Make key only readable by user and group
        sudo(['chmod', '440', key_destination])
        # Make certs readable by anyone
        sudo(['chmod', '444', cert_destination, ca_destination])

        self.logger.info('Updating configured certification locations.')
        config[self.component_name]['cert_path'] = cert_destination
        config[self.component_name]['key_path'] = key_destination
        config[self.component_name]['ca_path'] = ca_destination
        config[self.component_name]['key_password'] = key_pass

        # Supplied certificates were used
        return True

    @staticmethod
    def _enter_sanity_mode():
        write_to_file('sanity: True', SANITY_MODE_FILE_PATH)
        chown(CLOUDIFY_USER, CLOUDIFY_GROUP, SANITY_MODE_FILE_PATH)

    @staticmethod
    def _exit_sanity_mode():
        remove_files([SANITY_MODE_FILE_PATH])
