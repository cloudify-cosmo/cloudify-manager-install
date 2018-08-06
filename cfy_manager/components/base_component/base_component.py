

from ..components_dependencies import *

from ...exceptions import ValidationError
from ...utils.install import RpmPackageHandler
from ...logger import get_logger


class BaseComponent:

    def __init__(self):
        self.logger = get_logger(self.__class__.__name__)

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
        dependencies_list = COMPONENTS_DEPENDENCIES['default'] + \
                            COMPONENTS_DEPENDENCIES[self.__class__.__name__]
        for dependency in dependencies_list:
            dependencies_dict.update(DEPENDENCIES_ERROR_MESSAGES[dependency])
        return dependencies_dict

    def validate_dependencies(self):
        missing_packages = {}
        for dep, reason in self._get_dependencies():
            self.logger.debug(
                'Validating that `{dep}` is installed for '
                '{class_name}'.format(dep=dep,
                                      class_name=self.__class__.__name__))
            if not RpmPackageHandler.is_package_installed(dep):
                missing_packages[dep] = reason

        if missing_packages:
            error_msg = '\n'.join(
                '`{package}` - {reason}'.format(package=package, reason=reason)
                for package, reason in missing_packages.items()
            )
            packages = ' '.join(missing_packages.keys())
            raise ValidationError(
                'Prerequisite packages for {class_name} missing: \n'
                '{error_msg}.\n Please ensure these packages are installed '
                'and try again.\n Possible solution is to run - sudo yum '
                'install {packages}'.format(class_name=self.__class__.__name__,
                                            error_msg=error_msg,
                                            packages=packages)
            )
        else:
            self.logger.debug(
                'All prerequisites for {class_name} are met'.format(
                    class_name=self.__class__.__name__))
