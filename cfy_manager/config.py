import logging

from collections.abc import MutableMapping
from os.path import isabs, isfile, join, abspath

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError
from ruamel.yaml.comments import CommentedMap

from .exceptions import InputError, ValidationError
from .constants import (
    DEFAULT_CONFIG_FILE_NAME,
    DEFAULT_CONFIG_PATH,
    CLOUDIFY_HOME_DIR,
)
from cfy_manager.utils.install_state import get_installed_services
yaml = YAML()
logger = logging.getLogger('[CONFIG]')


def dict_merge(target, source):
    """Merge source into target (like dict.update, but deep)

    Returns the merged-into dict.
    """
    to_merge = [(target, source)]
    while to_merge:
        left, right = to_merge.pop()
        overrides = {}
        for k in left.keys() | right.keys():
            if k not in right:
                continue
            original = left.get(k)
            updated = right[k]
            if (
                isinstance(original, MutableMapping) and
                isinstance(updated, MutableMapping)
            ):
                to_merge.append((original, updated))
            else:
                overrides[k] = updated
        left.update(overrides)
    return target


class Config(CommentedMap):
    TEMP_PATHS = 'temp_paths_to_remove'

    def _load_defaults_config(self):
        """
        If some services are already installed, default the list of
        services to that (it can still be overridden by the user's
        config.yaml).
        """
        default_config = self._load_yaml(DEFAULT_CONFIG_PATH)
        already_installed = get_installed_services()
        if already_installed:
            default_config['services_to_install'] = already_installed
        self.update(default_config)

    def _load_user_config(self, config_file):
        # Allow config_file not to exist - this is normal for teardown
        if isfile(config_file):
            # Override any default values with values from config_file
            user_config = self._load_yaml(config_file)
            dict_merge(self, user_config)

    def _load_yaml(self, path_to_yaml):
        try:
            with open(path_to_yaml) as f:
                yaml_data = f.read()
        except IOError as e:
            raise RuntimeError(
                'Cannot access {config}: {error}'.format(
                    config=path_to_yaml,
                    error=e
                )
            )

        try:
            return yaml.load(yaml_data)
        except YAMLError as e:
            raise InputError(
                'User config file {0} is not a properly formatted '
                'YAML file:\n{1}'.format(path_to_yaml, e)
            )

    def load_config(self, config_files=None):
        self._load_defaults_config()
        if not config_files:
            config_files = [DEFAULT_CONFIG_FILE_NAME]
        cleaned_config_files = []
        for config_file in config_files:
            config_file_path = self._sanitized_config_path(config_file)
            if config_file_path:
                logger.debug('Loading configuration from %s',
                             config_file_path)
                self._load_user_config(config_file_path)
                cleaned_config_files.append(config_file_path)
            else:
                raise ValidationError(
                    'Expected configuration files to be in {0}, but '
                    'got: {1}'.format(CLOUDIFY_HOME_DIR, config_file))
        self['config_files'] = cleaned_config_files

    def _sanitized_config_path(self, file_path):
        """Returns a file path in the CLOUDIFY_HOME_DIR or None."""
        if not isabs(file_path):
            file_path = abspath(join(CLOUDIFY_HOME_DIR, file_path))
        return file_path if file_path.startswith(CLOUDIFY_HOME_DIR) else None

    def add_temp_path_to_clean(self, new_path_to_remove):
        paths_to_remove = self.setdefault(self.TEMP_PATHS, [])
        paths_to_remove.append(new_path_to_remove)


config = Config()
