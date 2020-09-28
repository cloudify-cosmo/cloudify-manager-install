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

import collections
import logging
import os
import pwd
import subprocess

from contextlib import contextmanager
from getpass import getuser
from os.path import isfile, join, abspath

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError
from ruamel.yaml.comments import CommentedMap

from .exceptions import InputError, BootstrapError, ValidationError
from .constants import (
    DEFAULT_CONFIG_FILE_NAME,
    USER_CONFIG_PATH,
    DEFAULT_CONFIG_PATH,
    CLOUDIFY_USER,
    CLOUDIFY_HOME_DIR,
    INITIAL_INSTALL_DIR
)
yaml = YAML()
logger = logging.getLogger('[CONFIG]')


def dict_merge(dct, merge_dct):
    """ Recursive dict merge. Inspired by :meth:``dict.update()``, instead of
    updating only top-level keys, dict_merge recurses down into dicts nested
    to an arbitrary depth, updating keys. The ``merge_dct`` is merged into
    ``dct``.
    Taken from: https://gist.github.com/angstwad/bf22d1822c38a92ec0a9
    :param dct: dict onto which the merge is executed
    :param merge_dct: dct merged into dct
    :return: None
    """
    for k, _ in merge_dct.items():
        if (k in dct and isinstance(dct[k], dict)
                and isinstance(merge_dct[k], collections.Mapping)):
            dict_merge(dct[k], merge_dct[k])
        else:
            dct[k] = merge_dct[k]


class Config(CommentedMap):
    TEMP_PATHS = 'temp_paths_to_remove'

    def _get_installed_services(self):
        """List of already installed services.

        If some services are already installed, default the list of
        services to that (it can still be overridden by the user's
        config.yaml).
        """
        try:
            return os.listdir(INITIAL_INSTALL_DIR)
        except OSError:
            return []

    def _load_defaults_config(self):
        default_config = self._load_yaml(DEFAULT_CONFIG_PATH)
        already_installed = self._get_installed_services()
        if already_installed:
            default_config['services_to_install'] = already_installed
        self.update(default_config)

    def _load_user_config(self, config_file):
        # Allow config_file not to exist - this is normal for teardown
        if isfile(config_file):
            # Override any default values with values from config_file
            user_config = self._load_yaml(config_file)
            dict_merge(self, user_config)

    @contextmanager
    def _own_config_file(self, config_file_path=USER_CONFIG_PATH):
        try:
            # Not using common module because of circular import issues
            subprocess.check_call([
                'sudo', 'chown', getuser() + '.', config_file_path
            ])
            yield
        finally:
            try:
                pwd.getpwnam('cfyuser')
                subprocess.check_call([
                    'sudo', 'chown', CLOUDIFY_USER + '.', config_file_path
                ])
            except KeyError:
                # No cfyuser, don't pass ownnership back (this is probably a
                # DB or rabbit node)
                pass

    def _load_yaml(self, path_to_yaml):
        try:
            with self._own_config_file(path_to_yaml):
                with open(path_to_yaml, 'r') as f:
                    return yaml.load(f)
        except YAMLError as e:
            raise InputError(
                'User config file {0} is not a properly formatted '
                'YAML file:\n{1}'.format(path_to_yaml, e)
            )
        except IOError as e:
            raise RuntimeError(
                'Cannot access {config}: {error}'.format(
                    config=path_to_yaml,
                    error=e
                )
            )

    def dump_config(self):
        if not self.get('save_config', True):
            return
        self.pop(self.TEMP_PATHS, None)
        try:
            with self._own_config_file():
                with open(USER_CONFIG_PATH, 'w') as f:
                    yaml.dump(CommentedMap(self, relax=True), f)
        except (IOError, YAMLError) as e:
            raise BootstrapError(
                'Could not dump config to {0}:\n{1}'.format(
                    USER_CONFIG_PATH, e
                )
            )

    def load_config(self, config_files=None):
        self._load_defaults_config()
        if not config_files:
            config_files = [DEFAULT_CONFIG_FILE_NAME]
        for config_file in config_files:
            config_file_path = self._sanitized_config_path(config_file)
            if config_file_path:
                logger.info('Loading configuration from %s',
                            config_file_path)
                self._load_user_config(config_file_path)
            else:
                raise ValidationError(
                    'Expected configuration files to be in {0}, but '
                    'got: {1}'.format(CLOUDIFY_HOME_DIR, config_file))

    def _sanitized_config_path(self, file_path):
        """Returns a file path in the CLOUDIFY_HOME_DIR or None."""
        sanitized = abspath(join(CLOUDIFY_HOME_DIR, file_path))
        return sanitized if sanitized.startswith(CLOUDIFY_HOME_DIR) else None

    def add_temp_path_to_clean(self, new_path_to_remove):
        paths_to_remove = self.setdefault(self.TEMP_PATHS, [])
        paths_to_remove.append(new_path_to_remove)


config = Config()
