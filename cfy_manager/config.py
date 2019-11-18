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
from contextlib import contextmanager
from getpass import getuser
from os.path import isfile
import pwd
import subprocess

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError
from ruamel.yaml.comments import CommentedMap

from .exceptions import InputError, BootstrapError
from .constants import USER_CONFIG_PATH, DEFAULT_CONFIG_PATH, CLOUDIFY_USER
from cfy_manager.components.components_constants import (
    ENABLE_REMOTE_CONNECTIONS,
    SERVICES_TO_INSTALL,
    SSL_ENABLED,
)
from cfy_manager.components.service_components import (
    DATABASE_SERVICE,
    MANAGER_SERVICE,
)
from cfy_manager.components.service_names import (
    POSTGRESQL_CLIENT,
    POSTGRESQL_SERVER,
)

yaml = YAML()


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
    for k, v in merge_dct.iteritems():
        if (k in dct and isinstance(dct[k], dict)
                and isinstance(merge_dct[k], collections.Mapping)):
            dict_merge(dct[k], merge_dct[k])
        else:
            dct[k] = merge_dct[k]


class Config(CommentedMap):
    TEMP_PATHS = 'temp_paths_to_remove'

    def _load_defaults_config(self):
        default_config = self._load_yaml(DEFAULT_CONFIG_PATH)
        self.update(default_config)

    def _load_user_config(self):
        # Allow `config.yaml` not to exist - this is normal for teardown
        if isfile(USER_CONFIG_PATH):
            # Override any default values with values from config.yaml
            user_config = self._load_yaml(USER_CONFIG_PATH)
            dict_merge(self, user_config)

    @contextmanager
    def _own_config_file(self):
        try:
            # Not using common module because of circular import issues
            subprocess.check_call([
                'sudo', 'chown', getuser() + '.', USER_CONFIG_PATH
            ])
            yield
        finally:
            try:
                pwd.getpwnam('cfyuser')
                subprocess.check_call([
                    'sudo', 'chown', CLOUDIFY_USER + '.', USER_CONFIG_PATH
                ])
            except KeyError:
                # No cfyuser, don't pass ownnership back (this is probably a
                # DB or rabbit node)
                pass

    def _load_yaml(self, path_to_yaml):
        try:
            with self._own_config_file():
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

    def _apply_forced_settings(self):
        if (
            (
                MANAGER_SERVICE not in self[SERVICES_TO_INSTALL]
                and DATABASE_SERVICE in self[SERVICES_TO_INSTALL]
            )
            or (
                DATABASE_SERVICE not in self[SERVICES_TO_INSTALL]
                and MANAGER_SERVICE in self[SERVICES_TO_INSTALL]
            )
        ):
            self[POSTGRESQL_SERVER][SSL_ENABLED] = True
            self[POSTGRESQL_SERVER][ENABLE_REMOTE_CONNECTIONS] = True
            self[POSTGRESQL_CLIENT][SSL_ENABLED] = True

    def load_config(self):
        self._load_defaults_config()
        self._load_user_config()
        # self._apply_forced_settings()

    def add_temp_path_to_clean(self, new_path_to_remove):
        paths_to_remove = self.setdefault(self.TEMP_PATHS, [])
        paths_to_remove.append(new_path_to_remove)


config = Config()
