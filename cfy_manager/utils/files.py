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

import os
import re
import json
from glob import glob
from tempfile import mkstemp
from os.path import join, isabs

import yaml
from jinja2 import Environment, FileSystemLoader

from .network import is_url, curl_download
from .common import move, sudo, copy, remove, chown

from ..config import config
from ..logger import get_logger
from ..exceptions import FileError
from ..constants import CLOUDIFY_SOURCES_PATH, COMPONENTS_DIR

logger = get_logger('Files')

_template_env = Environment(loader=FileSystemLoader('/'))


def read(path):
    with open(path, 'r') as f:
        return f.read()


def sudo_read(path):
    # This will probably fail with binary files
    # If we start needing it for such files, the best approach is likely:
    # copy to tmpfile; chown; read; delete tmpfile
    return sudo(['cat', path]).aggr_stdout


def replace_in_file(this, with_this, in_here):
    """Replaces all occurrences of the regex in all matches
    from a file with a specific value.
    """
    logger.debug('Replacing {0} with {1} in {2}...'.format(
        this, with_this, in_here))
    content = read(in_here)
    new_content = re.sub(this, with_this, content)
    write_to_file(new_content, in_here)


def ln(source, target, params=None):
    logger.debug('Linking {0} to {1} with params {2}'.format(
        source, target, params))
    command = ['ln']
    if params:
        command.append(params)
    command.append(source)
    command.append(target)
    if '*' in source or '*' in target:
        sudo(command, globx=True)
    else:
        sudo(command)


def get_local_source_path(source_url):
    if is_url(source_url):
        return curl_download(source_url)
    # If it's already an absolute path, just return it
    if isabs(source_url):
        return source_url

    # Otherwise, it's a relative `sources` path
    path = join(CLOUDIFY_SOURCES_PATH, source_url)
    path = get_glob_path(path)
    if not os.path.exists(path):
        raise FileError(
            'File {path} not found.'.format(path=path)
        )
    return path


def get_glob_path(path):
    if '*' in path:
        matching_paths = glob(path)
        if not matching_paths:
            raise FileError(
                'Could not locate source matching {0}'.format(path)
            )
        if len(matching_paths) > 1:
            raise FileError(
                'Expected to find single source matching '
                '{0}, but found: {1}'.format(path, matching_paths)
            )
        path = matching_paths[0]
    return path


def write_to_tempfile(contents, json_dump=False, cleanup=True):
    fd, file_path = mkstemp()
    os.close(fd)
    if json_dump:
        contents = json.dumps(contents)

    with open(file_path, 'w') as f:
        f.write(contents)

    if cleanup:
        config.add_temp_path_to_clean(file_path)
    return file_path


def write_to_file(contents, destination, json_dump=False):
    """ Used to write files to locations that require sudo to access """

    temp_path = write_to_tempfile(contents, json_dump=json_dump, cleanup=False)
    move(temp_path, destination)


def remove_temp_files():
    logger.debug('Cleaning temporary files...')
    for path in config.get('temp_paths_to_remove', []):
        remove(path)
    logger.debug('Cleaned temporary files')


def remove_files(file_list, ignore_failure=False):
    for path in file_list:
        logger.debug('Removing {0}...'.format(path))
        sudo(['rm', '-rf', path], ignore_failures=ignore_failure)


def deploy(src, dst, render=True, additional_render_context=None):
    if render:
        if additional_render_context is None:
            additional_render_context = {}
        template = _template_env.get_template(src)
        render_context = additional_render_context.copy()
        render_context.update(config)
        content = template.render(**render_context)
        write_to_file(content, dst)
    else:
        copy(src, dst)


def _get_notice_path(service_name):
    return join('/opt', '{0}_NOTICE.txt'.format(service_name))


def copy_notice(service_name):
    src = join(COMPONENTS_DIR, service_name, 'NOTICE.txt')
    copy(src, _get_notice_path(service_name))


def remove_notice(service_name):
    remove(_get_notice_path(service_name))


def temp_copy(source):
    """ Create a copy at a temporary location """
    content = read(source)
    return write_to_tempfile(content)


def touch(file_path):
    """ Create an empty file in the provided path """
    sudo(['touch', file_path])


def check_rpms_are_present(rpm_list):
    if not isinstance(rpm_list, list):
        rpm_list = [rpm_list]

    for rpm in rpm_list:
        try:
            get_local_source_path(rpm)
        except FileError:
            return False
    return True


def update_yaml_file(yaml_path, user_owner, group_owner, updated_content):
    if not isinstance(updated_content, dict):
        raise ValueError('Expected input of type dict, got {0} '
                         'instead'.format(type(updated_content)))
    if os.path.exists(yaml_path) and os.path.isfile(yaml_path):
        try:
            file_content = sudo_read(yaml_path)
            yaml_content = yaml.safe_load(file_content)
        except yaml.YAMLError as e:
            raise yaml.YAMLError('Failed to load yaml file {0}, due to '
                                 '{1}'.format(yaml_path, str(e)))
    else:
        yaml_content = {}

    yaml_content.update(**updated_content)
    updated_file = yaml.safe_dump(yaml_content,
                                  default_flow_style=False)
    write_to_file(updated_file, yaml_path)
    chown(user_owner,
          group_owner,
          yaml_path)
