import json
import os
import re
import shutil
from io import StringIO
from os.path import join
from tempfile import mkstemp

from jinja2 import Environment, FileSystemLoader
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from .common import (run, copy, chown,
                     ensure_destination_dir_exists)
from .. import constants
from ..config import config
from ..logger import get_logger

logger = get_logger('Files')

_template_env = Environment(loader=FileSystemLoader('/'))


def read(path):
    with open(path, 'r') as f:
        return f.read()


def replace_in_file(this, with_this, in_here):
    """Replaces all occurrences of the regex in all matches
    from a file with a specific value.
    """
    logger.debug('Replacing {0} with {1} in {2}...'.format(
        this, with_this, in_here))
    content = read(in_here)
    new_content = re.sub(this, with_this, content)
    write(new_content, in_here)


def ln(source, target, params=None):
    logger.debug('Linking {0} to {1} with params {2}'.format(
        source, target, params))
    command = ['ln']
    if params:
        command.append(params)
    command.append(source)
    command.append(target)
    if '*' in source or '*' in target:
        run(command, globx=True)
    else:
        run(command)


def write_to_tempfile(contents, json_dump=False, cleanup=True):
    fd, file_path = mkstemp()
    os.close(fd)
    write(contents, file_path, json_dump=json_dump)
    if cleanup:
        config.add_temp_path_to_clean(file_path)
    return file_path


def write(contents, destination, json_dump=False,
          owner=None, group=None, mode=None):
    if json_dump:
        contents = json.dumps(contents)
    ensure_destination_dir_exists(destination)
    with open(destination, 'w') as fh:
        fh.write(contents)

    if owner or group:
        shutil.chown(destination, owner, group)
    if mode:
        os.chmod(destination, mode)


def remove_temp_files():
    logger.debug('Cleaning temporary files...')
    remove(config.get('temp_paths_to_remove', []))
    logger.debug('Cleaned temporary files')


def remove(paths, ignore_failure=False):
    if not isinstance(paths, list):
        paths = [paths]
    for path in paths:
        logger.debug('Removing %s...', path)
        if os.path.isdir(path) and os.path.ismount(path):
            logger.debug('Mount point found in %s, deleting contents', path)
            remove(
                [os.path.join(path, subpath) for subpath in os.listdir(path)],
                ignore_failure=ignore_failure)
        else:
            run(['rm', '-rf', path], ignore_failures=ignore_failure)


def deploy(src, dst, render=True, additional_render_context=None):
    if render:
        if additional_render_context is None:
            additional_render_context = {}
        template = _template_env.get_template(src)
        render_context = additional_render_context.copy()
        render_context.update(config)
        render_context.update({'constants': constants})
        content = template.render(**render_context)
        write(content, dst)
    else:
        copy(src, dst)


def _get_notice_path(service_name):
    return join('/opt', '{0}_NOTICE.txt'.format(service_name))


def copy_notice(service_name):
    src = join(constants.COMPONENTS_DIR, service_name, 'NOTICE.txt')
    copy(src, _get_notice_path(service_name))


def remove_notice(service_name):
    remove(_get_notice_path(service_name))


def touch(file_path):
    """ Create an empty file in the provided path """
    ensure_destination_dir_exists(file_path)
    run(['touch', file_path])


def read_yaml_file(yaml_path):
    """Loads a YAML file.

    :param yaml_path: the path to the yaml file.
    :return: YAML file parsed content.
    """
    if os.path.isfile(yaml_path):
        try:
            file_content = read(yaml_path)
            yaml = YAML(typ='safe', pure=True)
            return yaml.load(file_content)
        except YAMLError as e:
            raise YAMLError('Failed to load yaml file {0}, due to {1}'
                            ''.format(yaml_path, str(e)))
    return None


def update_yaml_file(yaml_path,
                     updated_content,
                     user_owner=None,
                     group_owner=None):
    if not isinstance(updated_content, dict):
        raise ValueError('Expected input of type dict, got {0} '
                         'instead'.format(type(updated_content)))
    if bool(user_owner) != bool(group_owner):
        raise ValueError('Both `user_owner` and `group_owner` must be'
                         'specified, or neither.')
    yaml_content = read_yaml_file(yaml_path) or {}
    yaml_content.update(**updated_content)
    stream = StringIO()
    yaml = YAML(typ='safe')
    yaml.default_flow_style = False
    yaml.dump(yaml_content, stream)
    write(stream.getvalue(), yaml_path)
    if user_owner:
        chown(user_owner, group_owner, yaml_path)
