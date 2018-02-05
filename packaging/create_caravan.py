
import argparse
import urllib2
import json
import yaml
import tempfile
import os
import shutil
import tarfile
from cloudify_cli.utils import get_local_path

PLUGINS_TO_BUNDLE = ['vSphere',
                     'OpenStack',
                     'Fabric',
                     'GCP',
                     'AWS',
                     'Azure']


def _create_caravan(mappings, dest, tar_name):
    tempdir = tempfile.mkdtemp()
    metadata = {}

    for wgn_path, yaml_path in mappings.iteritems():
        plugin_root_dir = os.path.basename(wgn_path).rsplit('.', 1)[0]
        os.mkdir(os.path.join(tempdir, plugin_root_dir))

        dest_wgn_path = os.path.join(plugin_root_dir,
                                     os.path.basename(wgn_path))
        dest_yaml_path = os.path.join(plugin_root_dir,
                                      os.path.basename(yaml_path))

        get_local_path(wgn_path, os.path.join(tempdir, dest_wgn_path))
        get_local_path(yaml_path, os.path.join(tempdir, dest_yaml_path))
        metadata[dest_wgn_path] = dest_yaml_path

    with open(os.path.join(tempdir, 'METADATA'), 'w+') as f:
        yaml.dump(metadata, f)

    tar_path = os.path.join(dest, '{0}.tgz'.format(tar_name))
    tarfile_ = tarfile.open(tar_path, 'w:gz')
    try:
        tarfile_.add(tempdir, arcname=tar_name)
    finally:
        tarfile_.close()
        shutil.rmtree(tempdir, ignore_errors=True)

    return tar_path


def build_caravan(dir, name, path):
    plugins_json = urllib2.urlopen(path)
    plugins = json.loads(plugins_json.read())
    mapping = {}

    for plugin in plugins:
        if plugin['title'] in PLUGINS_TO_BUNDLE:
            mapping[plugin['wagons'][0]['url']] = plugin['link']
            mapping[plugin['wagons'][1]['url']] = plugin['link']

    return _create_caravan(mapping, dir, name)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        description=(
            'Create a plugins bundle'
        ),
    )

    parser.add_argument(
        '-d', '--dir',
        required=True,
        help='Destination directory for the bundle',
    )

    parser.add_argument(
        '-n', '--name',
        help='Filename of the bundle',
        default='cloudify-plugins-bundle',
    )

    # pylint: disable=E501
    parser.add_argument(
        '-p', '--path',
        help='Path to plugins urls json',
        default='http://repository.cloudifysource.org/'
                'cloudify/wagons/plugins.json',
    )

    args = parser.parse_args()

    build_caravan(
        dir=args.dir,
        name=args.name,
        path=args.path)
