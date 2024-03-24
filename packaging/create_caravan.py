from __future__ import print_function

import argparse
import json
import tempfile
import os
import shutil
import tarfile
import requests
from ruamel.yaml import YAML
from urllib.request import urlopen

PLUGINS_TO_BUNDLE = ['vSphere',
                     'OpenStack',
                     'Fabric',
                     'GCP',
                     'AWS',
                     'Azure',
                     'Ansible',
                     'Kubernetes',
                     'Utilities']


DISTROS_TO_BUNDLE = ['Centos Core', 'Redhat Maipo']


def download_file(url, dst):
    print('Downloading {0} to {1}'.format(url, dst))
    try:
        response = requests.get(url, stream=True)
        with open(dst, 'wb') as dst_file:
            for chunk in response.iter_content(1024):
                dst_file.write(chunk)
    except requests.exceptions.RequestException as ex:
        print('Failed to download {0}. ({1})'.format(url, str(ex)))
        raise


def _create_caravan(mappings, dest, tar_name):
    tempdir = tempfile.mkdtemp()
    metadata = {}

    for wgn_path, yaml_path in mappings.items():
        plugin_root_dir = os.path.basename(wgn_path).rsplit('.', 1)[0]
        os.mkdir(os.path.join(tempdir, plugin_root_dir))

        dest_wgn_path = os.path.join(plugin_root_dir,
                                     os.path.basename(wgn_path))
        dest_yaml_path = os.path.join(plugin_root_dir,
                                      os.path.basename(yaml_path))

        download_file(wgn_path, os.path.join(tempdir, dest_wgn_path))
        download_file(yaml_path, os.path.join(tempdir, dest_yaml_path))

        metadata[dest_wgn_path] = dest_yaml_path

    yaml = YAML()
    yaml.default_flow_style = False
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
    plugins_json = urlopen(path)
    plugins = json.loads(plugins_json.read())
    mapping = {}

    for plugin in plugins:
        if plugin['title'] in PLUGINS_TO_BUNDLE:
            plugin_yaml = plugin['link']
            for wagon in plugin['wagons']:
                if wagon['name'] in DISTROS_TO_BUNDLE:
                    mapping[wagon['url']] = plugin_yaml

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
        default='https://repository.cloudifysource.org/'
                'cloudify/wagons/plugins.json',
    )

    args = parser.parse_args()

    build_caravan(
        dir=os.path.basename(args.dir),
        name=args.name,
        path=args.path)
