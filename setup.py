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
from os.path import join

from setuptools import setup, find_packages


# This makes sure to include all the config/scripts directories
# in the python package
def package_files(directory):
    paths = []
    for (path, directories, filenames) in os.walk(directory):
        for filename in filenames:
            if filename.endswith('.pyc'):
                continue
            paths.append(join('..', path, filename))
    return paths


extra_files = package_files('cfy_manager')
extra_files.append(join('..', 'config.yaml'))


setup(
    name='cloudify-manager-install',
    version='7.1.0.dev1',
    author='Cloudify',
    author_email='cosmo-admin@cloudify.co',
    packages=find_packages(),
    license='LICENSE',
    description='Local install of a cloudify manager',
    entry_points={
        'console_scripts': [
            'cfy_manager = cfy_manager.main:main',
        ]
    },
    zip_safe=False,
    package_data={'': extra_files},
    install_requires=[
        'ruamel.yaml==0.16.10',
        'markupsafe==2.1.1',
        'jinja2>=3.1.4,<4',
        'argh==0.26.2',
        'netifaces==0.10.9',
        'psutil==5.7.2',
        'requests>=2.32.0,<3.0.0',
        'retrying==1.3.3',
        'cryptography',
        'distro',    # replacing deprecated platform.linux_distribution
        # supervisor is not used in this package directly, but it is
        # installed here to provide the `supervisord` executable
        'supervisor==4.2.2',
    ]
)
