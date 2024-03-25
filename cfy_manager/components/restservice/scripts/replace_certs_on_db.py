#!/usr/bin/env python
#########
# Copyright (c) 2020 Cloudify Platform Ltd. All rights reserved
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

from __future__ import print_function

import os
import json
import argparse
from datetime import datetime

from manager_rest import config
from manager_rest.flask_utils import setup_flask_app
from manager_rest.storage import models, get_storage_manager  # NOQA


def update_cert(cert_path, name):
    with open(cert_path) as cert_file:
        cert = cert_file.read()
    sm = get_storage_manager()
    instance = sm.get(models.Certificate,
                      None,
                      filters={'name': name},
                      fail_silently=True)
    if instance:
        if instance.value != cert:
            instance.value = cert
            instance.updated_at = datetime.now()
            sm.update(instance)
            print('Replaced cert {0} on DB'.format(instance.name))
            return

    print('CA cert {0} was already replaced'.format(name))


def init_flask_app():
    config.instance.load_configuration(from_db=False)
    setup_flask_app(
        manager_ip=config.instance.postgresql_host,
        hash_salt=config.instance.security_hash_salt,
        secret_key=config.instance.security_secret_key
    )


def main():
    parser = argparse.ArgumentParser(
        description='Replace the CA certificates in the Certificate table'
    )
    parser.add_argument(
        '--input',
        help='Path to a config file containing info needed by this script',
        required=True,
    )

    args = parser.parse_args()

    config_path = args.input
    if os.path.abspath(config_path) != config_path:
        exit("Invalid config file path")

    init_flask_app()

    with open(config_path, 'r') as f:
        script_input = json.load(f)

    update_cert(script_input.get('cert_path'), script_input.get('name'))


if __name__ == '__main__':
    main()
