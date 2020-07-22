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
            print('Replaced cert {0} on DB'.format(name))
            return

    print('CA cert {0} was already replaced'.format(name))


def init_parser():
    parser = argparse.ArgumentParser(
        description='Replace the CA certificates in the Certificate table'
    )
    parser.add_argument(
        '--input',
        help='Path to a config file containing info needed by this script',
        required=True,
    )

    return parser


def init_flask_app():
    config.instance.load_configuration()
    setup_flask_app(
        manager_ip=config.instance.postgresql_host,
        hash_salt=config.instance.security_hash_salt,
        secret_key=config.instance.security_secret_key
    )


def main():
    parser = init_parser()
    init_flask_app()
    args = parser.parse_args()

    with open(args.input, 'r') as f:
        script_input = json.load(f)

    update_cert(script_input.get('cert_path'), script_input.get('name'))


if __name__ == '__main__':
    main()
