#########
# Copyright (c) 2019 Cloudify Platform Ltd. All rights reserved
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
import json
import argparse

from manager_rest import config
from manager_rest.storage import idencoder


def get_encoded_user_id(user_id):
    return idencoder.get_encoder().encode(user_id)


def fill_encoded_ids(users):
    for user in users:
        user['encoded_id'] = get_encoded_user_id(user['id'])


def load_input(input_path):
    with open(input_path, 'r') as f:
        return json.load(f)


def file_path(path):
    if os.path.exists(path):
        return path
    else:
        raise argparse.ArgumentTypeError(
            "The file path \"{0}\" doesn't exist.".format(path))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Receives a list of users, adds their encoded IDs and '
                    'prints the updated list.'
    )
    parser.add_argument(
        '--input',
        help='Path to a config file containing info needed by this script',
        type=file_path,
        required=True,
    )

    args = parser.parse_args()
    config_env_var = 'MANAGER_REST_SECURITY_CONFIG_PATH'
    if config_env_var not in os.environ:
        raise RuntimeError("Please provide the "
                           "MANAGER_REST_SECURITY_CONFIG_PATH via an env var.")
    config.instance.load_configuration(from_db=False)

    users = load_input(args.input)
    fill_encoded_ids(users)
    print(json.dumps(users))
