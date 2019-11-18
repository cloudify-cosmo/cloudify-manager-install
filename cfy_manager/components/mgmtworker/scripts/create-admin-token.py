#!/opt/manager/env/bin/python
#########
# Copyright (c) 2018 Cloudify Platform Ltd. All rights reserved
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
import pwd
import grp
from stat import S_IREAD

from manager_rest import config, server, storage

RESTSERVICE_CONFIG_PATH = '/opt/manager/cloudify-rest.conf'
RESTSEC_CONFIG_PATH = '/opt/manager/rest-security.conf'
MANAGER_PYTHON = '/opt/manager/env/bin/python'
AUTH_TOKEN_LOCATION = '/opt/mgmtworker/work/admin_token'


def generate_auth_token():
    config.instance.load_from_file(RESTSERVICE_CONFIG_PATH)
    config.instance.rest_service_log_path = ''
    app = server.CloudifyFlaskApp(load_config=False)
    try:
        with app.app_context():
            sm = storage.get_storage_manager()

            enc_uid = storage.idencoder.get_encoder().encode(0)

            admin_user = sm.get(storage.models.User, 0)
            token_key = admin_user.api_token_key

            return enc_uid + token_key
    finally:
        config.reset(config.Config())


def update_auth_token(token):
    with open(AUTH_TOKEN_LOCATION, 'w') as token_handle:
        token_handle.write(token)
    uid = pwd.getpwnam("cfyuser").pw_uid
    gid = grp.getgrnam("cfyuser").gr_gid
    os.chown(AUTH_TOKEN_LOCATION, uid, gid)
    os.chmod(AUTH_TOKEN_LOCATION, S_IREAD)


if __name__ == '__main__':
    if 'MANAGER_REST_SECURITY_CONFIG_PATH' not in os.environ:
        os.environ['MANAGER_REST_SECURITY_CONFIG_PATH'] = (
            RESTSEC_CONFIG_PATH
        )

    update_auth_token(generate_auth_token())
