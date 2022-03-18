#!/opt/manager/env/bin/python
import os
import pwd
import grp
from stat import S_IREAD

from flask_security.utils import hash_password

from manager_rest import config, server, storage
from manager_rest.rest.resources_v3_1.tokens import _random_string

RESTSERVICE_CONFIG_PATH = '/opt/manager/cloudify-rest.conf'
RESTSEC_CONFIG_PATH = '/opt/manager/rest-security.conf'
AUTH_TOKEN_LOCATION = '/opt/mgmtworker/work/admin_token'


def generate_auth_token():
    config.instance.load_configuration(from_db=False)
    config.instance.rest_service_log_path = ''

    description = 'csys-mgmtworker'

    app = server.CloudifyFlaskApp(load_config=False)
    try:
        with app.app_context():
            sm = storage.get_storage_manager()

            # Don't leak existing Mgmtworker tokens
            for tok in sm.list(storage.models.Token,
                               filters={'description': description}):
                sm.delete(tok)

            # Add new token
            secret = _random_string(40)
            token = storage.models.Token(
                id=_random_string(),
                description=description,
                secret_hash=hash_password(secret),
                _user_fk=0,
            )
            sm.put(token)

            # Return new token value including secret
            token._secret = secret
            return token.to_response()['value']
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
    if 'MANAGER_REST_CONFIG_PATH' not in os.environ:
        os.environ['MANAGER_REST_CONFIG_PATH'] = \
            RESTSERVICE_CONFIG_PATH
    if 'MANAGER_REST_SECURITY_CONFIG_PATH' not in os.environ:
        os.environ['MANAGER_REST_SECURITY_CONFIG_PATH'] = \
            RESTSEC_CONFIG_PATH

    update_auth_token(generate_auth_token())
