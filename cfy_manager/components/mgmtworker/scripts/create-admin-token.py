#!/opt/cfy/bin/python
import os
import pwd
import grp
from stat import S_IREAD
import socket

from cloudify_cli.env import get_rest_client

AUTH_TOKEN_LOCATION = '/opt/mgmtworker/work/admin_token'


def generate_auth_token():
    hostname = socket.gethostname()
    description = f'Mgmtworker token for {hostname}'
    client = get_rest_client()

    for existing in client.tokens.list(description=description):
        client.tokens.delete(existing['id'])

    token = client.tokens.create(
        description=f'Mgmtworker token for {hostname}',
    )
    return token.value


def update_auth_token(token):
    with open(AUTH_TOKEN_LOCATION, 'w') as token_handle:
        token_handle.write(token)
    uid = pwd.getpwnam("cfyuser").pw_uid
    gid = grp.getgrnam("cfyuser").gr_gid
    os.chown(AUTH_TOKEN_LOCATION, uid, gid)
    os.chmod(AUTH_TOKEN_LOCATION, S_IREAD)


if __name__ == '__main__':
    update_auth_token(generate_auth_token())
