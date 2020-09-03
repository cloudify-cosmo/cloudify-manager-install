#!/usr/bin/env python
import argparse

from flask_security.utils import hash_password

from manager_rest import config
from manager_rest.flask_utils import setup_flask_app
from manager_rest.storage import user_datastore


RESTSERVICE_CONFIG_PATH = '/opt/manager/cloudify-rest.conf'
SECURITY_CONFIG_PATH = "/opt/manager/rest-security.conf"


def _update_admin_password(new_password):
    """Update the admin user's password."""
    with setup_flask_app().app_context():
        user = user_datastore.get_user('admin')
        user.password = hash_password(new_password)
        # Unlock account
        user.failed_logins_counter = 0
        user.active = True
        user_datastore.commit()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Update the admin user's password")
    parser.add_argument(
        'new_password',
        help="The new password for the admin user.",
    )
    args = parser.parse_args()

    config.instance.load_from_file(RESTSERVICE_CONFIG_PATH)
    config.instance.load_from_file(SECURITY_CONFIG_PATH, namespace='security')
    config.instance.load_configuration()
    _update_admin_password(args.new_password)
