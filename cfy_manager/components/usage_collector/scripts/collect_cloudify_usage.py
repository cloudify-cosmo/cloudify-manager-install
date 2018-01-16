
from requests import post
from os.path import expanduser

from cloudify_cli.env import get_rest_client


MANAGER_ID_PATH = '/etc/cloudify/.id'
PROFILE_CONTEXT_PATH = expanduser('~/.cloudify/profiles/localhost/context')
CLOUDIFY_ENDPOINT_URL = \
    'https://us-central1-omer-tenant.cloudfunctions.net/cloudifyUsage'


def _collect_metadata(data):
    with open(MANAGER_ID_PATH) as id_file:
        manager_id = id_file.read().strip()
    data['metadata'] = {
        'manager_id': manager_id
    }


def _collect_system_data(data):
    data['system'] = {}


def _collect_cloudify_data(data):
    client = get_rest_client()
    client.manager.get_status()
    data['cloudify_usage'] = {}


def _collect_cloudify_config(data):
    data['cloudify_config'] = {}


def _send_data(data):
    post(CLOUDIFY_ENDPOINT_URL, data=data)


def main():
    data = {}
    _collect_metadata(data)
    _collect_system_data(data)
    _collect_cloudify_data(data)
    _collect_cloudify_config(data)
    _send_data(data)


if __name__ == '__main__':
    main()
