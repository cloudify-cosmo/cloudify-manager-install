
from requests import post


MANAGER_ID_PATH = '/etc/cloudify/.id'
CLOUDIFY_ENDPOINT_UPTIME_URL = \
    'https://us-central1-omer-tenant.cloudfunctions.net/cloudifyAlive'


def _collect_metadata(data):
    with open(MANAGER_ID_PATH) as id_file:
        manager_id = id_file.read().strip()
    data['metadata'] = {'manager_id': manager_id}


def _send_data(data):
    post(CLOUDIFY_ENDPOINT_UPTIME_URL, data=data)


def main():
    data = {}
    _collect_metadata(data)
    _send_data(data)


if __name__ == '__main__':
    main()
