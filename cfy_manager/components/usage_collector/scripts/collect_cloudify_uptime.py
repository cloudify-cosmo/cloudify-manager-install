
from requests import post

try:
    from cloudify_premium.ha import node_status
    from cloudify_premium.ha.utils import is_master
except ImportError:
    node_status = {'initialized': False}


MANAGER_ID_PATH = '/etc/cloudify/.id'
CLOUDIFY_ENDPOINT_UPTIME_URL = \
    'https://us-central1-omer-tenant.cloudfunctions.net/cloudifyAlive'


def _collect_metadata(data):
    with open(MANAGER_ID_PATH) as id_file:
        manager_id = id_file.read().strip()
    data['metadata'] = {'manager_id': manager_id}


def _send_data(data):
    post(CLOUDIFY_ENDPOINT_UPTIME_URL, data=data)


def _is_clustered():
    return bool(node_status.get('initialized'))


def _is_active_manager():
    if _is_clustered():
        try:
            return is_master()
        except Exception:
            return False
    return True


def main():
    if not _is_active_manager():
        return
    data = {}
    _collect_metadata(data)
    _send_data(data)


if __name__ == '__main__':
    main()
