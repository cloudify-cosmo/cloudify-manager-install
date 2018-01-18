
from os import sysconf
from platform import platform
from os.path import expanduser
from multiprocessing import cpu_count

from requests import post
from cloudify_cli.env import get_rest_client


GIGA_SIZE = 1024 * 1024 * 1024
MANAGER_ID_PATH = '/etc/cloudify/.id'
PROFILE_CONTEXT_PATH = expanduser('~/.cloudify/profiles/localhost/context')
CLOUDIFY_ENDPOINT_USAGE_DATA_URL = \
    'https://us-central1-omer-tenant.cloudfunctions.net/cloudifyUsage'


def _find_substring_in_list(str_list, substring):
    return any(string for string in str_list if substring in string)


def _collect_metadata(data):
    with open(MANAGER_ID_PATH) as id_file:
        manager_id = id_file.read().strip()
    data['metadata'] = {
        'manager_id': manager_id
    }


def _collect_system_data(data):
    sys_tech = platform().lower()
    data['system'] = {
        'centos_os': 'centos' in sys_tech,
        'redhat_os': 'redhat' in sys_tech,
        'cpu_count': cpu_count(),
        'mem_size_gb':
            sysconf('SC_PAGE_SIZE') * sysconf('SC_PHYS_PAGES') / GIGA_SIZE
    }


def _collect_cloudify_data(data):
    client = get_rest_client()
    plugins_list = [plugin.package_name.lower()
                    for plugin in client.plugins.list(_all_tenants=True)]
    data['cloudify_usage'] = {
        'tenants_count': len(client.tenants.list()),
        'users_count': len(client.users.list()),
        'usergroups_count': len(client.user_groups.list()),
        'blueprints_count': len(client.blueprints.list(_all_tenants=True)),
        'deployments_count': len(client.deployments.list(_all_tenants=True)),
        'executions_count': len(client.executions.list(_all_tenants=True)),
        'secrets_count': len(client.secrets.list(_all_tenants=True)),
        'nodes_count': len(client.nodes.list(_all_tenants=True)),
        'node_instances_count': len(client.node_instances.list(
            _all_tenants=True)),
        'plugins_count': len(plugins_list),
        'aws-plugin': _find_substring_in_list(plugins_list, 'aws'),
        'azure-plugin': _find_substring_in_list(plugins_list, 'azure'),
        'gcp-plugin': _find_substring_in_list(plugins_list, 'gcp'),
        'openstack-plugin': _find_substring_in_list(plugins_list, 'openstack')
    }


def _collect_cloudify_config(data):
    client = get_rest_client()
    manager_version = client.manager.get_version()
    data['cloudify_config'] = {
        'ldap_enabled': client.ldap.get().lower() == 'enabled',
        'ha_enabled': client.cluster.status()['initialized'],
        'premium_edition': manager_version['edition'].lower() == 'premium',
        'version': manager_version['version']
    }


def _send_data(data):
    post(CLOUDIFY_ENDPOINT_USAGE_DATA_URL, data=data)


def main():
    data = {}
    _collect_metadata(data)
    _collect_system_data(data)
    _collect_cloudify_data(data)
    _collect_cloudify_config(data)
    _send_data(data)


if __name__ == '__main__':
    main()
