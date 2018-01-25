
from uuid import uuid4
from os import sysconf, path
from platform import platform
from os.path import expanduser
from multiprocessing import cpu_count

import pkg_resources
from requests import post
from contextlib import contextmanager
from manager_rest import config, server
from manager_rest.storage import get_storage_manager, models

try:
    from cloudify_premium.ha import node_status
    from cloudify_premium.ha.utils import is_master
except ImportError:
    node_status = {'initialized': False}


GIGA_SIZE = 1024 * 1024 * 1024
MANAGER_ID_PATH = '/etc/cloudify/.id'
RESTSERVICE_CONFIG_PATH = '/opt/manager/cloudify-rest.conf'
PROFILE_CONTEXT_PATH = expanduser('~/.cloudify/profiles/localhost/context')
CLOUDIFY_ENDPOINT_USAGE_DATA_URL = \
    'https://us-central1-omer-tenant.cloudfunctions.net/cloudifyUsage'


@contextmanager
def _get_storage_manager():
    """Configure and yield a storage_manager instance.
    This is to be used only OUTSIDE of the context of the REST API.
    """
    config.instance.load_from_file(RESTSERVICE_CONFIG_PATH)
    app = server.CloudifyFlaskApp()
    try:
        with app.app_context():
            sm = get_storage_manager()
            yield sm
    finally:
        config.reset(config.Config())


def _create_manager_id_file():
    if path.exists(MANAGER_ID_PATH):
        with open(MANAGER_ID_PATH) as f:
            existing_manager_id = f.read().strip()
            if existing_manager_id:
                return
    with open(MANAGER_ID_PATH, 'w') as f:
        f.write(uuid4().hex)


def _find_substring_in_list(str_list, substring):
    return any(string for string in str_list if substring in string)


def _collect_metadata(data):
    with open(MANAGER_ID_PATH) as id_file:
        manager_id = id_file.read().strip()
    data['metadata'] = {
        'manager-id': manager_id
    }


def _collect_system_data(data):
    sys_tech = platform().lower()
    data['system'] = {
        'centos-os': 'centos' in sys_tech,
        'redhat-os': 'redhat' in sys_tech,
        'cpu-count': cpu_count(),
        'mem-size-gb':
            sysconf('SC_PAGE_SIZE') * sysconf('SC_PHYS_PAGES') / GIGA_SIZE
    }


def _collect_cloudify_data(data):
    with _get_storage_manager() as sm:
        plugins_list = [plugin.package_name.lower()
                        for plugin in sm.list(models.Plugin, all_tenants=True)]
        data['cloudify-usage'] = {
            'tenants-count': len(sm.list(models.Tenant)),
            'users-count': len(sm.list(models.User)),
            'usergroups-count': len(sm.list(models.Group)),
            'blueprints-count': len(sm.list(models.Blueprint,
                                            all_tenants=True)),
            'deployments-count': len(sm.list(models.Deployment,
                                             all_tenants=True)),
            'executions-count': len(sm.list(models.Execution,
                                            all_tenants=True)),
            'secrets-count': len(sm.list(models.Secret, all_tenants=True)),
            'nodes-count': len(sm.list(models.Node, all_tenants=True)),
            'node-instances_count': len(sm.list(models.NodeInstance,
                                                all_tenants=True)),
            'plugins-count': len(plugins_list),
            'aws-plugin': _find_substring_in_list(plugins_list, 'aws'),
            'azure-plugin': _find_substring_in_list(plugins_list, 'azure'),
            'gcp-plugin': _find_substring_in_list(plugins_list, 'gcp'),
            'openstack-plugin': _find_substring_in_list(plugins_list,
                                                        'openstack')
        }


def _collect_cloudify_config(data):
    manager_version = pkg_resources.get_distribution('cloudify-rest-service') \
        .version
    config.instance.load_from_file(RESTSERVICE_CONFIG_PATH)
    app = server.CloudifyFlaskApp()
    try:
        with app.app_context():
            ldap = bool(app.ldap)
        data['cloudify-config'] = {
            'ldap-enabled': ldap,
            'ha-enabled': _is_clustered(),
            'premium-edition': config.instance.edition.lower() == 'premium',
            'version': manager_version
        }
    finally:
        config.reset(config.Config())


def _send_data(data):
    post(CLOUDIFY_ENDPOINT_USAGE_DATA_URL, data=data)


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
    _create_manager_id_file()
    if not _is_active_manager():
        return
    data = {}
    _collect_metadata(data)
    _collect_system_data(data)
    _collect_cloudify_data(data)
    _collect_cloudify_config(data)
    _send_data(data)


if __name__ == '__main__':
    main()
