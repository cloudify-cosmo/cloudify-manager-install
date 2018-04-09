import json
from uuid import uuid4
from os import sysconf, path
from platform import platform
from os.path import expanduser
from multiprocessing import cpu_count

import pkg_resources
from requests import post
from contextlib import contextmanager
from manager_rest import config, server, premium_enabled
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
CLOUDIFY_ENDPOINT_USAGE_DATA_URL = 'https://api.cloudify.co/cloudifyUsage'


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
    pkg_distribution = pkg_resources.get_distribution('cloudify-rest-service')
    manager_version = pkg_distribution.version
    with open(MANAGER_ID_PATH) as id_file:
        manager_id = id_file.read().strip()
    data['metadata'] = {
        'manager_id': manager_id,
        'premium_edition': premium_enabled,
        'version': manager_version
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
    with _get_storage_manager() as sm:
        plugins_list = [plugin.package_name.lower()
                        for plugin in sm.list(models.Plugin, all_tenants=True)]
        data['cloudify_usage'] = {
            'tenants_count': len(sm.list(models.Tenant)),
            'users_count': len(sm.list(models.User)),
            'usergroups_count': len(sm.list(models.Group)),
            'blueprints_count': len(sm.list(models.Blueprint,
                                            all_tenants=True)),
            'deployments_count': len(sm.list(models.Deployment,
                                             all_tenants=True)),
            'executions_count': len(sm.list(models.Execution,
                                            all_tenants=True)),
            'secrets_count': len(sm.list(models.Secret, all_tenants=True)),
            'nodes_count': len(sm.list(models.Node, all_tenants=True)),
            'node_instances_count': len(sm.list(models.NodeInstance,
                                                all_tenants=True)),
            'plugins_count': len(plugins_list),
            'aws_plugin': _find_substring_in_list(plugins_list, 'aws'),
            'azure_plugin': _find_substring_in_list(plugins_list, 'azure'),
            'gcp_plugin': _find_substring_in_list(plugins_list, 'gcp'),
            'openstack_plugin': _find_substring_in_list(plugins_list,
                                                        'openstack')
        }


def _collect_cloudify_config(data):
    config.instance.load_from_file(RESTSERVICE_CONFIG_PATH)
    app = server.CloudifyFlaskApp()
    try:
        with app.app_context():
            ldap = bool(app.external_auth and app.external_auth.ldap)
        data['cloudify_config'] = {
            'ldap_enabled': ldap,
            'ha_enabled': _is_clustered()
        }
    finally:
        config.reset(config.Config())


def _send_data(data):
    # for some reason. multi hierarchy dict doesn't pass well to the end point
    data = {'data': json.dumps(data)}
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
