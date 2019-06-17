import subprocess
from os import sysconf, path
from platform import platform
from os.path import expanduser
from multiprocessing import cpu_count

from manager_rest import config, server
from manager_rest.storage import models
from script_utils import (logger,
                          send_data,
                          collect_metadata,
                          create_manager_id_file,
                          RESTSERVICE_CONFIG_PATH,
                          get_storage_manager_instance)


GIGA_SIZE = 1024 * 1024 * 1024
PROFILE_CONTEXT_PATH = expanduser('~/.cloudify/profiles/localhost/context')
CLOUDIFY_ENDPOINT_USAGE_DATA_URL = 'https://api.cloudify.co/cloudifyUsage'
CPU_INFO_PATH = '/proc/cpuinfo'


def _find_substring_in_list(str_list, substring):
    return any(string for string in str_list if substring in string)


def _get_cpu_model():
    if not path.exists(CPU_INFO_PATH):
        return None

    model_command = "cat {0} | grep 'model name' | uniq".format(CPU_INFO_PATH)
    proc = subprocess.Popen(model_command, shell=True, stdout=subprocess.PIPE)
    stdout = proc.communicate()[0]
    if proc.returncode != 0:
        return None

    # Get only the model name
    return stdout.strip().split(': ')[1]


def _collect_system_data(data):
    sys_tech = platform().lower()
    data['system'] = {
        'centos_os': 'centos' in sys_tech,
        'redhat_os': 'redhat' in sys_tech,
        'cpu_count': cpu_count(),
        'cpu_model': _get_cpu_model(),
        'mem_size_gb':
            sysconf('SC_PAGE_SIZE') * sysconf('SC_PHYS_PAGES') / GIGA_SIZE
    }


def _collect_cloudify_data(data):
    with get_storage_manager_instance() as sm:
        plugins_list = [plugin.package_name.lower()
                        for plugin in sm.list(models.Plugin,
                                              all_tenants=True,
                                              get_all_results=True)]
        data['cloudify_usage'] = {
            'tenants_count': sm.count(models.Tenant),
            'users_count': sm.count(models.User),
            'usergroups_count': sm.count(models.Group),
            'blueprints_count': sm.count(models.Blueprint),
            'deployments_count': sm.count(models.Deployment),
            'executions_count': sm.count(models.Execution),
            'secrets_count': sm.count(models.Secret),
            'nodes_count': sm.count(models.Node),
            'node_instances_count': sm.count(models.NodeInstance),
            'plugins_count': len(plugins_list),
            'aws_plugin': _find_substring_in_list(plugins_list, 'aws'),
            'azure_plugin': _find_substring_in_list(plugins_list, 'azure'),
            'gcp_plugin': _find_substring_in_list(plugins_list, 'gcp'),
            'openstack_plugin': _find_substring_in_list(plugins_list,
                                                        'openstack'),
            'agents_count': sm.count(models.Agent),
            'compute_count': sm.count(models.NodeInstance,
                                      distinct_by=models.NodeInstance.host_id)
        }


def _collect_cloudify_config(data):
    config.instance.load_from_file(RESTSERVICE_CONFIG_PATH)
    app = server.CloudifyFlaskApp()
    try:
        with app.app_context():
            ldap = bool(app.external_auth and
                        app.external_auth.configured('ldap'))
        data['cloudify_config'] = {
            'ldap_enabled': ldap,
            'ha_enabled': _is_clustered()
        }
    finally:
        config.reset(config.Config())


def _is_clustered():
    with get_storage_manager_instance() as sm:
        managers = sm.list(models.Manager)
    return len(managers) > 1


def main():
    logger.info('Usage script started running')
    create_manager_id_file()
    data = {}
    collect_metadata(data)
    _collect_system_data(data)
    _collect_cloudify_data(data)
    _collect_cloudify_config(data)
    send_data(data, CLOUDIFY_ENDPOINT_USAGE_DATA_URL)
    logger.info('Usage script finished running')


if __name__ == '__main__':
    main()
