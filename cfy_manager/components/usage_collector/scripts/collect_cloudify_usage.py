import subprocess
from os import sysconf, path
from datetime import datetime
from platform import platform
from os.path import expanduser
from multiprocessing import cpu_count

from cloudify.models_states import ExecutionState

from manager_rest import config, server
from manager_rest.storage import models
from script_utils import (logger,
                          send_data,
                          DAYS_LOCK,
                          DAYS_INTERVAL,
                          collect_metadata,
                          should_send_data,
                          usage_collector_lock,
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
    if proc.returncode != 0 or not stdout:
        return None

    # Get only the model name
    return str(stdout).strip().split(': ')[1].rstrip("\\n'")


def _collect_system_data(data):
    sys_tech = platform().lower()
    data['system'] = {
        'centos_os': 'centos' in sys_tech,
        'redhat_os': 'redhat' in sys_tech,
        'cpu_count': cpu_count(),
        'cpu_model': _get_cpu_model(),
        'mem_size_gb':
            sysconf('SC_PAGE_SIZE') * sysconf('SC_PHYS_PAGES') // GIGA_SIZE
    }


def _collect_cloudify_data(data):
    with get_storage_manager_instance() as sm:
        plugins_list = [plugin.package_name.lower()
                        for plugin in sm.list(models.Plugin,
                                              all_tenants=True,
                                              get_all_results=True)]
        executions = _summarize_executions(sm)
        nodes = _summarize_nodes(sm)

        data['cloudify_usage'] = {
            'tenants_count': sm.count(models.Tenant),
            'users_count': sm.count(models.User),
            'users_by_role':  _summarize_users_by_role(sm),
            'usergroups_count': sm.count(models.Group),
            'sites_count': sm.count(models.Site),
            'blueprints_count': sm.count(models.Blueprint),
            'deployments_count': sm.count(models.Deployment),
            'environments_count': len(sm.list(
                models.Deployment,
                filters=_licensed_environments_filter())),
            'executions_count': executions['total'],
            'executions_succeeded': executions['succeeded'],
            'executions_failed': executions['failed'],
            'executions_by_type': executions['types'],
            'secrets_count': sm.count(models.Secret),
            'nodes_count': nodes['total'],
            'nodes_by_type': nodes['types'],
            'node_instances_count': sm.count(models.NodeInstance),
            'plugins_count': len(plugins_list),
            'aws_plugin': _find_substring_in_list(plugins_list, 'aws'),
            'azure_plugin': _find_substring_in_list(plugins_list, 'azure'),
            'gcp_plugin': _find_substring_in_list(plugins_list, 'gcp'),
            'openstack_plugin': _find_substring_in_list(plugins_list,
                                                        'openstack'),
            'agents_count': sm.count(models.Agent),
            'compute_count': sm.count(models.NodeInstance,
                                      filters={models.NodeInstance.state:
                                               'started'},
                                      distinct_by=models.NodeInstance.host_id)
        }
        data['cloudify_usage'].update(_get_first_and_last_login(sm))


def _summarize_users_by_role(sm):
    users_list = sm.list(models.User)
    roles = {}
    for user in users_list:
        if user.role == 'sys_admin':
            roles.setdefault('sys_admin', 0)
            roles['sys_admin'] += 1
        for tenant_role in user.user_tenants.values():
            roles.setdefault(tenant_role, 0)
            roles[tenant_role] += 1
    return roles


def _summarize_nodes(sm):
    nodes_summary = sm.summarize(
        target_field='type',
        sub_field=None,
        model_class=models.Node,
        pagination=None,
        all_tenants=True,
        get_all_results=True,
        filters=None)
    nodes = {'total': 0,  'types': {}}
    for node_type, amount in nodes_summary:
        nodes['total'] += amount
        nodes['types'].setdefault(node_type, 0)
        nodes['types'][node_type] += amount
    return nodes


def _summarize_executions(sm):
    executions_summary = sm.summarize(
        target_field='workflow_id',
        sub_field='status',
        model_class=models.Execution,
        pagination=None,
        all_tenants=True,
        get_all_results=True,
        filters=None)
    executions = {'total': 0, 'succeeded': 0, 'failed': 0, 'types': {}}
    for exec_type, status, amount in executions_summary:
        executions['total'] += amount
        if status == ExecutionState.TERMINATED:
            executions['succeeded'] += amount
        else:
            executions['failed'] += amount
        executions['types'].setdefault(exec_type, 0)
        executions['types'][exec_type] += amount
    return executions


def _get_first_and_last_login(sm):
    users_list = sm.list(models.User)
    in_fmt = '%Y-%m-%dT%H:%M:%S.%fZ'
    out_fmt = '%Y-%m-%dT%H:%M:%S'
    first_login = min(datetime.strptime(u.first_login_at, in_fmt)
                      for u in users_list)
    last_login = max(datetime.strptime(u.last_login_at, in_fmt)
                     for u in users_list)
    return {
        'first_login': datetime.strftime(first_login, out_fmt),
        'last_login': datetime.strftime(last_login, out_fmt)
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


def _licensed_environments_filter():
    # stolen from cloudify-manager/rest-service/manager_rest/rest/rest_utils.py
    return {
        '_storage_id': lambda col:
            ~models.InterDeploymentDependencies.query.filter(
                col ==
                models.InterDeploymentDependencies._target_deployment,
                models.InterDeploymentDependencies.dependency_creator.like(
                    'component.%')
            ).exists()
    }


def main():
    with usage_collector_lock(DAYS_LOCK) as locked:
        if not locked:
            logger.info('Other Manager is currently updating cloudify_usage')
            return
        logger.debug('Acquired usage_collector table lock')
        if should_send_data(DAYS_INTERVAL):
            logger.info('Usage script started running')
            data = {}
            collect_metadata(data)
            _collect_system_data(data)
            _collect_cloudify_data(data)
            _collect_cloudify_config(data)
            send_data(data, CLOUDIFY_ENDPOINT_USAGE_DATA_URL, DAYS_INTERVAL)
            logger.info('Usage script finished running')
        else:
            logger.info('cloudify_usage was updated by a different Manager')


if __name__ == '__main__':
    main()
