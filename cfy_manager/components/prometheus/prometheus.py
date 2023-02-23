import json
from os import sep
from os.path import join, exists, isfile
import re

from ..base_component import BaseComponent
from ...components_constants import (
    CLUSTER_JOIN,
    CONFIG,
    CONSTANTS,
    ENABLE_REMOTE_CONNECTIONS,
    HOSTNAME,
    PRIVATE_IP,
    SERVICES_TO_INSTALL,
    SSL_ENABLED,
)
from ...service_names import (
    COMPOSER,
    MANAGER,
    PROMETHEUS,
    NODE_EXPORTER,
    BLACKBOX_EXPORTER,
    POSTGRES_EXPORTER,
    POSTGRESQL_CLIENT,
    POSTGRESQL_SERVER,
    RABBITMQ,
    NGINX,
    DATABASE_SERVICE,
    MANAGER_SERVICE,
    MONITORING_SERVICE,
    QUEUE_SERVICE,
)
from ... import constants
from ...config import config
from ...constants import (
    CLOUDIFY_USER,
    CLOUDIFY_GROUP
)
from ..restservice.db import get_monitoring_config
from ...logger import get_logger
from ...exceptions import ValidationError
from ...utils import common, files, service, certificates, syslog
from ...utils.install import is_premium_installed
from ...utils.network import ipv6_url_compat


CONFIG_DIR = join(constants.COMPONENTS_DIR, PROMETHEUS, CONFIG)
LOG_DIR = join(constants.BASE_LOG_DIR, PROMETHEUS)
BIN_DIR = join(sep, 'usr', 'local', 'bin')
PROMETHEUS_DATA_DIR = join(sep, 'var', 'lib', 'prometheus')
PROMETHEUS_CONFIG_DIR = join(sep, 'etc', 'prometheus', )
PROMETHEUS_ALERTS_DIR = join(PROMETHEUS_CONFIG_DIR, 'alerts')
PROMETHEUS_TARGETS_DIR = join(PROMETHEUS_CONFIG_DIR, 'targets')
PROMETHEUS_CONFIG_PATH = join(PROMETHEUS_CONFIG_DIR, 'prometheus.yml')
CLUSTER_DETAILS_PATH = '/tmp/cluster_details.json'

AVAILABLE_EXPORTERS = [
    {
        'name': BLACKBOX_EXPORTER,
        'description': 'Blackbox Exporter',
        'deploy_config': {
            'blackbox.yml':
                join(PROMETHEUS_CONFIG_DIR, 'exporters', 'blackbox.yml')
        },
        'for': (MANAGER_SERVICE,),
    },
    {
        'name': NODE_EXPORTER,
        'description': 'Node Exporter',
        'for': (
            DATABASE_SERVICE, MANAGER_SERVICE, MONITORING_SERVICE,
            QUEUE_SERVICE,)
    },
    {
        'name': POSTGRES_EXPORTER,
        'description': 'Postgres Exporter',
        'for': (DATABASE_SERVICE,),
    },
]

logger = get_logger(PROMETHEUS)


def _prometheus_exporters():
    # generate exporters required for configured services
    return (exporter for exporter in AVAILABLE_EXPORTERS if
            any(s for s in exporter.get('for', []) if
                s in config.get(SERVICES_TO_INSTALL, [])))


class Prometheus(BaseComponent):
    component_name = 'prometheus'

    @property
    def services(self):
        services = {'prometheus': {'is_group': False}}
        for exporter in _prometheus_exporters():
            services.update({exporter['name']: {'is_group': False}})
        return services

    def replace_certificates(self):
        if (exists(constants.NEW_PROMETHEUS_CERT_FILE_PATH) or
                exists(constants.NEW_PROMETHEUS_CA_CERT_FILE_PATH)):
            self.validate_new_certs()
            logger.info('Replacing certificates on prometheus component')
            self.write_new_certs_to_config()
            handle_certs()
            service.reload(PROMETHEUS, ignore_failure=True)
        if exists(constants.NEW_INTERNAL_CA_CERT_FILE_PATH):
            service.restart(BLACKBOX_EXPORTER, ignore_failure=True)
            service.verify_alive(BLACKBOX_EXPORTER)
            service.restart(NGINX)
            service.verify_alive(NGINX)

    def validate_new_certs(self):
        if (exists(constants.NEW_PROMETHEUS_CERT_FILE_PATH) or
                exists(constants.NEW_PROMETHEUS_CA_CERT_FILE_PATH)):
            certificates.get_and_validate_certs_for_replacement(
                default_cert_location=constants.MONITORING_CERT_PATH,
                default_key_location=constants.MONITORING_KEY_PATH,
                default_ca_location=constants.MONITORING_CA_CERT_PATH,
                default_ca_key_location=constants.MONITORING_CA_KEY_PATH,
                new_cert_location=constants.NEW_PROMETHEUS_CERT_FILE_PATH,
                new_key_location=constants.NEW_PROMETHEUS_KEY_FILE_PATH,
                new_ca_location=constants.NEW_PROMETHEUS_CA_CERT_FILE_PATH,
                new_ca_key_location=constants.NEW_PROMETHEUS_CA_KEY_FILE_PATH
            )

    @staticmethod
    def write_new_certs_to_config():
        if exists(constants.NEW_PROMETHEUS_CERT_FILE_PATH):
            config['prometheus']['cert_path'] = \
                constants.NEW_PROMETHEUS_CERT_FILE_PATH
            config['prometheus']['key_path'] = \
                constants.NEW_PROMETHEUS_KEY_FILE_PATH
        if exists(constants.NEW_PROMETHEUS_CA_CERT_FILE_PATH):
            config['prometheus']['ca_path'] = \
                constants.NEW_PROMETHEUS_CA_CERT_FILE_PATH
        if exists(constants.NEW_INTERNAL_CA_CERT_FILE_PATH):
            config[PROMETHEUS][BLACKBOX_EXPORTER]['ca_cert_path'] = \
                constants.NEW_INTERNAL_CA_CERT_FILE_PATH

    def remove(self):
        logger.info('Updating prometheus configuration for removal...')
        _update_prometheus_configuration(uninstalling=True)

        if _prometheus_targets_exist():
            logger.info(
                'Prometheus targets still exist, not removing prometheus.')
            logger.info('To remove prometheus, remove remaining components.')
        else:
            logger.notice('Removing Prometheus and exporters...')
            files.remove([PROMETHEUS_DATA_DIR, PROMETHEUS_CONFIG_DIR])
            for exporter in _prometheus_exporters():
                service.remove(exporter['name'])
            service.remove(PROMETHEUS)
            logger.notice(
                'Successfully removed Prometheus and exporters files')

    def configure(self):
        logger.notice('Configuring Prometheus Service...')
        handle_certs()
        _create_prometheus_directories()
        _chown_resources_dir()
        _deploy_configuration()
        extra_conf = _prometheus_additional_configuration()
        service.configure(PROMETHEUS, external_configure_params=extra_conf)
        service.reload(PROMETHEUS, ignore_failure=True)
        for exporter in _prometheus_exporters():
            service.configure(
                exporter['name'],
                src_dir='prometheus',
            )
            service.reload(
                exporter['name'],
                ignore_failure=True
            )
        if isfile(CLUSTER_DETAILS_PATH):
            logger.notice(
                'File {0} exists will update Prometheus config...'.format(
                    CLUSTER_DETAILS_PATH))
            _deploy_configuration()

        services = ['prometheus']
        services.extend([exporter + '_exporter'
                         for exporter in ['postgres', 'node', 'blackbox']])
        syslog.deploy_rsyslog_filters('prometheus', services, logger)

        logger.notice('Prometheus successfully configured')
        self.start()

    def upgrade(self):
        try:
            _deploy_configuration()
        except FileNotFoundError:
            self.configure()

    def join_cluster(self):  # , restore_users_on_fail=False):
        logger.info('Would be joining cluster.')


def handle_certs():
    logger.info('Setting up TLS certificates.')
    supplied = certificates.use_supplied_certificates(
        PROMETHEUS,
        logger,
        cert_destination=constants.MONITORING_CERT_PATH,
        key_destination=constants.MONITORING_KEY_PATH,
        ca_destination=constants.MONITORING_CA_CERT_PATH)
    if supplied:  # When replacing certificates, supplied==True always
        logger.info('Deployed user provided external cert and key')
    else:
        config[PROMETHEUS]['ca_path'] = constants.MONITORING_CA_CERT_PATH
        config[PROMETHEUS]['cert_path'] = constants.MONITORING_CERT_PATH
        config[PROMETHEUS]['key_path'] = constants.MONITORING_KEY_PATH
        _generate_certs()


def _generate_certs():
    logger.info('Generating certificate...')
    if _installing_manager():
        has_ca_key = certificates.handle_ca_cert(logger)
    else:
        has_ca_key = False
        # If we're not installing the manager and user certs were not
        # supplied then we're about to generate self-signed certs.
        # As we're going to do this, we'll set the ca_path such that
        # anything consuming this value will get the path to the cert
        # that will allow them to trust the broker.
        config[PROMETHEUS]['ca_path'] = config[PROMETHEUS]['cert_path']
    if not common.is_all_in_one_manager():
        raise ValidationError(
            'Cannot generate self-signed certificates for Prometheus in a '
            'cluster - externally generated certificates must be provided '
            'as well as the appropriate CA certificate.'
        )
    # As we only support generating certificates on single-node setups,
    # we will take only the manager's details (having failed before now
    # if there is a different environment than all in one)
    hostname = config[MANAGER][HOSTNAME]
    private_ip = config[MANAGER][PRIVATE_IP]

    certificates.store_cert_metadata(
        hostname,
        new_networks=[private_ip],
    )

    sign_cert = constants.CA_CERT_PATH if has_ca_key else None
    sign_key = constants.CA_KEY_PATH if has_ca_key else None

    certificates._generate_ssl_certificate(
        ips=[private_ip],
        cn=hostname,
        cert_path=config[PROMETHEUS]['cert_path'],
        key_path=config[PROMETHEUS]['key_path'],
        sign_cert_path=sign_cert,
        sign_key_path=sign_key,
    )
    if has_ca_key:
        common.copy(constants.CA_CERT_PATH, constants.MONITORING_CA_CERT_PATH)


def _installing_manager():
    return MANAGER_SERVICE in config[SERVICES_TO_INSTALL]


def _installing_rabbit():
    return QUEUE_SERVICE in config[SERVICES_TO_INSTALL]


def _create_prometheus_directories():
    logger.notice('Creating Prometheus directories')
    common.mkdir(PROMETHEUS_DATA_DIR)
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, PROMETHEUS_DATA_DIR)
    for dir_name in ('alerts', 'exporters',):
        dest_dir_name = join(PROMETHEUS_CONFIG_DIR, dir_name)
        common.mkdir(dest_dir_name)


def _chown_resources_dir():
    logger.notice('Changing files and directories ownership for Prometheus')
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP,
                 join(BIN_DIR, 'prometheus'))
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP,
                 join(BIN_DIR, 'promtool'))
    for exporter in _prometheus_exporters():
        common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP,
                     join(BIN_DIR, exporter['name']))
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, PROMETHEUS_DATA_DIR)


def _deploy_configuration():
    _update_config()
    _update_prometheus_configuration()
    _deploy_exporters_configuration()


def _update_config():

    def postgresql_ip_address():
        if config.get(POSTGRESQL_SERVER, {}).get(ENABLE_REMOTE_CONNECTIONS):
            return ipv6_url_compat(config.get(MANAGER, {}).get(PRIVATE_IP))
        return 'localhost'

    def postgres_ca_cert_path():
        if ('ca_path' in config[POSTGRESQL_SERVER] and
                config[POSTGRESQL_SERVER]['ca_path']):
            return config[POSTGRESQL_SERVER]['ca_path']
        if config[POSTGRESQL_CLIENT][SSL_ENABLED]:
            return constants.POSTGRESQL_CA_CERT_PATH
        return ''

    logger.notice('Updating configuration for Prometheus...')
    if POSTGRES_EXPORTER in config[PROMETHEUS]:
        if ('ip_address' not in config[PROMETHEUS][POSTGRES_EXPORTER] or
                not config[PROMETHEUS][POSTGRES_EXPORTER]['ip_address']):
            config[PROMETHEUS][POSTGRES_EXPORTER].update(
                {'ip_address': postgresql_ip_address()})
        if config.get(POSTGRESQL_SERVER, {}).get(SSL_ENABLED):
            config[PROMETHEUS][POSTGRES_EXPORTER].update(
                {'sslmode': 'verify-full'})
            if ('ca_cert_path' not in config[PROMETHEUS][POSTGRES_EXPORTER] or
                    not config[PROMETHEUS][POSTGRES_EXPORTER]['ca_cert_path']):
                config[PROMETHEUS][POSTGRES_EXPORTER].update(
                    {'ca_cert_path': postgres_ca_cert_path()})
        else:
            config[PROMETHEUS][POSTGRES_EXPORTER].update(
                {'sslmode': 'disable'})
    if (MANAGER_SERVICE in config[SERVICES_TO_INSTALL] and
        ('ca_cert_path' not in config.get(PROMETHEUS,
                                          {}).get(BLACKBOX_EXPORTER, {}) or
         not config.get(PROMETHEUS,
                        {}).get(BLACKBOX_EXPORTER, {}).get('ca_cert_path'))):
        if not config[PROMETHEUS].get(BLACKBOX_EXPORTER):
            config[PROMETHEUS][BLACKBOX_EXPORTER] = {}
        config[PROMETHEUS][BLACKBOX_EXPORTER].update(
            {'ca_cert_path': config.get(CONSTANTS, {}).get('ca_cert_path')})


def _get_cluster_config():
    """Cluster setup for setting up monitoring targets.

    Based on config.yaml, but with fallback to reading nodes stored
    in the db (on manager-only nodes).
    """
    if common.is_only_manager_service_in_config():
        return get_monitoring_config()

    return {}


def _update_prometheus_configuration(uninstalling=False):
    logger.notice('Updating Prometheus configuration...')

    if not uninstalling:
        credentials = common.get_prometheus_credentials()
        files.deploy(
            join(CONFIG_DIR, 'prometheus.yml'),
            PROMETHEUS_CONFIG_PATH,
            additional_render_context={'credentials': credentials})
        common.run(['mkdir', '-p', PROMETHEUS_TARGETS_DIR])

    private_ip = config[MANAGER][PRIVATE_IP]

    _update_base_targets(private_ip, uninstalling)

    if common.service_is_in_config(MANAGER_SERVICE):
        if uninstalling:
            # When uninstalling we don't use the config anyway, so all that we
            # accomplish by trying to retrieve it is allowing the uninstall to
            # hang sometimes
            cluster_config = {}
        else:
            cluster_config = _get_cluster_config()
        http_probes_count = _update_manager_targets(
            private_ip, cluster_config, uninstalling)
        _deploy_alerts_configuration(
            http_probes_count, cluster_config, uninstalling)

    if common.service_is_in_config(DATABASE_SERVICE):
        _update_local_postgres_targets(private_ip, uninstalling)

    if common.service_is_in_config(QUEUE_SERVICE):
        _update_local_rabbit_targets(private_ip, uninstalling)

    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, PROMETHEUS_CONFIG_DIR)


def _prometheus_targets_exist():
    logger.info('Checking whether any prometheus targets still exist.')
    for conf in [
        'local_http_200_manager.yml',
        'local_postgres.yml',
        'local_rabbit.yml',
        'other_managers.yml',
        'other_rabbits.yml',
        'other_postgres.yml',
    ]:
        conf_path = join(PROMETHEUS_TARGETS_DIR, conf)
        logger.debug('Checking %s', conf_path)
        config = files.read_yaml_file(conf_path)
        if config and config[0].get('targets'):
            logger.info('Found remaining prometheus targets.')
            return True
    logger.info('No prometheus targets remain.')
    return False


def _update_local_rabbit_targets(private_ip, uninstalling):
    if uninstalling:
        logger.info(
            'Uninstall: prometheus local rabbit targets will be cleared.')
        local_rabbit_targets = []
        local_rabbit_labels = {}
    else:
        logger.info('Generating prometheus local rabbit targets.')
        local_rabbit_targets = ['localhost:15692']
        local_rabbit_labels = {'host': private_ip}
    logger.info('Updating prometheus local rabbit target configs')
    _deploy_targets('local_rabbit.yml',
                    local_rabbit_targets, local_rabbit_labels)


def _update_local_postgres_targets(private_ip, uninstalling):
    if uninstalling:
        logger.info(
            'Uninstall: prometheus local postgres targets will be cleared.')
        local_postgres_targets = []
        local_postgres_labels = {}
    else:
        logger.info('Generating prometheus local postgres targets.')
        local_postgres_targets = ['localhost:9187']
        local_postgres_labels = {'host': private_ip}
    logger.info('Updating prometheus local postgres target configs')
    _deploy_targets('local_postgres.yml',
                    local_postgres_targets, local_postgres_labels)


def _update_manager_targets(private_ip, cluster_config, uninstalling):
    http_200_targets = []
    http_200_labels = {}
    rabbit_targets = []
    rabbit_labels = {}
    postgres_targets = []
    postgres_labels = {}
    manager_targets = []
    manager_labels = {}
    if uninstalling:
        logger.info('Uninstall: prometheus manager targets will be cleared.')
    else:
        logger.info('Generating prometheus manager targets.')
        http_200_labels['host'] = private_ip
        composer_installed = (
            is_premium_installed()
            and not config[COMPOSER]['skip_installation']
        )
        if composer_installed:
            # Monitor composer directly and via nginx
            http_200_targets.append('http://127.0.0.1:3000/')
        # Monitor stage directly and via nginx
        http_200_targets.append('http://127.0.0.1:8088')
        # Monitor cloudify's internal port
        http_200_targets.append('https://{}:53333/api/v3.1/ok'
                                .format(private_ip))
        # Monitor cloudify restservice
        http_200_targets.append('http://127.0.0.1:8100/api/v3.1/ok')
        # Monitor cloudify-api's openapi.json
        http_200_targets.append('http://127.0.0.1:8101/openapi.json')

        monitoring_port = str(constants.MONITORING_PORT)

        # Monitor remote rabbit nodes
        use_rabbit_host = config[RABBITMQ]['use_hostnames_in_db']
        for host, ip in cluster_config.get('rabbitmq_nodes', {}).items():
            target = host if use_rabbit_host else ip
            if not (_installing_rabbit() and target == private_ip):
                rabbit_targets.append(target + ':' + monitoring_port)

        # Monitor remote postgres nodes
        for db_ip in cluster_config.get('db_nodes', []):
            postgres_targets.append(db_ip + ':' + monitoring_port)

        # Monitor remote manager nodes
        manager_nodes = cluster_config.get('manager_nodes', [])
        if len(manager_nodes) > 1:
            for manager in manager_nodes:
                manager_targets.append(
                    manager + ':' + monitoring_port)

    logger.info('Updating prometheus manager target configs')
    _deploy_targets('local_http_200_manager.yml',
                    http_200_targets, http_200_labels)
    _deploy_targets('other_rabbits.yml',
                    rabbit_targets, rabbit_labels)
    _deploy_targets('other_postgres.yml',
                    postgres_targets, postgres_labels)
    _deploy_targets('other_managers.yml',
                    manager_targets, manager_labels)
    return len(http_200_targets)


def _update_base_targets(private_ip, uninstalling):
    if uninstalling:
        logger.info('Uninstall: Doing nothing with base prometheus targets.')
        return

    logger.info('Updating prometheus base monitoring targets.')
    prometheus_targets = ['127.0.0.1:{}'.format(config[PROMETHEUS]['port'])]
    prometheus_labels = {'host': private_ip}
    _deploy_targets('local_prometheus.yml',
                    prometheus_targets, prometheus_labels)
    node_exporter_targets = [
        'localhost:{}'.format(
            config[PROMETHEUS]['node_exporter']['metrics_port']
        )
    ]
    node_exporter_labels = {'host': private_ip}
    _deploy_targets('local_node_exporter.yml',
                    node_exporter_targets, node_exporter_labels)


def _deploy_targets(destination, targets, labels):
    """Deploy a target file for prometheus.
    :param destination: Target file name in targets dir.
    :param targets: List of targets for prometheus.
    :param labels: Dict of labels with values for prometheus."""
    files.deploy(
        join(CONFIG_DIR, 'targets.yml'),
        join(PROMETHEUS_TARGETS_DIR, destination),
        additional_render_context={
            'target_addresses': json.dumps(targets),
            'target_labels': json.dumps(labels),
        },
    )


def _deploy_alerts_configuration(number_of_http_probes, cluster_config,
                                 uninstalling):
    render_context = {
        'number_of_http_probes': number_of_http_probes,
        'all_in_one': common.is_all_in_one_manager(),
        'alert_for': _calculate_alert_for(
            config.get(PROMETHEUS, {}).get('scrape_interval')),
        'fs_replication': common.filesystem_replication_enabled(),
    }
    manager_hosts = []
    rabbitmq_hosts = []
    postgres_hosts = []

    if uninstalling:
        logger.info('Uninstall: Prometheus "missing" alerts will be cleared.')
    else:
        if config.get(CLUSTER_JOIN):
            for manager in cluster_config.get('manager_nodes', []):
                manager_hosts.append(manager)
        else:
            manager_hosts.append(config[MANAGER][PRIVATE_IP])

        if cluster_config.get('db_nodes', []):
            for db_ip in cluster_config.get('db_nodes'):
                postgres_hosts.append(db_ip)
        else:
            postgres_hosts.append(config[MANAGER][PRIVATE_IP])

        if cluster_config.get('rabbitmq_nodes'):
            use_rabbit_host = config[RABBITMQ]['use_hostnames_in_db']
            for host, ip in cluster_config.get('rabbitmq_nodes', {}).items():
                rabbitmq_hosts.append(host if use_rabbit_host else ip)
        else:
            rabbitmq_hosts.append(config[MANAGER][PRIVATE_IP])

    for alert_group in ['manager', 'postgres', 'rabbitmq']:
        logger.notice('Deploying {0} alerts...'.format(alert_group))

        file_name = '{0}.yml'.format(alert_group)
        dest_file_name = join(PROMETHEUS_ALERTS_DIR, file_name)
        files.deploy(join(CONFIG_DIR, 'alerts', file_name), dest_file_name,
                     additional_render_context=render_context)
        common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, dest_file_name)

    logger.notice('Deploying "missing" alerts...')
    _deploy_alerts_missing(render_context, 'manager_missing.yml', 'manager',
                           manager_hosts)
    _deploy_alerts_missing(render_context, 'rabbitmq_missing.yml', 'rabbitmq',
                           rabbitmq_hosts)
    _deploy_alerts_missing(render_context, 'postgres_missing.yml', 'postgres',
                           postgres_hosts)


def _calculate_alert_for(scrape_interval):
    scrape_interval = '{0}'.format(scrape_interval).lower() if scrape_interval\
        else ''
    m = re.match(r'^((\d+)s)?((\d+)ms)?', scrape_interval)
    if not m or not m.lastindex or m.lastindex < 1:
        return '15s'
    scrape_seconds = int(m[2] or 0) + 0.001 * int(m[4] or 0)
    if scrape_seconds >= 15.0:
        return '15s'
    else:
        return m[0]


def _deploy_alerts_missing(render_context, destination, service_name, hosts):
    render_context.update({'name': service_name, 'hosts': hosts})
    dest_file_name = join(PROMETHEUS_ALERTS_DIR, destination)
    files.deploy(join(CONFIG_DIR, 'alerts', 'missing.yml'), dest_file_name,
                 additional_render_context=render_context)
    common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, dest_file_name)


def _deploy_exporters_configuration():
    for exporter in _prometheus_exporters():
        if 'deploy_config' not in exporter:
            continue
        logger.notice(
            'Deploying {0} configuration...'.format(exporter['description']))
        for file_name, dest_file_name in exporter['deploy_config'].items():
            files.deploy(join(CONFIG_DIR, file_name), dest_file_name)
            common.chown(CLOUDIFY_USER, CLOUDIFY_GROUP, dest_file_name)


def _prometheus_additional_configuration():
    # The prometheus_query_lookback_delta is used to render Prometheus'
    # `query.lookback-delta` flag.  The flag defines the maximum lookback
    # duration for retrieving metrics during expression evaluations and
    # federation.  The default value (5 minutes) might be too long to find out
    # about a missing cluster node.  The code here causes the cluster to become
    # accurate more quickly when a node is lost.
    return {
        'prometheus_query_lookback_delta':
            _calculate_lookback_delta_for(config['prometheus']
                                          .get('scrape_interval', ))
    }


def _calculate_lookback_delta_for(scrape_interval):
    scrape_interval = '{0}'.format(scrape_interval).lower() if scrape_interval\
        else ''
    # The scrape interval is expected to be in the form of 5s, 900ms or 2s500ms
    m = re.match(r'^((\d+)s)?((\d+)ms)?', scrape_interval)
    if not m or not m.lastindex or m.lastindex < 1:
        return '40s'
    scrape_seconds = int(m[2] or 0) + 0.001 * int(m[4] or 0)
    return '{0:d}s'.format(round(2.7 * scrape_seconds))
