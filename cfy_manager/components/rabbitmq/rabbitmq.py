import os
import json
import time
import base64
import socket
import hashlib
from os.path import join

from retrying import retry
import requests

from ..components_constants import (
    CONFIG,
    SCRIPTS,
    SERVICES_TO_INSTALL,
    HOSTNAME
)
from ..base_component import BaseComponent
from ..validations import validate_certificates
from ..service_names import RABBITMQ, MANAGER, MANAGER_SERVICE
from ... import constants
from ...utils import certificates, common
from ...config import config
from ...logger import get_logger
from ...exceptions import (
    ClusteringError,
    NetworkError,
    ProcessExecutionError,
    RabbitNodeListError,
    ValidationError,
)
from ...utils import service
from ...utils.network import wait_for_port, is_port_open
from ...utils.common import sudo, can_lookup_hostname, remove as remove_file
from ...utils.files import write_to_file, deploy


LOG_DIR = join(constants.BASE_LOG_DIR, RABBITMQ)
HOME_DIR = join('/etc', RABBITMQ)
CONFIG_PATH = join(constants.COMPONENTS_DIR, RABBITMQ, CONFIG)
SCRIPTS_PATH = join(
    constants.COMPONENTS_DIR,
    RABBITMQ,
    SCRIPTS,
)
RABBITMQ_CONFIG_PATH = '/etc/cloudify/rabbitmq/rabbitmq.config'
RABBITMQ_SERVER_SCRIPT = '/var/lib/rabbitmq/start_rabbitmq_server.sh'
RABBITMQ_ENV_PATH = '/etc/rabbitmq/rabbitmq-env.conf'
RABBITMQ_ENABLED_PLUGINS = '/etc/cloudify/rabbitmq/enabled_plugins'
SECURE_PORT = 5671

ALL_IN_ONE_ADDRESS = 'ALL_IN_ONE'

RABBITMQ_CTL = 'rabbitmqctl'
logger = get_logger(RABBITMQ)


class RabbitMQ(BaseComponent):
    component_name = 'rabbitmq'
    services = ['cloudify-rabbitmq']

    def _installing_manager(self):
        return MANAGER_SERVICE in config[SERVICES_TO_INSTALL]

    def _deploy_configuration(self):
        logger.info('Deploying RabbitMQ config')
        deploy(join(CONFIG_PATH, 'rabbitmq.config'), RABBITMQ_CONFIG_PATH)
        common.chown('rabbitmq', 'rabbitmq', RABBITMQ_CONFIG_PATH)
        deploy(join(CONFIG_PATH, 'enabled_plugins'), RABBITMQ_ENABLED_PLUGINS)
        common.chown('rabbitmq', 'rabbitmq', RABBITMQ_ENABLED_PLUGINS)

    def _deploy_env(self):
        # This will make 'sudo rabbitmqctl' work without specifying node name
        logger.info('Deploying RabbitMQ env')
        deploy(join(CONFIG_PATH, 'rabbitmq-env.conf'), RABBITMQ_ENV_PATH)
        common.chown('rabbitmq', 'rabbitmq', RABBITMQ_ENV_PATH)

    def _init_service(self):
        logger.info('Initializing RabbitMQ...')
        rabbit_config_path = join(HOME_DIR, 'rabbitmq.config')

        # Delete old mnesia node
        remove_file('/var/lib/rabbitmq/mnesia')
        remove_file(rabbit_config_path)
        self._deploy_configuration()
        self._deploy_env()
        service.reload('cloudify-rabbitmq', ignore_failure=True)

    def _rabbitmqctl(self, command, **kwargs):
        base_command = [RABBITMQ_CTL]
        if config[RABBITMQ]['use_long_name']:
            base_command.append('--longnames')
        return sudo(base_command + command, **kwargs)

    def user_exists(self, username):
        output = self._rabbitmqctl(['list_users'], retries=5).aggr_stdout
        return username in output

    def _manage_users(self):
        self._delete_guest_user()
        self._create_rabbitmq_user()

    def _delete_guest_user(self):
        if self.user_exists('guest'):
            logger.info('Disabling RabbitMQ guest user...')
            self._rabbitmqctl(['clear_permissions', 'guest'], retries=5)
            self._rabbitmqctl(['delete_user', 'guest'], retries=5)

    def _create_rabbitmq_user(self):
        rabbitmq_username = config[RABBITMQ]['username']
        rabbitmq_password = config[RABBITMQ]['password']
        if not self.user_exists(rabbitmq_username):
            logger.info('Creating new user and setting permissions...')
            self._rabbitmqctl(['add_user',
                               rabbitmq_username,
                               rabbitmq_password])
            self._rabbitmqctl(['set_permissions',
                               rabbitmq_username,
                               '.*',
                               '.*',
                               '.*'],
                              retries=5)
            self._rabbitmqctl(['set_user_tags',
                               rabbitmq_username,
                               'administrator'])

    def _possibly_set_nodename(self):
        nodename = config[RABBITMQ]['nodename']

        if not nodename:
            if config[RABBITMQ]['cluster_members']:
                raise ValidationError(
                    'Rabbitmq nodename must be set for clustering.'
                )
            nodename = 'localhost'

        if not config[RABBITMQ]['use_long_name']:
            nodename = nodename.split('.')[0]

        nodename = self.add_missing_nodename_prefix(nodename)

        config[RABBITMQ]['nodename'] = nodename

    def add_missing_nodename_prefix(self, nodename):
        if '@' not in nodename:
            # Use this prefix to make rabbitmqctl able to work without '-n'
            nodename = 'rabbit@' + nodename
        return nodename

    def _set_erlang_cookie(self):
        cookie = config[RABBITMQ]['erlang_cookie']
        if len(config[RABBITMQ]['cluster_members']) > 1 and not cookie:
            raise ValidationError(
                'Cluster members are configured but erlang_cookie has not '
                'been set.'
            )

        if cookie:
            write_to_file(cookie.strip(), '/var/lib/rabbitmq/.erlang.cookie')
            sudo(['chown', 'rabbitmq.', '/var/lib/rabbitmq/.erlang.cookie'])

    def _possibly_join_cluster(self):
        join_node = config[RABBITMQ]['join_cluster']
        if not join_node:
            return
        self.join_cluster(join_node)

    def join_cluster(self, join_node, restore_users_on_fail=False):
        join_node = self.add_missing_nodename_prefix(join_node)
        joined = False

        logger.info(
            'Joining cluster via node {target_node}.'.format(
                target_node=join_node,
            )
        )
        self._rabbitmqctl(['stop_app'])
        self._rabbitmqctl(['reset'])
        try:
            self._rabbitmqctl(['join_cluster', join_node])
            joined = True
        except ProcessExecutionError as err:
            if 'mnesia_not_running' in str(err):
                raise ClusteringError(
                    'Rabbit does not appear to be running on {target}. '
                    'You may need to start rabbit on that node, or restart '
                    'that node.'.format(target=join_node)
                )
            else:
                raise
        finally:
            self._rabbitmqctl(['start_app'])
            if restore_users_on_fail and not joined:
                self._manage_users()

        # Clustering completes very quickly but the management plugin can take
        # a long time to reflect the actual cluster state so we wait longer
        # than we should need to.
        attempt = 0
        max_attempts = 20
        delay = 5
        while attempt != max_attempts:
            attempt += 1
            logger.info(
                'Checking rabbit cluster is joined [{at}/{mx}]....'.format(
                    at=attempt,
                    mx=max_attempts,
                )
            )
            rabbit_nodes = self.list_rabbit_nodes()

            # Check that both this node and the node we're joining to are in
            # the cluster
            required = [
                join_node,
                config[RABBITMQ]['nodename'],
            ]
            if not all(node in rabbit_nodes['nodes'] for node in required):
                if attempt == max_attempts:
                    raise ClusteringError(
                        'Node did not join cluster within {num} attempts. '
                        'Attempted to join to {target_node}. '
                        'Last cluster status output was: {output}.'.format(
                            num=max_attempts,
                            target_node=join_node,
                            output=json.dumps(rabbit_nodes),
                        )
                    )
                else:
                    time.sleep(delay)
                    continue
            else:
                logger.info('Cluster successfully joined.')
                break

    def list_rabbit_nodes(self):
        nodename = config[RABBITMQ]['nodename'].split('@')[-1]
        nodes_url = 'https://{}:15671/api/nodes'.format(nodename)

        if config[RABBITMQ]['cluster_members']:
            try:
                default_ip = config[RABBITMQ]['cluster_members'][
                    nodename]['networks']['default']
            except KeyError:
                logger.warning('Current node %s has no default network '
                               'address set in cluster_members, falling '
                               'back to localhost', nodename)
            else:
                nodes_url = 'https://{0}:15671/api/nodes'.format(default_ip)

        auth = (
            config[RABBITMQ]['username'],
            config[RABBITMQ]['password'],
        )
        try:
            nodes_list = requests.get(
                nodes_url,
                auth=auth,
                verify=config[RABBITMQ]['ca_path'],
            ).json()
        except requests.ConnectionError as err:
            logger.error(
                'Failed to list rabbit nodes. Error was: {err}'.format(
                    err=str(err),
                )
            )
            return None

        if 'error' in nodes_list:
            raise RabbitNodeListError(
                'Error trying to list nodes. Response was: {0}'.format(
                    nodes_list,
                )
            )

        # The returned structure is based on Rabbitmq management plugin 3.7.7
        # It expects a list of nodes with structure similar to:
        # {
        #    "name": "<name of node>",
        #    "running": <true|false>,
        #    "some_alarm": <true|false>,
        #    "other_alarm": <true|false>,
        #    # The following listed items are also treated as alarms
        #    "badrpc": <true|false>,
        #    "nodedown": <true|false>,
        #    ...
        # }
        likely_name_resolution_issue = False
        alarms = {}
        for node in nodes_list:
            alarms[node['name']] = [
                entry for entry in node
                if 'alarm' in entry and node[entry]
            ]
            for resolution_fail_alarm in ('badrpc', 'nodedown'):
                if node.get(resolution_fail_alarm):
                    alarms[node['name']].append(resolution_fail_alarm)
                    likely_name_resolution_issue = True

        if likely_name_resolution_issue:
            logger.error(
                'badrpc and/or nodedown alarms found. '
                'This may indicate that the affected node(s) cannot resolve '
                'the names of other nodes in the cluster. This likely '
                'requires DNS or hosts entries for the affected nodes.'
            )

        return {
            'nodes': [node['name'] for node in nodes_list],
            'running_nodes': [
                node['name'] for node in nodes_list
                if node['running']
            ],
            'alarms': alarms,
        }

    def remove_node(self, node_name):
        self._rabbitmqctl(['forget_cluster_node', node_name])

    def _possibly_add_hosts_entries(self):
        cluster_nodes = config[RABBITMQ]['cluster_members']
        if cluster_nodes:
            logger.info(
                'Checking whether cluster nodes are resolvable via DNS'
            )
            not_resolved = []
            for node in cluster_nodes:
                if can_lookup_hostname(node):
                    logger.info(
                        'Successfully resolved {node}'.format(node=node)
                    )
                else:
                    not_resolved.append(node)

            if not not_resolved:
                logger.info('All nodes were resolvable.')
                return

            add_to_hosts = ['', '# Added for cloudify rabbitmq clustering']
            for node in not_resolved:
                ip = cluster_nodes[node]['networks']['default']
                if not ip:
                    raise ValidationError(
                        'IP not provided for unresolvable rabbit node '
                        '{node}. '
                        'A default network ip must be set for this '
                        'node.'.format(
                            node=node,
                        )
                    )
                try:
                    ip = socket.gethostbyname(ip)
                except socket.gaierror as e:
                    raise ValidationError(
                        'Cannot resolve: {addr} (rabbitmq node {node} default '
                        'network address): {err}'.format(
                            addr=ip, node=node, err=e
                        )
                    )
                add_to_hosts.append('{ip} {name}'.format(
                    ip=ip,
                    name=node,
                ))

            logger.info(
                'Adding rabbit nodes to hosts file: {adding_nodes}'.format(
                    adding_nodes=', '.join(not_resolved),
                )
            )
            with open('/etc/hosts') as hosts_handle:
                hosts = hosts_handle.readlines()

            # Append the data to the current hosts entries
            hosts.extend(add_to_hosts)
            hosts = [host.strip() for host in hosts]
            hosts = '\n'.join(hosts) + '\n'

            # Back up original hosts file
            sudo([
                'cp', '/etc/hosts', '/etc/hosts.bak-{timestamp:.0f}'.format(
                    timestamp=time.time()
                )
            ])

            write_to_file(hosts, '/etc/hosts')

            logger.info('Updated /etc/hosts')

    def _generate_rabbitmq_certs(self):
        supplied = self.handle_certificates()

        if supplied:
            logger.info('Using supplied certificates.')
            return
        else:
            config[RABBITMQ]['cert_path'] = constants.BROKER_CERT_LOCATION
            config[RABBITMQ]['key_path'] = constants.BROKER_KEY_LOCATION

        logger.info('Generating rabbitmq certificate...')

        if self._installing_manager():
            has_ca_key = certificates.handle_ca_cert(logger)
        else:
            has_ca_key = False
            # If we're not installing the manager and user certs were not
            # supplied then we're about to generate self-signed certs.
            # As we're going to do this, we'll set the ca_path such that
            # anything consuming this value will get the path to the cert
            # that will allow them to trust the broker.
            config[RABBITMQ]['ca_path'] = config[RABBITMQ]['cert_path']
        if len(config[RABBITMQ]['cluster_members']) > 1:
            raise ValidationError(
                'Cannot generate self-signed certificates for a rabbitmq '
                'cluster- externally generated certificates must be provided '
                'as well as the appropriate CA certificate.'
            )
        # As we only support generating certificates on single-broker setups,
        # we will take only the first cluster member (having failed before now
        # if there are multiple cluster members specified)
        rabbit_host = config[MANAGER][HOSTNAME]
        networks = config[RABBITMQ]['cluster_members'][rabbit_host]['networks']

        cert_addresses = list(networks.values())
        cert_addresses.append(config[RABBITMQ]['nodename'].split('@')[-1])

        certificates.store_cert_metadata(
            rabbit_host,
            new_brokers=cert_addresses,
            new_networks=list(networks.keys()),
            # The cfyuser won't exist yet (and may never exist if only rabbit
            # is being installed)
            owner='rabbitmq',
            group='rabbitmq',
        )

        sign_cert = constants.CA_CERT_PATH if has_ca_key else None
        sign_key = constants.CA_KEY_PATH if has_ca_key else None

        certificates._generate_ssl_certificate(
            ips=cert_addresses,
            cn=rabbit_host,
            cert_path=config[RABBITMQ]['cert_path'],
            key_path=config[RABBITMQ]['key_path'],
            sign_cert=sign_cert,
            sign_key=sign_key,
            owner='rabbitmq',
            group='rabbitmq',
        )

    def handle_certificates(self):
        ca_destination = (constants.CA_CERT_PATH if
                          common.is_all_in_one_manager()
                          else constants.BROKER_CA_LOCATION)
        cert_config = {
            'component_name': self.component_name,
            'logger': logger,
            'cert_destination': constants.BROKER_CERT_LOCATION,
            'key_destination': constants.BROKER_KEY_LOCATION,
            'ca_destination': ca_destination,
            'owner': 'rabbitmq',
            'group': 'rabbitmq',
            'key_perms': '440',
            'cert_perms': '444',
        }

        return certificates.use_supplied_certificates(**cert_config)

    def replace_certificates(self):
        if (os.path.exists(constants.NEW_BROKER_CERT_FILE_PATH) or
                os.path.exists(constants.NEW_BROKER_CA_CERT_FILE_PATH)):
            logger.info(
                'Replacing certificates on the rabbitmq component')
            self.stop()
            self._write_certs_to_config()
            self.handle_certificates()
            self.start()

    @staticmethod
    def _write_certs_to_config():
        if os.path.exists(constants.NEW_BROKER_CERT_FILE_PATH):
            config[RABBITMQ]['cert_path'] = \
                constants.NEW_BROKER_CERT_FILE_PATH
            config[RABBITMQ]['key_path'] = \
                constants.NEW_BROKER_KEY_FILE_PATH
        if common.is_all_in_one_manager():
            if os.path.exists(constants.NEW_INTERNAL_CA_CERT_FILE_PATH):
                config[RABBITMQ]['ca_path'] = \
                    constants.NEW_INTERNAL_CA_CERT_FILE_PATH
        else:
            if os.path.exists(constants.NEW_BROKER_CA_CERT_FILE_PATH):
                config[RABBITMQ]['ca_path'] = \
                    constants.NEW_BROKER_CA_CERT_FILE_PATH

    def validate_new_certs(self):
        if common.is_all_in_one_manager():
            if os.path.exists(constants.NEW_INTERNAL_CA_CERT_FILE_PATH):
                validate_certificates(
                    cert_filename=constants.NEW_BROKER_CERT_FILE_PATH,
                    key_filename=constants.NEW_BROKER_KEY_FILE_PATH,
                    ca_filename=constants.NEW_INTERNAL_CA_CERT_FILE_PATH)
        else:
            certificates.get_and_validate_certs_for_replacement(
                default_cert_location=constants.BROKER_CERT_LOCATION,
                default_key_location=constants.BROKER_KEY_LOCATION,
                default_ca_location=constants.BROKER_CA_LOCATION,
                new_cert_location=constants.NEW_BROKER_CERT_FILE_PATH,
                new_key_location=constants.NEW_BROKER_KEY_FILE_PATH,
                new_ca_location=constants.NEW_BROKER_CA_CERT_FILE_PATH
            )

    # Give rabbit time to finish starting
    @retry(stop_max_attempt_number=20, wait_fixed=3000)
    def verify_started(self):
        logger.info('Making sure RabbitMQ is live...')
        wait_for_port(SECURE_PORT)

        result = self._rabbitmqctl(['status'])
        if result.returncode != 0:
            raise ValidationError('Rabbitmq failed to start')

        if not is_port_open(SECURE_PORT, host='127.0.0.1'):
            raise NetworkError(
                '{0} error: port {1}:{2} was not open'.format(
                    RABBITMQ, '127.0.0.1', SECURE_PORT)
            )

    def _set_config(self):
        self._possibly_set_nodename()
        if common.is_all_in_one_manager():
            # We must populate the brokers table for an all-in-one manager
            config[RABBITMQ]['cluster_members'] = {
                config[MANAGER][HOSTNAME]: {
                    'address': ALL_IN_ONE_ADDRESS,
                    'networks': config['networks']
                }
            }

    def _configure_rabbitmq_wrapper_script(self):
        deploy(
            join(
                SCRIPTS_PATH,
                'start_rabbitmq_server.sh'
            ),
            '/var/lib/rabbitmq/',
            render=False
        )
        common.chown('rabbitmq', 'rabbitmq', RABBITMQ_SERVER_SCRIPT)
        common.chmod('755', RABBITMQ_SERVER_SCRIPT)

    def _rabbitmq_hash(self, password):
        salt = os.urandom(4)
        hashed = hashlib.sha256(salt + password.encode('utf-8')).digest()
        return base64.b64encode(salt + hashed).decode('utf-8')

    def _write_definitions_file(self):
        write_to_file({
            'vhosts': [{'name': '/'}],
            'users': [{
                'hashing_algorithm': 'rabbit_password_hashing_sha256',
                'name': config[RABBITMQ]['username'],
                'password_hash': self._rabbitmq_hash(
                    config[RABBITMQ]['password']),
                'tags': 'administrator'
            }],
            'permissions': [{
                'user': config[RABBITMQ]['username'],
                'vhost': '/',
                'configure': '.*',
                'write': '.*',
                'read': '.*'
            }],
            'policies': [{
                'name': policy['name'],
                'vhost': policy.get('vhost', '/'),
                'pattern': policy['expression'],
                'priority': policy.get('priority', 1),
                'apply-to': (policy.get('apply-to') or
                             policy.get('apply_to') or 'queues'),
                'definition': policy['policy']
            } for policy in config[RABBITMQ]['policies']]
        }, '/etc/cloudify/rabbitmq/definitions.json', json_dump=True)
        common.chown(
            'rabbitmq', 'rabbitmq', '/etc/cloudify/rabbitmq/definitions.json')

    def configure(self):
        logger.notice('Configuring RabbitMQ...')
        self._set_erlang_cookie()
        self._set_config()
        if self.service_type == 'supervisord':
            self._configure_rabbitmq_wrapper_script()
        if not common.is_all_in_one_manager():
            self._possibly_add_hosts_entries()
        service.configure('cloudify-rabbitmq',
                          user='rabbitmq', group='rabbitmq')
        self._generate_rabbitmq_certs()
        if self._installing_manager():
            config[RABBITMQ]['ca_path'] = constants.CA_CERT_PATH
        self._init_service()
        if self._installing_manager():
            config[RABBITMQ]['ca_path'] = constants.CA_CERT_PATH
        if not config[RABBITMQ]['join_cluster']:
            self._write_definitions_file()
        self.start()
        self._possibly_join_cluster()
        logger.notice('RabbitMQ successfully configured')

    def remove(self):
        logger.info('Stopping the Erlang Port Mapper Daemon...')
        sudo(['epmd', '-kill'], ignore_failures=True)
        service.remove('cloudify-rabbitmq', service_file=False)
        logger.info('Removing rabbit data...')
        sudo(['rm', '-rf', '/var/lib/rabbitmq'])
        sudo(['rm', '-rf', '/etc/rabbitmq'])
