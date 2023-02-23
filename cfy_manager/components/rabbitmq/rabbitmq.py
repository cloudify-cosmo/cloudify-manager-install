from os.path import join
import base64
import hashlib
import json
import os
import random
import socket
import string
import time

from retrying import retry
import requests

from ...components_constants import (
    CONFIG,
    HOSTNAME,
    PRIVATE_IP,
    SCRIPTS,
    SERVICES_TO_INSTALL,
)
from ..base_component import BaseComponent
from ...service_names import RABBITMQ, MANAGER, MANAGER_SERVICE
from ... import constants
from ...utils import certificates, common, network
from ...config import config
from ...logger import get_logger
from ...exceptions import (
    ClusteringError,
    NetworkError,
    ProcessExecutionError,
    RabbitNodeListError,
    ValidationError,
)
from ...utils import service, syslog
from ...utils.network import wait_for_port, is_port_open, lo_has_ipv6_addr
from ...utils.common import run, can_lookup_hostname
from ...utils.files import write, deploy, remove
from cfy_manager.utils.install_state import get_configured_services


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
RABBITMQ_ERL_INETRC = '/etc/rabbitmq/erl_inetrc'
QUEUES_REBALANCING_SCRIPT_PATH = '/etc/cloudify/rabbitmq/rebalance_queues.py'
SECURE_PORT = 5671

ALL_IN_ONE_ADDRESS = 'ALL_IN_ONE'

RABBITMQ_CTL = 'rabbitmqctl'
logger = get_logger(RABBITMQ)


class RabbitMQ(BaseComponent):
    component_name = 'rabbitmq'
    services = {'cloudify-rabbitmq': {'is_group': False}}

    def _installing_manager(self):
        return MANAGER_SERVICE in config[SERVICES_TO_INSTALL]

    def _deploy_configuration(self):
        logger.info('Deploying RabbitMQ config')
        deploy(join(CONFIG_PATH, 'rabbitmq.config'), RABBITMQ_CONFIG_PATH,
               additional_render_context={'ipv6_enabled': lo_has_ipv6_addr()})
        common.chown('rabbitmq', 'rabbitmq', RABBITMQ_CONFIG_PATH)
        deploy(join(CONFIG_PATH, 'enabled_plugins'), RABBITMQ_ENABLED_PLUGINS)
        common.chown('rabbitmq', 'rabbitmq', RABBITMQ_ENABLED_PLUGINS)

    def _deploy_env(self):
        # This will make 'sudo rabbitmqctl' work without specifying node name
        ipv6_enabled = _is_ipv6_enabled()
        logger.info('Deploying RabbitMQ env')
        deploy(join(CONFIG_PATH, 'rabbitmq-env.conf'), RABBITMQ_ENV_PATH,
               additional_render_context={'ipv6_enabled': ipv6_enabled})
        common.chown('rabbitmq', 'rabbitmq', RABBITMQ_ENV_PATH)
        if ipv6_enabled:
            logger.info('Deploying Erlang inet configuration')
            deploy(join(CONFIG_PATH, 'erl_inetrc'), RABBITMQ_ERL_INETRC)
            common.chown('rabbitmq', 'rabbitmq', RABBITMQ_ERL_INETRC)

    def _init_service(self):
        if 'queue_service' in get_configured_services():
            logger.info('RabbitMQ previously initialized.')
            return

        logger.info('Initializing RabbitMQ...')
        rabbit_config_path = join(HOME_DIR, 'rabbitmq.config')

        # Delete old mnesia node
        remove(['/var/lib/rabbitmq/mnesia', rabbit_config_path])
        self._deploy_configuration()
        self._deploy_env()
        service.reload('cloudify-rabbitmq', ignore_failure=True)
        if not config[RABBITMQ]['join_cluster']:
            self._write_definitions_file()

    def _rabbitmqctl(self, command, **kwargs):
        base_command = [RABBITMQ_CTL]
        if config[RABBITMQ]['use_long_name']:
            base_command.append('--longnames')
        return run(base_command + command, **kwargs)

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
        if not cookie:
            if len(config[RABBITMQ]['cluster_members']) > 1:
                raise ValidationError(
                    'Cluster members are configured but erlang_cookie has '
                    'not been set.'
                )
            else:
                # For single node, we generate a stronger-than-default cookie
                # in case the epmd port is left accessible to untrusted users.
                cookie = ''.join(
                    random.choice(string.ascii_letters + string.digits)
                    for _ in range(64)
                )

        write(cookie.strip(), '/var/lib/rabbitmq/.erlang.cookie',
              owner='rabbitmq', group='rabbitmq', mode=0o600)

    def _possibly_join_cluster(self):
        join_node = config[RABBITMQ]['join_cluster']
        if not join_node:
            return
        self.join_cluster(join_node)
        self._deploy_rebalancer_script_and_create_cronjob()

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
                self.add_missing_nodename_prefix(config[RABBITMQ]['nodename']),
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
        raw_nodename = config[RABBITMQ]['nodename'] or 'rabbit@localhost'
        nodename = raw_nodename.split('@')[-1]
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
                nodes_url = 'https://{0}:15671/api/nodes'.format(
                    network.ipv6_url_compat(default_ip))

        ca_path = config[RABBITMQ]['ca_path'] or constants.CA_CERT_PATH

        auth = (
            config[RABBITMQ]['username'],
            config[RABBITMQ]['password'],
        )
        try:
            nodes_list = requests.get(
                nodes_url,
                auth=auth,
                verify=ca_path,
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
                    ip = ip if network.is_ipv6(ip) \
                        else socket.gethostbyname(ip)
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
            run([
                'cp', '/etc/hosts', '/etc/hosts.bak-{timestamp:.0f}'.format(
                    timestamp=time.time()
                )
            ])

            write(hosts, '/etc/hosts')

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
            sign_cert_path=sign_cert,
            sign_key_path=sign_key,
            owner='rabbitmq',
            group='rabbitmq',
        )

    def handle_certificates(self):
        ca_destination = (constants.CA_CERT_PATH if
                          common.is_all_in_one_manager()
                          else constants.BROKER_CA_LOCATION)
        ca_key_destination = (constants.CA_KEY_PATH if
                              common.is_all_in_one_manager()
                              else constants.BROKER_CA_KEY_LOCATION)
        if not os.path.exists(ca_key_destination):
            ca_key_destination = None

        cert_config = {
            'component_name': self.component_name,
            'logger': logger,
            'cert_destination': constants.BROKER_CERT_LOCATION,
            'key_destination': constants.BROKER_KEY_LOCATION,
            'ca_destination': ca_destination,
            'ca_key_destination': ca_key_destination,
            'owner': 'cfyuser',
            'group': 'cfyuser',
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
            if os.path.exists(constants.NEW_INTERNAL_CA_KEY_FILE_PATH):
                config[RABBITMQ]['ca_key_path'] = \
                    constants.NEW_INTERNAL_CA_KEY_FILE_PATH
        else:
            if os.path.exists(constants.NEW_BROKER_CA_CERT_FILE_PATH):
                config[RABBITMQ]['ca_path'] = \
                    constants.NEW_BROKER_CA_CERT_FILE_PATH
            if os.path.exists(constants.NEW_BROKER_CA_KEY_FILE_PATH):
                config[RABBITMQ]['ca_key_path'] = \
                    constants.NEW_BROKER_CA_KEY_FILE_PATH

    def validate_new_certs(self):
        if common.is_all_in_one_manager():
            if os.path.exists(constants.NEW_INTERNAL_CA_CERT_FILE_PATH):
                certificates.validate_certificates(
                    cert_filename=constants.NEW_BROKER_CERT_FILE_PATH,
                    key_filename=constants.NEW_BROKER_KEY_FILE_PATH,
                    ca_filename=constants.NEW_INTERNAL_CA_CERT_FILE_PATH,
                    ca_key_filename=constants.NEW_INTERNAL_CA_KEY_FILE_PATH)
        else:
            certificates.get_and_validate_certs_for_replacement(
                default_cert_location=constants.BROKER_CERT_LOCATION,
                default_key_location=constants.BROKER_KEY_LOCATION,
                default_ca_location=constants.BROKER_CA_LOCATION,
                default_ca_key_location=constants.BROKER_CA_KEY_LOCATION,
                new_cert_location=constants.NEW_BROKER_CERT_FILE_PATH,
                new_key_location=constants.NEW_BROKER_KEY_FILE_PATH,
                new_ca_location=constants.NEW_BROKER_CA_CERT_FILE_PATH,
                new_ca_key_location=constants.NEW_BROKER_CA_KEY_FILE_PATH,
            )

    # Give rabbit time to finish starting
    @retry(stop_max_attempt_number=20, wait_fixed=3000)
    def verify_started(self):
        logger.info('Making sure RabbitMQ is live...')
        # If a previous start attempt failed because an old instance was
        # running then this should recover. As it's a start, it shouldn't
        # interrupt if the data is still being loaded by the new instance
        service.start('cloudify-rabbitmq')
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
        write(
            {
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
            },
            '/etc/cloudify/rabbitmq/definitions.json', json_dump=True,
            owner='rabbitmq', group='rabbitmq', mode=0o600,
        )

    def _activate_crash_log_permissions_fixup(self):
        time_string = '* * * * *'
        command = (
            '/usr/bin/find /var/log/cloudify/rabbitmq '
            '! -group cfylogs '  # Don't update perms unneccessarily
            '-exec /usr/bin/chgrp cfylogs {} \\; '
            '> /dev/null'  # Don't pollute root's mail with cron
        )
        comment = 'Make erlang crash log readable for cfy log download'
        # As it is changing group we run this as root
        common.add_cron_job(time_string, command, comment, 'root')

    def configure(self):
        logger.notice('Configuring RabbitMQ...')
        syslog.deploy_rsyslog_filters('rabbitmq', ['cloudify-rabbitmq'],
                                      logger)
        self._set_erlang_cookie()
        self._set_config()
        self._configure_rabbitmq_wrapper_script()
        if not common.is_all_in_one_manager():
            self._possibly_add_hosts_entries()
        service.configure('cloudify-rabbitmq',
                          user='rabbitmq', group='rabbitmq')
        self._generate_rabbitmq_certs()
        if self._installing_manager():
            config[RABBITMQ]['ca_path'] = constants.CA_CERT_PATH
        self._init_service()
        self.start()
        self._possibly_join_cluster()
        self._activate_crash_log_permissions_fixup()
        logger.notice('RabbitMQ successfully configured')

    def remove(self):
        logger.info('Stopping the Erlang Port Mapper Daemon...')
        run(['epmd', '-kill'], ignore_failures=True)
        service.remove('cloudify-rabbitmq')
        logger.info('Removing rabbit data...')
        remove(['/var/lib/rabbitmq', '/etc/rabbitmq'])

    def _deploy_rebalancer_script_and_create_cronjob(self):
        logger.info('Deploying queue rebalancing script...')
        source_path = join(constants.COMPONENTS_DIR,
                           RABBITMQ,
                           SCRIPTS,
                           'rebalance_queues.py')
        deploy(source_path, QUEUES_REBALANCING_SCRIPT_PATH)
        common.chmod('+x', QUEUES_REBALANCING_SCRIPT_PATH)
        common.chown(constants.CLOUDIFY_USER,
                     constants.CLOUDIFY_GROUP,
                     QUEUES_REBALANCING_SCRIPT_PATH)

        logger.info('Creating cron job for rebalancing queues...')
        time_string = '0 */4 * * *'  # run every 4 hours
        command = '{} {}'.format(
            '/opt/cloudify/cfy_manager/bin/python',
            QUEUES_REBALANCING_SCRIPT_PATH)
        comment = "Rebalance rabbit queues"
        common.add_cron_job(time_string, command, comment,
                            constants.CLOUDIFY_USER)
        logger.info('Queue rebalancing cron job successfully created')

    def upgrade(self):
        # On upgrade, the rabbit rpm may have started the systemd service.
        # If we leave it running, later upgrade steps may be unhappy.
        common.run(['systemctl', 'stop', 'rabbitmq-server'],
                   ignore_failures=True)  # In case there is no systemd

        logger.info('Waiting for rabbitmq to stop')
        check_num = 0
        max_checks = 60
        delay = 2
        # If we were using supervisord, 5672 will be open
        while is_port_open(5671) or is_port_open(5672):
            logger.info('...rabbit is still listening.')
            if check_num == max_checks:
                raise RuntimeError(
                    'Old rabbit is still listening.'
                )
            check_num += 1
            time.sleep(delay)
        super(RabbitMQ, self).upgrade()


def _is_ipv6_enabled():
    nodename = config[RABBITMQ]['nodename'].split('@')[-1]

    try:
        default_ip = config[RABBITMQ]['cluster_members'][nodename][
            'networks']['default']
    except KeyError:
        default_ip = config[MANAGER][PRIVATE_IP]

    if network.is_ipv6(default_ip):
        return True

    try:
        addresses = socket.getaddrinfo(default_ip, SECURE_PORT,
                                       family=socket.AddressFamily.AF_INET6)
    except socket.gaierror:
        # We can't get the v6 address info, so no IPv6
        return False

    for _family, _type, _proto, _canonname, sockaddr in addresses:
        # Assuming link-local will work breaks hostname based setups where
        # ipv6 isn't fully disabled but also isn't in use.
        if not network.is_ipv6_link_local(sockaddr[0]):
            return True

    # No non-link-local ipv6 addresses were found, we're ipv4
    return False
