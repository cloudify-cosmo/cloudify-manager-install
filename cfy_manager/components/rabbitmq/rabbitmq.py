#########
# Copyright (c) 2017 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.

import json
from os.path import join
import socket
import time

from ..components_constants import (
    CONFIG,
    PRIVATE_IP,
    SERVICES_TO_INSTALL,
    SOURCES,
)
from ..service_components import MANAGER_SERVICE
from ..base_component import BaseComponent
from ..service_names import RABBITMQ, MANAGER
from ... import constants
from ...utils import certificates
from ...config import config
from ...logger import get_logger
from ...exceptions import ValidationError, NetworkError, ClusteringError
from ...utils.systemd import systemd
from ...utils.install import yum_install, yum_remove
from ...utils.network import wait_for_port, is_port_open
from ...utils.common import sudo, remove as remove_file
from ...utils.files import write_to_file


LOG_DIR = join(constants.BASE_LOG_DIR, RABBITMQ)
HOME_DIR = join('/etc', RABBITMQ)
CONFIG_PATH = join(constants.COMPONENTS_DIR, RABBITMQ, CONFIG)
SECURE_PORT = 5671

RABBITMQ_CTL = 'rabbitmqctl'
logger = get_logger(RABBITMQ)


class RabbitMQComponent(BaseComponent):
    def __init__(self, skip_installation):
        super(RabbitMQComponent, self).__init__(skip_installation)

    def _install(self):
        sources = config[RABBITMQ][SOURCES]
        for source in sources.values():
            yum_install(source)

    def _install_manager(self):
        return MANAGER_SERVICE in config[SERVICES_TO_INSTALL]

    def _init_service(self):
        logger.info('Initializing RabbitMQ...')
        rabbit_config_path = join(HOME_DIR, 'rabbitmq.config')

        # Delete old mnesia node
        remove_file('/var/lib/rabbitmq/mnesia')
        remove_file(rabbit_config_path)
        systemd.systemctl('daemon-reload')

        if not self._install_manager():
            # If this isn't installed on a manager, we need the management
            # plugin to listen on all interfaces, not just 127.0.0.1
            sudo(['sed', '-i', '/{ip, "127.0.0.1"},/d',
                  '/etc/cloudify/rabbitmq/rabbitmq.config'])

        # rabbitmq restart exits with 143 status code that is valid in
        # this case.
        systemd.restart(RABBITMQ, ignore_failure=True)
        wait_for_port(SECURE_PORT)

    def _rabbitmqctl(self, command, **kwargs):
        nodename = config[RABBITMQ]['nodename']
        return sudo([RABBITMQ_CTL, '-n', nodename] + command, **kwargs)

    def user_exists(self, username):
        output = self._rabbitmqctl(['list_users'], retries=5).aggr_stdout
        return username in output

    def _delete_guest_user(self):
        if self.user_exists('guest'):
            logger.info('Disabling RabbitMQ guest user...')
            self._rabbitmqctl(['clear_permissions', 'guest'], retries=5)
            self._rabbitmqctl(['delete_user', 'guest'], retries=5)

    def _create_rabbitmq_user(self):
        rabbitmq_username = config[RABBITMQ]['username']
        rabbitmq_password = config[RABBITMQ]['password']
        if not self.user_exists(rabbitmq_username):
            logger.info('Creating new user and setting permissions...'.format(
                rabbitmq_username, rabbitmq_password)
            )
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
            with open('/etc/hostname') as host_handle:
                nodename = host_handle.read().strip()

        nodename = self._add_missing_nodename_prefix(nodename)

        config[RABBITMQ]['nodename'] = nodename

    def _add_missing_nodename_prefix(self, nodename):
        if '@' not in nodename:
            nodename = 'cloudify-manager@' + nodename
        return nodename

    def _set_erlang_cookie(self):
        cookie = config[RABBITMQ]['erlang_cookie']
        if config[RABBITMQ]['cluster_members'] and not cookie:
            raise ValidationError(
                'Cluster members are configured but erlang_cookie has not '
                'been set.'
            )

        if cookie:
            write_to_file(cookie, '/var/lib/rabbitmq/.erlang.cookie')
            sudo(['chown', 'rabbitmq.', '/var/lib/rabbitmq/.erlang.cookie'])

    def _possibly_join_cluster(self):
        join_node = config[RABBITMQ]['join_cluster']
        if not join_node:
            return

        join_node = self._add_missing_nodename_prefix(join_node)

        logger.info(
            'Joining cluster via node {target_node}.'.format(
                target_node=join_node,
            )
        )
        self._rabbitmqctl(['stop_app'])
        self._rabbitmqctl(['reset'])
        self._rabbitmqctl(['join_cluster', join_node])
        self._rabbitmqctl(['start_app'])

        # In initial testing the clustering completed in seconds, at most, so
        # this should be significantly more time than is needed, excepting
        # network issues
        attempt = 0
        max_attempts = 10
        delay = 3
        while attempt != max_attempts:
            attempt += 1
            logger.info(
                'Checking rabbit cluster is joined [{at}/{mx}]....'.format(
                    at=attempt,
                    mx=max_attempts,
                )
            )
            rmq_cluster_stat = self._rabbitmqctl(['cluster_status'])

            # Check that both this node and the node we're joining to are in
            # the cluster
            required = [
                join_node,
                config[RABBITMQ]['nodename'],
            ]
            if not all([node in rmq_cluster_stat.aggr_stdout
                        for node in required]):
                if attempt == max_attempts:
                    raise ClusteringError(
                        'Node did not join cluster within {num} attempts. '
                        'Attempted to join to {target_node}. '
                        'Last cluster status output was: {output}.'.format(
                            num=max_attempts,
                            target_node=join_node,
                            output=rmq_cluster_stat.aggr_stdout,
                        )
                    )
                else:
                    time.sleep(delay)
                    continue
            else:
                logger.info('Cluster successfully joined.')
                break

    def _possibly_add_hosts_entries(self):
        cluster_nodes = config[RABBITMQ]['cluster_members']
        if cluster_nodes:
            logger.info(
                'Checking whether cluster nodes are resolvable via DNS'
            )
            not_resolved = []
            for node in cluster_nodes:
                try:
                    socket.gethostbyname(node)
                    logger.info(
                        'Successfully resolved {node}'.format(node=node)
                    )
                except socket.gaierror:
                    not_resolved.append(node)

            add_to_hosts = ['', '# Added for cloudify rabbitmq clustering']
            for node in not_resolved:
                ip = cluster_nodes[node].get('ip')
                if not ip:
                    raise ValidationError(
                        'IP not provided for unresolvable rabbit node '
                        '{node}. '
                        'An ip property must be set for this node.'.format(
                            node=node,
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
        broker_cert_path = config[RABBITMQ]['broker_cert_path']
        broker_key_path = config[RABBITMQ]['broker_key_path']

        if broker_cert_path and broker_key_path:
            logger.info('Using supplied certificates.')
            return
        elif broker_cert_path or broker_key_path:
            raise ValidationError(
                'Both broker_cert_path and broker_cert_key must be '
                'provided if one of these settings is provided.'
            )
        else:
            config[RABBITMQ]['broker_cert_path'] = (
                '/etc/cloudify/ssl/rabbitmq_cert.pem'
            )
            config[RABBITMQ]['broker_key_path'] = (
                '/etc/cloudify/ssl/rabbitmq_key.pem'
            )

        logger.info('Generating rabbitmq certificate...')

        if self._install_manager():
            has_ca_key = certificates.handle_ca_cert()
        else:
            has_ca_key = False
        networks = config[RABBITMQ]['networks']
        rabbit_host = config[MANAGER][PRIVATE_IP]

        certificates.store_cert_metadata(
            rabbit_host,
            new_brokers=networks.values(),
            new_networks=networks.keys(),
            # The cfyuser won't exist yet (and may never exist if only rabbit
            # is being installed)
            owner='rabbitmq',
            group='rabbitmq',
        )

        sign_cert = constants.CA_CERT_PATH if has_ca_key else None
        sign_key = constants.CA_KEY_PATH if has_ca_key else None

        certificates._generate_ssl_certificate(
            ips=networks.values(),
            cn=rabbit_host,
            cert_path=config[RABBITMQ]['broker_cert_path'],
            key_path=config[RABBITMQ]['broker_key_path'],
            sign_cert=sign_cert,
            sign_key=sign_key,
        )

    def _set_rabbitmq_policy(self, name, expression, policy):
        policy = json.dumps(policy)
        logger.debug('Setting policy {0} on queues {1} to {2}'.format(
            name, expression, policy))
        # shlex screws this up because we need to pass json and shlex
        # strips quotes so we explicitly pass it as a list.
        self._rabbitmqctl(['set_policy',
                           name,
                           expression,
                           policy,
                           '--apply-to',
                           'queues'])

    def _set_policies(self):
        metrics = config[RABBITMQ]['policy_metrics']
        logs_queue_message_policy = {
            'message-ttl': metrics['logs_queue_message_ttl'],
            'max-length': metrics['logs_queue_length_limit']
        }
        events_queue_message_policy = {
            'message-ttl': metrics['events_queue_message_ttl'],
            'max-length': metrics['events_queue_length_limit']
        }

        logger.info("Setting RabbitMQ Policies...")
        self._set_rabbitmq_policy(
            name='logs_queue_message_policy',
            expression='^cloudify-logs$',
            policy=logs_queue_message_policy
        )
        self._set_rabbitmq_policy(
            name='events_queue_message_policy',
            expression='^cloudify-events$',
            policy=events_queue_message_policy
        )

    def _start_rabbitmq(self):
        logger.info("Starting RabbitMQ Service...")
        # rabbitmq restart exits with 143 status code that is valid
        # in this case.
        systemd.restart(RABBITMQ, ignore_failure=True)
        wait_for_port(SECURE_PORT)
        self._set_policies()
        systemd.restart(RABBITMQ)

    def _validate_rabbitmq_running(self):
        logger.info('Making sure RabbitMQ is live...')
        systemd.verify_alive(RABBITMQ)

        result = self._rabbitmqctl(['status'])
        if result.returncode != 0:
            raise ValidationError('Rabbitmq failed to start')

        if not is_port_open(SECURE_PORT, host='127.0.0.1'):
            raise NetworkError(
                '{0} error: port {1}:{2} was not open'.format(
                    RABBITMQ, '127.0.0.1', SECURE_PORT)
            )

    def _configure(self):
        self._possibly_set_nodename()
        self._set_erlang_cookie()
        self._possibly_add_hosts_entries()
        systemd.configure(RABBITMQ,
                          user='rabbitmq', group='rabbitmq')
        if not config[RABBITMQ]['networks']:
            config[RABBITMQ]['networks'] = config['networks']
        self._generate_rabbitmq_certs()
        self._init_service()
        self._delete_guest_user()
        self._create_rabbitmq_user()
        self._start_rabbitmq()
        self._validate_rabbitmq_running()
        self._possibly_join_cluster()

    def install(self):
        logger.notice('Installing RabbitMQ...')
        self._install()
        logger.notice('RabbitMQ successfully installed')

    def configure(self):
        logger.notice('Configuring RabbitMQ...')
        self._configure()
        logger.notice('RabbitMQ successfully configured')

    def remove(self):
        logger.notice('Removing RabbitMQ...')
        yum_remove('erlang')
        logger.info('Stopping the Erlang Port Mapper Daemon...')
        sudo(['epmd', '-kill'], ignore_failures=True)
        systemd.remove(RABBITMQ, service_file=False)
        yum_remove('socat')
        logger.notice('RabbitMQ successfully removed')

    def start(self):
        logger.notice('Starting RabbitMQ...')
        systemd.start(RABBITMQ)
        self._validate_rabbitmq_running()
        logger.notice('RabbitMQ successfully started')

    def stop(self):
        logger.notice('Stopping RabbitMQ...')
        systemd.stop(RABBITMQ)
        logger.notice('RabbitMQ successfully stopped')
