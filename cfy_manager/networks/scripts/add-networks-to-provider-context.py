#!/usr/bin/env python
#########
# Copyright (c) 2018 GigaSpaces Technologies Ltd. All rights reserved
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

import sys
from sqlalchemy.orm.attributes import flag_modified

from manager_rest.flask_utils import setup_flask_app
from manager_rest.constants import PROVIDER_CONTEXT_ID
from manager_rest.storage import get_storage_manager, models

try:
    from cloudify_premium.ha.consul import get_consul_client, cluster_status
except ImportError:
    get_consul_client = None


def _update_cluster_host_ip(networks, cluster_node_ip):
    """
    Add the new networks to the specified cluster node in the provider
    context.
    :param networks: a dict containing the new networks
    :param cluster_node_ip: the default IP of the node to add networks to
    """
    with setup_flask_app().app_context():
        sm = get_storage_manager()
        ctx = sm.get(models.ProviderContext, PROVIDER_CONTEXT_ID)
        old_networks = ctx.context['cloudify']['cloudify_agent']['networks']
        # if we're the current master, update pctx
        if cluster_node_ip == old_networks['default']:
            old_networks.update(networks)

        # find the node given by cluster_node_ip in the cluster list
        # and update it
        for node in ctx.context['cloudify']['cloudify_agent']['cluster']:
            if node['default'] == cluster_node_ip:
                node.update(networks)
                break
        else:
            # should be caught by the validations before this
            raise RuntimeError('Node not found')
        flag_modified(ctx, 'context')
        sm.update(ctx)

    # set the networks in consul k/v options so that the remote node knows
    # to re-generate the certs
    options = cluster_status.cluster_options
    if 'networks' not in options:
        options['networks'] = {}
    options['networks'][cluster_node_ip] = node
    cluster_status.cluster_options = options


def _update_provider_context(networks):
    """
    Add the new networks to the `provider context` DB table
    :param networks: a dict containing the new networks
    """
    with setup_flask_app().app_context():
        sm = get_storage_manager()
        ctx = sm.get(models.ProviderContext, PROVIDER_CONTEXT_ID)
        old_networks = ctx.context['cloudify']['cloudify_agent']['networks']
        old_networks.update(networks)
        flag_modified(ctx, 'context')
        sm.update(ctx)


def _validate_networks(new_networks, cluster_node_ip):
    """Check that new networks are valid, otherwise throw an error"""
    with setup_flask_app().app_context():
        sm = get_storage_manager()
        ctx = sm.get(models.ProviderContext, PROVIDER_CONTEXT_ID)
        _validate_duplicate_network(ctx, new_networks)
        if cluster_node_ip:
            _validate_premium()
            _validate_cluster_node_ip(ctx, cluster_node_ip)
            _validate_ca_key(ctx)


def _validate_premium():
    """Check that premium is installed.

    Only relevant if cluster_node_ip was given.
    """
    if get_consul_client is None:
        raise RuntimeError('Cloudify Premium is not available')


def _validate_ca_key():
    """Check that the cluster was created with the internal CA key.

    If the internal CA key is not available, then recreating the certs
    is not possible.
    """
    consul = get_consul_client()
    ca = consul.kv.get('ca')
    if 'internal_key' not in ca:
        raise RuntimeError('Internal CA key is not available')


def _validate_cluster_node_ip(ctx, cluster_node_ip):
    """Check that cluster_node_ip does exist in the cluster

    cluster_node_ip is the ip of the 'default' network of a cluster node.
    """
    try:
        cluster = ctx.context['cloudify']['cloudify_agent']['cluster']
    except KeyError:
        raise RuntimeError('No cluster started')
    if not any(node['default'] == cluster_node_ip for node in cluster):
        raise RuntimeError('No cluster node with default IP {0} found'
                           .format(cluster_node_ip))


def _validate_duplicate_network(ctx, new_networks):
    """Check that all networks have unique names"""
    old_networks = ctx.context['cloudify']['cloudify_agent']['networks']
    for network in new_networks:
        if network in old_networks:
            raise Exception('Network name {0} already exists. Cannot add '
                            'new networks. Choose uniqe network names and '
                            'run the command again'.format(network))


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise RuntimeError('`add-networks-to-provider-context.py` expects'
                           ' exactly two arguments, it received {0} arguments'
                           .format(len(sys.argv) - 1))
    networks = sys.argv[1]
    cluster_node_ip = sys.argv[2]

    networks = eval(networks)

    _validate_networks(networks)
    if cluster_node_ip:
        _update_cluster_host_ip(networks, cluster_node_ip)
    else:
        _update_provider_context(networks)
