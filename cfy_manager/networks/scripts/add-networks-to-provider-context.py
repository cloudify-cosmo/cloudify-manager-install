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


def _assert_uniqe_network_names(new_networks):
    with setup_flask_app().app_context():
        sm = get_storage_manager()
        ctx = sm.get(models.ProviderContext, PROVIDER_CONTEXT_ID)
        old_networks = ctx.context['cloudify']['cloudify_agent']['networks']
        for network in new_networks:
            if network in old_networks:
                raise Exception('Network name {0} already exists. Cannot add '
                                'new networks. Choose uniqe network names and '
                                'run the command again'.format(network))


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise RuntimeError('`add-networks-to-provider-context.py` expects'
                           ' exactly one argument, it received {0} arguments'
                           .format(len(sys.argv)-1))
    networks = sys.argv[1]
    networks = eval(networks)

    _assert_uniqe_network_names(networks)

    _update_provider_context(networks)
