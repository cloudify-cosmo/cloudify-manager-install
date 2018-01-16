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
from functools import wraps

from . import (
    handlers,
    service_names
)
from ..utils import systemd


DEFAULT_SERVICES_TO_RESTART = [
    service_names.MGMTWORKER,
    service_names.RESTSERVICE,
    service_names.RABBITMQ
]


def _order_services(func):
    @wraps(func)
    def _wrapper(services, *a, **kw):
        if services == 'all':
            # We are using the default services to restart
            services = DEFAULT_SERVICES_TO_RESTART

        # Order the services according to the execution order
        return func(
            [s_name
             for s_name in handlers.COMPONENTS_ORDER
             if s_name in services],
            *a,
            **kw
        )

    return _wrapper


@_order_services
def start(services):
    for service_name in services:
        try:
            handlers.COMPONENTS_ORDER[service_name].start_and_verify()
        except AttributeError:
            # Default handler - just start the service
            systemd.systemd.start(service_name)


@_order_services
def stop(services):
    for service_name in services:
        try:
            handlers.COMPONENTS_ORDER[service_name].stop_and_verify()
        except AttributeError:
            # Default handler - just stop the service
            systemd.systemd.stop(service_names)


