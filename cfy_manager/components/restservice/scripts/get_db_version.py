#!/usr/bin/env python
#########
# Copyright (c) 2019 Cloudify Platform Ltd. All rights reserved
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

"""Print out the database schema revision of this manager"""

from __future__ import print_function

from alembic.config import Config
from alembic.script import ScriptDirectory
from alembic.runtime.environment import EnvironmentContext

config = Config()
config.set_main_option(
    'script_location',
    '/opt/manager/resources/cloudify/migrations'
)
script = ScriptDirectory.from_config(config)

with EnvironmentContext(config, script) as env:
    revisions = script.get_revisions('head')
    if len(revisions) != 1:
        raise ValueError(
            'Expected 1 revision, found {0}'.format(len(revisions)))
    head = revisions[0]
    print(head.revision)
