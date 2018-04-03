#!/usr/bin/env python2
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

import argparse
from os import path
from distutils.dir_util import copy_tree

HOME_DIR = "{{ stage.home_dir }}"


def _restore(snapshot_root, override=False):
    folder = 'dist/userData'
    destination = path.join(HOME_DIR, folder)
    source = path.join(snapshot_root, folder)
    if not override:
        destination = path.join(destination, 'from_snapshot')
    if path.exists(source):
        copy_tree(source, destination)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('snapshot_root')
    parser.add_argument(
        '--override-existing',
        action='store_true',
        help='Override the existing stage files with the restored files.',
    )
    args = parser.parse_args()
    _restore(args.snapshot_root, override=args.override_existing)
