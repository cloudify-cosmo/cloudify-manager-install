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

from os.path import join

from ..components_constants import SOURCES
from ..base_component import BaseComponent
from ..service_names import POSTGRESQL_CLIENT
from ... import constants
from ...config import config
from ...logger import get_logger
from ...utils import common, files
from ...utils.install import (
    yum_install,
    yum_remove,
    RpmPackageHandler
)

POSTGRES_USER = POSTGRES_GROUP = 'postgres'
POSTGRES_USER_ID = POSTGRES_GROUP_ID = '26'
POSTGRES_USER_COMMENT = 'PostgreSQL Server'
HOST = 'host'

PGPASS_PATH = join(constants.CLOUDIFY_HOME_DIR, '.pgpass')

PG_PORT = 5432

logger = get_logger(POSTGRESQL_CLIENT)


class PostgresqlClientComponent(BaseComponent):
    def __init__(self, skip_installation):
        super(PostgresqlClientComponent, self).__init__(skip_installation)

    def _install(self):
        sources = config[POSTGRESQL_CLIENT][SOURCES]

        logger.debug('Installing PostgreSQL Client libraries...')
        yum_install(sources['ps_libs_rpm_url'])
        yum_install(sources['ps_rpm_url'])

        logger.debug('Installing python libs for PostgreSQL...')
        yum_install(sources['psycopg2_rpm_url'])

    def _create_postgres_group(self):
        logger.notice('Creating postgres group')
        try:
            common.sudo(['groupadd',
                         '-g', POSTGRES_GROUP_ID,
                         '-o', '-r',
                         POSTGRES_GROUP])
        except Exception as ex:
            if 'already exists' not in ex.message:
                raise ex
            else:
                logger.info('Group postgres already exists')

    def _create_postgres_user(self):
        logger.notice('Creating postgres user')
        try:
            # In case All-in-one, the user already exists so the home dir
            # won't be created.
            common.sudo(['useradd', '-m', '-N',
                         '-g', POSTGRES_GROUP_ID,
                         '-o', '-r',
                         '-d', '/var/lib/pgsql',
                         '-s', '/bin/bash',
                         '-c', POSTGRES_USER_COMMENT,
                         '-u', POSTGRES_USER_ID, POSTGRES_USER])
        except Exception as ex:
            if 'already exists' not in ex.message:
                raise ex
            else:
                logger.info('User postgres already exists')

    def _create_postgres_pass_file(self):
        logger.debug('Creating postgresql pgpass file: {0}'
                     .format(PGPASS_PATH))
        pg_config = config[POSTGRESQL_CLIENT]
        pgpass_content = '{host}:{port}:{db_name}:{user}:{password}'.format(
            host=pg_config['host'],
            port=PG_PORT,
            db_name='*',  # Allowing for the multiple DBs we have
            user=pg_config['username'],
            password=pg_config['password']
        )
        files.write_to_file(pgpass_content, PGPASS_PATH)
        common.chmod('400', PGPASS_PATH)
        common.chown(
            constants.CLOUDIFY_USER,
            constants.CLOUDIFY_GROUP,
            PGPASS_PATH
        )

        logger.debug('Postgresql pass file {0} created'.format(PGPASS_PATH))

    def _configure(self):
        files.copy_notice(POSTGRESQL_CLIENT)
        self._create_postgres_pass_file()

    def install(self):
        logger.notice('Installing PostgreSQL Client...')
        self._install()
        self._create_postgres_group()
        self._create_postgres_user()
        self._configure()
        logger.notice('PostgreSQL successfully installed')

    def configure(self):
        logger.notice('Configuring PostgreSQL Client...')
        self._configure()
        logger.notice('PostgreSQL successfully configured')

    def remove(self):
        logger.notice('Removing PostgreSQL Client...')
        files.remove_notice(POSTGRESQL_CLIENT)
        if not RpmPackageHandler.is_package_installed('postgresql10-server'):
            yum_remove('postgresql10')
            yum_remove('postgresql10-libs')
            logger.notice('PostgreSQL successfully removed')
        else:
            logger.info(
                'PostgreSQL Server is installed on the machine, cfy_manager '
                'remove will wait for dependant components to be removed prior'
                ' to removing PostgreSQL')
