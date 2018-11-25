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

from ...exceptions import ProcessExecutionError

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

GROUP_USER_ALREADY_EXISTS_EXIT_CODE = 9
POSTGRES_USER = POSTGRES_GROUP = 'postgres'
POSTGRES_USER_ID = POSTGRES_GROUP_ID = '26'
POSTGRES_USER_COMMENT = 'PostgreSQL Server'
POSTGRES_USER_HOME_DIR = '/var/lib/pgsql'
HOST = 'host'

CLOUDIFY_PGPASS_PATH = join(constants.CLOUDIFY_HOME_DIR, '.pgpass')
POSTGRES_PGPASS_PATH = join(POSTGRES_USER_HOME_DIR, '.pgpass')

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
        except ProcessExecutionError as ex:
            # Return code 9 for non-unique user/group
            if ex.return_code != GROUP_USER_ALREADY_EXISTS_EXIT_CODE:
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
                         '-d', POSTGRES_USER_HOME_DIR,
                         '-s', '/bin/bash',
                         '-c', POSTGRES_USER_COMMENT,
                         '-u', POSTGRES_USER_ID, POSTGRES_USER])
        except ProcessExecutionError as ex:
            # Return code 9 for non-unique user/group
            if ex.return_code != GROUP_USER_ALREADY_EXISTS_EXIT_CODE:
                raise ex
            else:
                logger.info('User postgres already exists')

    def _create_pgpass(self, host, port, db_name, user, password, pgpass_path,
                       owning_user, owning_group):
        logger.debug('Creating postgresql pgpass file: {0}'
                     .format(pgpass_path))
        pgpass_content = '{host}:{port}:{db_name}:{user}:{password}'.format(
            host=host,
            port=port,
            db_name=db_name,
            user=user,
            password=password
        )
        files.write_to_file(pgpass_content, pgpass_path)
        common.chmod('400', pgpass_path)
        common.chown(owning_user, owning_group, pgpass_path)

        logger.debug('Postgresql pass file {0} created'.format(pgpass_path))

    def _create_pgpass_files(self):
        pg_config = config[POSTGRESQL_CLIENT]
        host = pg_config['host'],
        port = PG_PORT,

        if pg_config['postgres_password']:
            postgres_password = pg_config['postgres_password']

            # Creating postgres .pgpass file
            self._create_pgpass(
                host=host,
                port=port,
                db_name='postgres',
                user='postgres',
                password=postgres_password,
                pgpass_path=POSTGRES_PGPASS_PATH,
                owning_user='postgres',
                owning_group='postgres'
            )

            logger.info('Removing postgres password from config.yaml')
            config[POSTGRESQL_CLIENT]['postgres_password'] = '<removed>'

        # Creating Cloudify .pgpass file
        db_name = '*',  # Allowing for the multiple DBs we have
        user = pg_config['username'],
        password = pg_config['password']
        self._create_pgpass(
            host=host,
            port=port,
            db_name=db_name,
            user=user,
            password=password,
            pgpass_path=CLOUDIFY_PGPASS_PATH,
            owning_user=constants.CLOUDIFY_USER,
            owning_group=constants.CLOUDIFY_GROUP
        )

    def _configure(self):
        files.copy_notice(POSTGRESQL_CLIENT)
        self._create_pgpass_files()

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
        if not RpmPackageHandler.is_package_installed('postgresql95-server'):
            yum_remove('postgresql95')
            yum_remove('postgresql95-libs')
            logger.notice('PostgreSQL successfully removed')
        else:
            logger.info(
                'PostgreSQL Server is installed on the machine, cfy_manager '
                'remove will wait for dependant components to be removed prior'
                ' to removing PostgreSQL')
