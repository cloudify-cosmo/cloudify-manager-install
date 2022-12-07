from contextlib import contextmanager
import json
import time
import uuid
from os.path import join

from .manager_config import make_manager_config
from ...components_constants import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    AGENT,
    CONFIG,
    HOSTNAME,
    PROVIDER_CONTEXT,
    SCRIPTS,
    SECURITY,
)

from ...service_names import (
    MANAGER,
    POSTGRESQL_CLIENT,
    POSTGRESQL_SERVER,
    RESTSERVICE,
)

from ... import constants
from ...config import config
from ...logger import get_logger
from ...exceptions import ValidationError

from ...utils import common
from ...utils.db import run_psql_command
from ...utils.install import is_premium_installed
from ...utils.scripts import run_script_on_manager_venv

logger = get_logger('DB')

SCRIPTS_PATH = join(constants.COMPONENTS_DIR, RESTSERVICE, SCRIPTS)
CONFIG_PATH = join(constants.COMPONENTS_DIR, RESTSERVICE, CONFIG)
REST_HOME_DIR = '/opt/manager'
NETWORKS = 'networks'
UUID4HEX_LEN = 32
ENCODED_USER_ID_LENGTH = 5


def drop_db():
    logger.notice('PREPARING TO DROP CLOUDIFY DATABASE...')
    logger.notice(
        'You have 10 seconds to press Ctrl+C if this was a mistake.'
    )
    time.sleep(10)
    db_name = config[POSTGRESQL_CLIENT]['cloudify_db_name']
    db_user = config[POSTGRESQL_CLIENT]['cloudify_username'].split('@')[0]
    run_psql_command('DROP DATABASE IF EXISTS {}'.format(db_name),
                     'server_db_name', logger)
    run_psql_command('DROP DATABASE IF EXISTS stage',
                     'server_db_name', logger)
    run_psql_command('DROP DATABASE IF EXISTS composer',
                     'server_db_name', logger)
    run_psql_command('DROP USER IF EXISTS {}'.format(db_user),
                     'server_db_name', logger)
    logger.info('Cloudify database successfully dropped.')


def prepare_db():
    logger.notice('Configuring SQL DB...')
    db_user = config[POSTGRESQL_CLIENT]['cloudify_username'].split('@')[0]
    db_pass = config[POSTGRESQL_CLIENT]['cloudify_password']
    _create_user(db_user, db_pass)
    with _azure_compatibility(db_user):
        _create_databases()
    logger.notice('SQL DB successfully configured')


@contextmanager
def _azure_compatibility(user):
    superuser = config[POSTGRESQL_CLIENT]['server_username'].split('@')[0]
    run_psql_command("GRANT {} TO {}".format(user, superuser),
                     'server_db_name', logger)
    yield
    run_psql_command("REVOKE {} FROM {}".format(user, superuser),
                     'server_db_name', logger)


def _create_user(db_user, db_pass):
    run_psql_command(
        "CREATE USER {} WITH PASSWORD '{}'".format(db_user, db_pass),
        'server_db_name', logger)
    run_psql_command('ALTER USER {} CREATEDB'.format(db_user),
                     'server_db_name', logger)


def _create_databases():
    user = config[POSTGRESQL_CLIENT]['cloudify_username'].split('@')[0]
    cloudify_db = config[POSTGRESQL_CLIENT]['cloudify_db_name']
    _create_database(cloudify_db, user)
    _create_database('stage', user)
    _create_database('composer', user)


def _create_database(db_name, user):
    run_psql_command('CREATE DATABASE {}'.format(db_name),
                     'server_db_name', logger)
    run_psql_command(
        'ALTER DATABASE {} OWNER TO {}'.format(db_name, user),
        'server_db_name', logger)
    run_psql_command(
        'GRANT ALL PRIVILEGES ON DATABASE {} to {}'.format(db_name, user),
        'server_db_name', logger)


def _get_provider_context():
    context = {'cloudify': config[PROVIDER_CONTEXT]}
    context['cloudify']['cloudify_agent'] = config[AGENT]
    return context


def _create_populate_db_args_dict():
    """
    Create and return a dictionary with all the information necessary for the
    script that creates and populates the DB to run
    """
    args_dict = {
        'provider_context': _get_provider_context(),
        'db_migrate_dir': join(constants.MANAGER_RESOURCES_HOME, 'cloudify',
                               'migrations'),
        'config': make_manager_config(),
        'premium': 'premium' if is_premium_installed() else 'community',
        'db_nodes': _create_db_nodes_info(),
        'usage_collector': _create_usage_collector_info(),
    }
    return args_dict


def _create_db_nodes_info():
    if common.is_all_in_one_manager():
        return [{
            'name': config[MANAGER][HOSTNAME],
            'host': config[NETWORKS]['default'],
            'is_external': False,
        }]

    if common.manager_using_db_cluster():
        db_nodes = config[POSTGRESQL_SERVER]['cluster']['nodes']
        return [
            {
                'name': name,
                'host': db['ip'],
                'is_external': False,
            }
            for name, db in db_nodes.items()
        ]

    # External db is used
    return [{
        'name': config[POSTGRESQL_CLIENT]['host'],
        'host': config[POSTGRESQL_CLIENT]['host'],
        'is_external': True,
    }]


def _create_usage_collector_info():
    cfy_uptime = config['usage_collector']['collect_cloudify_uptime']
    cfy_usage = config['usage_collector']['collect_cloudify_usage']
    return {
        'id': 0,
        'manager_id': uuid.uuid4().hex,
        'hourly_timestamp': None,
        'daily_timestamp': None,
        'hours_interval': cfy_uptime['interval_in_hours'],
        'days_interval': cfy_usage['interval_in_days']
    }


def _create_process_env(rest_config=None, authorization_config=None,
                        security_config=None):
    env = {}
    for value, envvar in [
            (rest_config, 'MANAGER_REST_CONFIG_PATH'),
            (security_config, 'MANAGER_REST_SECURITY_CONFIG_PATH'),
    ]:
        if value is not None:
            env[envvar] = value
    return env


def run_script(script_name, script_input=None, configs=None):
    """Runs a script in a separate process.

    :param script_name: script name inside the SCRIPTS_PATH dir.
    :param script_input: script input to pass to the script.
    :param configs: keword arguments dict to pass to _create_process_env(..).
    :return: the script's returned when it finished its execution.
    """
    env_dict = _create_process_env(**configs) if configs else None

    script_path = join(SCRIPTS_PATH, script_name)

    proc_result = run_script_on_manager_venv(script_path,
                                             script_input,
                                             envvars=env_dict)
    return _get_script_stdout(proc_result)


def populate_db(configs, additional_config_files=None):
    logger.notice('Populating DB and creating AMQP resources...')
    args_dict = _create_populate_db_args_dict()
    run_script('create_tables_and_add_defaults.py', args_dict, configs)
    if (
        config[MANAGER][SECURITY][ADMIN_USERNAME] and
        config[MANAGER][SECURITY][ADMIN_PASSWORD]
    ):
        args = ['manager_rest.configure_manager']
        args += ['--config-file-path', join(CONFIG_PATH, 'authorization.conf')]
        for path in config['config_files']:
            args += ['--config-file-path', path]
        if additional_config_files:
            for path in additional_config_files:
                args += ['--config-file-path', path]
        run_script_on_manager_venv('-m', script_args=args)
    logger.notice('DB populated and AMQP resources successfully created')


def _get_manager():
    try:
        with open(constants.CA_CERT_PATH) as f:
            ca_cert = f.read()
    except IOError:
        ca_cert = None
    return {
        'public_ip': config['manager']['public_ip'],
        'hostname': config[MANAGER][HOSTNAME],
        'private_ip': config['manager']['private_ip'],
        'networks': config[NETWORKS],
        'last_seen': common.get_formatted_timestamp(),
        'ca_cert': ca_cert
    }


def insert_manager(configs):
    logger.notice('Registering manager in the DB...')
    args = {'manager': _get_manager()}
    run_script('create_tables_and_add_defaults.py', args, configs)


def update_stored_manager(configs=None):
    logger.notice('Updating stored manager...')
    args = {
        'manager': _get_manager(),
        'admin_password': config[MANAGER][SECURITY][ADMIN_PASSWORD],
    }

    run_script('update_stored_manager.py', args, configs=configs)
    logger.notice('AMQP resources successfully created')


def get_monitoring_config():
    output = run_script('get_monitoring_config.py', configs={
        'rest_config': constants.REST_CONFIG_PATH,
    })
    return json.loads(output)


def check_db_exists():
    # Get the list of databases
    result = run_psql_command(
        '\\l',
        'server_db_name',
        logger,
    )

    # Example of expected output:
    # cloudify_db | cloudify | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =Tc/cloudify         +  # noqa
    #             |          |          |             |             | cloudify=CTc/cloudify   # noqa
    # composer    | cloudify | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =Tc/cloudify         +  # noqa
    #             |          |          |             |             | cloudify=CTc/cloudify   # noqa
    # postgres    | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 |                         # noqa
    # stage       | cloudify | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =Tc/cloudify         +  # noqa
    #             |          |          |             |             | cloudify=CTc/cloudify   # noqa
    # template0   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +  # noqa
    #             |          |          |             |             | postgres=CTc/postgres   # noqa
    # template1   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +  # noqa
    #             |          |          |             |             | postgres=CTc/postgres   # noqa
    #                                                                                         # noqa

    result = result.splitlines()
    dbs = [db.split('|')[0].strip() for db in result]
    dbs = [db for db in dbs if db]  # Clear out empty strings

    return config[POSTGRESQL_CLIENT]['cloudify_db_name'] in dbs


def get_managers():
    result = run_psql_command(
        'SELECT hostname FROM managers',
        'cloudify_db_name',
        logger
    )
    return [line.strip() for line in result.split('\n') if line.strip()]


def validate_schema_version(configs):
    """Check that the database schema version is the same as the current
    manager's migrations version.
    """
    migrations_version = run_script('get_db_version.py', configs=configs)
    db_version = run_psql_command(
        'SELECT version_num FROM alembic_version',
        'cloudify_db_name',
        logger,
    )
    migrations_version = migrations_version.strip()
    db_version = db_version.strip()
    if migrations_version != db_version:
        raise ValidationError(
            'Database schema version mismatch: this manager expects schema '
            'revision {0} but the database is {1})'
            .format(migrations_version, db_version))


def _get_script_stdout(result):
    """Log stderr output from the script and return the return stdout from the
    script.
    :param result: Popen result.
    """
    if result.aggr_stderr:
        output = result.aggr_stderr.split('\n')
        output = [line.strip() for line in output if line.strip()]
        for line in output:
            logger.debug(line)
    return result.aggr_stdout if result.aggr_stdout else ""
