#!/usr/bin/env python
from __future__ import print_function

import os
import sys
import json
import logging
import argparse

from flask_migrate import upgrade

from manager_rest import config
from manager_rest.flask_utils import setup_flask_app
from manager_rest.storage import db, models, get_storage_manager

logging.basicConfig(
    stream=sys.stderr, level=logging.INFO, format='%(message)s')
logger = \
    logging.getLogger('[{0}]'.format('create_tables_and_add_defaults'.upper()))
CA_CERT_PATH = '/etc/cloudify/ssl/cloudify_internal_ca_cert.pem'


def _init_db_tables(db_migrate_dir):
    logger.info('Setting up a Flask app')
    # Clean up the DB, in case it's not a clean install
    db.drop_all()
    db.engine.execute('DROP TABLE IF EXISTS alembic_version;')

    logger.info('Creating tables in the DB')
    upgrade(directory=db_migrate_dir)


def _insert_db_nodes(db_nodes):
    sm = get_storage_manager()
    for node in db_nodes:
        sm.put(models.DBNodes(**node))


def _insert_usage_collector(usage_collector_info):
    sm = get_storage_manager()
    sm.put(models.UsageCollector(**usage_collector_info))


def file_path(path):
    if os.path.exists(path):
        return path
    raise argparse.ArgumentTypeError(
        "The file path \"{0}\" doesn't exist.".format(path))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Create SQL DB tables and populate them with defaults'
    )
    parser.add_argument(
        '--input',
        help='Path to a config file containing info needed by this script',
        required=True,
    )

    args = parser.parse_args()
    config.instance.load_configuration(from_db=False)
    setup_flask_app(
        manager_ip=config.instance.postgresql_host,
        hash_salt=config.instance.security_hash_salt,
        secret_key=config.instance.security_secret_key
    )
    config_path = args.input
    if os.path.abspath(config_path) != config_path:
        exit("Invalid config file path")

    with open(config_path, 'r') as f:
        script_config = json.load(f)

    if script_config.get('db_migrate_dir'):
        _init_db_tables(script_config['db_migrate_dir'])
    if script_config.get('db_nodes'):
        _insert_db_nodes(script_config['db_nodes'])
    if script_config.get('usage_collector'):
        _insert_usage_collector(script_config['usage_collector'])
