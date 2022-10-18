#!/usr/bin/env python
from __future__ import print_function

import os
import sys
import json
import atexit
import logging
import tempfile
import argparse
import subprocess
from datetime import datetime

from flask_migrate import upgrade

from manager_rest import config, version
from manager_rest.amqp_manager import AMQPManager
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


def _populate_roles(data):
    for role in data['roles']:
        db.session.add(models.Role(
            name=role['name'],
            type=role['type'],
            description=role['description']
        ))
    roles = {r.name: r.id for r in
             db.session.query(models.Role.name, models.Role.id)}
    for permission, permission_roles in data['permissions'].items():
        for role_name in permission_roles:
            if role_name not in roles:
                continue
            db.session.add(models.Permission(
                role_id=roles[role_name],
                name=permission
            ))
    db.session.commit()


def _get_amqp_manager(script_config):
    with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
        f.write(script_config['rabbitmq_ca_cert'])
    broker = script_config['rabbitmq_brokers'][0]
    atexit.register(os.unlink, f.name)
    return AMQPManager(
        host=broker['management_host'],
        username=broker['username'],
        password=broker['password'],
        verify=f.name
    )


def _insert_config(config):
    sm = get_storage_manager()
    for scope, entries in config:
        for name, value in entries.items():
            inst = sm.get(models.Config, None,
                          filters={'name': name, 'scope': scope})
            inst.value = value
            sm.update(inst)


def _insert_rabbitmq_broker(brokers, ca_id):
    sm = get_storage_manager()
    for broker in brokers:
        inst = models.RabbitMQBroker(
            _ca_cert_id=ca_id,
            **broker
        )
        sm.put(inst)


def _insert_db_nodes(db_nodes):
    sm = get_storage_manager()
    for node in db_nodes:
        sm.put(models.DBNodes(**node))


def _insert_usage_collector(usage_collector_info):
    sm = get_storage_manager()
    sm.put(models.UsageCollector(**usage_collector_info))


def _insert_manager(config):
    sm = get_storage_manager()
    ca_cert = config.get('ca_cert')
    try:
        stored_cert = sm.list(models.Manager)[0].ca_cert
    except IndexError:
        stored_cert = None

    if not stored_cert and not ca_cert:
        raise RuntimeError('No manager certs found, and ca_cert not given')
    if stored_cert and not ca_cert:
        with open(CA_CERT_PATH, 'w') as f:
            f.write(stored_cert.value)
        subprocess.check_call(['/usr/bin/sudo', 'chown', 'cfyuser.',
                               CA_CERT_PATH])
        subprocess.check_call(['/usr/bin/sudo', 'chmod', '444', CA_CERT_PATH])
        ca = stored_cert.id
    elif ca_cert and not stored_cert:
        ca = _insert_cert(ca_cert, '{0}-ca'.format(config['hostname']))
    else:
        if stored_cert.value.strip() != ca_cert.strip():
            raise RuntimeError('ca_cert differs from existing manager CA')
        ca = stored_cert.id

    version_data = version.get_version_data()
    inst = models.Manager(
        public_ip=config['public_ip'],
        hostname=config['hostname'],
        private_ip=config['private_ip'],
        networks=config['networks'],
        edition=version_data['edition'],
        version=version_data['version'],
        distribution=version_data['distribution'],
        distro_release=version_data['distro_release'],
        _ca_cert_id=ca,
        last_seen=config['last_seen'],
    )
    sm.put(inst)


def _insert_cert(cert, name):
    sm = get_storage_manager()
    inst = models.Certificate(
        name=name,
        value=cert,
        updated_at=datetime.now(),
    )
    sm.put(inst)
    return inst.id


def _add_provider_context(context):
    sm = get_storage_manager()
    provider_context = models.ProviderContext(
        id='CONTEXT',
        name='provider',
        context=context
    )
    sm.put(provider_context)


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

    with open(args.input, 'r') as f:
        script_config = json.load(f)

    if script_config.get('db_migrate_dir'):
        _init_db_tables(script_config['db_migrate_dir'])
        _populate_roles(script_config['permissions'])
    if script_config.get('config'):
        _insert_config(script_config['config'])
    if script_config.get('rabbitmq_brokers'):
        rabbitmq_ca_id = _insert_cert(script_config['rabbitmq_ca_cert'],
                                      'rabbitmq-ca')
        _insert_rabbitmq_broker(
            script_config['rabbitmq_brokers'], rabbitmq_ca_id)
    if script_config.get('manager'):
        _insert_manager(script_config['manager'])
    if script_config.get('provider_context'):
        _add_provider_context(script_config['provider_context'])
    if script_config.get('db_nodes'):
        _insert_db_nodes(script_config['db_nodes'])
    if script_config.get('usage_collector'):
        _insert_usage_collector(script_config['usage_collector'])
