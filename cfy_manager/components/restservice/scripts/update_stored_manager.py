import argparse
import json
import uuid

from datetime import datetime
from flask_security.utils import hash_password, verify_password

from manager_rest import config, version
from manager_rest.amqp_manager import AMQPManager
from manager_rest.flask_utils import setup_flask_app
from manager_rest.storage import (
    db,
    models,
    get_storage_manager,
    user_datastore,
)
try:
    from cloudify_premium.ha import agents
    from cloudify_premium.ha import controller
except ImportError:
    agents = None
    controller = None


def _get_amqp_manager():
    return AMQPManager(
        host=config.instance.amqp_management_host,
        username=config.instance.amqp_username,
        password=config.instance.amqp_password,
        cadata=config.instance.amqp_ca,
    )


def _update_cert(manager, broker, new_cert_value):
    old_cert = manager.ca_cert
    if old_cert.value == new_cert_value:
        return

    new_cert = models.Certificate(
        name=str(uuid.uuid4()),
        value=new_cert_value,
        updated_at=datetime.utcnow(),
        _updater_id=0
    )
    manager.ca_cert = new_cert
    if broker:
        broker.ca_cert = new_cert
    if not old_cert.managers and not old_cert.rabbitmq_brokers:
        db.session.delete(old_cert)


def _update_admin_password(new_password):
    adm = user_datastore.get_user('admin')
    if verify_password(new_password, adm.password):  # no change
        return
    adm.password = hash_password(new_password)
    user_datastore.commit()


def main(new_manager):
    hostname = new_manager['hostname']
    version_data = version.get_version_data()

    manager = models.Manager.query.filter_by(hostname=hostname).first()
    if manager is None:
        manager = models.Manager(
            hostname=hostname,
            networks={},
        )

    new_networks = manager.networks.copy()
    for name, ip in new_networks.items():
        if ip == manager.private_ip:
            new_networks[name] = new_manager['private_ip']
        elif ip == manager.public_ip:
            new_networks[name] = new_manager['public_ip']
    for name, ip in new_manager['networks'].items():
        if name not in new_networks:
            new_networks[name] = ip

    manager.networks = new_networks
    for attr in ['private_ip', 'public_ip']:
        setattr(manager, attr, new_manager[attr])
    manager.version = version_data.get('version')
    manager.edition = version_data.get('edition')
    manager.distribution = version_data.get('distribution')
    manager.distro_release = version_data.get('distro_release')
    manager.last_seen = datetime.utcnow()

    broker = (
        models.RabbitMQBroker.query
        .filter_by(name=hostname, host=manager.private_ip)
        .first()
    )

    if broker:
        if broker.management_host == broker.host:
            broker.management_host = manager.private_ip
        broker.host = manager.private_ip
        broker.networks = manager.networks

    db_node = (
        models.DBNodes.query
        .filter_by(name=hostname, host=manager.private_ip)
        .all()
    )

    if db_node:
        db_node.host = manager.private_ip

    db.session.add(manager)
    if new_manager.get('ca_cert'):
        _update_cert(manager, broker, new_manager['ca_cert'])

    db.session.commit()

    config.instance.load_configuration()
    amqp_manager = _get_amqp_manager()
    default_tenant = models.Tenant.query.filter_by(name='default').one()
    amqp_manager.create_tenant_vhost_and_user(default_tenant)
    amqp_manager.sync_metadata()
    if controller:
        controller.add_manager(models.Manager.query.all())
    if agents:
        agents.update_agents(get_storage_manager())
    try:
        admin_password = new_manager['security']['admin_password']
    except KeyError:
        admin_password = None
    if admin_password:
        _update_admin_password(admin_password)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Update the current manager stored in the DB')
    parser.add_argument(
        '--input',
        help='JSON file containing the manager details',
        required=True,
    )

    args = parser.parse_args()
    with open(args.input) as f:
        inputs = json.load(f)

    config.instance.load_configuration(from_db=False)
    with setup_flask_app(
        manager_ip=config.instance.postgresql_host,
        hash_salt=config.instance.security_hash_salt,
        secret_key=config.instance.security_secret_key
    ).app_context():
        config.instance.load_configuration()
        main(inputs['manager'])
