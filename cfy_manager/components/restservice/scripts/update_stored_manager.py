import argparse
import json
import uuid

from datetime import datetime

from manager_rest import config
from manager_rest.amqp_manager import AMQPManager
from manager_rest.constants import DEFAULT_TENANT_ID
from manager_rest.flask_utils import setup_flask_app
from manager_rest.storage import models, get_storage_manager
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
        verify=config.instance.amqp_ca_path
    )


def _update_cert(sm, manager, broker, new_cert_value):
    old_cert = manager.ca_cert
    if old_cert.value == new_cert_value:
        return

    new_cert = models.Certificate(
        name=str(uuid.uuid4()),
        value=new_cert_value,
        updated_at=datetime.now(),
        _updater_id=0
    )
    manager.ca_cert = new_cert
    if broker:
        broker.ca_cert = new_cert
    if not old_cert.managers and not old_cert.rabbitmq_brokers:
        sm.delete(old_cert)


def main(new_manager):
    sm = get_storage_manager()

    hostname = new_manager['hostname']
    manager = sm.get(models.Manager, None, filters={'hostname': hostname})
    broker = sm.get(models.RabbitMQBroker, None, filters={
        'name': hostname,
        'host': manager.private_ip
    })
    db_node = sm.get(models.DBNodes, None, filters={
        'name': hostname,
        'host': manager.private_ip
    })
    for attr in ['private_ip', 'public_ip', 'networks',
                 'monitoring_username', 'monitoring_password']:
        setattr(manager, attr, new_manager[attr])

    sm.update(manager)
    if broker:
        if broker.management_host == broker.host:
            broker.management_host = manager.private_ip
        broker.host = manager.private_ip
        broker.networks = manager.networks
        broker.monitoring_username = manager.monitoring_username
        broker.monitoring_password = manager.monitoring_password
        sm.update(broker)

    if db_node:
        db_node.host = manager.private_ip
        db_node.monitoring_username = manager.monitoring_username
        db_node.monitoring_password = manager.monitoring_password
        sm.update(db_node)

    if new_manager.get('ca_cert'):
        _update_cert(sm, manager, broker, new_manager['ca_cert'])

    config.instance.load_configuration()
    amqp_manager = _get_amqp_manager()
    default_tenant = sm.get(models.Tenant, DEFAULT_TENANT_ID)
    amqp_manager.create_tenant_vhost_and_user(default_tenant)
    amqp_manager.sync_metadata()
    if controller:
        controller.add_manager(sm.list(models.Manager))
    if agents:
        agents.update_agents(sm)


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
