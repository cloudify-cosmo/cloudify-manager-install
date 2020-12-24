from __future__ import print_function
import json

from manager_rest import config
from manager_rest.storage import db, models, get_storage_manager  # NOQA
from manager_rest.flask_utils import setup_flask_app


def _prepare_config_for_monitoring():
    sm = get_storage_manager()
    rabbitmq_nodes = {
        node.name: node.private_ip for node in sm.list(models.RabbitMQBroker)
    }
    db_nodes = {
        node.name: node.private_ip for node in sm.list(models.DBNodes)
    }
    return {
        'rabbitmq_nodes': rabbitmq_nodes,
        'db_nodes': db_nodes
    }


if __name__ == '__main__':
    config.instance.load_configuration(from_db=False)
    setup_flask_app(
        manager_ip=config.instance.postgresql_host,
        hash_salt=config.instance.security_hash_salt,
        secret_key=config.instance.security_secret_key
    )
    monitoring_config = _prepare_config_for_monitoring()
    print(json.dumps(monitoring_config))
