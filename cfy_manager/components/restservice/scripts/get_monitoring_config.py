from __future__ import print_function
import json

from manager_rest import config
from manager_rest.storage import db, models, get_storage_manager  # NOQA
from manager_rest.flask_utils import setup_flask_app


def _prepare_config_for_monitoring():
    sm = get_storage_manager()
    cfg = {}
    rabbitmq_nodes = sm.list(models.RabbitMQBroker)
    if len(rabbitmq_nodes) > 0:
        tmp_ca_cert_path = rabbitmq_nodes[0].write_ca_cert()
        cfg['rabbitmq'] = {
            'ca_path': tmp_ca_cert_path,
            'cluster_members': {}
        }
        for node in rabbitmq_nodes:
            cfg['rabbitmq']['cluster_members'][node.name] = {
                'networks': {'default': node.private_ip}
            }
    postgresql_server_nodes = sm.list(models.DBNodes)
    if len(postgresql_server_nodes) > 0:
        cfg['postgresql_server'] = {'cluster': {'nodes': {}}}
        for node in postgresql_server_nodes:
            cfg['postgresql_server']['cluster']['nodes'][node.name] = {
                'ip': node.private_ip
            }
    return cfg


if __name__ == '__main__':
    config.instance.load_configuration(from_db=False)
    setup_flask_app(
        manager_ip=config.instance.postgresql_host,
        hash_salt=config.instance.security_hash_salt,
        secret_key=config.instance.security_secret_key
    )
    monitoring_config = _prepare_config_for_monitoring()
    print(json.dumps(monitoring_config))
