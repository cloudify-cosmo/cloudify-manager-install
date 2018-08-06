

from ..components import *


class ComponentsFactory:
    def __init__(self):
        pass

    @staticmethod
    def create_component(component_name):
        return {
            "manager": ManagerComponent(),
            "manager_ip_setter": ManagerIpSetterComponent(),
            "nginx": NginxComponent(),
            "python": PythonComponent(),
            "postgresql": PostgresqlComponent(),
            "rabbitmq": RabbitMQComponent(),
            "restservice": RestServiceComponent(),
            "influxdb": InfluxDBComponent(),
            "amqpinflux": AmqpInfluxComponent(),
            "java": JavaComponent(),
            "amqp_postgres": AmqpPostgresComponent(),
            "stage": StageComponent(),
            "composer": ComposerComponent(),
            "mgmtworker": MgmtWorker(),
            "riemann": RiemannComponent(),
            "cluster": ClusterComponent(),
            "cli": CliComponent(),
            "usage_collector": UsageCollectorComponent(),
            "sanity": SanityComponent()
        }[component_name]
