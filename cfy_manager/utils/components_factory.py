

from ..components import (
    AmqpPostgresComponent,
    AmqpInfluxComponent,
    ManagerComponent,
    ManagerIpSetterComponent,
    NginxComponent,
    PythonComponent,
    PostgresqlComponent,
    RabbitMQComponent,
    RestServiceComponent,
    InfluxDBComponent,
    JavaComponent,
    StageComponent,
    ComposerComponent,
    MgmtWorkerComponent,
    RiemannComponent,
    ClusterComponent,
    CliComponent,
    UsageCollectorComponent,
    SanityComponent
)


class ComponentsFactory:
    def __init__(self):
        pass

    @staticmethod
    def create_component(component_name):
        return {
            "amqp_postgres": AmqpPostgresComponent(),
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
            "stage": StageComponent(),
            "composer": ComposerComponent(),
            "mgmtworker": MgmtWorkerComponent(),
            "riemann": RiemannComponent(),
            "cluster": ClusterComponent(),
            "cli": CliComponent(),
            "usage_collector": UsageCollectorComponent(),
            "sanity": SanityComponent()
        }[component_name]
