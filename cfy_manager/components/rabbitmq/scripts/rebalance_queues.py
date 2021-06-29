import os
import logging
from subprocess import PIPE, run

from cfy_manager.config import config
from cfy_manager.components import RabbitMQ

logger = logging.getLogger(__name__)
LOGFILE = '/var/log/cloudify/manager/queue_rebalancer.log'

logging.basicConfig(level='INFO',
                    filename=LOGFILE,
                    format="%(asctime)s %(message)s")


def out(command):
    result = run(command, stdout=PIPE, stderr=PIPE,
                 universal_newlines=True, shell=True)
    return result.stdout


def main():
    config_files = [f for f in os.listdir('/etc/cloudify')
                    if f.endswith('config.yaml')]
    for f in config_files:
        config.load_config([f])
        nodename = config['rabbitmq']['nodename']
        if nodename:
            break

    if not nodename:
        logger.warning('Not a RabbitMQ node!')

    first_active_node = sorted(
        RabbitMQ().list_rabbit_nodes()['running_nodes'])[0]
    if nodename != first_active_node:
        logger.info('Not the first active node in cluster. Aborting...')
        return

    logger.info('Rebalancing queues...')
    output = out('sudo -u rabbitmq rabbitmq-queues rebalance '
                 '"all" --vhost-pattern "/" --queue-pattern ".*"')
    logger.info(output)


if __name__ == '__main__':
    main()
