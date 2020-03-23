import time
import json
import logging
from os import path
import pkg_resources

from requests import post
from contextlib import contextmanager
from logging.handlers import WatchedFileHandler

from manager_rest import config, server, premium_enabled
from manager_rest.storage import get_storage_manager, models

DAYS_INTERVAL = 'interval_in_days'
HOURS_INTERVAL = 'interval_in_hours'
DAILY_TIMESTAMP = 'daily_timestamp'
HOURLY_TIMESTAMP = 'hourly_timestamp'
USAGE_PATH = '/etc/cloudify/.usage'
USAGE_CONFIG_PATH = path.join(USAGE_PATH, 'config')
BUFFER_TIME = 900
CLOUDIFY_IMAGE_INFO = '/opt/cfy/image.info'
RESTSERVICE_CONFIG_PATH = '/opt/manager/cloudify-rest.conf'
LOGFILE = '/var/log/cloudify/usage_collector/usage_collector.log'

logger = logging.getLogger('usage_collector')
logger.setLevel(logging.INFO)
formatter = logging.Formatter(fmt='%(asctime)s [%(levelname)s] '
                                  '[%(name)s] %(message)s',
                              datefmt='%d/%m/%Y %H:%M:%S')
file_handler = WatchedFileHandler(filename=LOGFILE)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)


@contextmanager
def get_storage_manager_instance():
    """Configure and yield a storage_manager instance.
    This is to be used only OUTSIDE of the context of the REST API.
    """
    config.instance.load_from_file(RESTSERVICE_CONFIG_PATH)
    app = server.CloudifyFlaskApp()
    try:
        with app.app_context():
            sm = get_storage_manager()
            yield sm
    finally:
        config.reset(config.Config())


def needs_to_send_data(interval_type):
    timestamp, interval_sec = _get_timestamp_and_interval(interval_type)
    if timestamp is None:
        return True
    time_to_update = (timestamp + interval_sec + BUFFER_TIME) < time.time()
    if time_to_update:
        return True
    return False


def _get_timestamp_and_interval(interval_type):
    with open(USAGE_CONFIG_PATH) as usage_config_file:
        usage_config = json.load(usage_config_file)
    interval = usage_config.get(interval_type)
    if interval_type == HOURS_INTERVAL:
        timestamp = usage_config.get(HOURLY_TIMESTAMP)
        interval_sec = interval * 60 * 60
    else:
        timestamp = usage_config.get(DAILY_TIMESTAMP)
        interval_sec = interval * 24 * 60 * 60
    return timestamp, interval_sec


def collect_metadata(data):
    pkg_distribution = pkg_resources.get_distribution('cloudify-rest-service')
    manager_version = pkg_distribution.version
    with open(USAGE_CONFIG_PATH) as usage_config_file:
        usage_config = json.load(usage_config_file)
        manager_id = usage_config.get('id')
    if path.exists(CLOUDIFY_IMAGE_INFO):
        with open(CLOUDIFY_IMAGE_INFO) as image_file:
            image_info = image_file.read().strip()
    else:
        image_info = 'rpm'

    customer_id = None
    with get_storage_manager_instance() as sm:
        licenses = sm.list(models.License)
        if licenses:
            customer_id = str(licenses[0].customer_id)

    data['metadata'] = {
        'manager_id': manager_id,
        'customer_id': customer_id,
        'premium_edition': premium_enabled,
        'version': manager_version,
        'image_info': image_info
    }


def send_data(data, url, interval_type):
    with open(USAGE_CONFIG_PATH) as usage_config_file:
        usage_config = json.load(usage_config_file)
    if interval_type == HOURS_INTERVAL:
        usage_config[HOURLY_TIMESTAMP] = time.time()
    else:
        usage_config[DAILY_TIMESTAMP] = time.time()
    with open(USAGE_CONFIG_PATH, 'w') as usage_config_file:
        json.dump(usage_config, usage_config_file)
    logger.info('The sent data: {0}'.format(data))
    data = {'data': json.dumps(data)}
    post(url, data=data)
