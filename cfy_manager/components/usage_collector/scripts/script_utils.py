import json
import time
import logging
from os import path
import pkg_resources
from requests import post
from contextlib import contextmanager
from logging.handlers import WatchedFileHandler

from manager_rest import config, premium_enabled
from manager_rest.flask_utils import setup_flask_app
from manager_rest.storage import get_storage_manager, models, storage_utils

DAYS_LOCK = 1
HOURS_LOCK = 2
BUFFER_TIME = 300
DAYS_INTERVAL = 'days_interval'
HOURS_INTERVAL = 'hours_interval'
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
    try:
        with _get_flask_app().app_context():
            sm = get_storage_manager()
            yield sm
    finally:
        config.reset(config.Config())


def collect_metadata(data):
    pkg_distribution = pkg_resources.get_distribution('cloudify-rest-service')
    manager_version = pkg_distribution.version
    if path.exists(CLOUDIFY_IMAGE_INFO):
        with open(CLOUDIFY_IMAGE_INFO) as image_file:
            image_info = image_file.read().strip()
    else:
        image_info = 'rpm'

    with get_storage_manager_instance() as sm:
        usage_collector_info = (sm.list(models.UsageCollector))[0]
        manager_id = str(usage_collector_info.manager_id)
        licenses = sm.list(models.License)
        customer_id = str(licenses[0].customer_id) if licenses else None

    data['metadata'] = {
        'manager_id': manager_id,
        'customer_id': customer_id,
        'premium_edition': premium_enabled,
        'version': manager_version,
        'image_info': image_info
    }


def send_data(data, url, interval_type):
    with get_storage_manager_instance() as sm:
        usage_collector_info = (sm.list(models.UsageCollector))[0]
        if interval_type == HOURS_INTERVAL:
            usage_collector_info.hourly_timestamp = int(time.time())
        else:
            usage_collector_info.daily_timestamp = int(time.time())
        sm.update(usage_collector_info)
    logger.info('The sent data: {0}'.format(data))
    data = {'data': json.dumps(data)}
    post(url, data=data)


def try_usage_collector_lock(lock_number):
    table_name = models.UsageCollector.__tablename__
    with _get_flask_app().app_context():
        return storage_utils.try_acquire_lock_on_table(lock_number, table_name)


def unlock_usage_collector(lock_number):
    logger.info('Unlocking usage_collector table')
    with _get_flask_app().app_context():
        storage_utils.unlock_table(lock_number)


def should_send_data(interval_type):
    with get_storage_manager_instance() as sm:
        usage_collector_info = (sm.list(models.UsageCollector))[0]
    timestamp = _get_timestamp(usage_collector_info, interval_type)
    if timestamp is None:
        return True

    time_now = int(time.time())
    interval_sec = _get_interval(usage_collector_info, interval_type)
    time_to_update = (timestamp + interval_sec) < (time_now + BUFFER_TIME)
    if time_to_update:
        return True
    return False


def _get_interval(usage_collector_info, interval_type):
    return (usage_collector_info.hours_interval * 60 * 60
            if interval_type == HOURS_INTERVAL
            else usage_collector_info.days_interval * 24 * 60 * 60)


def _get_timestamp(usage_collector_info, interval_type):
    return (usage_collector_info.hourly_timestamp
            if interval_type == HOURS_INTERVAL
            else usage_collector_info.daily_timestamp)


def _get_flask_app():
    config.instance.load_from_file(RESTSERVICE_CONFIG_PATH)
    return setup_flask_app()
