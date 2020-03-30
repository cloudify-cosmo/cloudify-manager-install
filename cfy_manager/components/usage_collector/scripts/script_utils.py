import json
import logging
import datetime
from os import path
import pkg_resources
from uuid import uuid4

from requests import post
from contextlib import contextmanager
from logging.handlers import WatchedFileHandler

from manager_rest import config, server, premium_enabled
from manager_rest.storage import get_storage_manager, models, storage_utils

DAYS_LOCK = 1
HOURS_LOCK = 2
BUFFER_TIME = 120
DAYS_INTERVAL = 'days_interval'
HOURS_INTERVAL = 'hours_interval'
MANAGER_ID_PATH = '/etc/cloudify/.id'
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


def create_manager_id_file():
    if path.exists(MANAGER_ID_PATH):
        with open(MANAGER_ID_PATH) as f:
            existing_manager_id = f.read().strip()
            if existing_manager_id:
                return
    with open(MANAGER_ID_PATH, 'w') as f:
        f.write(uuid4().hex)


def collect_metadata(data):
    pkg_distribution = pkg_resources.get_distribution('cloudify-rest-service')
    manager_version = pkg_distribution.version
    with open(MANAGER_ID_PATH) as id_file:
        manager_id = id_file.read().strip()
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
    with get_storage_manager_instance() as sm:
        usage_collector_info = (sm.list(models.UsageCollector))[0]
        if interval_type == HOURS_INTERVAL:
            usage_collector_info.hourly_timestamp = datetime.datetime.now()
        else:
            usage_collector_info.daily_timestamp = datetime.datetime.now()
        sm.update(usage_collector_info)
    logger.info('The sent data: {0}'.format(data))
    data = {'data': json.dumps(data)}
    post(url, data=data)


def try_usage_collector_lock(lock_number):
    table_name = models.UsageCollector.__tablename__
    return storage_utils.try_acquire_lock_on_table(lock_number, table_name)


def should_send_data(interval_type):
    with get_storage_manager_instance() as sm:
        usage_collector_info = (sm.list(models.UsageCollector))[0]
    time_now = _datetime_to_epoch(datetime.datetime.now())
    timestamp = _get_timestamp(usage_collector_info, interval_type)
    interval_sec = _get_interval(usage_collector_info, interval_type)

    time_to_update = (timestamp + interval_sec) < (time_now + BUFFER_TIME)
    if (timestamp is None) or time_to_update:
        return True
    return False


def _get_interval(usage_collector_info, interval_type):
    if interval_type == HOURS_INTERVAL:
        interval_sec = usage_collector_info.hours_interval * 60 * 60
    else:
        interval_sec = usage_collector_info.days_interval * 24 * 60 * 60
    return interval_sec


def _get_timestamp(usage_collector_info, interval_type):
    if interval_type == HOURS_INTERVAL:
        hourly_timestamp = usage_collector_info.hourly_timestamp
        timestamp = (_datetime_to_epoch(hourly_timestamp)
                     if hourly_timestamp is not None else None)
    else:
        daily_timestamp = usage_collector_info.daily_timestamp
        timestamp = (_datetime_to_epoch(daily_timestamp)
                     if daily_timestamp is not None else None)

    return timestamp


def _datetime_to_epoch(datetime_object):
    return (datetime_object - datetime.datetime(1970, 1, 1)).total_seconds()
