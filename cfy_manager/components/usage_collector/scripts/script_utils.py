import json
import time
import logging
import pkg_resources
from requests import post
from contextlib import contextmanager
from logging.handlers import WatchedFileHandler

from manager_rest import config, premium_enabled
from manager_rest.flask_utils import setup_flask_app
from manager_rest.storage import models, storage_utils, db

DAYS_LOCK = 1
HOURS_LOCK = 2
BUFFER_TIME = 300
DAYS_INTERVAL = 'days_interval'
HOURS_INTERVAL = 'hours_interval'
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


def collect_metadata(data):
    pkg_distribution = pkg_resources.get_distribution('cloudify-rest-service')
    manager_version = pkg_distribution.version

    usage_collector_info = models.UsageCollector.query.first()
    manager_id = str(usage_collector_info.manager_id)
    licenses = models.License.query.all()
    customer_id = str(licenses[0].customer_id) if licenses else None

    data['metadata'] = {
        'manager_id': manager_id,
        'customer_id': customer_id,
        'premium_edition': premium_enabled,
        'version': manager_version,
        'image_info': 'rpm'
    }
    if _is_inside_docker():
        data['metadata']['image_info'] = 'docker'
    elif _is_inside_kubernetes():
        data['metadata']['image_info'] = 'kubernetes'


def send_data(data, url, interval_type):
    usage_collector_info = models.UsageCollector.query.first()
    if interval_type == HOURS_INTERVAL:
        usage_collector_info.hourly_timestamp = int(time.time())
    else:
        usage_collector_info.daily_timestamp = int(time.time())
    db.session.commit()
    logger.info('The sent data: {0}'.format(data))
    data = {'data': json.dumps(data)}
    post(url, data=data)


@contextmanager
def usage_collector_lock(lock_number):
    locked = _try_usage_collector_lock(lock_number)
    try:
        yield locked
    finally:
        if locked:
            _unlock_usage_collector(lock_number)


def _try_usage_collector_lock(lock_number):
    return storage_utils.try_acquire_lock_on_table(lock_number)


def _unlock_usage_collector(lock_number):
    logger.debug('Unlocking usage_collector table')
    storage_utils.unlock_table(lock_number)


def should_send_data(interval_type):
    usage_collector_info = models.UsageCollector.query.first()
    timestamp = _get_timestamp(usage_collector_info, interval_type)
    if timestamp is None:
        return True

    time_now = int(time.time())
    interval_sec = _get_interval(usage_collector_info, interval_type)
    time_to_update = (timestamp + interval_sec) < (time_now + BUFFER_TIME)
    return time_to_update


def _get_interval(usage_collector_info, interval_type):
    return (usage_collector_info.hours_interval * 60 * 60
            if interval_type == HOURS_INTERVAL
            else usage_collector_info.days_interval * 24 * 60 * 60)


def _get_timestamp(usage_collector_info, interval_type):
    return (usage_collector_info.hourly_timestamp
            if interval_type == HOURS_INTERVAL
            else usage_collector_info.daily_timestamp)


def _is_inside_docker():
    """ Check whether running inside a docker container"""
    with open('/proc/1/cgroup', 'rt') as f:
        return 'docker' in f.read()


def _is_inside_kubernetes():
    """ Check whether running inside a docker container"""
    with open('/proc/1/cgroup', 'rt') as f:
        return 'kubepods' in f.read()


@contextmanager
def setup_appctx():
    config.instance.load_from_file(RESTSERVICE_CONFIG_PATH)
    app = setup_flask_app()
    with app.app_context():
        yield app
