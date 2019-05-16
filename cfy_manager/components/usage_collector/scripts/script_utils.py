import json
import logging
from os import path
import pkg_resources
from uuid import uuid4

from requests import post
from contextlib import contextmanager
from logging.handlers import WatchedFileHandler

from manager_rest import config, server, premium_enabled
from manager_rest.storage import get_storage_manager, models


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


def send_data(data, url):
    # for some reason. multi hierarchy dict doesn't pass well to the end point
    logger.info('The sent data: {0}'.format(data))
    data = {'data': json.dumps(data)}
    post(url, data=data)
