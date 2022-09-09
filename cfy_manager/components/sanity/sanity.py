import sys
import time
import uuid
import pkg_resources
from contextlib import contextmanager

from ..restservice.db import get_managers
from ..base_component import BaseComponent
from ...service_names import SANITY
from ...logger import get_logger
from ...constants import CLOUDIFY_USER, CLOUDIFY_GROUP
from ...utils import common
from ...utils.files import write, remove


logger = get_logger(SANITY)


class Sanity(BaseComponent):
    def __init__(self):
        super(Sanity, self).__init__()
        random_postfix = str(uuid.uuid4())
        self.blueprint_name = '{0}_blueprint_{1}'.format(SANITY,
                                                         random_postfix)
        self.deployment_name = '{0}_deployment_{1}'.format(SANITY,
                                                           random_postfix)

    def _upload_blueprint(self):
        logger.info('Uploading sanity blueprint...')
        blueprint_path = pkg_resources.resource_filename(
            'cfy_manager',
            'components/sanity/blueprint/bp.yaml'
        )
        common.cfy('blueprints', 'upload', blueprint_path,
                   '-b', self.blueprint_name,
                   stdout=sys.stdout)

    def _deploy_app(self):
        logger.info('Deploying sanity app...')
        common.cfy('deployments', 'create', '-b', self.blueprint_name,
                   self.deployment_name,
                   '--skip-plugins-validation',
                   stdout=sys.stdout)

    def _install_sanity(self):
        logger.info('Installing sanity app...')
        common.cfy('executions', 'start', 'install', '-d',
                   self.deployment_name,
                   stdout=sys.stdout)

    def _clean_sanity(self):
        logger.info('Removing sanity...')
        common.cfy('executions', 'start', 'uninstall', '-d',
                   self.deployment_name,
                   stdout=sys.stdout)
        common.cfy('deployments', 'delete', self.deployment_name,
                   stdout=sys.stdout)
        time.sleep(3)
        common.cfy('blueprints', 'delete', self.blueprint_name,
                   stdout=sys.stdout)

    def run_sanity_check(self):
        logger.notice('Running Sanity...')
        self._upload_blueprint()
        self._deploy_app()
        self._install_sanity()
        self._clean_sanity()
        logger.notice('Sanity completed successfully')

    def configure(self):
        # This is start-like, but should only happen at install time, so it
        # is using configure instead
        if len(get_managers()) > 1:
            logger.notice('Not running the sanity check: part of a cluster')
            return
        with self.sanity_check_mode():
            self.run_sanity_check()

    @contextmanager
    def sanity_check_mode(self):
        marker_file = '/opt/manager/sanity_mode'
        try:
            write('sanity: True', marker_file,
                  owner=CLOUDIFY_USER, group=CLOUDIFY_GROUP)
            yield
        finally:
            remove([marker_file])
