import os
from os.path import join
from tempfile import gettempdir

from ..base_component import BaseComponent
from ...service_names import MANAGER, RABBITMQ, QUEUE_SERVICE
from ...components_constants import CONFIG, SERVICES_TO_INSTALL
from ... import constants
from ...config import config
from ...logger import get_logger
from ...utils import common, service
from ...utils.certificates import (
    use_supplied_certificates,
    validate_certificates,
)
from ...utils.files import remove, touch
from ...utils.logrotate import setup_logrotate
from ...utils.sudoers import add_entry_to_sudoers, allow_user_to_sudo_command

CONFIG_PATH = join(constants.COMPONENTS_DIR, MANAGER, CONFIG)

logger = get_logger(MANAGER)


class Manager(BaseComponent):
    def _allow_run_supervisorctl_command(self):
        command = '/usr/bin/supervisorctl'
        description = 'Allow running {0} for {1}'.format(
            command, constants.CLOUDIFY_USER
        )
        allow_user_to_sudo_command(command, description)

    def _get_exec_tempdir(self):
        return os.environ.get(constants.CFY_EXEC_TEMPDIR_ENVVAR) or \
               gettempdir()

    def _create_sudoers_file_and_disable_sudo_requiretty(self):
        remove(constants.CLOUDIFY_SUDOERS_FILE, ignore_failure=True)
        touch(constants.CLOUDIFY_SUDOERS_FILE)
        common.chmod('440', constants.CLOUDIFY_SUDOERS_FILE)
        entry = 'Defaults:{user} !requiretty'\
            .format(user=constants.CLOUDIFY_USER)
        description = 'Disable sudo requiretty for {0}'.format(
            constants.CLOUDIFY_USER
        )
        add_entry_to_sudoers(entry, description)

    def _create_manager_resources_dirs(self):
        resources_root = constants.MANAGER_RESOURCES_HOME
        common.mkdir(resources_root)
        common.mkdir(join(resources_root, 'cloudify_agent'))
        common.mkdir(join(resources_root, 'packages', 'scripts'))
        common.mkdir(join(resources_root, 'packages', 'templates'))

    @staticmethod
    def handle_certificates():
        use_supplied_certificates(component_name=RABBITMQ,
                                  logger=logger,
                                  ca_destination=constants.BROKER_CA_LOCATION)

    def _prepare_certificates(self):
        if not os.path.exists(constants.SSL_CERTS_TARGET_DIR):
            common.mkdir(constants.SSL_CERTS_TARGET_DIR)
        # Move the broker certificate if we're not installing it locally
        if QUEUE_SERVICE not in config[SERVICES_TO_INSTALL]:
            # ...but only if one was provided.
            if config[RABBITMQ]['ca_path']:
                self.handle_certificates()

    def replace_certificates(self):
        if (QUEUE_SERVICE not in config[SERVICES_TO_INSTALL] and
                os.path.exists(constants.NEW_BROKER_CA_CERT_FILE_PATH)):
            logger.info('Replacing rabbitmq CA cert on the manager component')
            config[RABBITMQ]['ca_path'] = \
                constants.NEW_BROKER_CA_CERT_FILE_PATH
            self.handle_certificates()

    def validate_new_certs(self):
        if (QUEUE_SERVICE not in config[SERVICES_TO_INSTALL] and
                os.path.exists(constants.NEW_BROKER_CA_CERT_FILE_PATH)):
            validate_certificates(
                ca_filename=constants.NEW_BROKER_CA_CERT_FILE_PATH)

    def install(self):
        logger.notice('Installing Cloudify Manager resources...')
        self._create_sudoers_file_and_disable_sudo_requiretty()
        self._allow_run_supervisorctl_command()
        setup_logrotate()
        self._create_manager_resources_dirs()
        logger.notice('Cloudify Manager resources successfully installed!')

    def configure(self):
        logger.notice('Configuring Cloudify Manager resources...')
        self._prepare_certificates()
        logger.notice('Cloudify Manager resources successfully configured!')
        self.start()

    def remove(self):
        logger.notice('Removing Cloudify Manager resources...')
        # Remove syncthing so a reinstall of a cluster node can work
        service.remove('cloudify-syncthing')
        remove([join(self._get_exec_tempdir(), 'cloudify-ctx'),
                '/opt/syncthing'])
        logger.notice('Cloudify Manager resources successfully removed!')
