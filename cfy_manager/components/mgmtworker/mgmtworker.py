from os.path import join

from ..base_component import BaseComponent
from ...components_constants import (
    CONFIG,
    HOME_DIR_KEY,
    LOG_DIR_KEY,
    SERVICE_USER,
    SERVICE_GROUP,
)
from ...service_names import MGMTWORKER
from ...config import config
from ...logger import get_logger
from ... import constants as const
from ...utils import (
    common,
    sudoers,
    service
)
from ...utils.files import deploy


HOME_DIR = '/opt/mgmtworker'
MGMTWORKER_VENV = join(HOME_DIR, 'env')
LOG_DIR = join(const.BASE_LOG_DIR, MGMTWORKER)
CONFIG_PATH = join(const.COMPONENTS_DIR, MGMTWORKER, CONFIG)
HOOKS_CONFIG = join(HOME_DIR, 'config', 'hooks.conf')
logger = get_logger(MGMTWORKER)


class MgmtWorker(BaseComponent):
    services = {'cloudify-mgmtworker': {'is_group': False}}

    def _add_snapshot_restore_sudo_commands(self):
        scripts = [
            (
                'allow-snapshot-ssl-client-cert-access',
                'Allow cfyuser to access ssl client certs for snapshots.'
            ),
            (
                'deny-snapshot-ssl-client-cert-access',
                'Restore ownership on ssl client certs after snapshot.'
            ),
        ]
        for script, description in scripts:
            sudoers.deploy_sudo_command_script(
                script,
                description,
                component=MGMTWORKER,
                allow_as='root',
            )
            script_path = join(const.BASE_RESOURCES_PATH, MGMTWORKER, script)
            common.chown('root', 'root', script_path)
            common.chmod('0500', script_path)

    def _deploy_mgmtworker_config(self):
        config[MGMTWORKER][HOME_DIR_KEY] = HOME_DIR
        config[MGMTWORKER][LOG_DIR_KEY] = LOG_DIR
        config[MGMTWORKER][SERVICE_USER] = const.CLOUDIFY_USER
        config[MGMTWORKER][SERVICE_GROUP] = const.CLOUDIFY_GROUP
        self._deploy_hooks_config()

    def _deploy_admin_token(self):
        script_name = 'create-admin-token.py'
        sudoers.deploy_sudo_command_script(
            script_name,
            'Create an admin token for mgmtworker',
            component=MGMTWORKER,
            allow_as='root',
        )
        script_path = join(const.BASE_RESOURCES_PATH, MGMTWORKER, script_name)
        common.chown('root', 'root', script_path)
        common.chmod('0500', script_path)
        common.run([script_path])

    def _deploy_hooks_config(self):
        # If the hooks config file already exists, do nothing. This file
        # can be altered by users, so we shouldn't overwrite it once present.
        # Can't use os.path.exists because the file is owned by cfyuser
        r = common.run(
            'ls {0}'.format(HOOKS_CONFIG), ignore_failures=True
        )
        if r.returncode == 0:
            return

        deploy(
            src=join(CONFIG_PATH, 'hooks.conf'),
            dst=HOOKS_CONFIG
        )

        # The user should use root to edit the hooks config file
        common.chmod('440', HOOKS_CONFIG)
        common.chown(const.CLOUDIFY_USER,
                     const.CLOUDIFY_GROUP,
                     HOOKS_CONFIG)

    def _prepare_snapshot_permissions(self):
        self._add_snapshot_restore_sudo_commands()
        # TODO: See if these are necessary
        common.run(['chgrp', const.CLOUDIFY_GROUP, '/opt/manager'])
        common.run(['chmod', 'g+rw', '/opt/manager'])

    def configure(self):
        logger.notice('Configuring Management Worker...')
        self._deploy_mgmtworker_config()
        service.configure('cloudify-mgmtworker')
        self._prepare_snapshot_permissions()
        self._deploy_admin_token()
        logger.notice('Management Worker successfully configured')
        self.start()

    def remove(self):
        service.remove('cloudify-mgmtworker')
        common.remove('/opt/mgmtworker')
        common.remove(join(const.BASE_RESOURCES_PATH, MGMTWORKER))
