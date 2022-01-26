from os.path import join

from ..components_constants import CONFIG
from ..base_component import BaseComponent
from ..service_names import MGMTWORKER
from ...logger import get_logger
from ... import constants as const
from ...utils import (
    common,
    sudoers,
    service
)
from ...utils.files import deploy


CONFIG_PATH = join(const.COMPONENTS_DIR, MGMTWORKER, CONFIG)
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
        self._deploy_hooks_config()
        # FIXME

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
            'ls {0}'.format(const.MGMWORKER_HOOKS_CONFIG),
            ignore_failures=True
        )
        if r.returncode == 0:
            return

        deploy(
            src=join(CONFIG_PATH, 'hooks.conf'),
            dst=const.MGMWORKER_HOOKS_CONFIG
        )

        # The user should use root to edit the hooks config file
        common.chmod('440', const.MGMWORKER_HOOKS_CONFIG)
        common.chown(const.CLOUDIFY_USER,
                     const.CLOUDIFY_GROUP,
                     const.MGMWORKER_HOOKS_CONFIG)

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
