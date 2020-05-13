import argh
from os.path import join

from .logger import get_logger
from .constants import (
    BASE_DIR,
)
from .utils.scripts import run_script_on_manager_venv

SCRIPT_DIR = join(BASE_DIR, 'scripts')

logger = get_logger('admin_account')


@argh.arg('new_password',
          help='The new password for the admin account to use.')
def reset_admin_password(new_password):
    """Reset the admin password."""
    logger.info('Resetting admin password...')

    script_path = join(SCRIPT_DIR, 'update-admin-password.py')
    args = [new_password]

    run_script_on_manager_venv(script_path, script_args=args)

    logger.notice('Admin password was successfully reset.')
