import os

from cfy_manager.constants import INITIAL_INSTALL_DIR, INITIAL_CONFIGURE_DIR


def get_installed_services():
    try:
        return [service_name for service_name in
                os.listdir(INITIAL_INSTALL_DIR)
                if not service_name.endswith('yaml')]
    except OSError:
        return []


def get_configured_services():
    try:
        return [service_name for service_name in
                os.listdir(INITIAL_CONFIGURE_DIR)
                if not service_name.endswith('yaml')]
    except OSError:
        return []
