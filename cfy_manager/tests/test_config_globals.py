import pytest

from cfy_manager import constants
from cfy_manager.config import config
from cfy_manager.components.globals import set_globals
from cfy_manager.service_names import MANAGER
from cfy_manager.components_constants import SECURITY, SSL_ENABLED


@pytest.fixture(autouse=True)
def _reset_config():
    for k in list(config):
        del config[k]
    config._load_defaults_config()


def test_no_listeners():
    config[MANAGER]['private_ip'] = 'example1.com'
    config[MANAGER]['public_ip'] = 'example2.com'
    set_globals()

    listeners = config[MANAGER]['listeners']
    assert len(listeners) == 2
    assert {
        ('example1.com', constants.INTERNAL_REST_PORT), ('example2.com', 443)
    } == {(li.host, li.port) for li in listeners}


def test_no_listeners_ssl_disabled():
    config[MANAGER]['public_ip'] = 'example2.com'
    config[MANAGER][SECURITY][SSL_ENABLED] = False
    set_globals()

    listeners = config[MANAGER]['listeners']
    assert len(listeners) == 2
    assert ('example2.com', 80) in {(li.host, li.port) for li in listeners}
