import pytest

from cfy_manager.config import config
from cfy_manager.components.globals import set_globals


@pytest.fixture(autouse=True)
def _reset_config():
    for k in list(config):
        del config[k]
    config._load_defaults_config()


def test_set_globals():
    set_globals()
