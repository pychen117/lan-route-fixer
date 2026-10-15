"""Test suite for lan-route-fixer.

The environment is pinned here, before any test module imports :mod:`lanrf`,
because ``lanrf`` resolves the config, state and system-config paths at import
time. Without this the suite would read (and write) the developer's real
``~/.config/lan-route-fixer``.
"""

import atexit
import os
import shutil
import tempfile

_TEST_ROOT = tempfile.mkdtemp(prefix="lanrf-tests-")
atexit.register(shutil.rmtree, _TEST_ROOT, True)

os.environ["LAN_ROUTE_FIXER_STATE"] = os.path.join(_TEST_ROOT, "state.json")
os.environ["LAN_ROUTE_FIXER_SYSTEM_CONFIG"] = os.path.join(
    _TEST_ROOT, "etc/lan-route-fixer/config.json"
)
os.environ["XDG_CONFIG_HOME"] = os.path.join(_TEST_ROOT, "config-home")
os.environ["LAN_ROUTE_FIXER_HOME"] = _TEST_ROOT
