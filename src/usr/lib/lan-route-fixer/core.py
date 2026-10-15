#!/usr/bin/env python3
"""Core compatibility facade.

Historically every non-GUI feature lived in this single module. The
implementation now lives in the :mod:`lanrf` package; this module keeps the old
names importable so existing callers -- the ``lan-route-fixer`` entry point, the
privileged helper, the systemd applier and the test suite -- keep working
unchanged.
"""

import ipaddress  # noqa: F401  (re-exported for callers that used core.ipaddress)
import json  # noqa: F401
import os  # noqa: F401
import subprocess  # noqa: F401  (patched by tests)
import sys  # noqa: F401
from pathlib import Path  # noqa: F401

from lanrf import model
from lanrf import targets as _targets
from lanrf.backends import get_backend, set_backend  # noqa: F401
from lanrf.checks import check_targets  # noqa: F401
from lanrf.cleanup import (  # noqa: F401
    analyze as analyze_cleanup,
    analyze_routes,
    analyze_targets,
    keep_configs,
    prune_routes,
    prune_targets,
    read_discovery_cache,
    update_discovery_cache,
)
from lanrf.config import (  # noqa: F401
    APP_DESCRIPTION,
    APP_DISPLAY_NAME,
    APP_ID,
    AUTOSTART_PATH,
    CONFIG_HOME,
    CONFIG_PATH,
    DEFAULT_CONFIG,
    DISCOVERY_CACHE_PATH,
    SYSTEM_CONFIG_PATH,
    Config,
    apply_autostart,
    autostart_content,
    collect_all_configs,
    collect_all_enabled_targets,
    collect_config_paths,
    load_config,
    read_state,
    save_config,
    write_state,
)
from lanrf.discovery import detect_targets  # noqa: F401
from lanrf.linux import (  # noqa: F401
    VIRTUAL_INTERFACE_PREFIXES,
    VIRTUAL_LINK_KINDS,
    get_default_interfaces,
    get_link_info,
    get_link_kind,
    get_local_networks,
    is_usable_interface,
    is_virtual_interface,
    list_usable_interfaces,
    parse_route_entry,
    parse_rule_entry,
    run_ip,
    run_ip_ok,
)
from lanrf.privileged import (  # noqa: F401
    HELPER_PATH,
    LEGACY_HELPER_PATHS,
    PACKAGED_HELPER_PATH,
    PKEXEC_PATH,
    build_route_items,
    describe_failure,
    fix_targets,
    fix_targets_direct,
    run_helper,
)
from lanrf.reconcile import (  # noqa: F401
    apply_actions,
    build_state,
    inspect,
    plan,
    reconcile,
    verify,
)
from lanrf.routing import (  # noqa: F401
    InterfaceSelector,
    choose_interface_for_target,
    get_default_interface,
)
from lanrf.system import apply_all_configs  # noqa: F401
from lanrf.targets import (  # noqa: F401
    PRIVATE_V4_NETWORKS,
    ULA_V6_NETWORK,
    normalize_interface_arg,
    normalize_targets,
    parse_ip_or_cidr,
    valid_local_target,
    valid_private_ipv4,
    valid_private_ipv6,
)

# Names that existed at module level in 2.0.x.
NEIGH_VALID_STATES = _targets.NEIGH_VALID_STATES
ROUTE_PROTOCOL = model.ROUTE_PROTOCOL
ROUTE_PROTOCOL_NAME = model.ROUTE_PROTOCOL_NAME
IP_PATH = os.environ.get("LAN_ROUTE_FIXER_IP") or "/usr/sbin/ip"

_find_target_indices = _targets.find_target_indices
_normalize_interface_arg = _targets.normalize_interface_arg


def _valid_interface_choice(interface):
    if not interface:
        return True
    return get_backend().is_usable(interface)


def _refresh_avahi_path():
    """Populate ``AVAHI_RESOLVE_PATH`` for callers that read it directly."""
    from lanrf import discovery

    global AVAHI_RESOLVE_PATH
    AVAHI_RESOLVE_PATH = discovery.avahi_resolve_path()
    return AVAHI_RESOLVE_PATH


AVAHI_RESOLVE_PATH = _refresh_avahi_path()


def cli_main(argv=None):
    from lanrf.cli import cli_main as cli_entry

    return cli_entry(argv if argv is not None else sys.argv[1:])


def daemon_client_status(timeout_ms=1500):
    """Whether a root daemon is reachable over D-Bus (used by the GUI).

    Never raises: absence of D-Bus, or of the daemon, is a normal state that
    simply means repairs will need an authorization prompt.
    """
    try:
        from lanrf import dbus as dbus_module

        client = dbus_module.DaemonClient(timeout_ms=timeout_ms)
        if not client.usable:
            return None
        return {"running": client.is_running(), "error": client.last_error}
    except Exception as exception:  # noqa: BLE001 - desktop integration
        return {"running": False, "error": str(exception)}
