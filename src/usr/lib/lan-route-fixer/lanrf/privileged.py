"""Client side of the privileged boundary.

The route-mutating code runs in a separate, root-owned process
(``/usr/libexec/lan-route-fixer/lan-route-helper``) reached through PolicyKit.
This module builds its payload and interprets its exit status. It never mutates
a route itself.

Exit codes are the contract with the helper (see :mod:`lanrf.helper`):

===== ==========================================================
0     every requested route is in place
64    the request was rejected by validation
65    the kernel refused a route change (see stderr)
126   the user cancelled or denied the PolicyKit prompt
127   pkexec could not start the helper at all
===== ==========================================================
"""

import json
import os
import subprocess
import sys
from pathlib import Path

from . import model
from .backends import get_backend

PACKAGED_HELPER_PATH = "/usr/libexec/lan-route-fixer/lan-route-helper"
# Keep the old paths around so upgrades from the initial deskflow package still
# find a helper without reconfiguration.
LEGACY_HELPER_PATHS = (
    "/usr/libexec/deskflow-route-fixer/deskflow-route-helper",
    "/usr/local/libexec/lan-route-helper",
)
HELPER_PATH = os.environ.get("LAN_ROUTE_FIXER_HELPER") or (
    PACKAGED_HELPER_PATH
    if Path(PACKAGED_HELPER_PATH).is_file()
    else next(
        (path for path in LEGACY_HELPER_PATHS if Path(path).is_file()),
        PACKAGED_HELPER_PATH,
    )
)
PKEXEC_PATH = os.environ.get("LAN_ROUTE_FIXER_PKEXEC") or "/usr/bin/pkexec"

EXIT_OK = 0
EXIT_INVALID = 64
EXIT_FAILED = 65
EXIT_CANCELLED = 126
EXIT_NO_HELPER = 127

EXIT_MESSAGES = {
    EXIT_INVALID: "请求被特权 helper 拒绝（参数校验失败）",
    EXIT_FAILED: "内核拒绝修改路由",
    EXIT_CANCELLED: "已取消或拒绝授权",
    EXIT_NO_HELPER: "无法启动特权 helper（策略可能未加载，请重新登录或重启 polkit）",
}


def build_route_items(targets, backend=None, config=None):
    """Convert target dicts into helper payload items.

    ``targets`` may be config target dicts (``address``/``interface``), check
    results from :mod:`lanrf.checks` (``ip``/``desired``) or reconcile snapshots
    (``effective_address``/``desired``). Every item carries ``address`` so the
    payload stays readable and compatible with the historical format; the extra
    keys tell the helper which table and protocol stamp to use.
    """
    backend = backend or get_backend()
    table = str(config.rule_table) if config and config.policy_routing else "main"
    items = []
    for target in targets:
        address = (
            target.get("effective_address")
            or target.get("address")
            or (f"{target['ip']}/{target['prefix']}" if target.get("ip") else "")
            or target.get("destination", "")
        )
        try:
            family, destination = model.normalize_destination(address)
        except ValueError:
            continue
        interface = (
            target.get("interface")
            or target.get("desired")
            or target.get("configured_interface")
        )
        if not interface:
            from .routing import InterfaceSelector

            interface = InterfaceSelector(backend).pick(destination)
        if not interface:
            continue
        source = str(target.get("source") or "")
        if not source:
            for local_interface, _network, local_address in backend.local_networks(family):
                if local_interface == interface:
                    source = str(local_address)
                    break
        items.append(
            {
                "address": destination,
                "family": family,
                "interface": interface,
                "table": target.get("table") or table,
                "protocol": model.ROUTE_PROTOCOL_NAME,
                "source": source,
                "metric": None,
            }
        )
    return items


def _helper_runner():
    """Resolve the module used to spawn the helper.

    Callers (and the test suite) may substitute ``core.subprocess`` to observe
    or stub the invocation without touching this module.
    """
    module = sys.modules.get("core")
    patched = getattr(module, "subprocess", None) if module is not None else None
    if patched is not None and patched is not subprocess:
        return patched
    return subprocess


def _daemon_repair(items):
    """Ask the running root daemon to reconcile, and check what it achieved.

    Returns ``(handled_items, remaining_items, report)``. When the daemon is
    unavailable every item is "remaining", which sends the caller down the
    pkexec path exactly as before.
    """
    from . import dbus as dbus_module

    client = dbus_module.DaemonClient()
    report = client.repair() if client.usable else None
    if report is None:
        return [], list(items), None

    # The bus cannot tell us *which* items were repaired, but the daemon
    # publishes its per-target state, so compare against that.
    from .config import read_state

    state = read_state()
    fixed = set()
    for snapshot in state.get("snapshots", []):
        for key in ("address", "effective_address"):
            value = str(snapshot.get(key) or "")
            if value and snapshot.get("ok"):
                fixed.add(value if "/" in value else f"{value}/32")
    handled = [
        item
        for item in items
        if item["address"] in fixed or item["address"].split("/")[0] + "/32" in fixed
    ]
    remaining = [item for item in items if item not in handled]
    return handled, remaining, report


def run_helper(items, use_pkexec=True, timeout=120, prefer_daemon=True):
    """Make *items* true, preferring the running daemon over a password prompt.

    The daemon path exists because ``auth_admin_keep`` expires: as long as a VPN
    client kept stealing the routes back, the user was re-prompted for their
    password indefinitely. Asking the already-root daemon to re-run its
    reconciliation involves no privilege delegation at all, so it needs no
    authorization.

    Falls back to the privileged helper (pkexec) for anything the daemon could
    not confirm - a target that is not in any config file, or a daemon that is
    not running.
    """
    if not items:
        return {
            "return_code": 0,
            "stderr": "",
            "items": [],
            "stdout": "",
            "method": "none",
        }

    remaining = list(items)
    if prefer_daemon and use_pkexec:
        handled, remaining, report = _daemon_repair(items)
        if not remaining:
            return {
                "return_code": 0,
                "stderr": "",
                "stdout": json.dumps(
                    [
                        {
                            "address": item["address"],
                            "destination": item["address"],
                            "interface": item["interface"],
                            "table": item.get("table", "main"),
                            "changed": bool(report.get("changed")),
                        }
                        for item in handled
                    ],
                    ensure_ascii=False,
                ),
                "items": items,
                "method": "daemon",
            }

    payload = json.dumps(remaining, ensure_ascii=False, separators=(",", ":"))
    if use_pkexec:
        command = [PKEXEC_PATH, HELPER_PATH, "--batch-json", payload]
    else:
        command = [HELPER_PATH, "--batch-json", payload]
    runner = _helper_runner()
    try:
        result = runner.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "return_code": EXIT_FAILED,
            "stderr": "特权 helper 超时",
            "items": remaining,
            "stdout": "",
            "method": "pkexec",
        }
    except OSError as exception:
        return {
            "return_code": EXIT_NO_HELPER,
            "stderr": str(exception),
            "items": remaining,
            "stdout": "",
            "method": "pkexec",
        }
    return {
        "return_code": result.returncode,
        "stderr": (result.stderr or "").strip(),
        "stdout": (result.stdout or "").strip(),
        "items": remaining,
        "method": "pkexec",
    }


def fix_targets(targets, backend=None, config=None, use_pkexec=True, prefer_daemon=True):
    """Fix targets from user context (prefers the daemon, falls back to pkexec)."""
    items = build_route_items(targets, backend=backend, config=config)
    return run_helper(items, use_pkexec=use_pkexec, prefer_daemon=prefer_daemon)


def fix_targets_direct(targets, backend=None, config=None):
    """Fix targets as root without pkexec (dispatcher/systemd use only)."""
    return fix_targets(
        targets, backend=backend, config=config, use_pkexec=False, prefer_daemon=False
    )


def describe_failure(return_code, stderr=""):
    """Human readable reason for a helper exit code."""
    message = EXIT_MESSAGES.get(return_code, f"修复失败（退出码 {return_code}）")
    if stderr:
        return f"{message}：{stderr}"
    return message


def helper_status():
    """Diagnostics for ``lan-route-fixer doctor``."""
    pkexec_ok = Path(PKEXEC_PATH).is_file()
    return {
        "helper_path": HELPER_PATH,
        "helper_exists": Path(HELPER_PATH).is_file(),
        "helper_executable": os.access(HELPER_PATH, os.X_OK),
        "pkexec_path": PKEXEC_PATH,
        "pkexec_exists": pkexec_ok,
    }
