"""Multi-config reconciliation for the root-owned background path.

The systemd service, the NetworkManager dispatcher and the long-running daemon
all need to reconcile *every* user's configuration, not just the one that
happens to be invoking the tool.
"""

from . import model
from .backends import get_backend
from .config import collect_all_configs, load_config
from .reconcile import apply_actions, build_state
from .routing import InterfaceSelector

# When several configs disagree about the same destination, the first one that
# mentions it wins; collect_targets() preserves that order deterministically.
def collect_targets(config_paths=None, require_auto_fix=False):
    """``(targets, config)`` merged from every discovered config file.

    The returned :class:`~lanrf.config.Config` carries the routing settings of
    the first config that defines them, so the daemon and the dispatcher agree
    with the GUI about which table to use.
    """
    from .config import DEFAULT_CONFIG, Config

    merged = Config(dict(DEFAULT_CONFIG))
    targets = []
    seen = set()
    for _path, config in collect_all_configs(config_paths):
        if require_auto_fix and not config.auto_fix:
            continue
        for key in ("routing_mode", "rule_table", "rule_preference", "expand_host_targets"):
            # First explicit value wins; keep the default until one appears.
            if merged.data.get(key) == DEFAULT_CONFIG.get(key):
                merged.data[key] = config.data.get(key, DEFAULT_CONFIG.get(key))
        # Disabled targets are kept: build_state() reports them as disabled but
        # still tears down the policy rule that used to point at them.
        for target in config.targets:
            address = str(target.get("address", ""))
            if not address or address in seen:
                continue
            seen.add(address)
            targets.append(target)
    return targets, merged


def apply_all_configs(config_paths=None, backend=None, selector=None, dry_run=False):
    """Check every discovered config and repair the routes that are wrong.

    Returns a report dict; never raises for a single failing target.
    """
    backend = backend or get_backend()
    selector = selector or InterfaceSelector(backend)
    targets, config = collect_targets(config_paths, require_auto_fix=True)

    if hasattr(backend, "invalidate"):
        backend.invalidate()

    if not targets:
        return {
            "checked": 0,
            "fixed": 0,
            "failed": 0,
            "changed": 0,
            "return_code": 0,
            "stderr": "",
            "errors": [],
            "items": [],
            "snapshots": [],
            "ok": True,
            "bad": 0,
        }

    snapshots, actions = build_state(
        targets, config, backend, selector=selector, dry_run=dry_run
    )
    outcome = apply_actions(actions, backend, dry_run=dry_run)
    bad = [snapshot for snapshot in snapshots if not snapshot.get("ok")]
    outcome.update(
        {
            "checked": len(snapshots),
            "fixed": outcome["changed"],
            "items": [
                {"address": action.get("destination"), "interface": action.get("interface")}
                for action in actions
                if action["kind"] in {"route", "rule"}
            ],
            "snapshots": snapshots,
            "return_code": 0 if outcome["failed"] == 0 else 1,
            "stderr": "; ".join(outcome["errors"]),
            "ok": outcome["failed"] == 0 and not bad,
            "bad": len(bad),
        }
    )
    return outcome


def status_report(config_paths=None, backend=None):
    """Read-only view of every configured target, for ``status``/``doctor``."""
    backend = backend or get_backend()
    targets, config = collect_targets(config_paths, require_auto_fix=False)
    selector = InterfaceSelector(backend)
    if hasattr(backend, "invalidate"):
        backend.invalidate()
    snapshots, actions = build_state(
        targets, config, backend, selector=selector, dry_run=True
    )
    return {
        "routing_mode": config.routing_mode,
        "rule_table": config.rule_table,
        "targets": snapshots,
        "actions": actions,
        "ok": all(snapshot.get("ok") for snapshot in snapshots),
        "bad": sum(1 for snapshot in snapshots if not snapshot.get("ok")),
        "protocol": model.ROUTE_PROTOCOL_NAME,
    }
