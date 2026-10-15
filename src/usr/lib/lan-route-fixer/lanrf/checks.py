"""Read-only status checks, shared by the CLI, the GUI and the daemon.

Unlike :mod:`lanrf.reconcile` this module never needs privileges: it only asks
the backend what the kernel currently does.
"""

from .backends import get_backend
from .config import Config
from .reconcile import inspect
from .routing import InterfaceSelector


def as_config(config):
    """Accept a :class:`~lanrf.config.Config` or the plain dict the GUI holds."""
    if isinstance(config, Config):
        return config
    return Config(config if isinstance(config, dict) else {})


def check_targets(config, backend=None, selector=None):
    """Return a check result for every enabled, valid target.

    The result keeps the historical keys (``address``, ``ip``, ``prefix``,
    ``interface``, ``desired``, ``current``, ``ok``) so 2.0.x callers and the
    GTK status view keep working, and adds richer diagnostics on top.
    """
    config = as_config(config)
    backend = backend or get_backend()
    selector = selector or InterfaceSelector(backend)
    snapshots = inspect(
        config.enabled_targets, config, backend, selector=selector, dry_run=True
    )

    results = []
    for snapshot in snapshots:
        if snapshot.get("skipped"):
            continue
        effective = snapshot.get("effective_address") or snapshot.get("address", "")
        try:
            ip = effective.rsplit("/", 1)[0]
        except AttributeError:  # pragma: no cover
            ip = effective
        results.append(
            {
                "name": snapshot.get("name"),
                "address": snapshot.get("address"),
                "effective_address": effective,
                "family": snapshot.get("family", 4),
                "ip": ip,
                "prefix": snapshot.get("prefix", 32),
                "interface": snapshot.get("desired") or None,
                "desired": snapshot.get("desired") or None,
                "current": snapshot.get("current") or None,
                "ok": bool(snapshot.get("ok")),
                "state": snapshot.get("state", "unknown"),
                "reason": snapshot.get("reason", ""),
                "table": snapshot.get("table", "main"),
                "policy_rule": bool(snapshot.get("policy_rule")),
                "rule_installed": snapshot.get("rule_installed"),
                "route_installed": snapshot.get("route_installed"),
                "covering": snapshot.get("covering", []),
                "pending": snapshot.get("pending", ""),
            }
        )
    return results


def summarize(results):
    """Counts used by the CLI and the GUI header."""
    return {
        "total": len(results),
        "ok": sum(1 for result in results if result["ok"]),
        "bad": sum(1 for result in results if not result["ok"]),
    }
