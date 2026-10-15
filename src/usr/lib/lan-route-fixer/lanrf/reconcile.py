"""The reconciliation engine.

This module is the heart of the tool and it is deliberately *pure*: it decides
what should be true and which actions close the gap, but performs no I/O of its
own. Everything platform specific arrives through the backend, everything about
*when* to reconcile arrives through the caller (event monitor, timer,
NetworkManager, or a user pressing a button).

Why this matters for the aTrust problem
---------------------------------------

aTrust (like several other VPN clients) enumerates the private IPv4 space and
installs hundreds of ``/25``..``/32`` routes that point at its ``utun`` device,
using netlink ``RouteAdd``/``RouteDel``. Two things then break LAN access:

1. A host route installed by this tool can be displaced when the VPN client
   re-asserts its view of the table, so the *timing* of the repair matters more
   than the correctness of a single repair.
2. Even when the main table looks right, a route that merely happens to be
   correct is fragile: any later table rewrite can take it away again.

The engine therefore supports two independent layers of protection:

* **Policy routing** (``routing_mode = "rule"``): routes live in a dedicated
  table selected by a high-priority ``ip rule``. Rules are evaluated before the
  main table, so a VPN client rewriting ``main`` cannot capture the traffic.
* **Event driven repair** (see :mod:`lanrf.daemon`): every ``RTM_*ROUTE``
  change triggers a plan/apply pass within milliseconds instead of waiting for
  the next poll tick.
"""

import ipaddress
import time

from . import model
from .routing import InterfaceSelector
from .targets import parse_ip_or_cidr, valid_local_target

# Action kinds
ACTION_ROUTE = "route"
ACTION_RULE = "rule"
ACTION_DELETE_ROUTE = "delete-route"
ACTION_DELETE_RULE = "delete-rule"

# Never expand a host target into a prefix broader than this.
MAX_EXPANDED_PREFIXLEN_V4 = 16
MAX_EXPANDED_PREFIXLEN_V6 = 64


def _route_interface(backend, destination, family, table, rule_installed=None):
    """Interface that will actually carry traffic to *destination*.

    In policy-routing mode the kernel walks our high-priority rule first, then
    falls back to ``main``. Modelling that order matters: reporting the main
    table's interface while our rule is missing would claim the target is safe
    when a VPN client can still capture it.
    """
    probes = []
    if table and table != "main":
        probes.append((table, False))
        if rule_installed is not False:
            probes.append(("main", True))
    else:
        probes.append(("main", True))
    probes.append(("all", False))

    for probe_table, fallback in probes:
        entry = backend.route_lookup(
            destination, family=family, table=probe_table, fallback=fallback
        )
        if not entry:
            continue
        interface = str(entry.get("interface") or "")
        entry_table = str(entry.get("table") or "")
        if interface and (not entry_table or entry_table == str(probe_table) or probe_table == "all"):
            return interface
    return ""


def _route_in_table(backend, destination, family, table, interface, source):
    """True when *table* contains the exact route we want."""
    for entry in backend.routes(table=table, family=family):
        if entry["prefix"] != destination:
            continue
        if entry["interface"] != interface:
            continue
        if source and entry["source"] and entry["source"] != source:
            continue
        return True
    return False


def _covering_routes(backend, destination, family, table):
    """Existing routes that are broader than *destination*, from either table.

    In policy-routing mode the competitor lives in ``main`` while our own table
    holds the host route, so both have to be inspected to name the culprit.
    """
    wanted = model.destination_index(destination)
    tables = [str(table)]
    if str(table) != "main":
        tables.append("main")
    covering = []
    for name in tables:
        for prefix in backend.route_prefixes(table=name, family=family):
            if prefix == destination or prefix in covering:
                continue
            if model.prefix_covers(prefix, wanted):
                covering.append(prefix)
    return covering


def _expand_target(target, backend):
    """Optionally widen a host target to the local subnet that contains it."""
    address = str(target.get("address", ""))
    parsed = parse_ip_or_cidr(address)
    if not parsed:
        return address
    family, ip, prefix = parsed
    default_prefix = model.DEFAULT_PREFIXLEN[family]
    if prefix != default_prefix:
        return address
    try:
        address_object = ipaddress.ip_address(ip)
    except ValueError:  # pragma: no cover - already validated
        return address
    for _interface, local_network, local_address in backend.local_networks(family):
        if address_object in local_network:
            floor = (
                MAX_EXPANDED_PREFIXLEN_V4
                if family == 4
                else MAX_EXPANDED_PREFIXLEN_V6
            )
            if local_network.prefixlen < floor:
                return address
            return f"{local_network.network_address}/{local_network.prefixlen}"
    return address


def build_state(targets, config, backend, selector=None, include_rules=True,
                dry_run=False, can_mutate=None):
    """Return ``(snapshots, actions)`` for *targets* under *config*.

    ``snapshots`` describes the desired and observed state of every target;
    ``actions`` is the ordered list of operations that would make them match.
    Both are plain data.

    ``dry_run`` keeps the plan complete but suppresses actions that cannot be
    *verified* to have taken effect: an unprivileged caller must not be told
    "route installed" when the kernel rejected it.
    """
    selector = selector or InterfaceSelector(backend)
    table = str(config.rule_table) if config.policy_routing else "main"
    preference = config.rule_preference
    use_rules = bool(include_rules and config.policy_routing and backend.supports_policy_rules)
    if can_mutate is None:
        can_mutate = bool(getattr(backend, "is_privileged", True))
    can_mutate = bool(can_mutate)
    expand = bool(config.expand_host_targets)

    snapshots = []
    actions = []
    desired_routes = []

    for target in targets:
        raw_address = str(target.get("address", ""))
        name = str(target.get("name") or raw_address)
        if not target.get("enabled") or not valid_local_target(raw_address):
            valid = valid_local_target(raw_address)
            snapshots.append(
                {
                    "name": name,
                    "address": raw_address,
                    "uid": model.target_uid(target),
                    "enabled": False,
                    "state": model.ROUTE_STATE_INVALID if not valid else "disabled",
                    # A disabled target is not a problem: it must not make the
                    # overall report look broken.
                    "ok": True,
                    "skipped": True,
                    "reason": "invalid address" if not valid else "disabled",
                }
            )
            continue

        # A target may ask for whole-subnet coverage either through the global
        # setting or per target (see targets.normalize_targets).
        want_expand = expand or bool(target.get("expand"))
        address = _expand_target(target, backend) if want_expand else raw_address
        family, destination = model.normalize_destination(address)
        interface = selector.pick(
            destination, configured=target.get("interface", "")
        )
        snapshot = {
            "name": name,
            "address": raw_address,
            "effective_address": destination,
            "uid": model.target_uid(target),
            "family": family,
            "prefix": int(destination.rsplit("/", 1)[1]),
            "enabled": True,
            "configured_interface": str(target.get("interface", "") or ""),
            "desired": interface or "",
            "current": "",
            "table": table,
            "policy_rule": bool(use_rules),
            "ok": False,
            "state": model.ROUTE_STATE_UNKNOWN,
            "reason": "",
        }

        if not interface:
            snapshot["state"] = model.ROUTE_STATE_MISSING
            snapshot["reason"] = "no usable LAN interface is available"
            snapshot["ok"] = False
            snapshots.append(snapshot)
            continue

        source = ""
        for local_interface, _network, local_address in backend.local_networks(family):
            if local_interface == interface:
                source = str(local_address)
                break

        item = model.target_route_item(
            {"address": destination}, interface, table=table, source=source
        )
        desired_routes.append(item)

        # The policy rule decides whether the dedicated table is even consulted.
        rule_installed = None
        rule_present = True
        if use_rules:
            rule_installed = any(
                model.rule_matches(rule, destination, table)
                for rule in backend.rules(family=family)
            )
            rule_present = rule_installed
            snapshot["rule_installed"] = rule_installed
            snapshot["rule_preference"] = preference

        route_present = _route_in_table(
            backend, destination, family, table, interface, source
        )
        current = _route_interface(
            backend, destination, family, table, rule_installed=rule_installed
        )
        snapshot["current"] = current
        snapshot["source"] = source
        snapshot["route_installed"] = route_present

        if route_present and rule_present:
            snapshot["ok"] = True
            snapshot["state"] = model.ROUTE_STATE_OK
            snapshot["reason"] = (
                f"pinned to {interface} in table {table}"
                + (f" via rule pref {preference}" if use_rules else "")
            )
        elif not route_present and not rule_present:
            snapshot["state"] = model.ROUTE_STATE_MISSING
            snapshot["reason"] = f"route missing from table {table} and policy rule absent"
        elif not route_present:
            snapshot["state"] = model.ROUTE_STATE_MISSING
            snapshot["reason"] = f"no route in table {table}"
        else:
            snapshot["state"] = model.ROUTE_STATE_MISSING
            snapshot["reason"] = (
                f"route exists in table {table} but no policy rule sends traffic there"
            )

        if not route_present and current and current != interface:
            snapshot["state"] = model.ROUTE_STATE_WRONG_INTERFACE
            covering = _covering_routes(backend, destination, family, table)
            snapshot["covering"] = covering
            snapshot["reason"] = (
                f"traffic leaves via {current} instead of {interface}"
                + (
                    f" (a broader route {covering[0]} is capturing it)"
                    if covering
                    else ""
                )
            )

        snapshots.append(snapshot)

        if not interface:
            # Without a route there is nothing for a policy rule to select, so
            # never install a rule pointing at an empty table.
            continue

        blocked = ""
        if not can_mutate:
            blocked = "route changes need root or pkexec"
        elif dry_run:
            blocked = "dry run"

        if not snapshot["ok"]:
            if blocked:
                snapshot["pending"] = blocked
                if use_rules and not rule_present:
                    snapshot["blocked_kinds"] = ["rule", "route"]
                else:
                    snapshot["blocked_kinds"] = ["route"]
            else:
                if use_rules and not rule_present:
                    actions.append(
                        {
                            "kind": ACTION_RULE,
                            "destination": destination,
                            "family": family,
                            "table": table,
                            "preference": preference,
                            "address": raw_address,
                            "name": name,
                        }
                    )
                if not route_present:
                    actions.append(
                        {
                            "kind": ACTION_ROUTE,
                            "destination": destination,
                            "family": family,
                            "interface": interface,
                            "table": table,
                            "source": source,
                            "protocol": model.ROUTE_PROTOCOL_NAME,
                            "metric": None,
                            "address": raw_address,
                            "name": name,
                        }
                    )

    if use_rules and not dry_run and can_mutate:
        actions.extend(
            _stale_rule_actions(backend, desired_routes, table, preference, snapshots)
        )
    return snapshots, actions


def _stale_rule_actions(backend, desired_routes, table, preference, snapshots):
    """Drop policy rules whose target is no longer configured."""
    wanted = {}
    for item in desired_routes:
        wanted[(item["family"], item["destination"])] = item
    actions = []
    for family in (4, 6):
        for rule in backend.rules(family=family):
            if str(rule.get("lookup")) != str(table):
                continue
            selector = str(rule.get("to") or "")
            if not selector:
                continue
            try:
                family_for_rule = 6 if ":" in selector else 4
                destination = model.normalize_destination(selector)[1]
            except ValueError:
                continue
            if (family_for_rule, destination) in wanted:
                continue
            actions.append(
                {
                    "kind": ACTION_DELETE_RULE,
                    "destination": destination,
                    "family": family_for_rule,
                    "table": table,
                    "preference": rule.get("pref", preference),
                    "address": destination,
                    "name": "stale policy rule",
                    "stale": True,
                }
            )
    if actions:
        for snapshot in snapshots:
            snapshot.setdefault("stale_rules", len(actions))
    return actions


def inspect(targets, config, backend, selector=None, dry_run=False):
    """Read-only status of every target."""
    snapshots, _actions = build_state(
        targets, config, backend, selector=selector, dry_run=dry_run
    )
    return snapshots


def plan(targets, config, backend, selector=None, dry_run=False):
    """Actions required to make *targets* match *config*."""
    _snapshots, actions = build_state(
        targets, config, backend, selector=selector, dry_run=dry_run
    )
    return actions


def apply_actions(actions, backend, dry_run=False):
    """Execute *actions*; returns a summary dict.

    Failures are collected instead of raised so one bad target cannot stop the
    repair of the others - a partial LAN outage is much better than none.
    """
    summary = {
        "changed": 0,
        "unchanged": 0,
        "failed": 0,
        "actions": len(actions),
        "details": [],
        "errors": [],
        "dry_run": bool(dry_run),
        "routes": 0,
        "rules": 0,
    }
    for action in actions:
        kind = action["kind"]
        try:
            if kind == ACTION_ROUTE:
                changed, detail = backend.ensure_route(action)
                summary["routes"] += 1
            elif kind == ACTION_RULE:
                changed, detail = backend.ensure_rule(
                    action["destination"],
                    action["table"],
                    family=action["family"],
                    preference=action["preference"],
                )
                summary["rules"] += 1
            elif kind == ACTION_DELETE_ROUTE:
                changed = backend.remove_route(action)
                detail = f"removed {action['destination']}"
            elif kind == ACTION_DELETE_RULE:
                changed = backend.remove_rule(
                    action["destination"],
                    action["table"],
                    family=action["family"],
                )
                detail = f"removed rule for {action['destination']}"
            else:  # pragma: no cover - programming error
                raise RuntimeError(f"unknown action kind: {kind}")
        except Exception as exception:  # noqa: BLE001 - reported, never fatal
            summary["failed"] += 1
            message = f"{kind} {action.get('address') or action.get('destination')}: {exception}"
            if message not in summary["errors"]:
                summary["errors"].append(message)
            continue

        if changed:
            summary["changed"] += 1
        else:
            summary["unchanged"] += 1
        if len(summary["details"]) < 500:
            summary["details"].append(detail)
    return summary


def finalize_outcome(outcome, snapshots, config, dry_run=False):
    """Turn a raw :func:`apply_actions` result into a report.

    ``report["ok"]`` must mean "the routes are in place *now*", not "we asked
    for them", so when anything was changed the state is re-inspected. A VPN
    client that re-asserts its table right after our repair would otherwise be
    reported as success.
    """
    outcome["planned"] = snapshots
    outcome["snapshots"] = snapshots
    outcome["targets"] = len(snapshots)
    outcome["bad"] = sum(1 for snapshot in snapshots if not snapshot.get("ok"))
    outcome["pending"] = sum(1 for snapshot in snapshots if snapshot.get("pending"))
    outcome["routing_mode"] = config.routing_mode
    outcome["rule_table"] = config.rule_table
    outcome["ok"] = outcome["failed"] == 0 and outcome["bad"] == 0
    return outcome


def reconcile(targets, config, backend, selector=None, dry_run=False):
    """One full pass: inspect, plan, apply, verify. Returns a report dict."""
    started = time.monotonic()
    selector = selector or InterfaceSelector(backend)
    if hasattr(backend, "invalidate"):
        backend.invalidate()
    snapshots, actions = build_state(
        targets, config, backend, selector=selector, dry_run=dry_run
    )
    outcome = apply_actions(actions, backend, dry_run=dry_run)

    final_snapshots = snapshots
    if actions and not dry_run and outcome["failed"] == 0:
        if hasattr(backend, "invalidate"):
            backend.invalidate()
        final_snapshots, _extra = build_state(
            targets, config, backend, selector=selector, dry_run=True
        )

    outcome = finalize_outcome(outcome, final_snapshots, config, dry_run=dry_run)
    outcome["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
    return outcome


def verify(snapshots, backend, config):
    """Re-inspect after an apply, to confirm the routes actually stuck.

    A VPN client that re-asserts its table immediately after our repair would
    otherwise go unnoticed; verification turns that into a visible warning.
    """
    return inspect(
        [
            {
                "name": snapshot["name"],
                "address": snapshot["address"],
                "interface": snapshot.get("configured_interface", ""),
                "enabled": True,
            }
            for snapshot in snapshots
            if snapshot.get("enabled")
        ],
        config,
        backend,
    )
