"""Garbage collection: keep the routing table and the config file free of cruft.

Two different kinds of residue accumulate over time, and both are handled here
so that the GUI, the CLI and the ``prune`` command share one implementation.

**Routes and policy rules.** Every address the user ever pinned leaves a host
route and an ``ip rule`` behind when they stop being a target. Deleting the
config entry is not enough: the leftovers keep redirecting traffic, and after a
few months of moving between networks the table is a pile of stale ``/32``s.
Routes installed by this tool carry a dedicated protocol stamp (``proto 66``),
which makes them exactly identifiable without guessing.

**Targets.** Network scanning turns up every phone and printer on the LAN, and
the user may enable two of them. The rest sit in the config forever as disabled
entries. A discovery cache records when each address was last seen, so a target
that has not been seen for weeks can be offered for removal instead of silently
rotting.
"""

import json
import time

from . import model
from .config import (
    DISCOVERY_CACHE_PATH,
    collect_all_configs,
    collect_config_paths,
    load_config,
)
from .targets import DEFAULT_PRUNED_AFTER_DAYS, normalize_targets, valid_local_target

# Why a target is being offered for removal.
REASON_NEVER_SEEN = "never-seen"
REASON_STALE = "stale"
REASON_DISABLED_INVALID = "invalid"
REASON_DUPLICATE = "duplicate"


def _route_key(destination, family, table):
    return (int(family), str(destination), str(table))


def _owned_routes(backend, table, family):
    """Routes in *table* that this tool installed (``proto`` stamp matches)."""
    owned = []
    for entry in backend.routes(table=table, family=family):
        if entry.get("owned") or entry.get("protocol") in {
            model.ROUTE_PROTOCOL_NAME,
            str(model.ROUTE_PROTOCOL),
        }:
            owned.append(entry)
    return owned


def analyze_routes(backend, configs):
    """Find routes and rules left over from targets that no longer exist.

    ``configs`` is ``[(path, Config), ...]``. Returns a dict with ``routes``,
    ``rules`` and ``keep`` plus the table that was inspected.
    """
    tables = set()
    for _path, config in configs:
        tables.add(str(config.rule_table) if config.policy_routing else "main")

    keep = set()
    for _path, config in configs:
        table = str(config.rule_table) if config.policy_routing else "main"
        for target in config.targets:
            if not target.get("enabled") or not valid_local_target(target.get("address", "")):
                continue
            try:
                family, destination = model.normalize_destination(target["address"])
            except ValueError:
                continue
            keep.add(_route_key(destination, family, table))

    stale_routes = []
    for table in sorted(tables):
        for family in (4, 6):
            for entry in _owned_routes(backend, table, family):
                prefix = str(entry["prefix"])
                if _route_key(prefix, family, table) in keep:
                    continue
                stale_routes.append(
                    {
                        "kind": "route",
                        "destination": prefix,
                        "family": family,
                        "table": table,
                        # Carrying the interface makes the delete target exactly
                        # the entry that was listed, not "some route for this
                        # prefix" if the table happens to hold more than one.
                        "interface": str(entry.get("interface") or ""),
                        "label": f"{prefix}（表 {table}）",
                    }
                )
            if table == "main":
                continue
            for rule in backend.rules(family=family):
                if str(rule.get("lookup")) != table:
                    continue
                selector = str(rule.get("to") or "").strip()
                if not selector:
                    continue
                try:
                    destination = model.normalize_destination(selector)[1]
                except ValueError:
                    continue
                if _route_key(destination, family, table) in keep:
                    continue
                stale_routes.append(
                    {
                        "kind": "rule",
                        "destination": destination,
                        "family": family,
                        "table": table,
                        "preference": rule.get("pref"),
                        "label": f"ip rule {destination} → 表 {table}",
                    }
                )
    return {
        "tables": sorted(tables),
        "keep": sorted(keep),
        "routes": stale_routes,
        "count": len(stale_routes),
    }


def read_discovery_cache(path=None):
    """Addresses seen on the LAN, with the last time each was observed."""
    cache_path = path or DISCOVERY_CACHE_PATH
    try:
        with open(cache_path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    seen = data.get("seen") if isinstance(data, dict) else None
    if not isinstance(seen, dict):
        return {}
    cleaned = {}
    for address, timestamp in seen.items():
        try:
            cleaned[str(address)] = float(timestamp)
        except (TypeError, ValueError):
            continue
    return cleaned


def update_discovery_cache(addresses, path=None, now=None):
    """Record that *addresses* were just seen. Returns the merged cache."""
    cache_path = path or DISCOVERY_CACHE_PATH
    now = time.time() if now is None else now
    seen = read_discovery_cache(cache_path)
    for address in addresses:
        address = str(address or "").strip()
        if address:
            seen[address] = now
    payload = {"version": 1, "updated_at": now, "seen": seen}
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = cache_path.with_name(cache_path.name + ".tmp")
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        temporary.replace(cache_path)
    except OSError:
        pass
    return seen


def analyze_targets(config, discovery=None, now=None, pruned_after_days=None):
    """Offer disabled targets for removal, with a reason for each.

    Only *disabled* targets are ever offered: an enabled one is a deliberate
    choice, no matter how long it has been offline. This is the difference
    between garbage collection and second-guessing the user.
    """
    discovery = read_discovery_cache() if discovery is None else discovery
    now = time.time() if now is None else now
    days = (
        DEFAULT_PRUNED_AFTER_DAYS
        if pruned_after_days is None
        else float(pruned_after_days)
    )
    threshold = days * 86400

    candidates = []
    seen_addresses = set()
    for target in config.targets:
        address = str(target.get("address", "")).strip()
        if target.get("enabled"):
            continue
        if not valid_local_target(address):
            candidates.append(
                {
                    "kind": "target",
                    "address": address,
                    "name": target.get("name") or address,
                    "reason": REASON_DISABLED_INVALID,
                    "detail": "地址已不再合法（可能被手工改坏）",
                }
            )
            continue
        if address in seen_addresses:
            candidates.append(
                {
                    "kind": "target",
                    "address": address,
                    "name": target.get("name") or address,
                    "reason": REASON_DUPLICATE,
                    "detail": "配置文件里有重复条目",
                }
            )
            continue
        seen_addresses.add(address)

        last_seen = discovery.get(address)
        if last_seen is None:
            candidates.append(
                {
                    "kind": "target",
                    "address": address,
                    "name": target.get("name") or address,
                    "reason": REASON_NEVER_SEEN,
                    "detail": "扫描记录里从未出现过这个地址",
                }
            )
            continue
        age = now - float(last_seen)
        if age > threshold:
            candidates.append(
                {
                    "kind": "target",
                    "address": address,
                    "name": target.get("name") or address,
                    "reason": REASON_STALE,
                    "age_days": round(age / 86400, 1),
                    "detail": f"已停用，且 {age / 86400:.0f} 天没有在局域网里出现过",
                }
            )
    return {
        "candidates": candidates,
        "count": len(candidates),
        "pruned_after_days": days,
    }


def keep_configs(config_paths=None):
    """Configs whose enabled targets must protect their routes from pruning.

    Always contains every *discovered* config, plus any explicitly named path.
    That union is what makes ``prune --config system.json`` safe: the report and
    the deletion both start from the same (possibly wider) keep-set, so a
    narrower ``--config`` can never make another config's live route look like
    residue.
    """
    configs = list(collect_all_configs())
    known = {str(path) for path, _config in configs}
    for path in config_paths or ():
        if str(path) not in known:
            configs.append((path, load_config(path)))
            known.add(str(path))
    return configs


def analyze(backend=None, config_paths=None, prune_days=None, discovery=None):
    """Everything that can be cleaned up, right now.

    *config_paths* scopes which config files **target** cleanup looks at (the
    GUI passes none and then filters to its own file; ``prune --config`` passes
    exactly one). Route ownership is deliberately *not* scoped that way; see
    :func:`keep_configs`.
    """
    from .backends import get_backend
    from .config import CONFIG_PATH

    backend = backend or get_backend()
    paths = list(config_paths) if config_paths is not None else collect_config_paths()
    if not paths:
        # Always describe the user's own config, even before it exists, so the
        # GUI can show an empty state rather than an error.
        paths = [CONFIG_PATH]
    configs = [(path, load_config(path)) for path in paths]

    routes = analyze_routes(backend, keep_configs(paths))
    targets = []
    for path, config in configs:
        result = analyze_targets(
            config, discovery=discovery, pruned_after_days=prune_days
        )
        for candidate in result["candidates"]:
            candidate["config"] = str(path)
        targets.append({"path": str(path), **result})
    total = routes["count"] + sum(item["count"] for item in targets)
    return {
        "routes": routes,
        "targets": targets,
        "count": total,
        "prune_after_days": (
            DEFAULT_PRUNED_AFTER_DAYS if prune_days is None else prune_days
        ),
    }


def prune_routes(backend, configs, dry_run=False):
    """Remove leftover routes and rules. Returns an outcome summary.

    A backend mutation that returns a false value did *not* remove anything
    (the kernel refused the request, or the entry was already gone between the
    scan and the delete). That counts as a failure rather than a success, so
    the CLI can exit non-zero and the GUI can explain what to do about it.
    """
    plan = analyze_routes(backend, configs)
    removed = []
    failed = []
    for item in plan["routes"]:
        if dry_run:
            removed.append(item["label"])
            continue
        try:
            if item["kind"] == "route":
                changed = backend.remove_route(
                    {
                        "destination": item["destination"],
                        "interface": item.get("interface", ""),
                        "family": item["family"],
                        "table": item["table"],
                    }
                )
            else:
                changed = backend.remove_rule(
                    item["destination"], item["table"], family=item["family"]
                )
        except Exception as exception:  # noqa: BLE001 - reported, never fatal
            failed.append(f"{item['label']}：{exception}")
            continue
        if not changed:
            failed.append(f"{item['label']}：内核没有删除（条目已不存在，或需要管理员权限）")
            continue
        removed.append(item["label"])
    return {
        "dry_run": dry_run,
        "removed": removed,
        "removed_count": len(removed),
        "failed": failed,
        "failed_count": len(failed),
        "ok": not failed,
    }


def prune_targets(config, candidates, save=True):
    """Drop the given target addresses from *config*."""
    addresses = {
        str(candidate.get("address", "")).strip()
        for candidate in candidates
        if str(candidate.get("address", "")).strip()
    }
    if not addresses:
        return {"removed": [], "removed_count": 0, "saved": True}
    before = len(config.targets)
    kept = [
        target
        for target in config.targets
        if str(target.get("address", "")).strip() not in addresses
    ]
    config.data["targets"] = normalize_targets(kept)
    saved = config.save() if save else True
    removed = sorted(addresses)
    return {
        "removed": removed,
        "removed_count": before - len(config.targets),
        "saved": saved,
    }
