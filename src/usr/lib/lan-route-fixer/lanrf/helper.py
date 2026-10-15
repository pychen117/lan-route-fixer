"""Privileged helper logic.

This module is the *inside* of the trust boundary: it runs as root (through
pkexec or directly under systemd) and therefore treats every input as hostile.

Invariants that must never regress:

* only private/local IPv4 and ULA/link-local IPv6 destinations are accepted;
* only non-tunnel, existing interfaces are accepted;
* the routing table defaults to ``main`` and is validated when supplied;
* the only kernel mutations are ``ip route replace`` and ``ip rule add/del``
  restricted to the configured table. No flush, no arbitrary command, no shell.
"""

import json
import os
import re
import sys

from . import model
from .backends import get_backend
from .config import DEFAULT_CONFIG, Config
from .targets import valid_local_target

EXIT_OK = 0
EXIT_INVALID = 64
EXIT_FAILED = 65

INTERFACE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,14}")

# Tables the helper refuses to touch. 253/254/255 are default/main/local.
PROTECTED_TABLES = {"local": 255, "main": 254, "default": 253}


class ValidationError(Exception):
    """Raised when a request is outside what the helper is allowed to do."""


class RouteFailure(Exception):
    """Raised when the kernel refuses a route or rule change."""


def validate_table(value):
    """Return a safe routing table name or number."""
    if value in (None, ""):
        return "main"
    text = str(value).strip()
    if text in PROTECTED_TABLES:
        return text
    if text.isdigit():
        number = int(text)
        if number < 1 or number > 252:
            raise ValidationError(f"routing table out of range: {text}")
        return str(number)
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,14}", text):
        # Named tables beyond main/default are resolved by iproute2 from
        # /etc/iproute2/rt_tables; refuse the ones we cannot validate.
        if text in {"local", "main", "default"}:
            return text
        raise ValidationError(f"named routing table not supported: {text}")
    raise ValidationError(f"invalid routing table: {text}")


def validate_interface(interface, backend=None):
    backend = backend or get_backend()
    text = str(interface or "")
    if not INTERFACE_PATTERN.fullmatch(text):
        raise ValidationError(f"invalid interface name: {text!r}")
    if text == "lo":
        raise ValidationError("refusing loopback interface")
    if not backend.is_usable(text):
        kind = backend.link_kind(text)
        if kind:
            raise ValidationError(f"refusing non-LAN interface: {text} ({kind})")
        raise ValidationError(f"interface is not a usable LAN device: {text}")
    return text


def validate_destination(address):
    text = str(address or "").strip()
    if not valid_local_target(text):
        raise ValidationError(f"destination must be a private/local address: {text}")
    return model.normalize_destination(text)


def normalize_item(raw):
    """Validate one route/rule request and return a backend-ready item."""
    if not isinstance(raw, dict):
        raise ValidationError("each item must be a JSON object")
    address = raw.get("address") or raw.get("destination")
    interface = raw.get("interface")
    if not address or not interface:
        raise ValidationError("each item requires address and interface")

    family, destination = validate_destination(address)
    declared_family = raw.get("family")
    if declared_family is not None and int(declared_family) != family:
        raise ValidationError(
            f"family mismatch for {destination}: declared {declared_family}, is {family}"
        )
    table = validate_table(raw.get("table"))
    return {
        "destination": destination,
        "family": family,
        "interface": validate_interface(interface),
        "table": table,
        "protocol": str(raw.get("protocol") or model.ROUTE_PROTOCOL_NAME),
        "source": str(raw.get("source") or ""),
        "metric": None,
    }


def apply_batch(items, config=None, backend=None):
    """Apply validated items. Returns ``(applied, errors)``.

    ``config`` enables the policy-routing layer: when the caller's config asks
    for ``routing_mode = "rule"``, a matching high-priority rule is installed
    before the route so a VPN client rewriting the main table cannot capture
    the destination.
    """
    backend = backend or get_backend()
    if not isinstance(items, list):
        raise ValidationError("JSON input must be an array")

    config = config or Config(dict(DEFAULT_CONFIG))
    use_rules = bool(config.policy_routing and backend.supports_policy_rules)
    applied = []
    errors = []
    for raw in items:
        try:
            item = normalize_item(raw)
        except ValidationError as exception:
            errors.append(str(exception))
            continue
        try:
            rule_changed = False
            if use_rules and item["table"] != "main":
                rule_changed, _detail = backend.ensure_rule(
                    item["destination"],
                    item["table"],
                    family=item["family"],
                    preference=config.rule_preference,
                )
            route_changed, _detail = backend.ensure_route(item)
        except Exception as exception:  # noqa: BLE001 - surfaced to the caller
            errors.append(f"{item['destination']}: {exception}")
            continue
        applied.append(
            {
                "destination": item["destination"],
                "interface": item["interface"],
                "table": item["table"],
                "family": item["family"],
                "changed": bool(rule_changed or route_changed),
                "rule": bool(use_rules and item["table"] != "main"),
            }
        )
    return applied, errors


def apply_single(address, interface, table="main", config=None, backend=None):
    applied, errors = apply_batch(
        [{"address": address, "interface": interface, "table": table}],
        config=config,
        backend=backend,
    )
    if errors:
        raise RouteFailure("; ".join(errors))
    if not applied:  # pragma: no cover - defensive
        raise RouteFailure("nothing was applied")
    return applied[0]


def main(argv=None):
    """Entry point of the ``lan-route-helper`` executable."""
    args = list(sys.argv[1:] if argv is None else argv)

    def fail(message, code=EXIT_INVALID):
        print(f"lan-route-helper: {message}", file=sys.stderr)
        return code

    if args and args[0] == "--batch-json":
        if len(args) != 2:
            return fail("usage: lan-route-helper --batch-json <json-array>")
        try:
            items = json.loads(args[1])
        except json.JSONDecodeError as exception:
            return fail(f"invalid JSON argument: {exception}")
        return _emit(items)

    if args and args[0] == "--batch":
        try:
            items = json.load(sys.stdin)
        except json.JSONDecodeError as exception:
            return fail(f"stdin is not valid JSON: {exception}")
        return _emit(items)

    if len(args) == 2 and not args[0].startswith("-"):
        try:
            result = apply_single(args[0], args[1])
        except ValidationError as exception:
            return fail(str(exception))
        except RouteFailure as exception:
            return fail(str(exception), EXIT_FAILED)
        print(f"{result['destination']} dev {result['interface']}")
        return EXIT_OK

    return fail(
        "usage: lan-route-helper <address> <interface> | "
        "lan-route-helper --batch-json <json-array> | "
        "lan-route-helper --batch"
    )


def _emit(items):
    try:
        applied, errors = apply_batch(items)
    except ValidationError as exception:
        print(f"lan-route-helper: {exception}", file=sys.stderr)
        return EXIT_INVALID
    if errors:
        print(f"lan-route-helper: {'; '.join(errors)}", file=sys.stderr)
    print(json.dumps(applied, ensure_ascii=False))
    return EXIT_OK if not errors else EXIT_FAILED


if __name__ == "__main__":  # pragma: no cover - executed as a script
    raise SystemExit(main())


def require_root():
    """Raise when not running with the privileges the helper needs."""
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() != 0:
        raise PermissionError("lan-route-helper must run as root")
