"""Platform-independent data model shared by every backend.

Nothing in this module imports a platform specific module, touches the file
system or shells out. Keeping the model pure is what makes the reconciliation
engine in :mod:`lanrf.reconcile` reusable on Linux, Windows and in tests.
"""

import ipaddress

# Protocol number stamped on host routes installed by this tool. Linux accepts
# any value in 0..255 for `proto`; using a dedicated value means our routes can
# be told apart from kernel/DHCP/VPN routes and garbage collected safely.
#
# The numeric form is what `ip route add ... proto 66` needs: iproute2 only
# accepts protocol *names* it knows (boot, static, ra, dhcp, ...) and rejects
# anything else, but it accepts the raw number.
ROUTE_PROTOCOL = 66
ROUTE_PROTOCOL_NAME = "lanrf"

# Prefix length used when a target is a bare address instead of a CIDR.
DEFAULT_PREFIXLEN = {4: 32, 6: 128}

ROUTE_STATE_UNKNOWN = "unknown"
ROUTE_STATE_OK = "ok"
ROUTE_STATE_MISSING = "missing"
ROUTE_STATE_WRONG_INTERFACE = "wrong-interface"
ROUTE_STATE_INVALID = "invalid"


def route_entry(prefix, interface, family, table, protocol="", source="", metric=None, scope=""):
    """A single entry read back from the routing table."""
    protocol_text = str(protocol or "")
    return {
        "prefix": str(prefix),
        "interface": str(interface or ""),
        "family": int(family),
        "table": str(table),
        "protocol": protocol_text,
        "source": str(source or ""),
        "metric": metric,
        "scope": str(scope or ""),
        "owned": protocol_text in {ROUTE_PROTOCOL_NAME, str(ROUTE_PROTOCOL)},
    }


def protocol_argument(protocol=None):
    """``ip`` command-line value for a route protocol."""
    value = str(protocol or "").strip()
    if not value:
        return str(ROUTE_PROTOCOL)
    if value == ROUTE_PROTOCOL_NAME:
        return str(ROUTE_PROTOCOL)
    return value


def normalize_destination(value):
    """Return ``(family, "address/prefix")`` for an address or CIDR string.

    Raises ``ValueError`` when the input is not an IP address or network.
    """
    text = str(value or "").strip()
    if not text:
        raise ValueError("empty destination")
    if "/" in text:
        parsed = ipaddress.ip_interface(text)
        return parsed.version, f"{parsed.ip}/{parsed.network.prefixlen}"
    parsed = ipaddress.ip_address(text)
    return parsed.version, f"{parsed}/{DEFAULT_PREFIXLEN[parsed.version]}"


def destination_index(prefix):
    """Return the first address of a prefix, used to test containment."""
    return ipaddress.ip_network(str(prefix), strict=False).network_address


def prefix_covers(prefix, candidate):
    """True when *prefix* is equal to or broader than *candidate*.

    ``192.168.4.0/24`` covers ``192.168.4.234/32``; the reverse is not true.
    Both values must be the same IP family, otherwise the answer is False.
    """
    try:
        outer = ipaddress.ip_network(str(prefix), strict=False)
        inner = ipaddress.ip_network(str(candidate), strict=False)
    except ValueError:
        return False
    if outer.version != inner.version:
        return False
    return inner.subnet_of(outer)


def target_uid(target):
    """Stable identity of a configured target, independent of its label."""
    address = str(target.get("address", "")).strip()
    try:
        family, destination = normalize_destination(address)
    except ValueError:
        return address
    return destination


def rule_matches(rule, destination=None, table=None):
    """True when a policy rule selects *destination* from *table*.

    The comparison must be semantic, not textual: ``ip rule show`` prints a
    host rule as ``to 192.168.4.19`` even though it was added as
    ``to 192.168.4.19/32``. Comparing the raw strings makes the tool believe its
    own rule is missing, so it reinstalls it on every pass and reports the
    target as broken forever.

    ``destination=None`` matches a rule with no destination selector at all
    (a whole-table rule); a rule that *has* a selector never matches it.
    """
    if table is not None and str(rule.get("lookup")) != str(table):
        return False
    selector = str(rule.get("to") or "").strip()
    if destination is None:
        return not selector
    if not selector:
        return False
    try:
        return ipaddress.ip_network(selector, strict=False) == ipaddress.ip_network(
            str(destination), strict=False
        )
    except ValueError:
        return selector == str(destination)


def target_route_item(target, interface, table="main", source=""):
    """Build a backend-agnostic route request from a target and an interface."""
    family, destination = normalize_destination(target.get("address", ""))
    return {
        "destination": destination,
        "family": family,
        "interface": str(interface),
        "table": str(table),
        "protocol": ROUTE_PROTOCOL_NAME,
        "source": str(source or ""),
        "metric": None,
    }
