"""Target parsing, validation and normalisation.

Pure logic: no subprocesses, no files. Also hosts the discovery result shape so
the CLI, the GUI and the reconciler agree on what a target is.
"""

import ipaddress

# Neighbour states that mean "we have a usable L2 entry for this host".
NEIGH_VALID_STATES = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"}

PRIVATE_V4_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
ULA_V6_NETWORK = ipaddress.ip_network("fc00::/7")
LINK_LOCAL_V4 = ipaddress.ip_network("169.254.0.0/16")


def parse_ip_or_cidr(value):
    """Return ``(family, address, prefix)`` for an IPv4/IPv6 address or CIDR.

    For a bare address, prefix is 32 (v4) or 128 (v6). Returns ``None`` when the
    text is not a valid address or network.
    """
    text = str(value or "").strip()
    if "/" in text:
        try:
            interface = ipaddress.ip_interface(text)
        except ValueError:
            return None
        return interface.version, str(interface.ip), interface.network.prefixlen
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    return address.version, str(address), 32 if address.version == 4 else 128


def valid_private_ipv4(value):
    try:
        address = ipaddress.IPv4Address(str(value).strip())
    except (ipaddress.AddressValueError, ValueError):
        return False
    return any(
        address in network
        for network in (*PRIVATE_V4_NETWORKS, LINK_LOCAL_V4)
    )


def valid_private_ipv6(value):
    try:
        address = ipaddress.IPv6Address(str(value).strip())
    except (ipaddress.AddressValueError, ValueError):
        return False
    # ULA and link-local are the reasonable "local" IPv6 families for this tool.
    return address in ULA_V6_NETWORK or address.is_link_local


def valid_local_target(value):
    """True when *value* is a private/local address or CIDR."""
    parsed = parse_ip_or_cidr(value)
    if not parsed:
        return False
    family, address, prefix = parsed
    if family == 4:
        try:
            network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
        except ValueError:
            return False
        # Both ends of the range must be private: a CIDR such as
        # 192.168.0.0/8 would otherwise smuggle public space into the helper.
        return valid_private_ipv4(network.network_address) and valid_private_ipv4(
            network.broadcast_address
        )
    return valid_private_ipv6(address)


def family_of(value):
    parsed = parse_ip_or_cidr(value)
    return parsed[0] if parsed else None


def normalize_targets(targets):
    """Normalise and deduplicate a list of user/saved target dicts."""
    normalized = []
    seen = set()
    if not isinstance(targets, list):
        return normalized
    for target in targets:
        if not isinstance(target, dict):
            continue
        address = str(target.get("address", "") or target.get("ip", "")).strip()
        if not address or address in seen:
            continue
        seen.add(address)
        entry = {
            "name": str(target.get("name", "")).strip() or address,
            "address": address,
            "interface": str(target.get("interface", "")).strip(),
            "enabled": bool(target.get("enabled", False)),
        }
        # Per-target override: install a route covering the whole local subnet
        # instead of a single host. Useful when a VPN client re-fragments the
        # subnet and neighbouring addresses come and go (see README).
        if target.get("expand"):
            entry["expand"] = True
        normalized.append(entry)
    return normalized


def find_target_indices(targets, query):
    """Indexes of targets matching an address or a (case-insensitive) name.

    Accepts either a list of target dicts or a config dict containing them, so
    the historical ``core._find_target_indices(config, query)`` call signature
    keeps working.
    """
    if isinstance(targets, dict):
        targets = targets.get("targets", [])
    query = str(query or "").strip()
    indices = []
    for index, target in enumerate(targets or []):
        if not isinstance(target, dict):
            continue
        if str(target.get("address", "")).strip() == query or (
            str(target.get("name", "")).strip().lower() == query.lower()
        ):
            indices.append(index)
    return indices


def normalize_interface_arg(value):
    interface = str(value or "").strip()
    return "" if interface.lower() in {"auto", "-", "none"} else interface
