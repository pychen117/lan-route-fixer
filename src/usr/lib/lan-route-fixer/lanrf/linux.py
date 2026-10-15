"""Linux network backend.

Every platform specific detail lives here: the ``ip`` binary, ``sysfs`` link
classification and policy routing tables. The rest of the package only sees the
small protocol defined in :mod:`lanrf.backends`.

Nothing in this module is exposed to the GUI; it is imported by the CLI, the
privileged helper and the reconciler.
"""

import ipaddress
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from . import netlink, model

IP_PATH = os.environ.get("LAN_ROUTE_FIXER_IP") or shutil.which("ip") or "/usr/sbin/ip"

SYS_CLASS_NET = Path(os.environ.get("LAN_ROUTE_FIXER_SYS_CLASS_NET", "/sys/class/net"))

# Prefixes of tunnel interfaces. This is a fast heuristic; the authoritative
# check is the link kind reported by `ip -d link show`.
VIRTUAL_INTERFACE_PREFIXES = (
    "utun",
    "tun",
    "tap",
    "tailscale",
    "wg",
    "ppp",
    "ipsec",
    "ovpn",
    "zerotier",
    "gpd",
    "proton",
    "mullvad",
    "surfshark",
)

VIRTUAL_LINK_KINDS = {
    "tun",
    "tap",
    "wireguard",
    "veth",
    "dummy",
    "sit",
    "ipip",
    "gre",
    "vti",
    "ip6tnl",
    "macvlan",
    "ipvlan",
    "openvpn",
    "ppp",
    "ifb",
    "xfrm",
    "nlmon",
    "6lowpan",
    "lowpan",
}

# Link kinds that are virtual but are still valid L2 exits on many machines.
TRUSTED_LINK_KINDS = {"bridge", "bond", "vlan"}

LINK_KIND_PATTERN = re.compile(
    r"\b(wireguard|tun|tap|veth|bridge|bond|vlan|dummy|sit|ipip|gre|vti|ip6tnl"
    r"|macvlan|ipvlan|openvpn|ppp|ifb|xfrm|nlmon|6lowpan|lowpan)\b",
    re.IGNORECASE,
)

# Keywords that may appear inside an `ip route show` entry.
_ROUTE_KEYWORDS = {
    "via",
    "dev",
    "src",
    "metric",
    "proto",
    "scope",
    "table",
    "pref",
    "realm",
    "mtu",
    "advmss",
    "hoplimit",
    "onlink",
    "linkdown",
    "expires",
    "error",
    "cache",
    "uid",
    "l3mdev",
    "nexthop",
    "protoinfo",
    "ecn",
    "quickack",
    "congctl",
    "fastopen_no_cookie",
    "from",
    "to",
    "iif",
    "oif",
    "mark",
    "suppress_prefixlength",
    "suppress_ifgroup",
    "lookup",
    "blackhole",
    "unreachable",
    "prohibit",
    "throw",
}

_ROUTE_KV_PATTERN = re.compile(r"(?P<key>[a-z_]+)\s+(?P<value>[^ ]+)")


def run_ip(*args, timeout=5):
    """Run ``ip`` and return ``(stdout, stderr, returncode)``.

    A missing binary or a timeout is reported as returncode ``-1`` with the
    exception text in stderr so callers can surface a useful reason.
    """
    try:
        result = subprocess.run(
            [IP_PATH, *[str(arg) for arg in args]],
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exception:
        return "", str(exception), -1
    return result.stdout, result.stderr.strip(), result.returncode


def run_ip_ok(*args, timeout=5):
    """Run ``ip`` and return its stdout, or None when it failed."""
    stdout, _stderr, returncode = run_ip(*args, timeout=timeout)
    return stdout if returncode == 0 else None


# --- link classification ----------------------------------------------------


def get_link_info():
    """Return ``{interface: {"kind", "up", "running", "carrier"}}``.

    ``up`` is the administrative flag (IFF_UP). ``running`` additionally
    requires the link to be usable -- LOWER_UP and an operstate other than
    ``down`` -- which is what distinguishes a real LAN exit from the many
    bridged/tunnel devices that are administratively up but carry no traffic
    (``docker0`` with no containers is the classic example).
    """
    output = run_ip_ok("-d", "-o", "link", "show")
    if not output:
        return {}
    info = {}
    for line in output.splitlines():
        match = re.match(r"^\d+:\s+([^:@]+)(?:@\S+)?:\s+<([^>]*)>", line)
        if not match:
            continue
        interface = match.group(1).strip()
        flags = {flag.upper() for flag in match.group(2).split(",")}
        kind_match = LINK_KIND_PATTERN.search(line)
        kind = (kind_match.group(1) if kind_match else "").lower()
        state_match = re.search(r"\bstate\s+(\S+)", line)
        operstate = (state_match.group(1) if state_match else "").lower()
        info[interface] = {
            "kind": kind,
            "up": "UP" in flags,
            "running": "UP" in flags and "LOWER_UP" in flags and operstate != "down",
            "carrier": "LOWER_UP" in flags,
            "state": operstate,
        }
    return info


def get_link_kind(interface):
    return get_link_info().get(interface, {}).get("kind", "")


def is_virtual_interface(interface, kind=""):
    lower = str(interface).lower()
    if lower.startswith(VIRTUAL_INTERFACE_PREFIXES):
        return True
    return str(kind).lower() in VIRTUAL_LINK_KINDS


def is_usable_interface(interface, kind="", link_info=None):
    """A non-loopback interface that is safe to use as a LAN exit."""
    interface = str(interface or "")
    if not interface or interface == "lo":
        return False
    if is_virtual_interface(interface, kind):
        return False
    # Normal physical NICs expose a device symlink; bridges/bonds/VLANs are
    # virtual but common LAN exits, so they are allowed explicitly.
    if (SYS_CLASS_NET / interface / "device").exists():
        return True
    return str(kind).lower() in TRUSTED_LINK_KINDS


def list_usable_interfaces(only_up=False):
    interfaces = []
    for interface, details in get_link_info().items():
        if not is_usable_interface(interface, details["kind"]):
            continue
        if only_up and not details.get("running", details["up"]):
            continue
        if interface not in interfaces:
            interfaces.append(interface)
    return interfaces


def get_local_networks(family=4):
    """Return ``[(interface, network, address), ...]`` for usable interfaces."""
    output = run_ip_ok(f"-{family}", "-o", "addr", "show", "scope", "global")
    if not output:
        return []
    link_info = get_link_info()
    networks = []
    for line in output.splitlines():
        fields = line.split()
        if "inet" not in fields and "inet6" not in fields:
            continue
        keyword = "inet" if "inet" in fields else "inet6"
        index = fields.index(keyword)
        if index < 1 or index + 1 >= len(fields):
            continue
        interface = fields[index - 1].split("@", 1)[0]
        try:
            interface_address = ipaddress.ip_interface(fields[index + 1])
        except ValueError:
            continue
        details = link_info.get(interface, {})
        if not is_usable_interface(interface, details.get("kind", "")):
            continue
        networks.append((interface, interface_address.network, interface_address.ip))
    return networks


def get_default_interfaces():
    """Usable interfaces owning a default route, best metric first."""
    output = run_ip_ok("-4", "-o", "route", "show", "default")
    if not output:
        return []
    link_info = get_link_info()
    candidates = []
    seen = set()
    for line in output.splitlines():
        match = re.search(r"\bdev\s+(\S+)", line)
        if not match:
            continue
        interface = match.group(1).split("@", 1)[0]
        if interface in seen:
            continue
        if not is_usable_interface(interface, link_info.get(interface, {}).get("kind", "")):
            continue
        metric_match = re.search(r"\bmetric\s+(\d+)", line)
        metric = int(metric_match.group(1)) if metric_match else 0
        seen.add(interface)
        candidates.append((metric, interface))
    return [interface for _metric, interface in sorted(candidates)]


# --- neighbour discovery ----------------------------------------------------


def parse_neighbours(output):
    """Parse ``ip -4 neigh show`` output into target dicts."""
    from .targets import NEIGH_VALID_STATES  # local import avoids a cycle

    link_info = get_link_info()
    discovered = []
    seen = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 4 or "dev" not in fields:
            continue
        address = fields[0]
        dev_index = fields.index("dev") + 1
        if dev_index >= len(fields):
            continue
        interface = fields[dev_index].split("@", 1)[0]
        state = next(
            (field.upper() for field in fields if field.upper() in NEIGH_VALID_STATES),
            "",
        )
        if address in seen or not state:
            continue
        if not is_usable_interface(interface, link_info.get(interface, {}).get("kind", "")):
            continue
        seen.add(address)
        mac = ""
        if "lladdr" in fields:
            lladdr_index = fields.index("lladdr") + 1
            if lladdr_index < len(fields):
                mac = fields[lladdr_index]
        discovered.append(
            {
                "name": address,
                "address": address,
                "family": 4,
                "interface": interface,
                "mac": mac,
                "state": state,
            }
        )
    return discovered


# --- route and rule parsing -------------------------------------------------


def parse_route_entry(line, default_table="main"):
    """Parse one ``ip -o route show`` line into a :func:`model.route_entry`."""
    text = line.strip()
    if not text:
        return None
    fields = text.split()
    if not fields:
        return None

    table = default_table
    # `ip -o` prints "192.168.1.0/24 dev eth0 table main ..." with the table
    # keyword inline; `ip route show table X -o` omits it.
    values = {}
    index = 1
    while index < len(fields):
        token = fields[index]
        if token in _ROUTE_KEYWORDS and index + 1 < len(fields):
            if token in values:
                index += 1
                continue
            values[token] = fields[index + 1]
            index += 2
            continue
        index += 1

    destination = fields[0]
    if destination in {"default", "unreachable", "blackhole", "prohibit", "throw"}:
        family = 4
        destination = "0.0.0.0/0"
    else:
        try:
            network = ipaddress.ip_network(destination, strict=False)
        except ValueError:
            return None
        family = network.version
        destination = str(network)

    if "table" in values:
        table = values["table"]
    metric = None
    if "metric" in values:
        try:
            metric = int(values["metric"])
        except ValueError:
            metric = None
    return model.route_entry(
        prefix=destination,
        interface=values.get("dev", ""),
        family=family,
        table=table,
        protocol=values.get("proto", ""),
        source=values.get("src", ""),
        metric=metric,
        scope=values.get("scope", ""),
    )


def parse_route_dump(output, default_table="main"):
    entries = []
    for line in output.splitlines():
        entry = parse_route_entry(line, default_table=default_table)
        if entry is not None:
            entries.append(entry)
    return entries


def parse_rule_entry(line):
    """Parse one ``ip -o rule show`` line into a dict.

    Example::

        1200:   from all to 192.168.4.234/32 lookup 168
    """
    text = line.strip()
    if not text:
        return None
    pref_match = re.match(r"^(\d+):\s*(.*)$", text)
    if not pref_match:
        return None
    preference = int(pref_match.group(1))
    rest = pref_match.group(2)

    rule = {
        "pref": preference,
        "from": "",
        "to": "",
        "fwmark": "",
        "iif": "",
        "oif": "",
        "lookup": "",
        "action": "",
        "raw": text,
    }
    tokens = rest.split()
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in {"from", "to", "lookup", "iif", "oif", "fwmark"} and index + 1 < len(tokens):
            value = tokens[index + 1]
            if token == "lookup":
                rule["lookup"] = value
            else:
                rule[token] = value
            index += 2
            continue
        if token in {"unreachable", "blackhole", "prohibit", "throw"}:
            rule["action"] = token
            index += 1
            continue
        index += 1
    return rule


def parse_rule_dump(output):
    rules = []
    for line in output.splitlines():
        rule = parse_rule_entry(line)
        if rule is not None:
            rules.append(rule)
    return rules


# --- backend ----------------------------------------------------------------


class LinuxBackend:
    """Concrete :class:`lanrf.backends.NetworkBackend` for Linux."""

    name = "linux"
    supports_policy_rules = True
    supports_events = netlink.available()

    def __init__(self):
        self._link_info_cache = None
        # Whether *this process* may change routes. Used to distinguish "the
        # route is fine" from "the route is fine but we cannot touch it".
        geteuid = getattr(os, "geteuid", None)
        self.is_privileged = bool(geteuid is None or geteuid() == 0)

    @property
    def privileges_note(self):
        if self.is_privileged:
            return "root"
        return "unprivileged: route changes require pkexec or the root daemon"

    # -- queries ------------------------------------------------------------

    def _link_info(self, refresh=False):
        if refresh or self._link_info_cache is None:
            self._link_info_cache = get_link_info()
        return self._link_info_cache

    def invalidate(self):
        self._link_info_cache = None

    def link_kind(self, interface):
        return self._link_info().get(interface, {}).get("kind", "")

    def is_usable(self, interface):
        return is_usable_interface(interface, self.link_kind(interface))

    def list_interfaces(self, only_up=False):
        interfaces = []
        for interface, details in self._link_info().items():
            if not is_usable_interface(interface, details["kind"]):
                continue
            if only_up and not details.get("running", details["up"]):
                continue
            interfaces.append(interface)
        return interfaces

    def local_networks(self, family=4):
        return get_local_networks(family)

    def default_interfaces(self):
        return get_default_interfaces()

    def route_lookup(self, destination, family=4, table=None, fallback=True):
        """Interface currently used for *destination*.

        ``table``/``fallback`` exist because ``ip route get ... table all`` can
        only be used by root: an unprivileged caller asks for a specific table,
        and the fallback pass lets the caller infer "the table is empty" by
        comparing a table-less lookup with the table-specific one.
        """
        command = [f"-{family}", "route", "get", str(destination)]
        if table and table != "all":
            command += ["table", str(table)]
        stdout, _stderr, returncode = run_ip(*command)
        if returncode != 0 or not stdout:
            return None
        first = stdout.splitlines()[0]
        dev_match = re.search(r"\bdev\s+(\S+)", first)
        via_match = re.search(r"\bvia\s+(\S+)", first)
        src_match = re.search(r"\bsrc\s+(\S+)", first)
        table_match = re.search(r"\btable\s+(\S+)", first)
        entry = {
            "interface": dev_match.group(1).split("@", 1)[0] if dev_match else "",
            "gateway": via_match.group(1) if via_match else "",
            "source": src_match.group(1) if src_match else "",
            "table": table_match.group(1) if table_match else "",
            "requested_table": str(table) if table else "",
            "fallback": bool(fallback),
        }
        if table and table != "all" and not entry["table"]:
            # The kernel did not name a table, so we cannot tell whether our
            # rule matched or main did.
            entry["table_ambiguous"] = True
        return entry

    def routes(self, table="main", family=4):
        stdout, _stderr, returncode = run_ip(
            f"-{family}", "-o", "route", "show", "table", str(table)
        )
        if returncode != 0 or stdout is None:
            return []
        return parse_route_dump(stdout, default_table=str(table))

    def route_prefixes(self, table="main", family=4):
        return {entry["prefix"] for entry in self.routes(table=table, family=family)}

    def rules(self, family=4):
        stdout, _stderr, returncode = run_ip(f"-{family}", "-o", "rule", "show")
        if returncode != 0 or stdout is None:
            return []
        return parse_rule_dump(stdout)

    # -- mutations ----------------------------------------------------------

    def ensure_route(self, item):
        """Install a route, returning ``(changed, detail)``."""
        destination = item["destination"]
        interface = item["interface"]
        table = str(item.get("table") or "main")
        family = int(item.get("family") or 4)
        source = str(item.get("source") or "")
        protocol = model.protocol_argument(item.get("protocol"))

        existing = self._route_for(destination, table, family)
        if existing is not None and existing.get("interface") == interface:
            source_ok = not source or not existing.get("source") or existing.get("source") == source
            protocol_ok = not protocol or not existing.get("protocol") or (
                existing.get("protocol") in {protocol, model.ROUTE_PROTOCOL_NAME}
            )
            if source_ok and protocol_ok:
                return False, "already routed through " + interface

        command = [f"-{family}", "route", "replace", destination, "dev", interface]
        if source and self._source_is_local(interface, source):
            command += ["src", source]
        if protocol:
            command += ["proto", protocol]
        if table and table != "main":
            command += ["table", table]

        _stdout, stderr, returncode = run_ip(*command)
        if returncode != 0:
            reason = " ".join((stderr or "").splitlines()) or f"ip exited with {returncode}"
            raise RuntimeError(f"{destination} dev {interface}: {reason}")
        return True, f"{destination} dev {interface} table {table}"

    def remove_route(self, item):
        destination = item["destination"]
        family = int(item.get("family") or 4)
        table = str(item.get("table") or "main")
        command = [f"-{family}", "route", "del", destination]
        interface = str(item.get("interface") or "")
        if interface:
            command += ["dev", interface]
        if table and table != "main":
            command += ["table", table]
        _stdout, _stderr, returncode = run_ip(*command, timeout=5)
        return returncode == 0

    def ensure_rule(self, match, table, family=4, preference=1200):
        """Install a policy rule, returning ``(changed, detail)``."""
        target = str(match) if match else ""
        existing = self._rule_for(target, str(table), family)
        if existing is not None:
            return False, f"pref {existing['pref']} -> {table}"
        command = [f"-{family}", "rule", "add", "pref", str(preference)]
        if target:
            command += ["to", target]
        command += ["lookup", str(table)]
        _stdout, stderr, returncode = run_ip(*command)
        if returncode != 0:
            reason = " ".join((stderr or "").splitlines()) or f"ip exited with {returncode}"
            raise RuntimeError(f"rule to {target or 'any'} lookup {table}: {reason}")
        return True, f"pref {preference} to {target or 'any'} lookup {table}"

    def remove_rule(self, match, table, family=4):
        target = str(match) if match else ""
        existing = self._rule_for(target, str(table), family)
        if existing is None:
            return False
        command = [f"-{family}", "rule", "del", "pref", str(existing["pref"])]
        if target:
            command += ["to", target]
        command += ["lookup", str(table)]
        _stdout, _stderr, returncode = run_ip(*command, timeout=5)
        return returncode == 0

    # -- helpers ------------------------------------------------------------

    def _route_for(self, destination, table, family):
        stdout, _stderr, returncode = run_ip(
            f"-{family}", "-o", "route", "show", "exact", str(destination),
            "table", str(table),
        )
        if returncode != 0 or not stdout:
            return None
        entries = parse_route_dump(stdout, default_table=str(table))
        for entry in entries:
            try:
                if ipaddress.ip_network(entry["prefix"], strict=False) == ipaddress.ip_network(
                    str(destination), strict=False
                ):
                    return entry
            except ValueError:
                continue
        return entries[0] if entries else None

    def _rule_for(self, target, table, family):
        """Find an existing rule selecting *target* from *table*.

        ``target=None`` looks for a rule with no destination selector (a
        whole-table rule). Comparison is semantic: ``ip rule`` prints a host
        rule without the ``/32``, so ``192.168.4.19`` and
        ``192.168.4.19/32`` must be treated as the same selector.
        """
        wanted = None
        if target:
            try:
                wanted = ipaddress.ip_network(str(target), strict=False)
            except ValueError:
                wanted = None
        for rule in self.rules(family=family):
            if str(rule.get("lookup")) != str(table):
                continue
            if model.rule_matches(rule, wanted, table):
                return rule
        return None

    def _source_is_local(self, interface, source):
        for local_interface, _network, address in get_local_networks(
            ipaddress.ip_address(source).version
        ):
            if local_interface == interface and str(address) == str(source):
                return True
        return False


def preferred_source_for(interface, family=4):
    """Best local address on *interface* to pin as the route source."""
    for local_interface, _network, address in get_local_networks(family):
        if local_interface == interface:
            return str(address)
    return ""
