"""Shared test doubles and helpers.

The interesting logic in this project is the decision making, not the syscalls,
so most tests run against :class:`FakeBackend` instead of the real kernel. That
also means the suite is hermetic and fast.
"""

import ipaddress
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LIB_DIR = REPO_ROOT / "src/usr/lib/lan-route-fixer"
if str(LIB_DIR) not in sys.path:
    sys.path.insert(0, str(LIB_DIR))

from lanrf import model  # noqa: E402
from lanrf.backends import NetworkBackend  # noqa: E402
from lanrf.model import ROUTE_PROTOCOL_NAME, route_entry  # noqa: E402


class FakeBackend(NetworkBackend):
    """In-memory routing table that behaves like the Linux backend."""

    name = "fake"
    supports_policy_rules = True
    supports_events = True

    def __init__(self, interfaces=None, networks=None, defaults=None, privileged=True,
                 rule_output_style="canonical"):
        # NB: use `is None` checks so callers can legitimately pass an empty
        # machine (no interfaces at all) to exercise the failure paths.
        if interfaces is None:
            interfaces = {
                "wlp0s20f3": {"kind": "", "up": True, "running": True},
                "docker0": {"kind": "bridge", "up": True, "running": False},
            }
        # interfaces: {name: {"kind": str, "up": bool, "running": bool}}
        self.interfaces = interfaces
        # networks: [(interface, "192.168.4.0/24", "192.168.4.238")]
        self.networks = (
            [("wlp0s20f3", "192.168.4.0/24", "192.168.4.238")]
            if networks is None
            else list(networks)
        )
        self.defaults = ["wlp0s20f3"] if defaults is None else list(defaults)
        # How `rules()` echoes a selector back. The real `ip rule show` prints a
        # host rule as "192.168.4.19", dropping the /32 it was added with, so
        # "kernel" reproduces that and catches string-comparison bugs.
        self.rule_output_style = rule_output_style
        self.is_privileged = privileged
        self.routes_by_table = {"main": [], "168": []}
        self.rules_by_family = {4: [], 6: []}
        self.calls = []
        self.fail_ensure_route = False
        self.fail_ensure_rule = False
        self.route_lookup_overrides = {}

    # -- queries ------------------------------------------------------------

    def link_kind(self, interface):
        return self.interfaces.get(interface, {}).get("kind", "")

    def is_usable(self, interface):
        """Mirror the real classifier, minus the sysfs probe.

        The real backend also requires ``/sys/class/net/<iface>/device``; the
        fake trusts its own interface table instead so tests can describe a
        machine that does not exist.
        """
        details = self.interfaces.get(interface)
        if not details:
            return False
        if interface == "lo":
            return False
        from lanrf.linux import is_virtual_interface

        return not is_virtual_interface(interface, details.get("kind", ""))

    def list_interfaces(self, only_up=False):
        result = []
        for name, details in self.interfaces.items():
            if not self.is_usable(name):
                continue
            if only_up and not details.get("running", details.get("up")):
                continue
            result.append(name)
        return result

    def local_networks(self, family=4):
        return [
            (interface, ipaddress.ip_network(network, strict=False), ipaddress.ip_address(address))
            for interface, network, address in self.networks
            if ipaddress.ip_address(address).version == family
        ]

    def default_interfaces(self):
        return list(self.defaults)

    def route_lookup(self, destination, family=4, table=None, fallback=True):
        key = (str(destination), str(table))
        if key in self.route_lookup_overrides:
            return self.route_lookup_overrides[key]
        entries = self._search(destination, family=family, table=table)
        if not entries:
            return None
        best = entries[0]
        return {
            "interface": best["interface"],
            "gateway": "",
            "source": best["source"],
            "table": best["table"],
        }

    def routes(self, table="main", family=4):
        return [entry for entry in self.routes_by_table.get(str(table), []) if entry["family"] == family]

    def route_prefixes(self, table="main", family=4):
        return {entry["prefix"] for entry in self.routes(table=table, family=family)}

    def rules(self, family=4):
        return list(self.rules_by_family.get(family, []))

    # -- mutations ----------------------------------------------------------

    def ensure_route(self, item):
        self.calls.append(("ensure_route", dict(item)))
        if self.fail_ensure_route:
            raise RuntimeError("kernel said no")
        table = str(item.get("table") or "main")
        entries = self.routes_by_table.setdefault(table, [])
        for entry in entries:
            if (
                entry["prefix"] == item["destination"]
                and entry["interface"] == item["interface"]
                and entry["family"] == item["family"]
            ):
                entry["source"] = item.get("source", "")
                entry["protocol"] = ROUTE_PROTOCOL_NAME
                return False, "already present"
        entries.append(
            route_entry(
                prefix=item["destination"],
                interface=item["interface"],
                family=item["family"],
                table=table,
                protocol=ROUTE_PROTOCOL_NAME,
                source=item.get("source", ""),
            )
        )
        return True, "installed"

    def remove_route(self, item):
        self.calls.append(("remove_route", dict(item)))
        table = str(item.get("table") or "main")
        before = len(self.routes_by_table.get(table, []))
        self.routes_by_table[table] = [
            entry
            for entry in self.routes_by_table.get(table, [])
            if not (
                entry["prefix"] == item["destination"]
                and (not item.get("interface") or entry["interface"] == item["interface"])
            )
        ]
        return len(self.routes_by_table[table]) != before

    def ensure_rule(self, match, table, family=4, preference=1200):
        self.calls.append(("ensure_rule", str(match), str(table), preference))
        if self.fail_ensure_rule:
            raise RuntimeError("kernel said no")
        wanted = None
        try:
            import ipaddress

            wanted = ipaddress.ip_network(str(match), strict=False)
        except ValueError:
            wanted = None
        for rule in self.rules_by_family.setdefault(family, []):
            if not model.rule_matches(rule, wanted, str(table)):
                continue
            return False, "already present"
        self.rules_by_family[family].append(
            {"pref": preference, "to": self._echo_selector(match), "lookup": str(table)}
        )
        return True, "installed"

    def _echo_selector(self, match):
        """Render a selector the way `ip rule show` would."""
        if self.rule_output_style != "kernel":
            return str(match)
        import ipaddress

        try:
            network = ipaddress.ip_network(str(match), strict=False)
        except ValueError:
            return str(match)
        if network.prefixlen == network.max_prefixlen:
            return str(network.network_address)
        return str(network)

    def remove_rule(self, match, table, family=4):
        self.calls.append(("remove_rule", str(match), str(table)))
        rules = self.rules_by_family.setdefault(family, [])
        before = len(rules)
        self.rules_by_family[family] = [
            rule
            for rule in rules
            if not (str(rule.get("lookup")) == str(table) and str(rule.get("to") or "") == str(match))
        ]
        return len(self.rules_by_family[family]) != before

    # -- test helpers -------------------------------------------------------

    def _search(self, destination, family=4, table=None):
        """Longest-prefix match, mirroring what the kernel would do."""
        wanted = ipaddress.ip_network(str(destination), strict=False)
        tables = [str(table)] if table and table != "all" else list(self.routes_by_table)
        matches = []
        for name in tables:
            for entry in self.routes_by_table.get(name, []):
                if entry["family"] != family:
                    continue
                network = ipaddress.ip_network(entry["prefix"], strict=False)
                if wanted.subnet_of(network):
                    matches.append(entry)
        if not matches:
            return []
        matches.sort(key=lambda entry: ipaddress.ip_network(entry["prefix"]).prefixlen, reverse=True)
        return matches

    def add_raw_route(self, prefix, interface, table="main", protocol="dhcp", family=None, source=""):
        """Install a route that this tool does not own (a VPN route, say)."""
        network = ipaddress.ip_network(prefix, strict=False)
        self.routes_by_table.setdefault(str(table), []).append(
            route_entry(
                prefix=str(network),
                interface=interface,
                family=family or network.version,
                table=str(table),
                protocol=protocol,
                source=source,
            )
        )

    def dump(self):
        return json.dumps(
            {
                "routes": self.routes_by_table,
                "rules": {str(k): v for k, v in self.rules_by_family.items()},
            },
            indent=2,
            ensure_ascii=False,
            default=str,
        )


def make_config(**overrides):
    """A Config object with sensible test defaults."""
    from lanrf.config import DEFAULT_CONFIG, Config

    data = dict(DEFAULT_CONFIG)
    data.update(overrides)
    return Config(data)
