"""Tests for the Windows IP Helper bindings and the Windows backend.

The layout tests run on every platform: they only inspect ``ctypes`` structure
definitions, which is the part that silently corrupts data when it drifts.
Anything that actually calls ``iphlpapi`` is guarded by ``sys.platform`` and
never mutates the routing table (this suite runs unelevated).

No test writes a file: this project's environment has no usable temporary
directory, and ``tests/__init__`` already owns the one real temp directory the
suite uses for config state.
"""

import ctypes
import ipaddress
import sys
import unittest

try:  # ``python -B tests/test_windows_winapi.py``: tests/ is on sys.path
    from support import FakeBackend, make_config
except ImportError:  # ``python -m unittest tests.test_windows_winapi``
    from tests.support import FakeBackend, make_config

from lanrf import model, winapi

if sys.platform.startswith("win"):
    from lanrf import privileged, windows
else:  # the module imports fine on Linux; only the calls need Windows
    from lanrf import privileged, windows  # noqa: F401

IS_WINDOWS = sys.platform.startswith("win")


class SocketAddressLayoutTests(unittest.TestCase):
    """The 28-byte union: wrong alignment shifts every containing struct."""

    def test_sockaddr_size_and_alignment(self):
        self.assertEqual(winapi.SOCKADDR_INET_SIZE, 28)
        self.assertEqual(ctypes.sizeof(winapi.SOCKADDR_INET), 28)
        self.assertEqual(ctypes.alignment(winapi.SOCKADDR_INET), 4)

    def test_ipv4_round_trip_uses_offset_four(self):
        sockaddr = winapi.sockaddr_from_ip("192.168.4.31")
        self.assertEqual(sockaddr.si_family, winapi.AF_INET)
        self.assertEqual(
            ctypes.string_at(ctypes.addressof(sockaddr) + winapi.SOCKADDR_ADDR_V4, 4),
            bytes((192, 168, 4, 31)),
        )
        self.assertEqual(str(winapi.ip_from_sockaddr(sockaddr)), "192.168.4.31")
        self.assertEqual(winapi.sockaddr_text(sockaddr), "192.168.4.31")

    def test_ipv6_round_trip_uses_offset_eight(self):
        sockaddr = winapi.sockaddr_from_ip("fe80::1")
        self.assertEqual(sockaddr.si_family, winapi.AF_INET6)
        self.assertEqual(winapi.SOCKADDR_ADDR_V6, 8)
        self.assertEqual(
            ctypes.string_at(ctypes.addressof(sockaddr) + winapi.SOCKADDR_ADDR_V6, 16),
            bytes.fromhex("fe800000000000000000000000000001"),
        )
        self.assertEqual(str(winapi.ip_from_sockaddr(sockaddr)), "fe80::1")

    def test_unknown_family_yields_none(self):
        sockaddr = winapi.SOCKADDR_INET()
        sockaddr.si_family = winapi.AF_UNSPEC
        self.assertIsNone(winapi.ip_from_sockaddr(sockaddr))
        self.assertEqual(winapi.sockaddr_text(sockaddr), "")


class ForwardRowLayoutTests(unittest.TestCase):
    """MIB_IPFORWARD_ROW2 offsets: NextHop 44, Metric 84, Protocol 88, Origin 100."""

    def test_prefix_layout(self):
        self.assertEqual(winapi.IP_ADDRESS_PREFIX_SIZE, 32)
        self.assertEqual(ctypes.sizeof(winapi.IP_ADDRESS_PREFIX), 32)
        self.assertEqual(winapi.IP_ADDRESS_PREFIX.PrefixLength.offset, 28)

    def test_forward_row_layout(self):
        self.assertEqual(winapi.MIB_IPFORWARD_ROW2_SIZE, 104)
        self.assertEqual(winapi.OFFSET_NEXT_HOP, 44)
        self.assertEqual(winapi.OFFSET_METRIC, 84)
        self.assertEqual(winapi.OFFSET_PROTOCOL, 88)
        self.assertEqual(winapi.OFFSET_ORIGIN, 100)
        self.assertEqual(winapi.MIB_IPFORWARD_ROW2.NextHop.offset, 44)
        self.assertEqual(winapi.MIB_IPFORWARD_ROW2.Metric.offset, 84)
        self.assertEqual(winapi.MIB_IPFORWARD_ROW2.Protocol.offset, 88)
        self.assertEqual(winapi.MIB_IPFORWARD_ROW2.Origin.offset, 100)

    def test_table_header_layout(self):
        self.assertEqual(winapi.TABLE_ROW_OFFSET, 8)
        self.assertEqual(ctypes.sizeof(winapi.MIB_IPFORWARD_TABLE2), 112)

    def test_layout_report_is_ok(self):
        self.assertTrue(
            winapi.LAYOUT_OK,
            f"ctypes layout drifted: {winapi.LAYOUT}",
        )
        self.assertEqual(winapi.LAYOUT["mib_ipforward_row2"], 104)
        self.assertEqual(winapi.LAYOUT["sockaddr_inet"], 28)
        self.assertEqual(winapi.LAYOUT["ip_address_prefix"], 32)
        self.assertEqual(winapi.LAYOUT["ip_adapter_prefix"], 40)
        self.assertEqual(winapi.LAYOUT["ip_adapter_unicast_address"], 64)

    def test_unicast_row_and_adapter_layouts(self):
        self.assertEqual(winapi.MIB_UNICASTIPADDRESS_ROW_SIZE, 64)
        self.assertEqual(winapi.IP_ADAPTER_ADDRESSES_SIZE, 184)
        self.assertEqual(winapi.IP_ADAPTER_PREFIX_SIZE, 40)
        self.assertEqual(winapi.IP_ADAPTER_UNICAST_ADDRESS_SIZE, 64)
        # OnLinkPrefixLength follows LeaseLifetime in the LH unicast struct; it
        # is what makes the subnet mask readable from GetAdaptersAddresses.
        self.assertEqual(
            winapi.IP_ADAPTER_UNICAST_ADDRESS.OnLinkPrefixLength.offset, 56
        )

    def test_destination_parser(self):
        self.assertEqual(
            str(winapi._parse_destination("192.168.4.94")), "192.168.4.94/32"
        )
        self.assertEqual(
            str(winapi._parse_destination("10.0.0.0/8")), "10.0.0.0/8"
        )
        self.assertEqual(
            str(winapi._parse_destination("2001:db8::1", family=6)),
            "2001:db8::1/128",
        )
        with self.assertRaises(ValueError):
            winapi._parse_destination("192.168.4.94", family=6)


@unittest.skipUnless(IS_WINDOWS, "IP Helper calls require Windows")
class WindowsReadOnlyTests(unittest.TestCase):
    """Read-only probes against the live IP Helper API."""

    def test_forward_table_is_readable(self):
        rows = winapi.get_forward_table(winapi.AF_INET)
        self.assertTrue(rows)
        for row in rows[:20]:
            self.assertIsInstance(row["interface_index"], int)
            self.assertIn("/", row["prefix"])
            self.assertIsInstance(row["metric"], int)
            self.assertIsInstance(row["protocol"], int)

    def test_best_route_for_a_local_address_comes_back_through_it(self):
        addresses = [
            entry
            for entry in winapi.get_unicast_addresses(winapi.AF_INET)
            if not ipaddress.ip_address(entry["address"]).is_link_local
        ]
        self.assertTrue(addresses)
        resolved = None
        for entry in addresses:
            try:
                ifindex, next_hop = winapi.get_best_route(entry["address"])
            except OSError:
                # GetBestRoute2 can refuse addresses on adapters that are down.
                continue
            resolved = (entry, ifindex, next_hop)
            break
        self.assertIsNotNone(resolved, "no local unicast address resolved")
        entry, ifindex, next_hop = resolved
        self.assertEqual(ifindex, entry["interface_index"])
        self.assertIsInstance(next_hop, str)

    def test_adapters_and_unicast_addresses(self):
        adapters = winapi.get_adapters()
        self.assertTrue(adapters)
        for adapter in adapters[:10]:
            self.assertIsInstance(adapter["ifindex"], int)
            self.assertIn("name", adapter)
            self.assertIn("description", adapter)
            self.assertIsInstance(adapter["iftype"], int)
            self.assertIsInstance(adapter["oper_status"], int)
            self.assertIsInstance(adapter["addresses"], list)
            self.assertIsInstance(adapter["prefixes"], list)
        unicast = winapi.get_unicast_addresses(winapi.AF_INET)
        self.assertTrue(unicast)
        for entry in unicast[:10]:
            self.assertEqual(entry["family"], 4)
            self.assertIsInstance(entry["prefix_length"], int)
            self.assertGreater(entry["prefix_length"], 0)
            self.assertIn("/", entry["prefix"])

    def test_build_forward_row_without_writing(self):
        adapter = winapi.get_adapters()[0]
        row = winapi.build_forward_row(
            "203.0.113.77/32", family=4, ifindex=adapter["ifindex"]
        )
        self.assertEqual(row.InterfaceIndex, adapter["ifindex"])
        self.assertEqual(row.DestinationPrefix.PrefixLength, 32)
        self.assertEqual(row.Metric, 0)
        self.assertEqual(row.Protocol, winapi.MIB_IPPROTO_NETMGMT)
        self.assertEqual(row.ValidLifetime, winapi.INFINITE_LIFETIME)
        self.assertEqual(row.PreferredLifetime, winapi.INFINITE_LIFETIME)
        self.assertTrue(row.Immortal)
        self.assertEqual(winapi.sockaddr_text(row.NextHop), "0.0.0.0")


@unittest.skipUnless(IS_WINDOWS, "the Windows backend requires Windows")
class WindowsBackendQueryTests(unittest.TestCase):
    """Query semantics of :class:`lanrf.windows.WindowsBackend`."""

    @classmethod
    def setUpClass(cls):
        cls.backend = windows.WindowsBackend()

    def test_contract_flags(self):
        backend = self.backend
        self.assertEqual(backend.name, "windows")
        self.assertFalse(backend.supports_policy_rules)
        self.assertFalse(backend.supports_events)
        self.assertIsInstance(backend.is_privileged, bool)
        self.assertIsInstance(backend.privileges_note, str)

    def test_list_interfaces_excludes_tunnels_and_loopback(self):
        backend = self.backend
        names = backend.list_interfaces()
        up = backend.list_interfaces(only_up=True)
        self.assertTrue(set(up) <= set(names))
        for name in names:
            self.assertEqual(backend.link_kind(name), "")
        for name in up:
            self.assertTrue(backend.is_usable(name))
        self.assertEqual(
            {name for name in names if backend.is_usable(name)}, set(up)
        )
        for tunnel in backend.tunnel_interfaces():
            self.assertIn(tunnel["kind"], ("tunnel", "loopback"))
            self.assertNotIn(tunnel["name"], names)
            self.assertFalse(backend.is_usable(tunnel["name"]))

    def test_local_networks_skip_link_local(self):
        backend = self.backend
        networks = backend.local_networks(4)
        for interface, network, address in networks:
            self.assertEqual(network.version, 4)
            self.assertEqual(address.version, 4)
            self.assertFalse(address.is_link_local, f"{interface} {address}")
            self.assertFalse(address.is_loopback, f"{interface} {address}")
            self.assertIn(address, network)
            self.assertTrue(backend.is_usable(interface))

    def test_default_interfaces_are_usable(self):
        backend = self.backend
        defaults = backend.default_interfaces()
        usable = set(backend.list_interfaces(only_up=True))
        for name in defaults:
            self.assertIn(name, usable)

    def test_route_lookup_main_and_named_table(self):
        backend = self.backend
        entry = backend.route_lookup("127.0.0.1", family=4)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["table"], "main")
        self.assertEqual(entry["requested_table"], "")
        self.assertIsNone(backend.route_lookup("127.0.0.1", family=4, table="168"))
        self.assertEqual(
            backend.route_lookup("127.0.0.1", family=4, table="main")["table"],
            "main",
        )

    def test_route_lookup_accepts_a_normalized_destination(self):
        backend = self.backend
        bare = backend.route_lookup("192.168.4.94", family=4)
        self.assertIsNotNone(bare)
        narrowed = backend.route_lookup("192.168.4.94/32", family=4)
        self.assertIsNotNone(narrowed)
        self.assertEqual(narrowed["interface"], bare["interface"])
        self.assertEqual(narrowed["gateway"], bare["gateway"])
        self.assertEqual(narrowed["prefix"], bare["prefix"])
        self.assertEqual(narrowed["destination"], bare["destination"])

    def test_best_route_detail_parses_cidr_destinations(self):
        bare = winapi.get_best_route_detail("192.168.4.94", family=4)
        narrowed = winapi.get_best_route_detail("192.168.4.94/32", family=4)
        self.assertEqual(narrowed["prefix"], bare["prefix"])
        self.assertEqual(narrowed["interface_index"], bare["interface_index"])
        self.assertEqual(narrowed["next_hop"], bare["next_hop"])
        with self.assertRaises(ValueError):
            winapi.get_best_route_detail("192.168.4.94/32", family=6)

    def test_routes_contract_and_owned_heuristic(self):
        backend = self.backend
        entries = backend.routes("main", 4)
        self.assertTrue(entries)
        for entry in entries[:50]:
            self.assertEqual(
                set(entry),
                {
                    "prefix",
                    "interface",
                    "family",
                    "table",
                    "protocol",
                    "source",
                    "metric",
                    "scope",
                    "owned",
                },
            )
            self.assertEqual(entry["family"], 4)
            self.assertEqual(entry["table"], "main")
            self.assertIn(entry["protocol"], ("local", "netmgmt", "other"))
            if entry["owned"]:
                self.assertEqual(entry["metric"], 0)
                self.assertTrue(entry["prefix"].endswith("/32"))
        self.assertEqual(backend.routes("168", 4), [])
        self.assertEqual(
            backend.route_prefixes("main", 4),
            {entry["prefix"] for entry in entries},
        )

    def test_owned_heuristic_requires_on_link_and_metric_zero(self):
        backend = self.backend
        original = windows.winapi.get_forward_table
        base = {
            "destination": "192.168.4.94",
            "prefix": "192.168.4.94/32",
            "prefix_length": 32,
            "next_hop": "0.0.0.0",
            "interface_index": backend._adapters()[0]["ifindex"],
            "interface_luid": 0,
            "metric": 0,
            "protocol": 3,
            "origin": 0,
            "age": 0,
            "valid_lifetime": 0xFFFFFFFF,
            "preferred_lifetime": 0xFFFFFFFF,
            "loopback": False,
            "immortal": True,
        }
        rows = [
            dict(base),
            dict(base, prefix="192.168.4.0/24", prefix_length=24),
            dict(base, prefix="192.168.4.96/32", next_hop="10.85.35.164"),
            dict(base, prefix="192.168.4.97/32", metric=5),
            dict(base, prefix="203.0.113.9/32", protocol=99),
            dict(base, prefix="192.168.4.95/32", protocol=2),
        ]
        # VPN clients install the same /32 + metric 0 + on-link shape for their
        # own peers (Tailscale does).  A route on a tunnel/loopback/virtual
        # adapter must not be reported as ours, or prune would delete it.
        tunnel = next(
            (adapter for adapter in backend._adapters() if backend._classify(adapter)),
            None,
        )
        if tunnel is not None:
            rows.append(
                dict(
                    base,
                    prefix="100.66.103.47/32",
                    interface_index=tunnel["ifindex"],
                )
            )
        windows.winapi.get_forward_table = lambda family: rows
        try:
            entries = {entry["prefix"]: entry for entry in backend.routes("main", 4)}
        finally:
            windows.winapi.get_forward_table = original
        self.assertTrue(entries["192.168.4.94/32"]["owned"])
        self.assertFalse(entries["192.168.4.0/24"]["owned"])
        self.assertFalse(entries["192.168.4.96/32"]["owned"])
        self.assertFalse(entries["192.168.4.97/32"]["owned"])
        self.assertEqual(entries["192.168.4.95/32"]["protocol"], "local")
        if tunnel is not None:
            self.assertFalse(entries["100.66.103.47/32"]["owned"])
        # A foreign host route on a *physical* adapter with the same shape is
        # still indistinguishable, because Windows rows cannot carry our
        # protocol stamp.
        self.assertTrue(entries["203.0.113.9/32"]["owned"])
        self.assertEqual(entries["203.0.113.9/32"]["protocol"], "other")

    def test_rules_are_unsupported(self):
        backend = self.backend
        self.assertEqual(backend.rules(4), [])
        with self.assertRaises(NotImplementedError) as caught:
            backend.ensure_rule("192.168.4.0/24", "168")
        self.assertIn("routing_mode='main'", str(caught.exception))
        with self.assertRaises(NotImplementedError):
            backend.remove_rule("192.168.4.0/24", "168")

    def test_ensure_route_rejects_foreign_table_before_writing(self):
        backend = self.backend
        interfaces = backend.list_interfaces()
        self.assertTrue(interfaces)
        with self.assertRaises(ValueError):
            backend.ensure_route(
                {
                    "destination": "203.0.113.77/32",
                    "address": "203.0.113.77/32",
                    "family": 4,
                    "interface": interfaces[0],
                    "table": "168",
                }
            )

    def test_ensure_route_rejects_unknown_interface_before_writing(self):
        backend = self.backend
        with self.assertRaises(ValueError):
            backend.ensure_route(
                {
                    "destination": "203.0.113.77/32",
                    "address": "203.0.113.77/32",
                    "family": 4,
                    "interface": "no-such-adapter",
                }
            )

    def test_remove_route_for_absent_prefix_is_false(self):
        backend = self.backend
        interfaces = backend.list_interfaces()
        self.assertTrue(interfaces)
        self.assertFalse(
            backend.remove_route(
                {
                    "destination": "203.0.113.77/32",
                    "address": "203.0.113.77/32",
                    "family": 4,
                    "interface": interfaces[0],
                    "table": "main",
                }
            )
        )


class FixTargetsWindowsTests(unittest.TestCase):
    """The Windows fix path never reaches pkexec and reports elevation clearly."""

    def test_unelevated_windows_fix_returns_helper_shaped_failure(self):
        backend = FakeBackend(privileged=False)
        config = make_config(routing_mode="main")
        result = privileged._fix_targets_windows(
            [{"address": "192.168.4.94", "interface": "wlp0s20f3"}],
            backend=backend,
            config=config,
        )
        self.assertEqual(result["return_code"], privileged.EXIT_FAILED)
        self.assertEqual(result["method"], "windows-direct")
        self.assertIn("elevated", result["stderr"])
        self.assertIn("PowerShell", result["stderr"])
        self.assertEqual(result["stdout"], "")
        self.assertEqual(len(result["items"]), 1)
        self.assertEqual(backend.calls, [])


if __name__ == "__main__":  # allow running the file without the tests package
    unittest.main()