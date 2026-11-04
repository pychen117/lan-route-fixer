"""Tests for the OpenSSH config importer and the physical-LAN filter.

Everything here parses from strings: this box has no usable temporary
directory, so ``Include`` resolution is exercised through the injectable
resolver instead of real files.
"""

import ipaddress
import unittest
from pathlib import Path

SSH_DIR = str(Path("/home/u/.ssh"))
SSH_CONF_DIR = str(Path("/home/u/.ssh/conf.d"))

try:  # works both as a package and with `discover -s tests`
    from tests import support  # noqa: F401  (sets sys.path)
except ImportError:  # pragma: no cover - direct invocation
    import support  # noqa: F401

from lanrf.sshconfig import (
    DEFAULT_SSH_PORT,
    default_ssh_config_paths,
    filter_by_backend,
    host_to_target,
    parse_ssh_config,
    parse_ssh_config_text,
)


class VirtualIncludes:
    """Injectable ``include(pattern, base_dir)`` backed by a dict.

    Keys may be ``(pattern, base_dir)`` for exact matches or a bare ``pattern``
    for convenience; values are ``[(path, text), ...]``.
    """

    def __init__(self, files=None):
        self.files = dict(files or {})
        self.calls = []

    def __call__(self, pattern, base_dir):
        self.calls.append((pattern, base_dir))
        entries = self.files.get((pattern, base_dir))
        if entries is None:
            entries = self.files.get(pattern)
        return list(entries or [])


class StubBackend:
    """Minimal physical-LAN backend: one WLAN, one VPN route."""

    name = "stub"

    def __init__(self):
        self.networks = [
            (
                "WLAN",
                ipaddress.ip_network("192.168.4.0/24"),
                ipaddress.ip_address("192.168.4.238"),
            )
        ]
        self.kinds = {"WLAN": "", "aTrustVNIC": "tun"}
        self.routes = {
            "10.10.60.101": {
                "interface": "aTrustVNIC",
                "gateway": "10.85.35.164",
            }
        }

    def local_networks(self, family=4):
        return [entry for entry in self.networks if entry[1].version == family]

    def is_usable(self, interface):
        return interface == "WLAN"

    def link_kind(self, interface):
        return self.kinds.get(interface, "")

    def route_lookup(self, destination, family=4):
        return self.routes.get(str(destination))


class ParsingBasicsTests(unittest.TestCase):
    def test_comments_and_trailing_comments(self):
        hosts = parse_ssh_config_text(
            "\n".join(
                [
                    "# a whole-line comment",
                    "Host commented   # trailing comment",
                    "  HostName 192.168.4.94  # inline comment",
                    "  # another whole-line comment",
                    "  Port 2200",
                ]
            )
        )
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].name, "commented")
        self.assertEqual(hosts[0].address, "192.168.4.94")
        self.assertEqual(hosts[0].port, 2200)

    def test_keywords_are_case_insensitive_and_values_may_be_quoted(self):
        hosts = parse_ssh_config_text(
            "\n".join(
                [
                    "host quoted",
                    '  HOSTNAME "192.168.4.94"',
                    "  port 2200",
                    '  USER "user name"',
                ]
            )
        )
        self.assertEqual(hosts[0].name, "quoted")
        self.assertEqual(hosts[0].address, "192.168.4.94")
        self.assertEqual(hosts[0].port, 2200)
        self.assertEqual(hosts[0].user, "user name")

    def test_multiple_patterns_expand_to_several_hosts(self):
        hosts = parse_ssh_config_text(
            "Host alpha beta\n  HostName 192.168.4.94\n  User lan\n"
        )
        self.assertEqual([host.name for host in hosts], ["alpha", "beta"])
        self.assertEqual({host.address for host in hosts}, {"192.168.4.94"})
        self.assertEqual({host.user for host in hosts}, {"lan"})

    def test_wildcards_are_not_enumerated(self):
        hosts = parse_ssh_config_text(
            "\n".join(
                [
                    "Host *",
                    "  User everybody",
                    "Host *.lan",
                    "  User domain",
                    "Host db?? prod*",
                    "  User wild",
                    "Host lone",
                    "  HostName 192.168.4.94",
                ]
            )
        )
        self.assertEqual([host.name for host in hosts], ["lone"])

    def test_hostname_defaults_to_the_host_value(self):
        hosts = parse_ssh_config_text("Host defaulted\n  Port 2200\n")
        self.assertEqual(hosts[0].address, "defaulted")
        self.assertEqual(hosts[0].port, 2200)

    def test_unset_port_defaults_and_non_numeric_port_falls_back(self):
        hosts = parse_ssh_config_text(
            "Host plain\nHost weird\n  Port not-a-number\n"
        )
        self.assertEqual([host.port for host in hosts], [DEFAULT_SSH_PORT, DEFAULT_SSH_PORT])

    def test_source_path_and_line_are_recorded(self):
        hosts = parse_ssh_config_text(
            "Host tracked\n  HostName 192.168.4.94\n", source_path="/home/u/.ssh/config"
        )
        self.assertEqual(hosts[0].source_path, "/home/u/.ssh/config")
        self.assertEqual(hosts[0].line, 1)


class ResolutionTests(unittest.TestCase):
    def test_first_match_wins_for_hostname_port_and_user(self):
        hosts = parse_ssh_config_text(
            "\n".join(
                [
                    "Host alpha",
                    "  HostName 10.0.0.1",
                    "  Port 2200",
                    "Host alpha beta",
                    "  HostName 10.0.0.2",
                    "  Port 2201",
                    "  User second",
                    "Host *",
                    "  Port 2222",
                    "  User fallback",
                ]
            )
        )
        by_name = {host.name: host for host in hosts}
        self.assertEqual(by_name["alpha"].address, "10.0.0.1")
        self.assertEqual(by_name["alpha"].port, 2200)
        self.assertEqual(by_name["alpha"].user, "second")
        self.assertEqual(by_name["beta"].address, "10.0.0.2")
        self.assertEqual(by_name["beta"].port, 2201)
        self.assertEqual(by_name["beta"].user, "second")

    def test_negated_pattern_excludes_a_block(self):
        hosts = parse_ssh_config_text(
            "\n".join(
                [
                    "Host *.lan !nas.lan",
                    "  HostName 10.0.0.5",
                    "Host nas.lan",
                    "  HostName 192.168.4.94",
                ]
            )
        )
        self.assertEqual([host.name for host in hosts], ["nas.lan"])
        # The wildcard block was skipped, not silently applied, because the
        # concrete alias is negated there.
        self.assertEqual(hosts[0].address, "192.168.4.94")
        self.assertNotIn("10.0.0.5", [host.address for host in hosts])

    def test_match_blocks_are_ignored_as_host_patterns(self):
        hosts = parse_ssh_config_text(
            "\n".join(
                [
                    "Host realhost",
                    "  HostName 192.168.4.94",
                    "Match host realhost",
                    "  HostName 10.0.0.1",
                    "  Port 2222",
                    "Match all",
                    "  User ignored",
                    "Host other",
                    "  HostName 192.168.4.234",
                ]
            )
        )
        by_name = {host.name: host for host in hosts}
        self.assertEqual(set(by_name), {"realhost", "other"})
        self.assertEqual(by_name["realhost"].address, "192.168.4.94")
        self.assertEqual(by_name["realhost"].port, DEFAULT_SSH_PORT)
        self.assertEqual(by_name["realhost"].user, "")
        self.assertEqual(by_name["other"].user, "")


class IncludeTests(unittest.TestCase):
    def test_include_directives_apply_to_the_current_host(self):
        include = VirtualIncludes(
            {"dropin": [("/home/u/.ssh/dropin", "Port 2200\nHostName 192.168.4.94\n")]}
        )
        hosts = parse_ssh_config_text(
            "Host foo\n  Include dropin\n",
            source_path="/home/u/.ssh/config",
            include=include,
        )
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].address, "192.168.4.94")
        self.assertEqual(hosts[0].port, 2200)

    def test_include_glob_expands_relative_to_the_including_file(self):
        include = VirtualIncludes(
            {
                ("conf.d/*.conf", SSH_DIR): [
                    ("/home/u/.ssh/conf.d/a.conf", "Host first\n  HostName 192.168.4.94\n"),
                    ("/home/u/.ssh/conf.d/b.conf", "Host second\n  HostName 192.168.4.234\n"),
                ]
            }
        )
        hosts = parse_ssh_config_text(
            "Include conf.d/*.conf\n",
            source_path="/home/u/.ssh/config",
            include=include,
        )
        self.assertEqual([host.name for host in hosts], ["first", "second"])
        self.assertEqual(include.calls[0], ("conf.d/*.conf", SSH_DIR))

    def test_include_relative_to_the_including_file_in_a_subdirectory(self):
        include = VirtualIncludes(
            {
                ("*.conf", SSH_CONF_DIR): [
                    ("/home/u/.ssh/conf.d/x.conf", "Host nested\n  HostName 192.168.4.19\n")
                ]
            }
        )
        hosts = parse_ssh_config_text(
            "Include *.conf\n",
            source_path="/home/u/.ssh/conf.d/site.conf",
            include=include,
        )
        self.assertEqual([host.name for host in hosts], ["nested"])
        self.assertEqual(include.calls[0][1], SSH_CONF_DIR)

    def test_a_file_cannot_include_itself(self):
        text = "Host me\n  HostName 192.168.4.94\nInclude config\n"
        include = VirtualIncludes(
            {"config": [("/home/u/.ssh/config", text)]}
        )
        hosts = parse_ssh_config_text(
            text, source_path="/home/u/.ssh/config", include=include
        )
        self.assertEqual([host.name for host in hosts], ["me"])

    def test_include_depth_is_bounded(self):
        include = VirtualIncludes(
            {
                "a": [("/home/u/.ssh/a", "Host ahost\n  HostName 192.168.4.1\nInclude b\n")],
                "b": [("/home/u/.ssh/b", "Host bhost\n  HostName 192.168.4.2\nInclude c\n")],
                "c": [("/home/u/.ssh/c", "Host chost\n  HostName 192.168.4.3\nInclude d\n")],
                "d": [("/home/u/.ssh/d", "Host dhost\n  HostName 192.168.4.4\nInclude e\n")],
                "e": [("/home/u/.ssh/e", "Host ehost\n  HostName 192.168.4.5\n")],
            }
        )
        hosts = parse_ssh_config_text(
            "Include a\n", source_path="/home/u/.ssh/config", include=include
        )
        names = [host.name for host in hosts]
        self.assertEqual(names, ["ahost", "bhost", "chost", "dhost"])
        self.assertNotIn("ehost", names)

    def test_a_missing_default_include_is_harmless(self):
        hosts = parse_ssh_config_text(
            "Include lanrf-no-such-include-*",
            source_path="/home/u/.ssh/config",
        )
        self.assertEqual(hosts, [])


class ParsePathsTests(unittest.TestCase):
    def test_default_path_is_the_user_ssh_config(self):
        paths = default_ssh_config_paths()
        self.assertEqual(len(paths), 1)
        self.assertTrue(str(paths[0]).replace("\\", "/").endswith(".ssh/config"))

    def test_missing_files_are_skipped(self):
        self.assertEqual(parse_ssh_config(["/definitely/not/a/real/ssh_config"]), [])


class TargetHelperTests(unittest.TestCase):
    def test_host_to_target_applies_prefix_and_interface(self):
        host = parse_ssh_config_text("Host server\n  HostName 192.168.4.94\n")[0]
        target = host_to_target(host, interface="WLAN", name_prefix="ssh-")
        self.assertEqual(target["name"], "ssh-server")
        self.assertEqual(target["address"], "192.168.4.94")
        self.assertEqual(target["interface"], "WLAN")
        self.assertTrue(target["enabled"])


class PhysicalFilterTests(unittest.TestCase):
    def setUp(self):
        self.backend = StubBackend()

    def _target(self, address, name=None):
        return {"name": name or address, "address": address, "interface": "", "enabled": True}

    def test_physical_host_is_kept(self):
        kept, skipped = filter_by_backend(
            [self._target("192.168.4.94", "u55c")], self.backend
        )
        self.assertEqual([target["address"] for target in kept], ["192.168.4.94"])
        self.assertEqual(skipped, [])

    def test_atrust_host_is_skipped_with_the_capturing_route(self):
        kept, skipped = filter_by_backend(
            [self._target("10.10.60.101", "ic_eda")], self.backend
        )
        self.assertEqual(kept, [])
        self.assertEqual(len(skipped), 1)
        self.assertEqual(skipped[0]["name"], "ic_eda")
        self.assertIn("aTrustVNIC", skipped[0]["reason"])
        self.assertIn("10.85.35.164", skipped[0]["reason"])
        self.assertIn("不在本机物理网段内", skipped[0]["reason"])

    def test_public_address_is_rejected_as_not_private(self):
        kept, skipped = filter_by_backend(
            [self._target("198.51.100.2", "ubuntu-cyp2")], self.backend
        )
        self.assertEqual(kept, [])
        self.assertIn("不是有效的局域网私有地址", skipped[0]["reason"])

    def test_tunnel_networks_in_local_networks_do_not_count_as_physical(self):
        self.backend.networks.append(
            (
                "aTrustVNIC",
                ipaddress.ip_network("10.8.0.0/13"),
                ipaddress.ip_address("10.85.35.164"),
            )
        )
        self.backend.kinds["aTrustVNIC"] = "tun"
        kept, skipped = filter_by_backend(
            [self._target("10.10.60.101", "ic_eda")], self.backend
        )
        self.assertEqual(kept, [])
        self.assertIn("aTrustVNIC", skipped[0]["reason"])

    def test_include_tunnel_is_an_explicit_opt_in(self):
        kept, skipped = filter_by_backend(
            [self._target("10.10.60.101", "ic_eda")],
            self.backend,
            include_tunnel=True,
        )
        self.assertEqual([target["address"] for target in kept], ["10.10.60.101"])
        self.assertEqual(skipped, [])

    def test_no_matching_route_is_explained(self):
        kept, skipped = filter_by_backend(
            [self._target("192.168.5.10", "elsewhere")], self.backend
        )
        self.assertEqual(kept, [])
        self.assertIn("无匹配路由", skipped[0]["reason"])

    def test_targets_that_are_not_dicts_are_ignored(self):
        kept, skipped = filter_by_backend([None, "junk"], self.backend)
        self.assertEqual(kept, [])
        self.assertEqual(skipped, [])

    def test_user_machine_import_keeps_exactly_the_three_wlan_hosts(self):
        text = "\n".join(
            [
                "Host ic_eda",
                "  HostName 10.10.60.101",
                "  Port 2222",
                "Host ubuntu-cyp",
                "  HostName 100.66.103.47",
                "Host ubuntu-cyp2",
                "  HostName 198.51.100.2",
                "Host 192.168.4.94",
                "Host 192.168.4.234",
                "Host 192.168.4.19",
            ]
        )
        hosts = parse_ssh_config_text(text)
        candidates = [host_to_target(host) for host in hosts]
        kept, skipped = filter_by_backend(candidates, self.backend)
        self.assertEqual(
            sorted(target["address"] for target in kept),
            ["192.168.4.19", "192.168.4.234", "192.168.4.94"],
        )
        self.assertEqual(
            sorted(entry["name"] for entry in skipped),
            ["ic_eda", "ubuntu-cyp", "ubuntu-cyp2"],
        )


if __name__ == "__main__":
    unittest.main()