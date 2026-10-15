"""Parsing and validation of routes, rules and addresses."""

import unittest

try:  # works both as a package and with `discover -s tests`
    from tests import support  # noqa: F401  (sets sys.path and provides fakes)
except ImportError:  # pragma: no cover - direct invocation
    import support  # noqa: F401
from lanrf import model, targets
from lanrf.linux import parse_route_dump, parse_route_entry, parse_rule_dump, parse_rule_entry


class DestinationTests(unittest.TestCase):
    def test_normalize_bare_address_gets_host_prefix(self):
        self.assertEqual(
            model.normalize_destination("192.168.4.169"), (4, "192.168.4.169/32")
        )
        self.assertEqual(model.normalize_destination("fd00::1"), (6, "fd00::1/128"))

    def test_normalize_cidr_keeps_prefix(self):
        self.assertEqual(model.normalize_destination("192.168.8.0/24"), (4, "192.168.8.0/24"))

    def test_normalize_rejects_garbage(self):
        for value in ("", "not-an-ip", "192.168.4.0/33", "1.2.3.4.5"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                model.normalize_destination(value)

    def test_prefix_covers(self):
        self.assertTrue(model.prefix_covers("192.168.4.0/24", "192.168.4.234"))
        self.assertTrue(model.prefix_covers("192.168.0.0/16", "192.168.4.0/24"))
        self.assertFalse(model.prefix_covers("192.168.4.234/32", "192.168.4.0/24"))
        self.assertFalse(model.prefix_covers("192.168.4.0/24", "10.0.0.1/32"))
        self.assertFalse(model.prefix_covers("192.168.4.0/24", "fd00::1/128"))

    def test_protocol_argument_is_numeric(self):
        # iproute2 rejects unknown protocol *names* such as "lanrf".
        self.assertEqual(model.protocol_argument("lanrf"), "66")
        self.assertEqual(model.protocol_argument(None), "66")
        self.assertEqual(model.protocol_argument("dhcp"), "dhcp")


class RuleMatchingTests(unittest.TestCase):
    """Semantic rule comparison: the kernel drops /32 from host selectors."""

    def test_host_selector_with_and_without_prefixlen(self):
        rule = {"pref": 1200, "to": "192.168.4.19", "lookup": "168"}
        self.assertTrue(model.rule_matches(rule, "192.168.4.19/32", "168"))
        self.assertTrue(model.rule_matches(rule, "192.168.4.19", "168"))

    def test_different_destination_does_not_match(self):
        rule = {"pref": 1200, "to": "192.168.4.19", "lookup": "168"}
        self.assertFalse(model.rule_matches(rule, "192.168.4.20/32", "168"))
        self.assertFalse(model.rule_matches(rule, "192.168.4.0/24", "168"))

    def test_different_table_does_not_match(self):
        rule = {"pref": 1200, "to": "192.168.4.19", "lookup": "168"}
        self.assertFalse(model.rule_matches(rule, "192.168.4.19/32", "52"))

    def test_whole_table_rule_only_matches_without_a_destination(self):
        rule = {"pref": 5270, "to": "", "lookup": "52"}
        self.assertTrue(model.rule_matches(rule, None, "52"))
        self.assertFalse(model.rule_matches(rule, "192.168.4.19/32", "52"))

    def test_destination_rule_never_matches_a_wildcard_query(self):
        rule = {"pref": 1200, "to": "192.168.4.19", "lookup": "168"}
        self.assertFalse(model.rule_matches(rule, None, "168"))

    def test_ipv6_selector(self):
        rule = {"pref": 1200, "to": "fd00::5", "lookup": "168"}
        self.assertTrue(model.rule_matches(rule, "fd00::5/128", "168"))
        self.assertFalse(model.rule_matches(rule, "fd00::6/128", "168"))

    def test_unparsable_selector_falls_back_to_text_comparison(self):
        rule = {"pref": 1, "to": "weird", "lookup": "168"}
        self.assertTrue(model.rule_matches(rule, "weird", "168"))
        self.assertFalse(model.rule_matches(rule, "other", "168"))


class TargetValidationTests(unittest.TestCase):
    def test_private_ranges_accepted(self):
        for value in ("10.0.0.1", "172.16.0.1", "172.31.255.254", "192.168.4.169", "169.254.1.1"):
            with self.subTest(value=value):
                self.assertTrue(targets.valid_local_target(value))

    def test_public_and_mixed_ranges_rejected(self):
        for value in ("8.8.8.8", "172.15.0.1", "172.32.0.1", "2606:4700::1111", "192.168.0.0/8"):
            with self.subTest(value=value):
                self.assertFalse(targets.valid_local_target(value))

    def test_ipv6_local_ranges_accepted(self):
        for value in ("fd00::1234", "fe80::1234", "fc00::1/64"):
            with self.subTest(value=value):
                self.assertTrue(targets.valid_local_target(value))

    def test_normalize_interface_arg(self):
        self.assertEqual(targets.normalize_interface_arg("auto"), "")
        self.assertEqual(targets.normalize_interface_arg("AUTO"), "")
        self.assertEqual(targets.normalize_interface_arg(" none "), "")
        self.assertEqual(targets.normalize_interface_arg("eth0"), "eth0")


class RouteParsingTests(unittest.TestCase):
    def test_parses_device_route(self):
        entry = parse_route_entry("192.168.4.0/25 dev wlp0s20f3 scope link")
        self.assertEqual(entry["prefix"], "192.168.4.0/25")
        self.assertEqual(entry["interface"], "wlp0s20f3")
        self.assertEqual(entry["family"], 4)
        self.assertEqual(entry["table"], "main")
        self.assertFalse(entry["owned"])

    def test_parses_default_route_with_metric_and_source(self):
        entry = parse_route_entry(
            "default via 192.168.4.1 dev wlp0s20f3 proto dhcp src 192.168.4.238 metric 600"
        )
        self.assertEqual(entry["prefix"], "0.0.0.0/0")
        self.assertEqual(entry["interface"], "wlp0s20f3")
        self.assertEqual(entry["metric"], 600)
        self.assertEqual(entry["source"], "192.168.4.238")

    def test_parses_inline_and_explicit_table(self):
        inline = parse_route_entry("10.0.0.1 dev utun7 table 52", default_table="main")
        self.assertEqual(inline["table"], "52")
        explicit = parse_route_entry("192.168.4.19 dev wlp0s20f3", default_table="168")
        self.assertEqual(explicit["table"], "168")

    def test_own_routes_are_flagged(self):
        entry = parse_route_entry("192.168.4.19/32 dev wlp0s20f3 proto 66 scope link")
        self.assertTrue(entry["owned"])
        named = parse_route_entry("192.168.4.19/32 dev wlp0s20f3 proto lanrf scope link")
        self.assertTrue(named["owned"])

    def test_ipv6_route(self):
        entry = parse_route_entry("fd00::/64 dev wlp0s20f3 proto 66 metric 1024")
        self.assertEqual(entry["family"], 6)
        self.assertEqual(entry["prefix"], "fd00::/64")

    def test_special_destinations_do_not_crash(self):
        for line in ("unreachable default", "blackhole 10.0.0.0/8", "throw 192.168.0.0/16"):
            with self.subTest(line=line):
                self.assertIsNotNone(parse_route_entry(line))

    def test_dump_skips_unparsable_lines(self):
        dump = "\n".join(
            [
                "192.168.4.0/25 dev wlp0s20f3 scope link",
                "not a route at all",
                "10.0.0.0/8 dev utun7",
            ]
        )
        entries = parse_route_dump(dump)
        self.assertEqual([entry["prefix"] for entry in entries], ["192.168.4.0/25", "10.0.0.0/8"])


class RuleParsingTests(unittest.TestCase):
    def test_parses_policy_rule(self):
        rule = parse_rule_entry("1200:\tfrom all to 192.168.4.234/32 lookup 168")
        self.assertEqual(rule["pref"], 1200)
        self.assertEqual(rule["to"], "192.168.4.234/32")
        self.assertEqual(rule["lookup"], "168")

    def test_parses_fwmark_rule(self):
        rule = parse_rule_entry("5210:\tfrom all fwmark 0x80000/0xff0000 lookup main")
        self.assertEqual(rule["fwmark"], "0x80000/0xff0000")
        self.assertEqual(rule["lookup"], "main")

    def test_parses_unreachable_action(self):
        rule = parse_rule_entry("5250:\tfrom all fwmark 0x80000/0xff0000 unreachable")
        self.assertEqual(rule["action"], "unreachable")
        self.assertEqual(rule["lookup"], "")

    def test_dump_parses_multiple(self):
        dump = "\n".join(
            [
                "0:\tfrom all lookup local",
                "1200:\tfrom all to 192.168.4.19/32 lookup 168",
                "32766:\tfrom all lookup main",
            ]
        )
        rules = parse_rule_dump(dump)
        self.assertEqual([rule["pref"] for rule in rules], [0, 1200, 32766])


if __name__ == "__main__":
    unittest.main()
