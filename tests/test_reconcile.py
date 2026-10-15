"""Tests for the reconciliation engine: the aTrust scenarios, as fixtures.

Each test below encodes a failure mode observed in the field:

* the VPN client delegates a prefix to the physical NIC, so a target that was
  never added silently works - until the delegation changes;
* the VPN client installs a *broader* route that captures a pinned host;
* the VPN client deletes our host route outright when it connects;
* policy routing must keep working even when the main table is rewritten.
"""

import unittest

try:  # works both as a package and with `discover -s tests`
    from tests.support import FakeBackend, make_config
except ImportError:  # pragma: no cover - direct invocation
    from support import FakeBackend, make_config
from lanrf import model
from lanrf.reconcile import (
    ACTION_DELETE_RULE,
    ACTION_ROUTE,
    ACTION_RULE,
    apply_actions,
    build_state,
    inspect,
    plan,
    reconcile,
)
from lanrf.routing import InterfaceSelector


def _config(targets, **overrides):
    overrides.setdefault("targets", targets)
    return make_config(**overrides)


class PlanTests(unittest.TestCase):
    def test_empty_table_produces_rule_then_route(self):
        backend = FakeBackend()
        config = _config([{"name": "u55c", "address": "192.168.4.19", "interface": "", "enabled": True}])

        snapshots, actions = build_state(config.enabled_targets, config, backend)

        self.assertEqual([action["kind"] for action in actions], [ACTION_RULE, ACTION_ROUTE])
        self.assertEqual(actions[0]["destination"], "192.168.4.19/32")
        self.assertEqual(actions[0]["table"], "168")
        self.assertEqual(actions[1]["interface"], "wlp0s20f3")
        self.assertEqual(snapshots[0]["desired"], "wlp0s20f3")
        self.assertEqual(snapshots[0]["state"], model.ROUTE_STATE_MISSING)

    def test_main_mode_skips_policy_rules(self):
        backend = FakeBackend()
        config = _config(
            [{"address": "192.168.4.19", "interface": "", "enabled": True}],
            routing_mode="main",
        )
        _snapshots, actions = build_state(config.enabled_targets, config, backend)
        self.assertEqual([action["kind"] for action in actions], [ACTION_ROUTE])
        self.assertEqual(actions[0]["table"], "main")

    def test_host_target_pins_to_same_subnet_interface(self):
        backend = FakeBackend(
            interfaces={
                "eth0": {"kind": "", "up": True, "running": True},
                "wlp0s20f3": {"kind": "", "up": True, "running": True},
            },
            networks=[
                ("eth0", "10.8.0.0/24", "10.8.0.5"),
                ("wlp0s20f3", "192.168.4.0/24", "192.168.4.238"),
            ],
            defaults=["eth0"],
        )
        config = _config([{"address": "192.168.4.234", "interface": "", "enabled": True}])
        snapshots, _actions = build_state(config.enabled_targets, config, backend)
        # The default route is eth0, but the target lives on the Wi-Fi subnet.
        self.assertEqual(snapshots[0]["desired"], "wlp0s20f3")

    def test_explicit_interface_is_respected(self):
        backend = FakeBackend(
            interfaces={
                "eth0": {"kind": "", "up": True, "running": True},
                "wlp0s20f3": {"kind": "", "up": True, "running": True},
            }
        )
        config = _config([{"address": "192.168.4.234", "interface": "eth0", "enabled": True}])
        snapshots, _actions = build_state(config.enabled_targets, config, backend)
        self.assertEqual(snapshots[0]["desired"], "eth0")

    def test_unusable_explicit_interface_falls_back(self):
        backend = FakeBackend()
        config = _config([{"address": "192.168.4.234", "interface": "utun7", "enabled": True}])
        snapshots, _actions = build_state(config.enabled_targets, config, backend)
        self.assertEqual(snapshots[0]["desired"], "wlp0s20f3")

    def test_broader_vpn_route_is_reported_as_the_culprit(self):
        backend = FakeBackend()
        # aTrust captured the whole /24 for its tunnel.
        backend.add_raw_route("192.168.4.0/24", "utun7", protocol="boot")
        config = _config([{"address": "192.168.4.234", "interface": "", "enabled": True}])

        snapshots, actions = build_state(config.enabled_targets, config, backend)

        self.assertEqual(snapshots[0]["state"], model.ROUTE_STATE_WRONG_INTERFACE)
        self.assertEqual(snapshots[0]["current"], "utun7")
        self.assertIn("192.168.4.0/24", snapshots[0]["covering"])
        # A policy rule plus a host route is the fix, not "move the route".
        self.assertEqual([action["kind"] for action in actions], [ACTION_RULE, ACTION_ROUTE])

    def test_already_correct_route_is_not_touched(self):
        backend = FakeBackend()
        backend.add_raw_route("192.168.4.19/32", "wlp0s20f3", table="168", protocol="lanrf")
        backend.ensure_rule("192.168.4.19/32", "168")
        config = _config([{"address": "192.168.4.19", "interface": "", "enabled": True}])

        snapshots, actions = build_state(config.enabled_targets, config, backend)

        self.assertEqual(actions, [])
        self.assertTrue(snapshots[0]["ok"])
        self.assertEqual(snapshots[0]["state"], model.ROUTE_STATE_OK)
        self.assertTrue(snapshots[0]["route_installed"])
        self.assertTrue(snapshots[0]["rule_installed"])

    def test_missing_policy_rule_makes_a_present_route_unsafe(self):
        backend = FakeBackend()
        backend.add_raw_route("192.168.4.19/32", "wlp0s20f3", table="168", protocol="lanrf")
        config = _config([{"address": "192.168.4.19", "interface": "", "enabled": True}])

        snapshots, actions = build_state(config.enabled_targets, config, backend)

        self.assertFalse(snapshots[0]["ok"])
        self.assertTrue(snapshots[0]["route_installed"])
        self.assertFalse(snapshots[0]["rule_installed"])
        self.assertIn("policy rule", snapshots[0]["reason"])
        self.assertEqual([action["kind"] for action in actions], [ACTION_RULE])

    def test_disabled_and_invalid_targets_are_skipped(self):
        backend = FakeBackend()
        config = _config(
            [
                {"address": "192.168.4.19", "interface": "", "enabled": False},
                {"address": "8.8.8.8", "interface": "", "enabled": True},
            ]
        )
        snapshots, actions = build_state(config.targets, config, backend)
        self.assertEqual(actions, [])
        self.assertEqual(len(snapshots), 2)
        self.assertTrue(snapshots[0]["skipped"])
        self.assertTrue(snapshots[1]["skipped"])
        self.assertEqual(snapshots[1]["state"], model.ROUTE_STATE_INVALID)

    def test_no_usable_interface_is_reported_not_crashed(self):
        backend = FakeBackend(interfaces={}, networks=[], defaults=[])
        config = _config([{"address": "192.168.4.19", "interface": "", "enabled": True}])
        snapshots, actions = build_state(config.enabled_targets, config, backend)
        self.assertEqual(actions, [])
        self.assertFalse(snapshots[0]["ok"])
        self.assertIn("no usable LAN interface", snapshots[0]["reason"])

    def test_kernel_style_rule_output_is_recognised_as_installed(self):
        """`ip rule show` prints a host rule without the /32 it was added with.

        Comparing the raw strings made the tool believe its own rule was
        missing: it reinstalled it every pass and reported the target as broken
        forever. Verified against the real kernel by tools/verify-namespace.
        """
        backend = FakeBackend(rule_output_style="kernel")
        config = _config([{"address": "192.168.4.19", "interface": "", "enabled": True}])

        reconcile(config.enabled_targets, config, backend)

        self.assertEqual(backend.rules(4)[0]["to"], "192.168.4.19")
        snapshots, actions = build_state(config.enabled_targets, config, backend)
        self.assertTrue(snapshots[0]["rule_installed"], snapshots[0])
        self.assertTrue(snapshots[0]["ok"], snapshots[0])
        self.assertEqual(actions, [])

    def test_kernel_style_rule_output_is_still_garbage_collected(self):
        backend = FakeBackend(rule_output_style="kernel")
        config = _config([{"address": "192.168.4.19", "interface": "", "enabled": True}])
        reconcile(config.enabled_targets, config, backend)

        backend.routes_by_table["168"] = []
        empty = _config([])
        snapshots, actions = build_state(empty.targets, empty, backend)

        deletions = [action for action in actions if action["kind"] == ACTION_DELETE_RULE]
        self.assertEqual([action["destination"] for action in deletions], ["192.168.4.19/32"])

    def test_stale_policy_rules_are_garbage_collected(self):
        backend = FakeBackend()
        backend.ensure_rule("10.0.0.5/32", "168")
        backend.ensure_rule("192.168.4.19/32", "168")
        config = _config([{"address": "192.168.4.19", "interface": "", "enabled": True}])

        _snapshots, actions = build_state(config.enabled_targets, config, backend)

        deletions = [action for action in actions if action["kind"] == ACTION_DELETE_RULE]
        self.assertEqual([action["destination"] for action in deletions], ["10.0.0.5/32"])

    def test_foreign_policy_rules_are_left_alone(self):
        backend = FakeBackend()
        # Tailscale-style rule pointing somewhere else entirely.
        backend.rules_by_family[4].append({"pref": 5270, "to": "", "lookup": "52"})
        config = _config([{"address": "192.168.4.19", "interface": "", "enabled": True}])
        _snapshots, actions = build_state(config.enabled_targets, config, backend)
        self.assertEqual([action for action in actions if action["kind"] == ACTION_DELETE_RULE], [])

    def test_per_target_expand_only_affects_that_target(self):
        backend = FakeBackend(
            interfaces={
                "eth0": {"kind": "", "up": True, "running": True},
                "wlp0s20f3": {"kind": "", "up": True, "running": True},
            },
            networks=[
                ("eth0", "10.8.0.0/24", "10.8.0.5"),
                ("wlp0s20f3", "192.168.4.0/24", "192.168.4.238"),
            ],
            defaults=["eth0"],
        )
        config = _config(
            [
                {"name": "whole-subnet", "address": "192.168.4.234", "interface": "eth0",
                 "enabled": True, "expand": True},
                {"name": "single-host", "address": "10.8.0.9", "interface": "eth0",
                 "enabled": True},
            ]
        )
        snapshots, actions = build_state(config.targets, config, backend)
        destinations = {
            action["destination"] for action in actions if action["kind"] == ACTION_ROUTE
        }
        self.assertIn("192.168.4.0/24", destinations)
        self.assertIn("10.8.0.9/32", destinations)
        self.assertEqual(snapshots[0]["effective_address"], "192.168.4.0/24")
        self.assertEqual(snapshots[1]["effective_address"], "10.8.0.9/32")

    def test_expand_host_targets_widens_to_local_subnet(self):
        backend = FakeBackend()
        config = _config(
            [{"address": "192.168.4.234", "interface": "", "enabled": True}],
            expand_host_targets=True,
        )
        snapshots, actions = build_state(config.enabled_targets, config, backend)
        self.assertEqual(snapshots[0]["effective_address"], "192.168.4.0/24")
        route_actions = [action for action in actions if action["kind"] == ACTION_ROUTE]
        self.assertEqual(route_actions[0]["destination"], "192.168.4.0/24")

    def test_source_address_is_pinned_from_the_interface(self):
        backend = FakeBackend()
        config = _config([{"address": "192.168.4.19", "interface": "", "enabled": True}])
        _snapshots, actions = build_state(config.enabled_targets, config, backend)
        route_actions = [action for action in actions if action["kind"] == ACTION_ROUTE]
        self.assertEqual(route_actions[0]["source"], "192.168.4.238")

    def test_unprivileged_caller_gets_no_actions_but_sees_pending(self):
        backend = FakeBackend(privileged=False)
        config = _config([{"address": "192.168.4.19", "interface": "", "enabled": True}])
        snapshots, actions = build_state(config.enabled_targets, config, backend)
        self.assertEqual(actions, [])
        self.assertIn("root", snapshots[0]["pending"])

    def test_ipv6_target_uses_default_interface(self):
        backend = FakeBackend()
        config = _config([{"address": "fd00::5", "interface": "", "enabled": True}])
        snapshots, actions = build_state(config.enabled_targets, config, backend)
        self.assertEqual(snapshots[0]["family"], 6)
        self.assertEqual(actions[0]["destination"], "fd00::5/128")


class ApplyTests(unittest.TestCase):
    def test_apply_installs_rule_and_route(self):
        backend = FakeBackend()
        config = _config([{"address": "192.168.4.19", "interface": "", "enabled": True}])
        snapshots, actions = build_state(config.enabled_targets, config, backend)

        outcome = apply_actions(actions, backend)

        self.assertEqual(outcome["changed"], 2)
        self.assertEqual(outcome["failed"], 0)
        self.assertIn("192.168.4.19/32", backend.route_prefixes("168"))
        self.assertEqual(backend.rules(4)[0]["lookup"], "168")

    def test_apply_is_idempotent(self):
        backend = FakeBackend()
        config = _config([{"address": "192.168.4.19", "interface": "", "enabled": True}])
        reconcile(config.enabled_targets, config, backend)
        second = reconcile(config.enabled_targets, config, backend)
        self.assertEqual(second["changed"], 0)
        self.assertEqual(second["failed"], 0)
        self.assertTrue(second["ok"])

    def test_one_failure_does_not_stop_the_others(self):
        backend = FakeBackend()
        backend.fail_ensure_route = True
        backend.fail_ensure_rule = True
        config = _config(
            [
                {"address": "192.168.4.19", "interface": "", "enabled": True},
                {"address": "192.168.4.234", "interface": "", "enabled": True},
            ]
        )
        snapshots, actions = build_state(config.enabled_targets, config, backend)
        outcome = apply_actions(actions, backend)
        self.assertEqual(outcome["failed"], len(actions))
        self.assertTrue(outcome["errors"])

    def test_reconcile_reports_verification_state(self):
        backend = FakeBackend()
        config = _config([{"address": "192.168.4.19", "interface": "", "enabled": True}])
        report = reconcile(config.enabled_targets, config, backend)
        self.assertTrue(report["ok"])
        self.assertEqual(report["bad"], 0)
        self.assertEqual(report["routing_mode"], "rule")
        self.assertEqual(report["rule_table"], 168)

    def test_inspect_is_read_only(self):
        backend = FakeBackend()
        config = _config([{"address": "192.168.4.19", "interface": "", "enabled": True}])
        inspect(config.enabled_targets, config, backend)
        self.assertEqual(backend.calls, [])


class VpnScenarioTests(unittest.TestCase):
    """The regression that matters: a VPN client rewriting the table."""

    def test_host_route_survives_vpn_rewriting_the_main_table(self):
        backend = FakeBackend()
        config = _config([{"address": "192.168.4.19", "interface": "", "enabled": True}])
        selector = InterfaceSelector(backend)

        # 1. Working state: our rule + route exist.
        first = reconcile(config.enabled_targets, config, backend, selector=selector)
        self.assertTrue(first["ok"])

        # 2. aTrust connects and floods the main table, capturing the /24.
        backend.add_raw_route("192.168.4.0/25", "utun7", protocol="boot")
        backend.add_raw_route("192.168.4.128/26", "utun7", protocol="boot")
        backend.add_raw_route("192.168.4.192/27", "utun7", protocol="boot")

        # 3. The very next inspect must still report "ok": the policy rule keeps
        #    the dedicated table authoritative no matter what main says.
        snapshots, actions = build_state(
            config.enabled_targets, config, backend, selector=selector
        )
        self.assertTrue(snapshots[0]["ok"], snapshots[0])
        self.assertEqual(actions, [])

    def test_vpn_deleting_our_route_is_repaired_by_the_next_pass(self):
        backend = FakeBackend()
        config = _config([{"address": "192.168.4.19", "interface": "", "enabled": True}])
        selector = InterfaceSelector(backend)
        reconcile(config.enabled_targets, config, backend, selector=selector)

        # aTrust's route installation deletes conflicting entries.
        backend.routes_by_table["168"] = []
        backend.routes_by_table["main"] = [
            entry
            for entry in backend.routes_by_table["main"]
            if entry["prefix"] != "192.168.4.19/32"
        ]
        backend.add_raw_route("192.168.4.0/25", "utun7", protocol="boot")

        snapshots, actions = build_state(
            config.enabled_targets, config, backend, selector=selector
        )
        self.assertFalse(snapshots[0]["ok"])
        self.assertEqual(snapshots[0]["current"], "utun7")
        self.assertIn(ACTION_ROUTE, [action["kind"] for action in actions])

        apply_actions(actions, backend)
        self.assertIn("192.168.4.19/32", backend.route_prefixes("168"))

    def test_same_subnet_match_beats_the_default_route(self):
        backend = FakeBackend(
            interfaces={
                "eth0": {"kind": "", "up": True, "running": True},
                "wlp0s20f3": {"kind": "", "up": True, "running": True},
            },
            networks=[
                ("eth0", "10.8.0.0/24", "10.8.0.5"),
                ("wlp0s20f3", "192.168.4.0/24", "192.168.4.238"),
            ],
            defaults=["eth0"],
        )
        config = _config([{"address": "192.168.4.234", "interface": "", "enabled": True}])
        selector = InterfaceSelector(backend)
        first, _actions = build_state(
            config.enabled_targets, config, backend, selector=selector
        )
        self.assertEqual(first[0]["desired"], "wlp0s20f3")

        # The Wi-Fi address briefly disappears while the VPN reconfigures, so
        # the default route (eth0) is the only remaining signal.
        backend.networks = [("eth0", "10.8.0.0/24", "10.8.0.5")]
        second, _actions = build_state(
            config.enabled_targets, config, backend, selector=selector
        )
        self.assertEqual(second[0]["desired"], "eth0")

        # When the address comes back the same-subnet interface wins again, so
        # a transient blip does not permanently move the route.
        backend.networks = [
            ("eth0", "10.8.0.0/24", "10.8.0.5"),
            ("wlp0s20f3", "192.168.4.0/24", "192.168.4.238"),
        ]
        third, _actions = build_state(
            config.enabled_targets, config, backend, selector=selector
        )
        self.assertEqual(third[0]["desired"], "wlp0s20f3")

    def test_previous_choice_is_reused_when_nothing_matches(self):
        """A remembered interface beats picking an arbitrary first candidate."""
        backend = FakeBackend(
            interfaces={
                "eth0": {"kind": "", "up": True, "running": True},
                "enp0s31f6": {"kind": "", "up": True, "running": True},
            },
            networks=[("eth0", "10.8.0.0/24", "10.8.0.5")],
            defaults=[],
        )
        config = _config([{"address": "192.168.4.234", "interface": "", "enabled": True}])
        selector = InterfaceSelector(backend)
        first, _actions = build_state(
            config.enabled_targets, config, backend, selector=selector
        )
        picked = first[0]["desired"]
        self.assertIn(picked, {"eth0", "enp0s31f6"})

        # Drop every signal: no matching subnet, no default route.
        backend.networks = []
        second, _actions = build_state(
            config.enabled_targets, config, backend, selector=selector
        )
        self.assertEqual(second[0]["desired"], picked)


class DomainSplitTargetTests(unittest.TestCase):
    def test_subnet_and_host_targets_coexist(self):
        backend = FakeBackend()
        config = _config(
            [
                {"name": "NAS 网段", "address": "192.168.8.0/24", "interface": "eth0", "enabled": True},
                {"name": "台式机", "address": "192.168.4.234", "interface": "", "enabled": True},
            ]
        )
        snapshots, actions = build_state(config.enabled_targets, config, backend)
        destinations = [action["destination"] for action in actions if action["kind"] == ACTION_ROUTE]
        self.assertIn("192.168.8.0/24", destinations)
        self.assertIn("192.168.4.234/32", destinations)
        self.assertEqual(len(snapshots), 2)

    def test_plan_helper_matches_build_state(self):
        backend = FakeBackend()
        config = _config([{"address": "192.168.4.19", "interface": "", "enabled": True}])
        selector = InterfaceSelector(backend)
        actions = plan(config.enabled_targets, config, backend, selector=selector)
        self.assertEqual(len(actions), 2)


if __name__ == "__main__":
    unittest.main()
