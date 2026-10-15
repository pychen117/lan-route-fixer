"""Tests for garbage collection: route residue and target cruft."""

import json
import tempfile
import time
import unittest
from pathlib import Path

try:
    from tests.support import FakeBackend, make_config
except ImportError:  # pragma: no cover - direct invocation
    from support import FakeBackend, make_config

from lanrf.cleanup import (
    REASON_DISABLED_INVALID,
    REASON_NEVER_SEEN,
    REASON_STALE,
    analyze,
    analyze_routes,
    analyze_targets,
    keep_configs,
    prune_routes,
    prune_targets,
    read_discovery_cache,
    update_discovery_cache,
)
from lanrf.config import Config, load_config
from lanrf.model import ROUTE_PROTOCOL_NAME


class StaleRouteTests(unittest.TestCase):
    def setUp(self):
        self.backend = FakeBackend()

    def _configs(self, targets, **overrides):
        config = make_config(targets=targets, **overrides)
        return [("/tmp/config.json", config)]

    def test_our_leftover_route_is_detected(self):
        # A route this tool installed for a target that is gone.
        self.backend.add_raw_route("192.168.4.99/32", "wlp0s20f3", table="168",
                                   protocol=ROUTE_PROTOCOL_NAME)
        configs = self._configs(
            [{"address": "192.168.4.19", "interface": "", "enabled": True}]
        )
        plan = analyze_routes(self.backend, configs)
        self.assertIn("192.168.4.99/32", [item["destination"] for item in plan["routes"]])

    def test_configured_target_is_not_touched(self):
        self.backend.add_raw_route("192.168.4.19/32", "wlp0s20f3", table="168",
                                   protocol=ROUTE_PROTOCOL_NAME)
        configs = self._configs(
            [{"address": "192.168.4.19", "interface": "", "enabled": True}]
        )
        plan = analyze_routes(self.backend, configs)
        self.assertEqual(plan["routes"], [])

    def test_foreign_routes_are_never_touched(self):
        # Tailscale's table 52, a DHCP default route, aTrust's own routes.
        self.backend.rules_by_family[4].append({"pref": 5270, "to": "", "lookup": "52"})
        self.backend.add_raw_route("192.168.4.0/24", "utun7", table="168", protocol="boot")
        self.backend.add_raw_route("10.0.0.0/8", "utun7", protocol="boot")
        configs = self._configs([])
        plan = analyze_routes(self.backend, configs)
        self.assertEqual(plan["routes"], [])

    def test_leftover_policy_rule_is_detected(self):
        self.backend.ensure_rule("10.0.0.5/32", "168")
        configs = self._configs([])
        plan = analyze_routes(self.backend, configs)
        self.assertEqual([item["kind"] for item in plan["routes"]], ["rule"])

    def test_prune_removes_only_the_residue(self):
        self.backend.add_raw_route("192.168.4.99/32", "wlp0s20f3", table="168",
                                   protocol=ROUTE_PROTOCOL_NAME)
        self.backend.add_raw_route("192.168.4.19/32", "wlp0s20f3", table="168",
                                   protocol=ROUTE_PROTOCOL_NAME)
        self.backend.ensure_rule("10.0.0.5/32", "168")
        self.backend.ensure_rule("192.168.4.19/32", "168")
        configs = self._configs(
            [{"address": "192.168.4.19", "interface": "", "enabled": True}]
        )

        outcome = prune_routes(self.backend, configs)

        self.assertTrue(outcome["ok"], outcome)
        self.assertEqual(outcome["removed_count"], 2)
        self.assertIn("192.168.4.19/32", self.backend.route_prefixes("168"))
        self.assertEqual(
            [rule["to"] for rule in self.backend.rules(4)], ["192.168.4.19/32"]
        )

    def test_dry_run_changes_nothing(self):
        self.backend.add_raw_route("192.168.4.99/32", "wlp0s20f3", table="168",
                                   protocol=ROUTE_PROTOCOL_NAME)
        configs = self._configs([])
        outcome = prune_routes(self.backend, configs, dry_run=True)
        self.assertEqual(outcome["removed_count"], 1)
        self.assertIn("192.168.4.99/32", self.backend.route_prefixes("168"))

    def test_main_mode_residue_is_found_in_the_main_table(self):
        self.backend.add_raw_route("192.168.4.99/32", "wlp0s20f3", table="main",
                                   protocol=ROUTE_PROTOCOL_NAME)
        configs = self._configs([], routing_mode="main")
        plan = analyze_routes(self.backend, configs)
        self.assertEqual(plan["tables"], ["main"])
        self.assertEqual(len(plan["routes"]), 1)

    def test_disabled_target_does_not_protect_its_route(self):
        """Turning a target off should release its route, not keep it forever."""
        self.backend.add_raw_route("192.168.4.19/32", "wlp0s20f3", table="168",
                                   protocol=ROUTE_PROTOCOL_NAME)
        configs = self._configs(
            [{"address": "192.168.4.19", "interface": "", "enabled": False}]
        )
        plan = analyze_routes(self.backend, configs)
        self.assertEqual(len(plan["routes"]), 1)


class StaleTargetTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_700_000_000.0

    def _config(self, targets):
        return Config({"targets": targets})

    def test_enabled_targets_are_never_offered(self):
        config = self._config(
            [{"address": "192.168.4.19", "enabled": True}]
        )
        result = analyze_targets(config, discovery={}, now=self.now)
        self.assertEqual(result["candidates"], [])

    def test_never_seen_disabled_target_is_offered(self):
        config = self._config([{"address": "192.168.4.77", "enabled": False}])
        result = analyze_targets(config, discovery={}, now=self.now)
        self.assertEqual(result["candidates"][0]["reason"], REASON_NEVER_SEEN)

    def test_recently_seen_disabled_target_is_kept(self):
        config = self._config([{"address": "192.168.4.19", "enabled": False}])
        discovery = {"192.168.4.19": self.now - 3 * 86400}
        result = analyze_targets(config, discovery=discovery, now=self.now)
        self.assertEqual(result["candidates"], [])

    def test_long_unseen_disabled_target_is_offered(self):
        config = self._config([{"address": "192.168.4.19", "enabled": False}])
        discovery = {"192.168.4.19": self.now - 90 * 86400}
        result = analyze_targets(config, discovery=discovery, now=self.now)
        self.assertEqual(result["candidates"][0]["reason"], REASON_STALE)
        self.assertEqual(result["candidates"][0]["age_days"], 90.0)

    def test_retention_window_is_configurable(self):
        config = self._config([{"address": "192.168.4.19", "enabled": False}])
        discovery = {"192.168.4.19": self.now - 10 * 86400}
        self.assertEqual(
            analyze_targets(config, discovery=discovery, now=self.now, pruned_after_days=7)[
                "count"
            ],
            1,
        )
        self.assertEqual(
            analyze_targets(config, discovery=discovery, now=self.now, pruned_after_days=30)[
                "count"
            ],
            0,
        )

    def test_invalid_address_is_offered_regardless_of_discovery(self):
        config = self._config([{"address": "not-an-ip", "enabled": False}])
        result = analyze_targets(config, discovery={}, now=self.now)
        self.assertEqual(result["candidates"][0]["reason"], REASON_DISABLED_INVALID)

    def test_prune_targets_removes_only_the_named_addresses(self):
        config = self._config(
            [
                {"name": "keep", "address": "192.168.4.19", "enabled": True},
                {"name": "drop", "address": "192.168.4.77", "enabled": False},
            ]
        )
        outcome = prune_targets(config, [{"address": "192.168.4.77"}], save=False)
        self.assertEqual(outcome["removed"], ["192.168.4.77"])
        self.assertEqual([t["address"] for t in config.targets], ["192.168.4.19"])

    def test_prune_targets_with_nothing_to_do(self):
        config = self._config([{"address": "192.168.4.19", "enabled": True}])
        outcome = prune_targets(config, [], save=False)
        self.assertEqual(outcome["removed_count"], 0)
        self.assertEqual(len(config.targets), 1)


class AnalyzeIntegrationTests(unittest.TestCase):
    def test_analyze_reads_configs_from_disk(self):
        """analyze() must re-read the files.

        A ``--config`` path is not part of the discovery list, and missing it
        would make that config's routes look like residue and get deleted.
        """
        backend = FakeBackend()
        backend.add_raw_route("192.168.4.99/32", "wlp0s20f3", table="168",
                              protocol=ROUTE_PROTOCOL_NAME)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "targets": [{"address": "192.168.4.77", "enabled": False}],
                        "routing_mode": "rule",
                        "rule_table": 168,
                    }
                ),
                encoding="utf-8",
            )
            report = analyze(
                backend=backend, config_paths=[str(path)], discovery={}, prune_days=30
            )
        self.assertEqual(report["routes"]["count"], 1)
        self.assertEqual(report["targets"][0]["count"], 1)
        self.assertEqual(report["count"], 2)

    def test_a_config_passed_explicitly_protects_its_routes(self):
        """The bug this guards against: pruning a route that is still in use."""
        backend = FakeBackend()
        backend.add_raw_route("192.168.4.19/32", "wlp0s20f3", table="168",
                              protocol=ROUTE_PROTOCOL_NAME)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "targets": [{"address": "192.168.4.19", "enabled": True}],
                        "routing_mode": "rule",
                        "rule_table": 168,
                    }
                ),
                encoding="utf-8",
            )
            report = analyze(backend=backend, config_paths=[str(path)], discovery={})
            outcome = prune_routes(backend, [(Path(path), load_config(path))])
        self.assertEqual(report["routes"]["count"], 0)
        self.assertEqual(outcome["removed_count"], 0)
        self.assertIn("192.168.4.19/32", backend.route_prefixes("168"))

    def test_analyze_with_an_empty_config_list_still_reports(self):
        backend = FakeBackend()
        report = analyze(backend=backend, config_paths=[], discovery={})
        self.assertEqual(report["count"], 0)
        self.assertTrue(report["targets"][0]["path"])

    def test_a_narrow_config_never_makes_another_configs_routes_look_stale(self):
        """The footgun: `--config system.json prune` must not delete the user's
        routes just because that one file was the only one inspected."""
        from unittest import mock

        backend = FakeBackend()
        backend.add_raw_route("192.168.4.19/32", "wlp0s20f3", table="168",
                              protocol=ROUTE_PROTOCOL_NAME)
        discovered = Config(
            {
                "targets": [{"address": "192.168.4.19", "enabled": True}],
                "routing_mode": "rule",
                "rule_table": 168,
            }
        )
        with mock.patch(
            "lanrf.cleanup.collect_all_configs",
            return_value=[(Path("/etc/lan-route-fixer/config.json"), discovered)],
        ):
            report = analyze(
                backend=backend, config_paths=["/tmp/mine.json"], discovery={}
            )
            # The deletion path must use the same keep-set as the report.
            outcome = prune_routes(backend, keep_configs(["/tmp/mine.json"]))
        self.assertEqual(report["routes"]["count"], 0)
        self.assertEqual(outcome["removed_count"], 0)
        self.assertIn("192.168.4.19/32", backend.route_prefixes("168"))


class RemovalFailureTests(unittest.TestCase):
    """A backend that refuses the delete must not be reported as success."""

    def test_refused_route_deletion_is_a_failure(self):
        backend = FakeBackend()
        backend.add_raw_route("192.168.4.99/32", "wlp0s20f3", table="168",
                              protocol=ROUTE_PROTOCOL_NAME)
        backend.remove_route = lambda item: False
        outcome = prune_routes(backend, [("/tmp/config.json", Config({"targets": []}))])
        self.assertEqual(outcome["removed_count"], 0)
        self.assertEqual(outcome["failed_count"], 1)
        self.assertFalse(outcome["ok"])
        self.assertIn("192.168.4.99/32", outcome["failed"][0])

    def test_a_raising_backend_is_reported_without_aborting_the_rest(self):
        backend = FakeBackend()
        backend.add_raw_route("192.168.4.98/32", "wlp0s20f3", table="168",
                              protocol=ROUTE_PROTOCOL_NAME)
        backend.add_raw_route("192.168.4.99/32", "wlp0s20f3", table="168",
                              protocol=ROUTE_PROTOCOL_NAME)
        calls = []

        def flaky(item):
            calls.append(item["destination"])
            if item["destination"] == "192.168.4.98/32":
                raise RuntimeError("permission denied")
            return True

        backend.remove_route = flaky
        outcome = prune_routes(backend, [("/tmp/config.json", Config({"targets": []}))])
        self.assertEqual(outcome["failed_count"], 1)
        self.assertEqual(outcome["removed_count"], 1)
        self.assertEqual(len(calls), 2)

    def test_the_listed_interface_is_passed_to_the_delete(self):
        backend = FakeBackend()
        backend.add_raw_route("192.168.4.99/32", "wlp0s20f3", table="168",
                              protocol=ROUTE_PROTOCOL_NAME)
        prune_routes(backend, [("/tmp/config.json", Config({"targets": []}))])
        _, item = next(call for call in backend.calls if call[0] == "remove_route")
        self.assertEqual(item["interface"], "wlp0s20f3")


class DiscoveryCacheTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.path = Path(self._tmpdir.name) / "discovered.json"

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_missing_or_broken_cache_reads_as_empty(self):
        self.assertEqual(read_discovery_cache(self.path), {})
        self.path.write_text("{not json", encoding="utf-8")
        self.assertEqual(read_discovery_cache(self.path), {})
        self.path.write_text('{"seen": "nope"}', encoding="utf-8")
        self.assertEqual(read_discovery_cache(self.path), {})

    def test_unparsable_timestamps_are_dropped(self):
        self.path.write_text(
            json.dumps({"seen": {"192.168.4.19": "yesterday", "192.168.4.20": 1700}}),
            encoding="utf-8",
        )
        self.assertEqual(read_discovery_cache(self.path), {"192.168.4.20": 1700.0})

    def test_update_merges_and_preserves_the_first_sighting_of_others(self):
        update_discovery_cache(["192.168.4.19"], path=self.path, now=1000.0)
        cache = update_discovery_cache(["192.168.4.20"], path=self.path, now=2000.0)
        self.assertEqual(cache["192.168.4.19"], 1000.0)
        self.assertEqual(cache["192.168.4.20"], 2000.0)
        # The same address is refreshed, not duplicated.
        cache = update_discovery_cache(["192.168.4.19"], path=self.path, now=3000.0)
        self.assertEqual(cache["192.168.4.19"], 3000.0)
        self.assertEqual(len(read_discovery_cache(self.path)), 2)

    def test_blank_addresses_are_ignored(self):
        cache = update_discovery_cache(["", "  ", None, "192.168.4.19"],
                                       path=self.path, now=5.0)
        self.assertEqual(list(cache), ["192.168.4.19"])

    def test_scan_records_what_it_saw(self):
        """`scan` is what feeds the cache that cleanup later consults."""
        from unittest import mock

        from lanrf import discovery, cleanup

        neighbour_output = (
            "192.168.4.19 dev wlp0s20f3 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
        )
        with mock.patch.object(cleanup, "DISCOVERY_CACHE_PATH", self.path), \
                mock.patch.object(discovery, "run_ip_ok", return_value=neighbour_output):
            found = discovery.detect_targets(resolve_names=False)
        self.assertEqual([target["address"] for target in found], ["192.168.4.19"])
        self.assertIn("192.168.4.19", read_discovery_cache(self.path))

        # record=False must leave the cache alone (used by read-only callers).
        self.path.unlink()
        with mock.patch.object(cleanup, "DISCOVERY_CACHE_PATH", self.path), \
                mock.patch.object(discovery, "run_ip_ok", return_value=neighbour_output):
            discovery.detect_targets(resolve_names=False, record=False)
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
