"""Tests for config handling and the privileged helper's trust boundary."""

import json
import os
import tempfile
import unittest
from pathlib import Path


try:
    from tests.support import FakeBackend, make_config
except ImportError:  # pragma: no cover - direct invocation
    from support import FakeBackend, make_config

from lanrf import helper, model
from lanrf.backends import set_backend
from lanrf.config import (
    DEFAULT_CONFIG,
    Config,
    load_config,
    read_state,
    save_config,
    write_state,
)


class ConfigCompatibilityTests(unittest.TestCase):
    def test_two_zero_x_file_still_loads(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "targets": [
                            {
                                "name": "u55c",
                                "address": "192.168.4.19",
                                "interface": "",
                                "enabled": True,
                            },
                            {"name": "alias", "ip": "192.168.4.20", "enabled": True},
                        ],
                        "interval_seconds": 30,
                        "auto_fix": True,
                        "autostart": False,
                    }
                ),
                encoding="utf-8",
            )
            config = load_config(path)

        self.assertEqual(len(config.targets), 2)
        self.assertEqual(config.targets[1]["address"], "192.168.4.20")
        # New behaviour defaults are applied without touching the caller's keys.
        self.assertEqual(config.routing_mode, "rule")
        self.assertEqual(config.rule_table, 168)
        self.assertEqual(config.interval_seconds, 30)

    def test_unknown_keys_are_preserved_on_save(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.json"
            path.write_text(
                json.dumps({"targets": [], "future_setting": {"a": 1}}), encoding="utf-8"
            )
            config = load_config(path)
            self.assertTrue(config.save())
            saved = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(saved["future_setting"], {"a": 1})

    def test_invalid_values_fall_back_to_defaults(self):
        config = Config(
            {
                "routing_mode": "nonsense",
                "rule_table": 99999,
                "rule_preference": 999999,
                "interval_seconds": "soon",
            }
        )
        self.assertEqual(config.routing_mode, "rule")
        self.assertEqual(config.rule_table, 168)
        self.assertEqual(config.rule_preference, 1200)
        self.assertEqual(config.interval_seconds, 10)

    def test_policy_routing_flag_tracks_mode(self):
        self.assertTrue(make_config(routing_mode="rule").policy_routing)
        self.assertFalse(make_config(routing_mode="main").policy_routing)

    def test_save_is_atomic_and_leaves_no_temp_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.json"
            config = Config(DEFAULT_CONFIG, path=path)
            self.assertTrue(config.save())
            leftovers = [
                entry.name for entry in Path(tmpdir).iterdir() if entry.name != "config.json"
            ]
            self.assertEqual(leftovers, [])
            self.assertTrue(json.loads(path.read_text(encoding="utf-8")))

    def test_save_config_accepts_plain_dict(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.json"
            self.assertTrue(save_config({"targets": [], "auto_fix": False}, path))
            self.assertFalse(load_config(path).auto_fix)

    def test_write_and_read_state_round_trip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "state.json"
            self.assertTrue(write_state({"ok": True, "targets": 2}, path))
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["targets"], 2)

        # The default path is honoured too (pointed at a temp dir by the env).
        self.assertTrue(write_state({"ok": False, "reason": "poll"}))
        self.assertEqual(read_state().get("reason"), "poll")


class HelperValidationTests(unittest.TestCase):
    def test_protected_tables_are_accepted_verbatim(self):
        for value in ("main", "local", "default", None, ""):
            with self.subTest(value=value):
                self.assertIn(helper.validate_table(value), {"main", "local", "default"})

    def test_numeric_tables_in_range(self):
        self.assertEqual(helper.validate_table("168"), "168")
        self.assertEqual(helper.validate_table(52), "52")

    def test_reserved_and_out_of_range_tables_rejected(self):
        for value in ("253", "254", "255", "0", "99999", "1; rm -rf /", "weird name"):
            with self.subTest(value=value):
                with self.assertRaises(helper.ValidationError):
                    helper.validate_table(value)

    def test_interface_must_be_usable(self):
        backend = FakeBackend()
        self.assertEqual(helper.validate_interface("wlp0s20f3", backend=backend), "wlp0s20f3")
        # A bridge is a legitimate LAN exit (common on servers), so it stays
        # allowed; tunnels, loopback and malformed names never are.
        self.assertEqual(helper.validate_interface("docker0", backend=backend), "docker0")
        for value in ("utun7", "lo", "", "bad name!", "wlp0s20f3;sh", "nosuchif"):
            with self.subTest(value=value):
                with self.assertRaises(helper.ValidationError):
                    helper.validate_interface(value, backend=backend)

    def test_destination_must_be_private(self):
        self.assertEqual(helper.validate_destination("192.168.4.19"), (4, "192.168.4.19/32"))
        self.assertEqual(helper.validate_destination("192.168.8.0/24"), (4, "192.168.8.0/24"))
        self.assertEqual(helper.validate_destination("fd00::1"), (6, "fd00::1/128"))
        for value in ("8.8.8.8", "0.0.0.0/0", "2001:4860::8888", "192.168.0.0/8", "", "junk"):
            with self.subTest(value=value):
                with self.assertRaises(helper.ValidationError):
                    helper.validate_destination(value)

    def test_family_mismatch_is_rejected(self):
        with self.assertRaises(helper.ValidationError):
            helper.normalize_item(
                {"address": "192.168.4.19", "interface": "wlp0s20f3", "family": 6}
            )

    def test_batch_reports_partial_failures_without_aborting(self):
        backend = FakeBackend()
        applied, errors = helper.apply_batch(
            [
                {"address": "192.168.4.19", "interface": "wlp0s20f3"},
                {"address": "8.8.8.8", "interface": "wlp0s20f3"},
                {"address": "192.168.4.20", "interface": "utun7"},
            ],
            backend=backend,
        )
        self.assertEqual(len(applied), 1)
        self.assertEqual(len(errors), 2)
        self.assertEqual(applied[0]["destination"], "192.168.4.19/32")

    def test_batch_installs_rule_when_config_asks_for_it(self):
        backend = FakeBackend()
        config = make_config(routing_mode="rule", rule_table=168, rule_preference=1200)
        applied, errors = helper.apply_batch(
            [{"address": "192.168.4.19", "interface": "wlp0s20f3", "table": "168"}],
            config=config,
            backend=backend,
        )
        self.assertEqual(errors, [])
        self.assertTrue(applied[0]["rule"])
        self.assertTrue(applied[0]["changed"])
        self.assertEqual(backend.rules(4)[0]["pref"], 1200)

    def test_batch_in_main_mode_skips_rules(self):
        backend = FakeBackend()
        config = make_config(routing_mode="main")
        helper.apply_batch(
            [{"address": "192.168.4.19", "interface": "wlp0s20f3"}],
            config=config,
            backend=backend,
        )
        self.assertEqual(backend.rules(4), [])
        self.assertIn("192.168.4.19/32", backend.route_prefixes("main"))

    def test_batch_rejects_non_list(self):
        with self.assertRaises(helper.ValidationError):
            helper.apply_batch({"address": "192.168.4.19"})

    def test_apply_single_reports_kernel_failure(self):
        backend = FakeBackend()
        backend.fail_ensure_route = True
        with self.assertRaises(helper.RouteFailure):
            helper.apply_single("192.168.4.19", "wlp0s20f3", backend=backend)


class DaemonPreferredFixTests(unittest.TestCase):
    """The authorization experience: the daemon must be tried before pkexec."""

    def setUp(self):
        from lanrf.backends import set_backend

        self.backend = FakeBackend()
        self._previous = set_backend(self.backend)
        self.items = [{"address": "192.168.4.19/32", "family": 4, "interface": "wlp0s20f3"}]

    def tearDown(self):
        from lanrf.backends import set_backend

        set_backend(self._previous)

    def _spawn(self, outcome):
        import contextlib
        import io

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = helper.main(["--batch-json", json.dumps(self.items)])
        return code

    def test_daemon_short_circuits_pkexec_when_it_confirms_the_routes(self):
        from lanrf import privileged
        from lanrf.config import write_state

        write_state(
            {
                "snapshots": [
                    {"address": "192.168.4.19", "effective_address": "192.168.4.19/32", "ok": True}
                ]
            }
        )
        with unittest.mock.patch.object(
            privileged, "_daemon_repair", return_value=(list(self.items), [], {"changed": 1})
        ), unittest.mock.patch.object(privileged.subprocess, "run") as spawn:
            outcome = privileged.run_helper(self.items, use_pkexec=True)

        spawn.assert_not_called()
        self.assertEqual(outcome["method"], "daemon")
        self.assertEqual(outcome["return_code"], 0)

    def test_falls_back_to_pkexec_for_targets_the_daemon_cannot_handle(self):
        from lanrf import privileged

        with unittest.mock.patch.object(
            privileged, "_daemon_repair", return_value=([], list(self.items), {"changed": 0})
        ), unittest.mock.patch.object(privileged.subprocess, "run") as spawn:
            spawn.return_value = unittest.mock.Mock(returncode=0, stdout="[]", stderr="")
            outcome = privileged.run_helper(self.items, use_pkexec=True)

        spawn.assert_called_once()
        self.assertEqual(outcome["method"], "pkexec")
        command = spawn.call_args.args[0]
        self.assertEqual(command[0], privileged.PKEXEC_PATH)

    def test_daemon_is_not_consulted_when_asked_to_go_direct(self):
        from lanrf import privileged

        with unittest.mock.patch.object(privileged, "_daemon_repair") as daemon_call, \
                unittest.mock.patch.object(privileged.subprocess, "run") as spawn:
            spawn.return_value = unittest.mock.Mock(returncode=0, stdout="[]", stderr="")
            outcome = privileged.run_helper(self.items, prefer_daemon=False)

        daemon_call.assert_not_called()
        self.assertEqual(outcome["method"], "pkexec")

    def test_missing_daemon_reports_every_item_as_remaining(self):
        from lanrf import privileged

        with unittest.mock.patch.object(
            privileged, "_daemon_repair", return_value=([], list(self.items), None)
        ):
            handled, remaining, report = privileged._daemon_repair(self.items)

        self.assertEqual(handled, [])
        self.assertEqual(remaining, self.items)
        self.assertIsNone(report)


class HelperCliTests(unittest.TestCase):
    def _run(self, argv):
        import contextlib
        import io

        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = helper.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def setUp(self):
        self._previous = set_backend(FakeBackend())

    def tearDown(self):
        set_backend(self._previous)

    def test_batch_json_success(self):
        payload = json.dumps([{"address": "192.168.4.19", "interface": "wlp0s20f3"}])
        code, stdout, stderr = self._run(["--batch-json", payload])
        self.assertEqual(code, helper.EXIT_OK, stderr)
        self.assertEqual(json.loads(stdout)[0]["destination"], "192.168.4.19/32")

    def test_invalid_json_exits_64(self):
        code, _stdout, stderr = self._run(["--batch-json", "{not json"])
        self.assertEqual(code, helper.EXIT_INVALID)
        self.assertIn("invalid JSON", stderr)

    def test_public_destination_is_rejected(self):
        payload = json.dumps([{"address": "8.8.8.8", "interface": "wlp0s20f3"}])
        code, _stdout, stderr = self._run(["--batch-json", payload])
        self.assertEqual(code, helper.EXIT_FAILED)
        self.assertIn("private", stderr)

    def test_usage_without_arguments(self):
        code, _stdout, stderr = self._run([])
        self.assertEqual(code, helper.EXIT_INVALID)
        self.assertIn("usage:", stderr)


class ProtocolStampTests(unittest.TestCase):
    def test_owned_detection_handles_numeric_and_named(self):
        numeric = model.route_entry("10.0.0.1/32", "eth0", 4, "main", protocol="66")
        named = model.route_entry("10.0.0.1/32", "eth0", 4, "main", protocol="lanrf")
        foreign = model.route_entry("10.0.0.1/32", "eth0", 4, "main", protocol="dhcp")
        self.assertTrue(numeric["owned"])
        self.assertTrue(named["owned"])
        self.assertFalse(foreign["owned"])


class ConfigDiscoveryScopeTests(unittest.TestCase):
    """Who is allowed to show up in the list of config files."""

    def _entries(self, tmpdir):
        from types import SimpleNamespace

        other_home = Path(tmpdir) / "other"
        (other_home / ".config/lan-route-fixer").mkdir(parents=True)
        other = other_home / ".config/lan-route-fixer/config.json"
        other.write_text("{}", encoding="utf-8")
        entries = [
            SimpleNamespace(pw_uid=0, pw_dir="/root"),
            SimpleNamespace(pw_uid=1000, pw_dir=str(Path(tmpdir) / "me")),
            SimpleNamespace(pw_uid=1001, pw_dir=str(other_home)),
        ]
        return entries, other

    def test_an_unprivileged_run_ignores_other_users_configs(self):
        from unittest import mock

        from lanrf import config

        with tempfile.TemporaryDirectory() as tmpdir:
            entries, other = self._entries(tmpdir)
            system = Path(tmpdir) / "system.json"
            own = Path(tmpdir) / "me.json"
            with mock.patch("pwd.getpwall", return_value=entries), \
                    mock.patch("os.geteuid", return_value=1000), \
                    mock.patch.object(config, "SYSTEM_CONFIG_PATH", system), \
                    mock.patch.object(config, "CONFIG_PATH", own):
                self.assertEqual(config.collect_config_paths(), [])

            # The same machine as root sees the other user's file.
            with mock.patch("pwd.getpwall", return_value=entries), \
                    mock.patch("os.geteuid", return_value=0), \
                    mock.patch.object(config, "SYSTEM_CONFIG_PATH", system), \
                    mock.patch.object(config, "CONFIG_PATH", own):
                self.assertEqual(config.collect_config_paths(), [other])

    def test_the_callers_own_file_follows_xdg_config_home(self):
        from unittest import mock

        from lanrf import config

        with tempfile.TemporaryDirectory() as tmpdir:
            entries, _other = self._entries(tmpdir)
            system = Path(tmpdir) / "system.json"
            own = Path(tmpdir) / "xdg" / "config.json"
            own.parent.mkdir()
            own.write_text("{}", encoding="utf-8")
            with mock.patch("pwd.getpwall", return_value=entries), \
                    mock.patch("os.geteuid", return_value=1000), \
                    mock.patch.object(config, "SYSTEM_CONFIG_PATH", system), \
                    mock.patch.object(config, "CONFIG_PATH", own):
                self.assertEqual(config.collect_config_paths(), [own])


if __name__ == "__main__":
    unittest.main()
