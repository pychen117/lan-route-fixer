"""Daemon, netlink decoding, diagnostics and CLI tests."""

import contextlib
import io
import json
import os
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path


try:
    from tests.support import FakeBackend, make_config
except ImportError:  # pragma: no cover - direct invocation
    from support import FakeBackend, make_config

from lanrf import netlink
from lanrf.backends import set_backend
from lanrf.config import Config, write_state
from lanrf.daemon import (
    REASON_EVENT,
    REASON_POLL,
    REASON_START,
    REASON_TUNNEL,
    ReconcileDaemon,
    is_tunnel_name,
)


def _attribute(kind, payload):
    raw = struct.pack("=HH", 4 + len(payload), kind) + payload
    return raw + b"\x00" * ((4 - len(raw) % 4) % 4)


def _route_message(prefix, prefixlen, table, interface_index=2):
    """Build a synthetic RTM_NEWROUTE datagram."""
    rtmsg = struct.pack(
        "=BBBBBBBBI",
        socket.AF_INET,
        prefixlen,
        0,
        0,
        table if table <= 255 else 0,
        66,
        0,
        1,
        0,
    )
    body = _attribute(netlink.RTA_DST, socket.inet_aton(prefix))
    body += _attribute(netlink.RTA_OIF, struct.pack("=I", interface_index))
    if table > 255:
        body += _attribute(netlink.RTA_TABLE, struct.pack("=I", table))
    payload = rtmsg + body
    return struct.pack("=IHHII", netlink.HEADER_SIZE + len(payload), netlink.RTM_NEWROUTE, 0, 0, 0) + payload


def _link_message(ifname, message_type=netlink.RTM_NEWLINK):
    ifinfomsg = struct.pack("=BBHiII", socket.AF_UNSPEC, 0, 0, 0x10043, 0x0, 0x0)
    payload = ifinfomsg + _attribute(netlink.IFLA_IFNAME, ifname.encode() + b"\x00")
    return struct.pack("=IHHII", netlink.HEADER_SIZE + len(payload), message_type, 0, 0, 0) + payload


class NetlinkDecodeTests(unittest.TestCase):
    def test_route_message_decodes_prefix_and_table(self):
        events = netlink.decode_messages(_route_message("192.168.4.0", 25, 254))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.prefix, "192.168.4.0/25")
        self.assertEqual(event.table, 254)
        self.assertTrue(event.is_route)
        self.assertTrue(event.is_main_table)
        self.assertEqual(event.name, "route-add")

    def test_route_message_with_custom_table_is_not_main(self):
        events = netlink.decode_messages(_route_message("192.168.4.19", 32, 168))
        self.assertEqual(events[0].table, 168)
        self.assertFalse(events[0].is_main_table)

    def test_link_message_decodes_interface_name(self):
        events = netlink.decode_messages(_link_message("utun7"))
        self.assertEqual(events[0].ifname, "utun7")
        self.assertTrue(events[0].is_link)
        self.assertEqual(events[0].name, "link-up")

    def test_multiple_messages_in_one_datagram(self):
        combined = _route_message("10.0.0.0", 8, 254) + _link_message("wg0") + _route_message("192.168.4.19", 32, 168)
        events = netlink.decode_messages(combined)
        self.assertEqual(len(events), 3)
        self.assertEqual([event.name for event in events], ["route-add", "link-up", "route-add"])

    def test_truncated_datagram_is_ignored(self):
        message = _route_message("192.168.4.19", 32, 168)
        self.assertEqual(netlink.decode_messages(message[:12]), [])

    def test_error_and_done_messages_are_skipped(self):
        error = struct.pack("=IHHII", netlink.HEADER_SIZE + 4, netlink.NLMSG_ERROR, 0, 0, 0) + struct.pack("=i", 0)
        self.assertEqual(netlink.decode_messages(error), [])

    def test_monitor_is_available_on_linux(self):
        if not sys.platform.startswith("linux"):  # pragma: no cover
            self.skipTest("linux only")
        self.assertTrue(netlink.available())


class DaemonEventTests(unittest.TestCase):
    def test_tunnel_name_detection(self):
        for name in ("utun7", "tun0", "wg0", "tailscale0", "ppp0", "ipsec0", "vpn0"):
            with self.subTest(name=name):
                self.assertTrue(is_tunnel_name(name))
        for name in ("wlp0s20f3", "eth0", "eno1", "docker0", ""):
            with self.subTest(name=name):
                self.assertFalse(is_tunnel_name(name))

    def test_classify_marks_tunnel_transitions(self):
        daemon = ReconcileDaemon(backend=FakeBackend())
        events = netlink.decode_messages(_link_message("utun7"))
        self.assertEqual(daemon._classify_events(events), REASON_TUNNEL)
        self.assertEqual(daemon.stats["events"], 1)

    def test_classify_marks_plain_route_changes(self):
        daemon = ReconcileDaemon(backend=FakeBackend())
        events = netlink.decode_messages(_route_message("192.168.4.0", 25, 254))
        self.assertEqual(daemon._classify_events(events), REASON_EVENT)

    def test_debounce_swallows_a_burst(self):
        class BurstMonitor:
            def __init__(self, bursts):
                self.bursts = list(bursts)

            def wait(self, timeout=None):
                return self.bursts.pop(0) if self.bursts else []

            def close(self):
                pass

        daemon = ReconcileDaemon(backend=FakeBackend())
        burst = netlink.decode_messages(_route_message("10.0.0.0", 8, 254))
        daemon._monitor = BurstMonitor([burst, burst, []])
        daemon._debounce()
        # Two bursts absorbed (each counted), then the empty wait ends it.
        self.assertEqual(daemon.stats["events"], 2)


class DaemonLoopTests(unittest.TestCase):
    def setUp(self):
        self.backend = FakeBackend()
        self._previous = set_backend(self.backend)
        self._tmpdir = tempfile.TemporaryDirectory()
        self.config_path = Path(self._tmpdir.name) / "config.json"
        self.config_path.write_text(
            json.dumps(
                {
                    "targets": [
                        {"name": "u55c", "address": "192.168.4.19", "interface": "", "enabled": True}
                    ]
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self):
        set_backend(self._previous)
        self._tmpdir.cleanup()

    def _daemon(self, **kwargs):
        return ReconcileDaemon(
            backend=self.backend, config_paths=[str(self.config_path)], **kwargs
        )

    def test_first_pass_repairs_then_second_pass_is_quiet(self):
        daemon = self._daemon()
        first = daemon.pass_once(reason=REASON_START)
        self.assertEqual(first["changed"], 2)
        self.assertTrue(first["ok"])

        second = daemon.pass_once(reason=REASON_POLL)
        self.assertEqual(second["changed"], 0)
        self.assertTrue(second["ok"])
        self.assertEqual(daemon.stats["passes"], 2)

    def test_pass_recovers_after_the_vpn_deletes_the_route(self):
        daemon = self._daemon()
        daemon.pass_once(reason=REASON_START)

        # aTrust connects: our dedicated-table route disappears.
        self.backend.routes_by_table["168"] = []
        self.backend.add_raw_route("192.168.4.0/25", "utun7", protocol="boot")

        report = daemon.pass_once(reason=REASON_TUNNEL)

        self.assertEqual(report["changed"], 1)
        self.assertTrue(report["ok"], report)
        self.assertIn("192.168.4.19/32", self.backend.route_prefixes("168"))

    def test_dry_run_never_mutates(self):
        daemon = self._daemon(dry_run=True)
        report = daemon.pass_once(reason=REASON_START)
        self.assertEqual(report["changed"], 0)
        self.assertEqual(self.backend.calls, [])
        self.assertEqual(self.backend.route_prefixes("168"), set())

    def test_config_changes_are_picked_up_without_restart(self):
        daemon = self._daemon()
        daemon.pass_once(reason=REASON_START)
        self.config_path.write_text(
            json.dumps(
                {
                    "targets": [
                        {"name": "u55c", "address": "192.168.4.19", "interface": "", "enabled": True},
                        {"name": "nas", "address": "192.168.4.234", "interface": "", "enabled": True},
                    ]
                }
            ),
            encoding="utf-8",
        )
        report = daemon.pass_once(reason=REASON_POLL)
        self.assertEqual(report["targets"], 2)
        self.assertIn("192.168.4.234/32", self.backend.route_prefixes("168"))

    def test_disabled_targets_are_dropped_and_rules_collected(self):
        daemon = self._daemon()
        daemon.pass_once(reason=REASON_START)
        self.assertTrue(self.backend.rules(4))

        self.config_path.write_text(
            json.dumps({"targets": [{"address": "192.168.4.19", "enabled": False}]}),
            encoding="utf-8",
        )
        daemon.pass_once(reason=REASON_POLL)
        self.assertEqual(self.backend.rules(4), [])

    def test_state_is_exported_for_unprivileged_readers(self):
        daemon = self._daemon()
        daemon.pass_once(reason=REASON_TUNNEL)
        state = daemon.export_state()
        self.assertTrue(state["running"])
        self.assertEqual(state["reason"], REASON_TUNNEL)
        self.assertEqual(state["routing_mode"], "rule")
        self.assertEqual(state["stats"]["passes"], 1)
        self.assertTrue(state["ok"])
        self.assertEqual(len(state["snapshots"]), 1)

    def test_no_config_is_not_an_error(self):
        daemon = ReconcileDaemon(backend=self.backend, config_paths=[])
        report = daemon.pass_once(reason=REASON_START)
        self.assertTrue(report["ok"])
        self.assertEqual(report["targets"], 0)

    def test_kernel_failure_is_recorded_not_raised(self):
        self.backend.fail_ensure_route = True
        self.backend.fail_ensure_rule = True
        daemon = self._daemon()
        report = daemon.pass_once(reason=REASON_START)
        self.assertGreater(report["failed"], 0)
        self.assertFalse(report["ok"])
        self.assertTrue(daemon.export_state()["errors"])


class DoctorTests(unittest.TestCase):
    def setUp(self):
        self.backend = FakeBackend()
        self._previous = set_backend(self.backend)

    def tearDown(self):
        set_backend(self._previous)

    def test_diagnose_names_the_capturing_route(self):
        from lanrf.doctor import diagnose_targets

        self.backend.add_raw_route("192.168.4.0/24", "utun7", protocol="boot")
        config = make_config(
            targets=[{"name": "u55c", "address": "192.168.4.34", "interface": "", "enabled": True}]
        )
        from lanrf.system import status_report

        report = status_report(config_paths=["/nonexistent/config.json"])
        # status_report reads files; drive the target analysis directly instead.
        from lanrf.reconcile import inspect
        from lanrf.routing import InterfaceSelector

        snapshots = inspect(
            config.enabled_targets, config, self.backend, selector=InterfaceSelector(self.backend)
        )
        findings = diagnose_targets({"targets": snapshots}, self.backend)
        self.assertTrue(any(finding["severity"] == "fail" for finding in findings))
        hints = " ".join(finding.get("hint", "") for finding in findings)
        self.assertIn("192.168.4.0/24", hints)

    def test_environment_findings_report_backend_capabilities(self):
        from lanrf.doctor import diagnose_environment, SEVERITY_OK

        findings = diagnose_environment(self.backend)
        titles = [finding["title"] for finding in findings]
        self.assertTrue(any("策略路由" in title for title in titles))
        self.assertTrue(any(finding["severity"] == SEVERITY_OK for finding in findings))

    def test_format_findings_without_color(self):
        from lanrf.doctor import format_findings

        rendered = format_findings(
            [{"severity": "fail", "title": "boom", "detail": "why", "hint": "fix it"}],
            use_color=False,
        )
        self.assertIn("✗ boom", rendered)
        self.assertIn("→ fix it", rendered)


class CliTests(unittest.TestCase):
    def setUp(self):
        # STATE_PATH was resolved at import time, so the test uses whichever
        # path the suite pinned (see tests/__init__.py) instead of mutating the
        # environment mid-run.
        from lanrf.config import STATE_PATH

        self._tmpdir = tempfile.TemporaryDirectory()
        self.config_path = Path(self._tmpdir.name) / "config.json"
        self.state_path = Path(STATE_PATH)
        self.backend = FakeBackend()
        self._previous = set_backend(self.backend)

    def tearDown(self):
        set_backend(self._previous)
        try:
            self.state_path.unlink()
        except OSError:
            pass
        self._tmpdir.cleanup()

    def _run(self, *argv):
        from lanrf.cli import cli_main

        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli_main(list(argv))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_add_list_and_remove(self):
        code, stdout, stderr = self._run(
            "--config", str(self.config_path), "add", "192.168.4.19", "--name", "u55c"
        )
        self.assertEqual(code, 0, stderr)
        self.assertIn("已添加目标", stdout)

        code, stdout, _stderr = self._run("--config", str(self.config_path), "list")
        self.assertEqual(code, 0)
        self.assertIn("192.168.4.19", stdout)

        code, _stdout, _stderr = self._run(
            "--config", str(self.config_path), "remove", "u55c"
        )
        self.assertEqual(code, 0)
        saved = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.assertEqual(saved["targets"], [])

    def test_add_with_expand_flag_is_persisted(self):
        code, stdout, stderr = self._run(
            "--config", str(self.config_path), "add", "192.168.4.19", "--expand"
        )
        self.assertEqual(code, 0, stderr)
        saved = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.assertTrue(saved["targets"][0]["expand"])
        self.assertIn("整个本地子网", stdout)

        # Re-adding without the flag clears the override again.
        self._run("--config", str(self.config_path), "add", "192.168.4.19")
        saved = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.assertNotIn("expand", saved["targets"][0])

    def test_add_rejects_public_address(self):
        code, _stdout, stderr = self._run(
            "--config", str(self.config_path), "add", "8.8.8.8"
        )
        self.assertEqual(code, 1)
        self.assertIn("无效", stderr)

    def test_add_rejects_unusable_interface(self):
        code, _stdout, stderr = self._run(
            "--config", str(self.config_path), "add", "192.168.4.19", "--interface", "utun7"
        )
        self.assertEqual(code, 1)
        self.assertIn("不可用", stderr)

    def test_enable_disable_and_set_interface(self):
        self._run("--config", str(self.config_path), "add", "192.168.4.19")
        self._run("--config", str(self.config_path), "disable", "192.168.4.19")
        saved = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.assertFalse(saved["targets"][0]["enabled"])

        self._run("--config", str(self.config_path), "enable", "192.168.4.19")
        self._run(
            "--config", str(self.config_path), "set-interface", "192.168.4.19", "auto"
        )
        saved = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.assertTrue(saved["targets"][0]["enabled"])
        self.assertEqual(saved["targets"][0]["interface"], "")

    def test_check_reports_missing_routes(self):
        self.config_path.write_text(
            json.dumps(
                {"targets": [{"name": "u55c", "address": "192.168.4.19", "enabled": True}]}
            ),
            encoding="utf-8",
        )
        code, stdout, _stderr = self._run("--config", str(self.config_path), "check")
        self.assertEqual(code, 1)
        self.assertIn("bad", stdout)

    def test_check_json_output_is_machine_readable(self):
        self.config_path.write_text(
            json.dumps(
                {"targets": [{"name": "u55c", "address": "192.168.4.19", "enabled": True}]}
            ),
            encoding="utf-8",
        )
        code, stdout, _stderr = self._run("--config", str(self.config_path), "check", "--json")
        payload = json.loads(stdout)
        self.assertEqual(code, 1)
        self.assertEqual(payload[0]["address"], "192.168.4.19")
        self.assertFalse(payload[0]["ok"])

    def test_scan_outputs_json(self):
        code, stdout, stderr = self._run("scan", "--no-names")
        self.assertEqual(code, 0, stderr)
        self.assertIsInstance(json.loads(stdout), list)

    def test_status_returns_nonzero_when_a_target_is_broken(self):
        self.config_path.write_text(
            json.dumps(
                {"targets": [{"name": "u55c", "address": "192.168.4.19", "enabled": True}]}
            ),
            encoding="utf-8",
        )
        code, stdout, _stderr = self._run("--config", str(self.config_path), "status")
        self.assertEqual(code, 1)
        self.assertIn("bad", stdout)

    def test_status_is_ok_once_routes_exist(self):
        self.config_path.write_text(
            json.dumps(
                {"targets": [{"name": "u55c", "address": "192.168.4.19", "enabled": True}]}
            ),
            encoding="utf-8",
        )
        daemon = ReconcileDaemon(backend=self.backend, config_paths=[str(self.config_path)])
        daemon.pass_once()
        code, stdout, _stderr = self._run("--config", str(self.config_path), "status")
        self.assertEqual(code, 0, stdout)

    def test_config_set_and_get(self):
        code, stdout, _stderr = self._run(
            "--config", str(self.config_path), "config", "set", "routing_mode", "main"
        )
        self.assertEqual(code, 0, stdout)
        code, stdout, _stderr = self._run(
            "--config", str(self.config_path), "config", "get", "routing_mode"
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout), "main")

    def test_config_set_rejects_unknown_key(self):
        code, _stdout, stderr = self._run(
            "--config", str(self.config_path), "config", "set", "nope", "1"
        )
        self.assertEqual(code, 1)
        self.assertIn("未知设置", stderr)

    def test_config_set_validates_routing_mode(self):
        code, _stdout, stderr = self._run(
            "--config", str(self.config_path), "config", "set", "routing_mode", "bogus"
        )
        self.assertEqual(code, 1)
        self.assertIn("routing_mode", stderr)

    def test_status_daemon_reads_state_file(self):
        # `status --daemon` is purely a reader: it must show the published
        # daemon state and must not trigger a reconcile of its own.
        write_state(
            {
                "pid": 1234,
                "running": True,
                "reason": "route-event",
                "updated_at": 0,
                "routing_mode": "rule",
                "rule_table": 168,
                "stats": {"passes": 5, "events": 42, "changes": 3, "failures": 0},
                "snapshots": [],
            },
            self.state_path,
        )
        code, stdout, _stderr = self._run("status", "--daemon")
        self.assertEqual(code, 0)
        self.assertIn("内核事件 42", stdout)

    def test_daemon_once_is_dry_run_capable(self):
        self.config_path.write_text(
            json.dumps(
                {"targets": [{"name": "u55c", "address": "192.168.4.19", "enabled": True}]}
            ),
            encoding="utf-8",
        )
        code, _stdout, _stderr = self._run(
            "--config", str(self.config_path), "daemon", "--once", "--dry-run", "--quiet"
        )
        self.assertEqual(code, 0)
        self.assertEqual(self.backend.calls, [])


class PruneCliTests(unittest.TestCase):
    """`lan-route-fixer prune` walks the same code the GUI cleanup page uses."""

    def setUp(self):
        from lanrf.config import DISCOVERY_CACHE_PATH
        from lanrf.model import ROUTE_PROTOCOL_NAME

        self.protocol = ROUTE_PROTOCOL_NAME
        self._tmpdir = tempfile.TemporaryDirectory()
        self.config_path = Path(self._tmpdir.name) / "config.json"
        self.discovery_path = Path(self._tmpdir.name) / "discovered.json"
        self._default_cache = Path(DISCOVERY_CACHE_PATH)
        # An empty cache means "nothing was ever seen", which is deterministic
        # regardless of what the real neighbour table looked like.
        self._write_cache({})
        self.backend = FakeBackend()
        self._previous = set_backend(self.backend)

    def tearDown(self):
        set_backend(self._previous)
        import lanrf.cleanup as cleanup

        cleanup.DISCOVERY_CACHE_PATH = self._default_cache
        self._tmpdir.cleanup()

    def _write_cache(self, seen):
        self.discovery_path.write_text(
            json.dumps({"version": 1, "updated_at": 0, "seen": seen}), encoding="utf-8"
        )
        import lanrf.cleanup as cleanup

        cleanup.DISCOVERY_CACHE_PATH = self.discovery_path

    def _write_config(self, targets, **extra):
        payload = {"targets": targets, "routing_mode": "rule", "rule_table": 168}
        payload.update(extra)
        self.config_path.write_text(json.dumps(payload), encoding="utf-8")

    def _run(self, *argv):
        from lanrf.cli import cli_main

        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli_main(list(argv))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_dry_run_lists_residue_without_touching_anything(self):
        self.backend.add_raw_route(
            "192.168.4.99/32", "wlp0s20f3", table="168", protocol=self.protocol
        )
        self._write_config(
            [
                {"name": "u55c", "address": "192.168.4.19", "enabled": True},
                {"name": "旧设备", "address": "192.168.4.77", "enabled": False},
            ]
        )

        code, stdout, stderr = self._run("--config", str(self.config_path), "prune")

        self.assertEqual(code, 0, stderr)
        self.assertIn("192.168.4.99/32", stdout)
        self.assertIn("192.168.4.77", stdout)
        self.assertIn("预演", stdout)
        self.assertIn("192.168.4.99/32", self.backend.route_prefixes("168"))
        self.assertIn(
            "192.168.4.77",
            [target["address"] for target in json.loads(self.config_path.read_text())["targets"]],
        )

    def test_yes_removes_orphan_route_and_keeps_configured_targets(self):
        self.backend.add_raw_route(
            "192.168.4.99/32", "wlp0s20f3", table="168", protocol=self.protocol
        )
        self.backend.add_raw_route(
            "192.168.4.19/32", "wlp0s20f3", table="168", protocol=self.protocol
        )
        self._write_config(
            [{"name": "u55c", "address": "192.168.4.19", "enabled": True}]
        )

        code, _stdout, stderr = self._run(
            "--config", str(self.config_path), "prune", "--routes", "--yes"
        )

        self.assertEqual(code, 0, stderr)
        self.assertNotIn("192.168.4.99/32", self.backend.route_prefixes("168"))
        self.assertIn("192.168.4.19/32", self.backend.route_prefixes("168"))

    def test_yes_drops_a_disabled_never_seen_target(self):
        self._write_config(
            [
                {"name": "keep", "address": "192.168.4.19", "enabled": True},
                {"name": "drop", "address": "192.168.4.77", "enabled": False},
            ]
        )

        code, _stdout, stderr = self._run(
            "--config", str(self.config_path), "prune", "--targets", "--yes"
        )

        self.assertEqual(code, 0, stderr)
        saved = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.assertEqual([target["address"] for target in saved["targets"]], ["192.168.4.19"])

    def test_retention_window_comes_from_the_config_file(self):
        import time

        self._write_cache({"192.168.4.77": time.time() - 5 * 86400})
        self._write_config(
            [{"name": "drop", "address": "192.168.4.77", "enabled": False}],
            prune_after_days=3,
        )

        code, stdout, _stderr = self._run("--config", str(self.config_path), "prune")
        self.assertEqual(code, 0)
        self.assertIn("192.168.4.77", stdout)

        # ...and a --days override wins for that one run.
        code, stdout, _stderr = self._run(
            "--config", str(self.config_path), "prune", "--days", "30"
        )
        self.assertEqual(code, 0)
        self.assertIn("没有需要清理的内容", stdout)

    def test_a_refused_removal_is_reported_and_exits_nonzero(self):
        self.backend.add_raw_route(
            "192.168.4.99/32", "wlp0s20f3", table="168", protocol=self.protocol
        )
        self._write_config([])
        self.backend.remove_route = lambda item: False  # kernel said no

        code, stdout, stderr = self._run(
            "--config", str(self.config_path), "prune", "--yes"
        )

        self.assertEqual(code, 1)
        self.assertIn("失败", stdout)
        self.assertIn("sudo lan-route-fixer prune --yes", stderr)

    def test_json_output_carries_the_report_and_what_was_applied(self):
        self.backend.add_raw_route(
            "192.168.4.99/32", "wlp0s20f3", table="168", protocol=self.protocol
        )
        self._write_config([])

        code, stdout, _stderr = self._run(
            "--config", str(self.config_path), "prune", "--yes", "--json"
        )

        self.assertEqual(code, 0)
        payload = json.loads(stdout)
        self.assertTrue(payload["applied"])
        self.assertEqual(payload["report"]["routes"]["count"], 1)
        self.assertEqual(payload["routes"][0]["removed_count"], 1)

    def test_nothing_to_do_is_a_success(self):
        self._write_config([])
        code, stdout, _stderr = self._run("--config", str(self.config_path), "prune")
        self.assertEqual(code, 0)
        self.assertIn("没有需要清理的内容", stdout)

    def test_another_users_config_is_not_edited_without_root(self):
        """Only roots get to rewrite somebody else's config file."""
        from unittest import mock

        import lanrf.cleanup as cleanup
        import lanrf.cli as cli

        other = "/home/someone/.config/lan-route-fixer/config.json"
        report = {
            "routes": {"tables": ["168"], "keep": [], "routes": [], "count": 0},
            "targets": [
                {
                    "path": str(self.config_path),
                    "count": 1,
                    "candidates": [
                        {"name": "drop", "address": "192.168.4.77",
                         "detail": "从未出现", "reason": "never-seen"}
                    ],
                },
                {
                    "path": other,
                    "count": 1,
                    "candidates": [
                        {"name": "other", "address": "10.0.0.9",
                         "detail": "从未出现", "reason": "never-seen"}
                    ],
                },
            ],
            "count": 2,
            "prune_after_days": 30,
        }
        pruned = []

        def fake_prune_targets(config, candidates, save=True):
            pruned.append(str(config.path))
            return {"removed": [], "removed_count": 0, "saved": True}

        with mock.patch.object(cleanup, "analyze", return_value=report), \
                mock.patch.object(cleanup, "prune_targets", side_effect=fake_prune_targets), \
                mock.patch.object(cli, "CONFIG_PATH", self.config_path), \
                mock.patch("os.geteuid", return_value=1000):
            code, stdout, stderr = self._run("prune", "--targets", "--yes")

        self.assertEqual(code, 0, stderr)
        self.assertEqual(pruned, [str(self.config_path)])
        self.assertIn("跳过其他用户", stdout)


if __name__ == "__main__":
    unittest.main()
