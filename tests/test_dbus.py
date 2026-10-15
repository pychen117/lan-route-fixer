"""Tests for the D-Bus control interface.

These exercise the parts that do not need a privileged daemon: the interface
definition, the client's fail-soft behaviour, and the sender check that backs up
the D-Bus policy shipped in ``/usr/share/dbus-1/system.d``.
"""

import json
import os
import sys
import unittest
from unittest import mock

try:
    from tests.support import FakeBackend, make_config
except ImportError:  # pragma: no cover - direct invocation
    from support import FakeBackend, make_config

from lanrf import dbus as dbus_module
from lanrf.config import Config
from lanrf.daemon import ReconcileDaemon

HAS_GI = dbus_module.AVAILABLE


class IntrospectionTests(unittest.TestCase):
    def test_interface_xml_is_valid_and_complete(self):
        if not HAS_GI:  # pragma: no cover
            self.skipTest("python3-gi is not available")
        from gi.repository import Gio

        node = Gio.DBusNodeInfo.new_for_xml(dbus_module.INTROSPECTION_XML)
        self.assertEqual(len(node.interfaces), 1)
        interface = node.interfaces[0]
        self.assertEqual(interface.name, dbus_module.INTERFACE_NAME)
        methods = {method.name for method in interface.methods}
        self.assertEqual(methods, {"Repair", "GetStatus", "Reload"})
        self.assertEqual([signal.name for signal in interface.signals], ["StateChanged"])
        self.assertEqual([prop.name for prop in interface.properties], ["Version"])

    def test_bus_name_and_object_path_are_reverse_dns(self):
        self.assertTrue(dbus_module.BUS_NAME.startswith("io.github."))
        self.assertTrue(dbus_module.OBJECT_PATH.startswith("/"))
        self.assertTrue(dbus_module.INTERFACE_NAME.startswith(dbus_module.BUS_NAME))


class SenderCheckTests(unittest.TestCase):
    """The daemon's own guard, independent of the bus policy file."""

    def setUp(self):
        self.daemon = ReconcileDaemon(backend=FakeBackend(), config_paths=[])
        self.service = dbus_module.DaemonService.__new__(dbus_module.DaemonService)
        self.service.daemon = self.daemon
        self.service.bus_name = dbus_module.BUS_NAME

    def test_anonymous_sender_is_allowed(self):
        # A message with no sender cannot be attributed; the bus policy is then
        # the only gate and it already denies non-owners.
        self.service._connection = None
        self.assertTrue(self.service._sender_is_owner(None))

    def test_same_uid_is_allowed(self):
        self.service._connection = mock.Mock()
        self.service._connection.call_sync.return_value.unpack.return_value = (os.geteuid(),)
        self.assertTrue(self.service._sender_is_owner(":1.42"))

    def test_other_uid_is_rejected(self):
        self.service._connection = mock.Mock()
        other = 0 if os.geteuid() != 0 else 1000
        self.service._connection.call_sync.return_value.unpack.return_value = (other,)
        self.assertFalse(self.service._sender_is_owner(":1.43"))

    def test_bus_error_fails_open_so_policy_decides(self):
        if not HAS_GI:  # pragma: no cover
            self.skipTest("python3-gi is not available")
        from gi.repository import GLib

        self.service._connection = mock.Mock()
        self.service._connection.call_sync.side_effect = GLib.Error("boom")
        self.assertTrue(self.service._sender_is_owner(":1.44"))


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.backend = FakeBackend()
        self.config = Config(
            {"targets": [{"name": "u55c", "address": "192.168.4.19", "enabled": True}]}
        )
        self.daemon = ReconcileDaemon(backend=self.backend, config_paths=[])
        self.daemon._load_targets = lambda: (self.config.targets, self.config, ())
        self.service = dbus_module.DaemonService.__new__(dbus_module.DaemonService)
        self.service.daemon = self.daemon
        self.service._connection = None

    def test_repair_returns_a_json_report_and_installs_routes(self):
        payload = json.loads(self.service._dispatch("Repair", None))
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["changed"], 2)
        self.assertIn("192.168.4.19/32", self.backend.route_prefixes("168"))

    def test_repair_is_idempotent_through_the_interface(self):
        self.service._dispatch("Repair", None)
        second = json.loads(self.service._dispatch("Repair", None))
        self.assertEqual(second["changed"], 0)
        self.assertTrue(second["ok"])

    def test_get_status_does_not_change_anything(self):
        state = json.loads(self.service._dispatch("GetStatus", None))
        self.assertEqual(self.backend.calls, [])
        self.assertIn("snapshots", state)
        self.assertIn("stats", state)

    def test_reload_triggers_a_pass(self):
        json.loads(self.service._dispatch("Reload", None))
        self.assertGreaterEqual(self.daemon.stats["passes"], 1)

    def test_unknown_method_raises(self):
        with self.assertRaises(ValueError):
            self.service._dispatch("Fly", None)


class GlibModeTests(unittest.TestCase):
    def test_unprivileged_daemon_refuses_to_publish_the_interface(self):
        """Serving a control interface that cannot repair would be a lie."""
        backend = FakeBackend(privileged=False)
        daemon = ReconcileDaemon(backend=backend, config_paths=[])
        calls = []
        daemon.run = lambda: calls.append("run") or 0
        self.assertEqual(daemon.run_glib(), 0)
        self.assertEqual(calls, ["run"])
        self.assertIsNone(daemon._service)

    def test_event_classification_still_feeds_the_glib_timer(self):
        from lanrf import netlink

        daemon = ReconcileDaemon(backend=FakeBackend(), config_paths=[])
        daemon._glib = mock.Mock()
        daemon._monitor = mock.Mock()
        daemon._monitor.wait.return_value = []
        # An empty read must not start a debounce timer.
        self.assertTrue(daemon._on_monitor_ready(0, None))
        daemon._glib.timeout_add.assert_not_called()


class ClientTests(unittest.TestCase):
    def test_client_is_fail_soft_without_a_bus(self):
        client = dbus_module.DaemonClient(bus_name="io.github.pychen117.NoSuchService")
        if not client.usable:  # pragma: no cover - no bus in the sandbox
            self.assertIsNone(client.repair())
            self.assertIsNone(client.status())
            self.assertTrue(client.last_error)
            return
        self.assertFalse(client.is_running())
        self.assertIsNone(client.repair())
        self.assertIn("NoSuchService", client.last_error)

    def test_dummy_backend_reports_no_daemon(self):
        from lanrf.privileged import _daemon_repair

        items = [{"address": "10.0.0.1/32", "family": 4, "interface": "eth0", "table": "main"}]
        with mock.patch.object(dbus_module, "bus_available", return_value=False):
            handled, remaining, report = _daemon_repair(items)
        self.assertEqual(handled, [])
        self.assertEqual(remaining, items)
        self.assertIsNone(report)


if __name__ == "__main__":
    unittest.main()
