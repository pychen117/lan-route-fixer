from unittest import mock

import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src/usr/lib/lan-route-fixer"))

import core


class ParseAndValidationTests(unittest.TestCase):
    def test_valid_private_ipv4(self):
        self.assertTrue(core.valid_private_ipv4("192.168.4.169"))
        self.assertTrue(core.valid_private_ipv4("10.0.0.1"))
        self.assertTrue(core.valid_private_ipv4("172.16.0.1"))
        self.assertFalse(core.valid_private_ipv4("172.15.255.255"))
        self.assertFalse(core.valid_private_ipv4("8.8.8.8"))
        self.assertFalse(core.valid_private_ipv4("not-an-ip"))

    def test_valid_local_target(self):
        self.assertTrue(core.valid_local_target("192.168.4.0/24"))
        self.assertTrue(core.valid_local_target("10.0.0.1"))
        self.assertTrue(core.valid_local_target("fd00::1234"))
        self.assertTrue(core.valid_local_target("fe80::1234"))
        self.assertFalse(core.valid_local_target("8.8.8.0/24"))
        self.assertFalse(core.valid_local_target("2606:4700::1111"))

    def test_parse_ip_or_cidr(self):
        self.assertEqual(core.parse_ip_or_cidr("192.168.4.169"), (4, "192.168.4.169", 32))
        self.assertEqual(core.parse_ip_or_cidr("192.168.4.0/24"), (4, "192.168.4.0", 24))
        self.assertEqual(core.parse_ip_or_cidr("fd00::1234/128"), (6, "fd00::1234", 128))
        self.assertIsNone(core.parse_ip_or_cidr("bad"))

    def test_normalize_targets(self):
        targets = [
            {"name": "a", "ip": "192.168.4.20", "enabled": True},
            {"name": "b", "address": "192.168.4.20", "enabled": False},
            {"name": "c", "address": "10.0.0.1", "enabled": 1},
        ]
        normalized = core.normalize_targets(targets)
        self.assertEqual(len(normalized), 2)
        self.assertEqual(normalized[0]["address"], "192.168.4.20")
        self.assertEqual(normalized[1]["enabled"], True)

    def test_is_virtual_interface(self):
        self.assertTrue(core.is_virtual_interface("utun7"))
        self.assertTrue(core.is_virtual_interface("wg0"))
        self.assertTrue(core.is_virtual_interface("eth0", "tun"))
        self.assertFalse(core.is_virtual_interface("wlp0s20f3"))


if __name__ == "__main__":
    unittest.main()


class TargetManagementTests(unittest.TestCase):
    def test_find_target_indices_by_address_and_name(self):
        config = {
            "targets": [
                {"name": "server", "address": "192.168.4.169", "interface": "", "enabled": True},
                {"name": "nas", "address": "192.168.8.0/24", "interface": "", "enabled": True},
            ]
        }
        self.assertEqual(core._find_target_indices(config, "192.168.4.169"), [0])
        self.assertEqual(core._find_target_indices(config, "SERVER"), [0])
        self.assertEqual(core._find_target_indices(config, "missing"), [])

    def test_normalize_interface_arg(self):
        self.assertEqual(core._normalize_interface_arg(""), "")
        self.assertEqual(core._normalize_interface_arg("auto"), "")
        self.assertEqual(core._normalize_interface_arg(" eth0 "), "eth0")


class HelperInvocationTests(unittest.TestCase):
    def test_run_helper_passes_json_as_argument(self):
        items = [
            {"address": "192.168.4.169/32", "family": 4, "interface": "wlp0s20f3"}
        ]
        fake = mock.Mock(returncode=0, stdout="[]\n", stderr="")
        with mock.patch.object(core, "subprocess") as subprocess_mock:
            subprocess_mock.run.return_value = fake
            outcome = core.run_helper(items, use_pkexec=True)
            run_kwargs = subprocess_mock.run.call_args.kwargs
            run_args = subprocess_mock.run.call_args.args[0]

        self.assertEqual(outcome["return_code"], 0)
        self.assertNotIn("input", run_kwargs)
        self.assertIn("--batch-json", run_args)
        payload = run_args[run_args.index("--batch-json") + 1]
        self.assertEqual(json.loads(payload), items)
        self.assertEqual(run_args[0], core.PKEXEC_PATH)

    def test_run_helper_direct_uses_helper_without_pkexec(self):
        items = [{"address": "10.0.0.1/32", "family": 4, "interface": "eth0"}]
        fake = mock.Mock(returncode=0, stdout="[]\n", stderr="")
        with mock.patch.object(core, "subprocess") as subprocess_mock:
            subprocess_mock.run.return_value = fake
            core.run_helper(items, use_pkexec=False)
            run_args = subprocess_mock.run.call_args.args[0]
        self.assertEqual(run_args[0], core.HELPER_PATH)
        self.assertIn("--batch-json", run_args)

    def test_run_helper_empty_batch_does_not_spawn(self):
        with mock.patch.object(core, "subprocess") as subprocess_mock:
            outcome = core.run_helper([], use_pkexec=True)
        subprocess_mock.run.assert_not_called()
        self.assertEqual(outcome["return_code"], 0)
        self.assertEqual(outcome["items"], [])


class BackgroundApplierTests(unittest.TestCase):
    def test_collect_all_enabled_targets_respects_auto_fix(self):
        import tempfile
        import json
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            disabled_path = root / "disabled.json"
            enabled_path = root / "enabled.json"
            disabled_path.write_text(
                json.dumps(
                    {
                        "auto_fix": False,
                        "targets": [
                            {"name": "a", "address": "192.168.4.10", "interface": "", "enabled": True}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            enabled_path.write_text(
                json.dumps(
                    {
                        "auto_fix": True,
                        "targets": [
                            {"name": "b", "address": "192.168.4.11", "interface": "", "enabled": True}
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with unittest.mock.patch.object(
                core, "collect_config_paths", return_value=[str(disabled_path), str(enabled_path)]
            ):
                all_targets = core.collect_all_enabled_targets(require_auto_fix=False)
                auto_fix_targets = core.collect_all_enabled_targets(require_auto_fix=True)

            self.assertEqual({t["address"] for t in all_targets}, {"192.168.4.10", "192.168.4.11"})
            self.assertEqual({t["address"] for t in auto_fix_targets}, {"192.168.4.11"})
