"""Systemd units must keep the capabilities needed to read user configs.

Regression test for 2.2.0: both units bounded the capability set to
CAP_NET_ADMIN/CAP_NET_RAW, but the daemon and the one-shot applier are supposed
to discover every user's config as root. A bounded root without
CAP_DAC_READ_SEARCH is "other" for a 0750 home directory (and a 0700 ~/.config)
and cannot traverse into it, so discovery silently returned no configs:
``checked=0``/``targets=0`` while the GUI still listed the targets, and the user
had to repair by hand after every VPN connect.
"""

import unittest
from pathlib import Path

UNITS = Path(__file__).resolve().parents[1] / "src/usr/lib/systemd/system"
REQUIRED = ("CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_DAC_READ_SEARCH")
UNIT_NAMES = ("lan-route-fixer.service", "lan-route-fixer-daemon.service")


class UnitCapabilityTests(unittest.TestCase):
    def test_units_can_traverse_user_home_directories(self):
        for name in UNIT_NAMES:
            text = (UNITS / name).read_text(encoding="utf-8")
            for key in ("AmbientCapabilities", "CapabilityBoundingSet"):
                line = next(
                    (row for row in text.splitlines() if row.startswith(key + "=")),
                    None,
                )
                self.assertIsNotNone(line, f"{name}: missing {key}")
                granted = line.split("=", 1)[1].split()
                for capability in REQUIRED:
                    self.assertIn(
                        capability,
                        granted,
                        f"{name}: {key} lacks {capability}",
                    )

    def test_home_stays_visible_but_read_only(self):
        for name in UNIT_NAMES:
            text = (UNITS / name).read_text(encoding="utf-8")
            # ProtectHome=yes would hide /home from the unit entirely; the
            # daemon needs to read configs there, so it must stay read-only.
            self.assertIn("ProtectHome=read-only", text, name)
            self.assertNotIn("ProtectHome=yes", text, name)


if __name__ == "__main__":  # pragma: no cover - manual invocation
    unittest.main()
