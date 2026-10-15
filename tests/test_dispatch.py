"""Tests for the CLI/GUI dispatch decision.

Regression: ``--config PATH check`` used to open the GUI, because the option's
*value* was tested as if it were a command name.
"""

import unittest

from lanrf import dispatch


class DispatchTests(unittest.TestCase):
    def test_commands_are_recognised(self):
        for command in sorted(dispatch.CLI_COMMANDS):
            with self.subTest(command=command):
                self.assertTrue(dispatch.wants_cli([command]))

    def test_option_value_is_not_treated_as_a_command(self):
        # The regression that made `--config x.json check` silently open the GUI.
        self.assertTrue(dispatch.wants_cli(["--config", "/tmp/x.json", "check"]))
        self.assertTrue(dispatch.wants_cli(["--config", "/tmp/x.json", "daemon", "--once"]))
        self.assertTrue(dispatch.wants_cli(["--config", "check", "check"]))
        self.assertTrue(dispatch.wants_cli(["--interval", "5", "daemon"]))

    def test_unknown_option_value_without_command_is_false(self):
        self.assertFalse(dispatch.wants_cli(["--config", "/tmp/x.json"]))
        self.assertFalse(dispatch.wants_cli(["--config", "check"]))

    def test_desktop_launch_is_the_gui(self):
        self.assertFalse(dispatch.wants_cli([]))
        self.assertFalse(dispatch.wants_cli(None))

    def test_unknown_command_falls_through_to_the_gui(self):
        # The real parser rejects it; opening the GUI for a typo is the old
        # behaviour and is deliberately not treated as a CLI invocation.
        self.assertFalse(dispatch.wants_cli(["scna"]))

    def test_help_flags_mean_cli(self):
        for flag in ("-h", "--help", "--version"):
            with self.subTest(flag=flag):
                self.assertTrue(dispatch.wants_cli([flag]))
                self.assertTrue(dispatch.wants_cli(["--config", "/tmp/x", flag]))

    def test_unknown_flag_does_not_claim_to_be_the_cli(self):
        self.assertFalse(dispatch.wants_cli(["--frobnicate"]))

    def test_flags_after_the_command_still_work(self):
        self.assertTrue(dispatch.wants_cli(["daemon", "--interval", "5", "--dbus"]))
        self.assertTrue(dispatch.wants_cli(["check", "--json"]))


if __name__ == "__main__":
    unittest.main()
