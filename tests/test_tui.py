"""Tests for the terminal dashboard.

The renderer is deliberately pure: :func:`lanrf.tui.build_view` turns a snapshot
into a canvas without touching a real terminal, so these tests can assert
geometry, content and colour handling on any platform -- including Windows,
where the interactive loop cannot run at all.  No test writes a file.
"""

import re
import unittest

try:  # ``python -B tests/test_tui.py``: tests/ is on sys.path
    from support import REPO_ROOT  # noqa: F401 - inserts the lib directory
except ImportError:  # ``python -m unittest tests.test_tui``
    from tests.support import REPO_ROOT  # noqa: F401

from lanrf import tui

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def strip_ansi(text):
    return ANSI.sub("", text)


class CanvasGeometryTests(unittest.TestCase):
    """Every frame must be exactly ``width`` columns wide, no clipping."""

    def check(self, state, width, height):
        canvas = tui.build_view(state, width, height)
        self.assertEqual(canvas.issues, [])
        rows = canvas.text_rows()
        self.assertEqual(len(rows), height)
        for row in rows:
            self.assertEqual(tui.text_width(row), width)
        return canvas

    def test_typical_terminal_sizes(self):
        state = tui.demo_state()
        for width, height in ((126, 40), (100, 30), (160, 48), (200, 60)):
            with self.subTest(size=(width, height)):
                self.check(state, width, height)

    def test_compact_layout(self):
        state = tui.demo_state()
        canvas = self.check(state, 76, 20)
        text = "\n".join(canvas.text_rows())
        self.assertIn("TARGETS", text)
        self.assertIn("SECURED", text)

    def test_too_small_terminal_says_so(self):
        canvas = self.check(tui.demo_state(), 50, 10)
        self.assertIn("窗口太小", "\n".join(canvas.text_rows()))

    def test_status_badges_are_visible(self):
        text = "\n".join(self.check(tui.demo_state(), 126, 40).text_rows())
        self.assertIn("SECURED", text)
        self.assertIn("CAPTURED", text)
        self.assertIn("OFF", text)
        self.assertIn("aTrustVNIC", text)

    def test_selected_card_is_marked(self):
        state = tui.demo_state()
        state["selected"] = 1
        text = "\n".join(self.check(state, 126, 40).text_rows())
        self.assertIn("challenge_4090", text)

    def test_overlay_fits(self):
        state = tui.demo_state()
        state["overlay"] = {
            "title": "DIAGNOSE",
            "lines": [f"第 {index} 行：aTrustVNIC 正在接管 192.168.4.0/24" for index in range(40)],
            "scroll": 0,
        }
        canvas = self.check(state, 100, 30)
        text = "\n".join(canvas.text_rows())
        self.assertIn("DIAGNOSE", text)
        self.assertIn("Esc", text)

    def test_overlay_wraps_long_lines(self):
        state = tui.demo_state()
        state["overlay"] = {
            "title": "TARGET",
            "lines": ["地址 192.168.4.234/32", "", "说明 " + "x" * 200],
        }
        self.check(state, 76, 20)


class TextGeometryTests(unittest.TestCase):
    def test_cjk_width(self):
        self.assertEqual(tui.text_width("修复"), 4)
        self.assertEqual(tui.text_width("fix"), 3)

    def test_truncate_respects_width(self):
        clipped = tui.truncate("修复路由表里的残留条目", 8)
        self.assertLessEqual(tui.text_width(clipped), 8)
        self.assertTrue(clipped.endswith("…") or clipped == "修复路由")

    def test_fit_pads_and_clips(self):
        self.assertEqual(tui.text_width(tui.fit("abc", 6)), 6)
        self.assertEqual(tui.text_width(tui.fit("修复路由表里的残留条目", 6)), 6)

    def test_wrap_keeps_content(self):
        wrapped = tui.wrap("a" * 10, 4)
        self.assertEqual(len(wrapped), 3)
        self.assertEqual("".join(wrapped), "a" * 10)


class SerialisationTests(unittest.TestCase):
    def test_ansi_frame_contains_only_row_content(self):
        canvas = tui.build_view(tui.demo_state(), 100, 30)
        frame = canvas.ansi()
        self.assertTrue(frame.startswith("\033[H"))
        # Rows are joined with CRLF, so the frame itself must not end with one
        # (that would scroll the alt screen by a line on every redraw).
        self.assertFalse(frame.endswith("\r\n"))
        plain = strip_ansi(frame)
        self.assertEqual(plain.count("\r\n"), 29)
        self.assertIn("LAN ROUTE FIXER", plain)
        self.assertIn("EVENT STREAM", plain)

    def test_plain_rows_have_no_escapes(self):
        canvas = tui.build_view(tui.demo_state(), 100, 30)
        for row in canvas.text_rows():
            self.assertNotIn("\x1b", row)

    def test_mono_mode_emits_no_colour(self):
        canvas = tui.build_view(tui.demo_state(), 88, 24)
        frame = canvas.ansi()
        if tui._color_depth() == "mono":
            self.assertNotIn("\033[38;", frame)


class KeyHandlingTests(unittest.TestCase):
    def setUp(self):
        self.app = tui.Tui(interval=5.0)
        self.app.state["targets"] = tui.demo_state()["targets"]

    def test_navigation_moves_selection(self):
        self.app.handle_key("KEY_DOWN")
        self.assertEqual(self.app.state["selected"], 1)
        self.app.handle_key("KEY_UP")
        self.assertEqual(self.app.state["selected"], 0)

    def test_selection_clamps(self):
        self.app.handle_key("KEY_UP")
        self.assertEqual(self.app.state["selected"], 0)
        for _ in range(10):
            self.app.handle_key("KEY_DOWN")
        self.assertEqual(self.app.state["selected"], len(self.app.state["targets"]) - 1)

    def test_help_overlay(self):
        self.app.handle_key("?")
        self.app._drain()
        self.assertIsNotNone(self.app.state["overlay"])
        self.assertEqual(self.app.state["overlay"]["title"], "HELP")

    def test_escape_closes_overlay(self):
        self.app.handle_key("?")
        self.app._drain()
        self.app.handle_key("\x1b")
        self.assertIsNone(self.app.state["overlay"])

    def test_quit(self):
        self.app.handle_key("q")
        self.assertFalse(self.app.running)

    def test_import_confirmation_does_not_write(self):
        self.app.action_import_confirm = lambda: setattr(self, "confirmed", True)
        self.app.state["overlay"] = {"title": "IMPORT SSH · 预演", "lines": []}
        self.app.handle_key("y")
        self.assertIsNone(self.app.state["overlay"])
        self.assertTrue(getattr(self, "confirmed", False))

    def test_help_lists_every_action(self):
        text = "\n".join(tui.HELP_LINES)
        for keyword in ("扫描", "修复", "导入", "诊断", "看门狗", "退出"):
            self.assertIn(keyword, text)

    def test_detail_overlay_for_selected_target(self):
        self.app.action_detail()
        self.app._drain()
        overlay = self.app.state["overlay"]
        self.assertEqual(overlay["title"], "TARGET")
        self.assertIn("192.168.4.94/32", "\n".join(overlay["lines"]))


class SnapshotMergeTests(unittest.TestCase):
    def test_disabled_targets_are_kept_visible(self):
        class Config:
            targets = [
                {"name": "printer", "address": "192.168.4.50/32", "enabled": False},
                {"name": "nas", "address": "192.168.4.10/32", "enabled": True,
                 "interface": "WLAN"},
            ]

        merged = tui._merge_targets(Config(), [])
        self.assertEqual([item["name"] for item in merged], ["printer", "nas"])
        self.assertEqual(merged[0]["state"], "disabled")
        self.assertFalse(merged[1]["ok"])

    def test_disabled_targets_never_show_secured(self):
        class Config:
            targets = [
                {"name": "printer", "address": "192.168.4.50/32", "enabled": False},
            ]

        result = {"name": "printer", "address": "192.168.4.50/32", "ok": True,
                  "state": "ok", "desired": "WLAN", "current": "WLAN"}
        merged = tui._merge_targets(Config(), [result])
        self.assertFalse(merged[0]["ok"])
        self.assertEqual(merged[0]["state"], "disabled")


if __name__ == "__main__":
    unittest.main()