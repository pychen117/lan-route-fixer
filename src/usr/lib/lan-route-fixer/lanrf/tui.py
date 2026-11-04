"""Interactive terminal dashboard -- the Ubuntu counterpart of the GTK app.

The GTK window is the right thing when you are at the desktop, but a large part
of this tool's audience works over SSH: ``ssh box`` then ``lan-route-fixer`` in
the shell.  This module turns that invocation into a full-screen dashboard in
the style of the Windows control deck: a defence-grid header, the target cards
with their live SECURED / CAPTURED state, an integrity radar, the system grid,
and an event stream that records every action.

Why not curses?  Two reasons:

* the Windows Python distribution ships no ``curses`` module, and the test suite
  has to import this module on every platform;
* a small retained-mode canvas gives exact control over the truecolour theme,
  and -- more importantly -- it can be rendered without a terminal at all, so
  ``--tui-probe`` and the unit tests can check the geometry instead of a human
  eyeballing it.

The canvas is therefore the renderer; the terminal is only a serialiser.  That
is also why the layout code is pure and lives in :func:`build_view`: given a
snapshot and a size it produces a :class:`Canvas`, and nothing in it touches the
real screen.
"""

from __future__ import annotations

import contextlib
import io
import math
import os
import platform
import queue
import subprocess
import sys
import threading
import time
import unicodedata
from collections import deque

try:  # POSIX only; the Windows interpreter has neither module.
    import select
    import termios
    import tty
except ImportError:  # pragma: no cover - exercised on Windows
    select = None
    termios = None
    tty = None

from . import __version__, checks, config as config_module, doctor as doctor_module
from . import privileged
from .backends import get_backend

# --------------------------------------------------------------------------- #
# Theme
# --------------------------------------------------------------------------- #

RGB = "tuple[int, int, int]"

BG = (4, 6, 11)
PANEL = (7, 12, 20)
PANEL_2 = (10, 17, 25)
LINE = (24, 38, 52)
WHITE = (214, 226, 238)
INK = (160, 178, 196)
DIM = (104, 122, 142)
CYAN = (35, 211, 234)
CYAN_D = (18, 116, 136)
GREEN = (61, 220, 151)
RED = (255, 92, 122)
AMBER = (245, 185, 66)
MAGENTA = (255, 79, 216)
BLACK = (0, 0, 0)

RESET = "\033[0m"
ALT_SCREEN_ON = "\033[?1049h"
ALT_SCREEN_OFF = "\033[?1049l"
CURSOR_HIDE = "\033[?25l"
CURSOR_SHOW = "\033[?25h"

BOX = {
    "tl": "\u250c", "tr": "\u2510", "bl": "\u2514", "br": "\u2518",
    "h": "\u2500", "v": "\u2502", "t": "\u252c", "b": "\u2534",
}

STATUS_TEXT = {
    "ok": "SECURED",
    "wrong-interface": "CAPTURED",
    "missing": "NO ROUTE",
    "invalid": "INVALID",
    "unknown": "UNKNOWN",
}


def _color_depth():
    """How much colour the terminal gets: truecolor, 256, or none."""
    if os.environ.get("LANRF_TUI_MONO") or not sys.stdout.isatty():
        return "mono"
    if os.environ.get("COLORTERM", "").lower() in {"truecolor", "24bit"}:
        return "truecolor"
    term = os.environ.get("TERM", "")
    if "256" in term:
        return "256"
    if term in {"", "dumb"}:
        return "mono"
    return "256"


def _ansi256(rgb):
    """Nearest xterm-256 index for an RGB triple."""
    r, g, b = rgb
    if r == g == b:
        if r < 8:
            return 16
        if r > 248:
            return 231
        return 232 + round((r - 8) / 247 * 24)
    index = 16 + 36 * round(r / 255 * 5) + 6 * round(g / 255 * 5) + round(b / 255 * 5)
    return index


def _sgr(fg, bg, bold):
    """SGR sequence for one style, honouring the terminal's colour depth."""
    depth = _color_depth()
    if depth == "mono":
        return "\033[1m" if bold else ""
    parts = ["\033[1m"] if bold else []
    if depth == "truecolor":
        parts.append(f"\033[38;2;{fg[0]};{fg[1]};{fg[2]}m")
        if bg != PANEL:
            parts.append(f"\033[48;2;{bg[0]};{bg[1]};{bg[2]}m")
    else:
        parts.append(f"\033[38;5;{_ansi256(fg)}m")
        if bg != PANEL:
            parts.append(f"\033[48;5;{_ansi256(bg)}m")
    return "".join(parts)


# --------------------------------------------------------------------------- #
# Text geometry
# --------------------------------------------------------------------------- #

def char_width(char):
    """Display columns for one character (CJK wide, combining zero)."""
    if unicodedata.combining(char):
        return 0
    return 2 if unicodedata.east_asian_width(char) in {"W", "F"} else 1


def text_width(text):
    return sum(char_width(char) for char in text)


def truncate(text, width, ellipsis="\u2026"):
    """Cut *text* to at most *width* columns, appending an ellipsis if cut."""
    if width <= 0:
        return ""
    if text_width(text) <= width:
        return text
    budget = width - text_width(ellipsis)
    out = []
    used = 0
    for char in text:
        step = char_width(char)
        if used + step > budget:
            break
        out.append(char)
        used += step
    return "".join(out) + ellipsis


def fit(text, width):
    """Truncate and pad *text* to exactly *width* columns."""
    clipped = truncate(text, width)
    return clipped + " " * max(0, width - text_width(clipped))


def wrap(text, width):
    """Greedy wrap that respects display width (CJK-safe)."""
    if width <= 0:
        return [""]
    lines = []
    current = ""
    used = 0
    for char in text:
        if char == "\n":
            lines.append(current)
            current, used = "", 0
            continue
        step = char_width(char)
        if used + step > width:
            lines.append(current)
            current, used = "", 0
        current += char
        used += step
    lines.append(current)
    return lines


# --------------------------------------------------------------------------- #
# Canvas: retained-mode cells, serialised to ANSI or plain text
# --------------------------------------------------------------------------- #

class Canvas:
    """A grid of styled characters.

    ``issues`` collects the places where something did not fit, which is how
    the probe turns "looks fine on my terminal" into a checkable assertion.
    """

    def __init__(self, width, height):
        self.width = width
        self.height = height
        self.cells = [
            [[" ", WHITE, PANEL, False] for _ in range(width)] for _ in range(height)
        ]
        self.issues = []

    # -- low level ---------------------------------------------------------
    def set(self, x, y, char, fg=WHITE, bg=PANEL, bold=False):
        if 0 <= x < self.width and 0 <= y < self.height:
            self.cells[y][x] = [char, fg, bg, bold]

    def put(self, x, y, text, fg=WHITE, bg=PANEL, bold=False):
        """Draw *text* at (x, y); records an issue when it is clipped."""
        if y < 0 or y >= self.height:
            if text:
                self.issues.append(f"row {y} outside canvas: {text!r}")
            return
        column = x
        for char in text:
            step = char_width(char)
            if step == 0:
                continue
            if column < 0 or column + step > self.width:
                self.issues.append(
                    f"row {y} col {column}: {text!r} does not fit in {self.width}"
                )
                return
            self.set(column, y, char, fg=fg, bg=bg, bold=bold)
            if step == 2:
                self.set(column + 1, y, "", fg=fg, bg=bg, bold=bold)
            column += step

    def put_fit(self, x, y, text, width, fg=WHITE, bg=PANEL, bold=False):
        """Draw *text* padded/clipped to exactly *width* columns."""
        self.fill(x, y, width, 1, " ", fg=fg, bg=bg)
        self.put(x, y, fit(text, width), fg=fg, bg=bg, bold=bold)

    def fill(self, x, y, width, height, char=" ", fg=WHITE, bg=PANEL, bold=False):
        for row in range(y, y + height):
            for column in range(x, x + width):
                if 0 <= row < self.height and 0 <= column < self.width:
                    self.cells[row][column] = [char, fg, bg, bold]

    def hline(self, x, y, width, char=BOX["h"], fg=LINE, bg=PANEL):
        for column in range(x, x + width):
            self.set(column, y, char, fg=fg, bg=bg)

    def vline(self, x, y, height, char=BOX["v"], fg=LINE, bg=PANEL):
        for row in range(y, y + height):
            self.set(x, row, char, fg=fg, bg=bg)

    # -- composite ---------------------------------------------------------
    def box(self, x, y, width, height, title="", border=LINE, title_color=CYAN,
            bg=PANEL):
        if width < 4 or height < 3:
            return
        self.fill(x, y, width, height, " ", bg=bg)
        self.put(x, y, BOX["tl"], fg=border, bg=bg)
        self.put(x + width - 1, y, BOX["tr"], fg=border, bg=bg)
        self.put(x, y + height - 1, BOX["bl"], fg=border, bg=bg)
        self.put(x + width - 1, y + height - 1, BOX["br"], fg=border, bg=bg)
        self.hline(x + 1, y, width - 2, fg=border, bg=bg)
        self.hline(x + 1, y + height - 1, width - 2, fg=border, bg=bg)
        self.vline(x, y + 1, height - 2, fg=border, bg=bg)
        self.vline(x + width - 1, y + 1, height - 2, fg=border, bg=bg)
        if title:
            label = f" {truncate(title, width - 8)} "
            self.put(x + 2, y, label, fg=title_color, bg=bg, bold=True)

    def text_rows(self):
        """Plain-text rows, exactly ``width`` display columns each."""
        rows = []
        for row in self.cells:
            rows.append("".join(cell[0] for cell in row))
        return rows

    def ansi(self):
        """Serialize to one full-screen ANSI frame (no trailing newline)."""
        home = "\033[H"
        chunks = [home]
        last = None
        for row in self.cells:
            for char, fg, bg, bold in row:
                style = (fg, bg, bold)
                if style != last:
                    chunks.append(_sgr(fg, bg, bold))
                    last = style
                chunks.append(char)
            chunks.append("\033[0m\r\n")
            last = None
        # Drop the final CRLF: writing exactly ``height`` lines avoids the
        # scroll that would shift every border by one row.
        frame = "".join(chunks[:-1])
        return frame


# --------------------------------------------------------------------------- #
# Data
# --------------------------------------------------------------------------- #

def _systemctl(*args, timeout=2.0):
    """Ask systemd something, returning '' when it is not available."""
    try:
        result = subprocess.run(
            ["systemctl", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _watchdog_state():
    """Daemon/timer activity plus the age of the published state file."""
    info = {"daemon": "unknown", "timer": "unknown", "enabled": "unknown", "age": None}
    if platform.system() == "Linux":
        daemon = _systemctl("is-active", "lan-route-fixer-daemon.service")
        timer = _systemctl("is-active", "lan-route-fixer.timer")
        enabled = _systemctl("is-enabled", "lan-route-fixer-daemon.service")
        info["daemon"] = daemon or "inactive"
        info["timer"] = timer or "inactive"
        info["enabled"] = enabled or "unknown"
    try:
        state = config_module.read_state()
    except Exception:  # noqa: BLE001 - state is optional
        state = None
    if state:
        try:
            info["age"] = max(0.0, time.time() - float(state.get("updated_at") or 0))
        except (TypeError, ValueError):
            info["age"] = None
        info["interval"] = state.get("interval_seconds")
    return info


def _merge_targets(config, results):
    """Join configured targets with their check results, disabled ones included."""
    by_address = {result.get("address"): result for result in results}
    items = []
    for target in config.targets:
        address = str(target.get("address", "")).strip()
        result = by_address.get(address, {})
        enabled = bool(target.get("enabled"))
        items.append(
            {
                "name": str(target.get("name") or address or "未命名"),
                "address": address,
                "enabled": enabled,
                "desired": result.get("desired") or target.get("interface") or "",
                "current": result.get("current") or "",
                "state": result.get("state") if enabled else "disabled",
                "reason": result.get("reason") or "",
                "ok": bool(result.get("ok")) and enabled,
                "prefix": result.get("prefix", 32),
                "table": result.get("table", "main"),
                "policy_rule": result.get("policy_rule", False),
                "covering": result.get("covering") or [],
                "pending": result.get("pending") or "",
            }
        )
    return items


def gather_snapshot(config_path=None):
    """Read everything the dashboard shows.  Read-only; never asks for auth."""
    config = config_module.load_config(config_path)
    backend = get_backend(refresh=True)
    results = checks.check_targets(config, backend=backend)
    targets = _merge_targets(config, results)
    summary = checks.summarize(results)

    try:
        networks = backend.local_networks(4)
    except Exception:  # noqa: BLE001 - a backend hiccup must not kill the TUI
        networks = []
    addresses = {name: address for name, _network, address in networks}

    try:
        interfaces = backend.list_interfaces(only_up=True)
    except Exception:  # noqa: BLE001
        interfaces = []

    try:
        tunnels = list(backend.tunnel_interfaces())
    except Exception:  # noqa: BLE001 - optional diagnostic hook
        tunnels = []

    tunnel_names = [entry.get("name", "") for entry in tunnels]
    tunnel_set = {name.lower() for name in tunnel_names}
    physical = [
        {
            "name": name,
            "address": addresses.get(name, ""),
        }
        for name in interfaces
        if name.lower() not in tunnel_set
    ]

    try:
        routes = backend.routes()
    except Exception:  # noqa: BLE001
        routes = []
    owned = sum(1 for entry in routes if entry.get("owned"))

    atrust = next(
        (name for name in tunnel_names if "atrust" in name.lower() or "sangfor" in name.lower()),
        "",
    )

    return {
        "config_path": str(config.path),
        "targets": targets,
        "summary": summary,
        "physical": physical,
        "tunnels": tunnel_names,
        "atrust": atrust,
        "admin": bool(backend.is_privileged),
        "backend": backend.name,
        "watchdog": _watchdog_state(),
        "routes": {"total": len(routes), "owned": owned},
        "elapsed": 0.0,
        "error": "",
        "config": config,
    }


def demo_state():
    """A fixed snapshot used by the probe and the tests (no backend needed)."""
    return {
        "config_path": "~/.config/lan-route-fixer/config.json",
        "targets": [
            {"name": "4090-1", "address": "192.168.4.94/32", "enabled": True,
             "desired": "WLAN", "current": "WLAN", "state": "ok", "ok": True,
             "reason": "", "prefix": 32, "table": "main", "policy_rule": False,
             "covering": [], "pending": ""},
            {"name": "challenge_4090", "address": "192.168.4.234/32", "enabled": True,
             "desired": "WLAN", "current": "aTrustVNIC", "state": "wrong-interface",
             "ok": False, "reason": "当前经 aTrustVNIC（网关 10.85.35.164）转发",
             "prefix": 32, "table": "main", "policy_rule": False,
             "covering": ["192.168.4.128/25"], "pending": ""},
            {"name": "u55c", "address": "192.168.4.19/32", "enabled": True,
             "desired": "WLAN", "current": "WLAN", "state": "ok", "ok": True,
             "reason": "", "prefix": 32, "table": "main", "policy_rule": False,
             "covering": [], "pending": ""},
            {"name": "printer", "address": "192.168.4.50/32", "enabled": False,
             "desired": "", "current": "", "state": "disabled", "ok": False,
             "reason": "", "prefix": 32, "table": "main", "policy_rule": False,
             "covering": [], "pending": ""},
        ],
        "summary": {"total": 3, "ok": 2, "bad": 1},
        "physical": [{"name": "WLAN", "address": "192.168.4.31"}],
        "tunnels": ["aTrustVNIC", "Tailscale", "et_10_o12v", "Loopback Pseudo-Interface 1"],
        "atrust": "aTrustVNIC",
        "admin": False,
        "backend": "linux",
        "watchdog": {"daemon": "active", "timer": "active", "enabled": "enabled", "age": 3.2},
        "routes": {"total": 618, "owned": 3},
        "elapsed": 0.0,
        "error": "",
        "config": None,
    }


# --------------------------------------------------------------------------- #
# View
# --------------------------------------------------------------------------- #

MAX_LOG_LINES = 200


def _badge(target):
    """Colour + label for the state pill on a target card."""
    if not target["enabled"]:
        return "OFF", DIM
    if target["ok"]:
        return STATUS_TEXT["ok"], GREEN
    state = target["state"] if target["state"] in STATUS_TEXT else "unknown"
    colour = RED if state in {"wrong-interface", "missing"} else AMBER
    return STATUS_TEXT[state], colour


def _header(canvas, state, width):
    canvas.box(0, 0, width, 3, border=LINE)
    brand = "  LAN ROUTE FIXER"
    canvas.put(2, 1, brand, fg=CYAN, bold=True)
    brand_end = 2 + text_width(brand)
    clock = state.get("clock") or time.strftime("%H:%M:%S")
    version = state.get("version", __version__)
    right = f"{clock}  \u00b7  v{version}" if width >= 70 else clock
    right = truncate(right, width - 4)
    right_x = width - 2 - text_width(right)
    canvas.put(right_x, 1, right, fg=INK)
    grid = "  //  A T R U S T   D E F E N S E   G R I D"
    label = " ADMINISTRATOR " if state.get("admin") else " STANDARD USER "
    colour = AMBER if state.get("admin") else DIM
    label_x = right_x - 2 - text_width(label)
    if label_x > brand_end + 4:
        canvas.put(label_x, 1, label, fg=colour, bold=True)
    grid_x = brand_end + 2
    if grid_x + text_width(grid) <= label_x - 2:
        canvas.put(grid_x, 1, grid, fg=CYAN_D)


def _targets(canvas, state, x, y, width, height):
    canvas.box(x, y, width, height, "TARGETS", title_color=CYAN)
    if width < 16 or height < 5:
        return
    targets = state.get("targets") or []
    compact = height < 18
    card_h = 3 if compact else 4
    inner_w = width - 4
    top = y + 2
    visible = max(0, (height - 4) // card_h)
    if visible == 0:
        return
    selected = int(state.get("selected") or 0)
    selected = min(max(0, selected), max(0, len(targets) - 1))
    if len(targets) > visible:
        first = max(0, min(selected - visible // 2, len(targets) - visible))
    else:
        first = 0
    if not targets:
        canvas.put(x + 3, top, "没有目标。", fg=DIM)
        canvas.put(x + 3, top + 2, "按 i 从 ~/.ssh/config 导入，", fg=DIM)
        canvas.put(x + 3, top + 3, "或 lan-route-fixer add <IP>。", fg=DIM)
        return
    for row, target in enumerate(targets[first:first + visible]):
        index = first + row
        card_y = top + row * card_h
        is_selected = index == selected
        bg = PANEL_2 if is_selected else PANEL
        canvas.fill(x + 1, card_y, width - 2, card_h - 1, " ", bg=bg)
        if is_selected:
            canvas.vline(x + 1, card_y, card_h - 1, char="\u258c", fg=CYAN, bg=bg)
        name = target["name"]
        badge, colour = _badge(target)
        name_w = inner_w - text_width(badge) - 1
        canvas.put(x + 3, card_y, truncate(name, name_w), fg=WHITE, bg=bg, bold=True)
        canvas.put(x + 3 + name_w + 1, card_y, badge, fg=colour, bg=bg, bold=True)
        canvas.put(x + 3, card_y + 1, truncate(target["address"], inner_w - 1),
                   fg=INK, bg=bg)
        if compact:
            continue
        desired = target["desired"] or "?"
        current = target["current"] or "\u2014"
        arrow_x = x + 3 + text_width(desired) + 2
        canvas.put(x + 3, card_y + 2, desired, fg=CYAN, bg=bg)
        canvas.hline(arrow_x, card_y + 2, 2, char=BOX["h"], fg=CYAN_D, bg=bg)
        canvas.set(arrow_x + 2, card_y + 2, "\u25b8", fg=CYAN_D, bg=bg)
        current_colour = GREEN if target["ok"] else (RED if target["current"] else DIM)
        canvas.put(arrow_x + 4, card_y + 2, truncate(current, inner_w - (arrow_x - x) - 4),
                   fg=current_colour, bg=bg)
    if len(targets) > visible:
        canvas.put(x + 2, y + height - 2, f" {selected + 1}/{len(targets)} ",
                   fg=DIM)


def _radar(canvas, x, y, width, height, state):
    """Concentric grid plus a rotating sweep and one tick per target."""
    cx = x + width // 2
    cy = y + height // 2
    rx = max(3, width // 2 - 1)
    ry = max(1, height // 2 - 1)
    for fraction in (0.5, 0.85, 1.0):
        stepped = 0.0
        while stepped < 6.28318:
            angle = stepped
            px = cx + round(rx * fraction * 0.92 * math.cos(angle))
            py = cy + round(ry * fraction * 0.92 * math.sin(angle))
            if x < px < x + width - 1 and y < py < y + height - 1:
                canvas.set(px, py, "\u00b7", fg=LINE, bg=PANEL)
            stepped += 0.18
    sweep = state.get("sweep", 0.0)
    radius = 1.0
    step = 0.03
    value = 0.15
    while value < radius:
        angle = sweep
        px = cx + round(rx * value * 0.92 * math.cos(angle))
        py = cy + round(ry * value * 0.92 * math.sin(angle))
        if x < px < x + width - 1 and y < py < y + height - 1:
            canvas.set(px, py, "\u00b7", fg=CYAN_D, bg=PANEL)
        value += step
    targets = state.get("targets") or []
    for index, target in enumerate(targets[:6]):
        angle = -2.2 + index * 0.62
        px = cx + round(rx * 0.78 * 0.92 * math.cos(angle))
        py = cy + round(ry * 0.78 * 0.92 * math.sin(angle))
        colour = GREEN if target.get("ok") else (RED if target.get("enabled") else DIM)
        canvas.set(px, py, "\u25cf", fg=colour, bg=PANEL, bold=True)
    canvas.set(cx, cy, "+", fg=CYAN, bg=PANEL, bold=True)


def _stats(canvas, state, x, y, width, height):
    canvas.box(x, y, width, height, "ROUTE INTEGRITY", title_color=GREEN)
    inner_w = width - 4
    radar_w = min(30, max(12, inner_w // 2))
    _radar(canvas, x + 2, y + 2, radar_w, max(3, height - 4), state)
    summary = state.get("summary") or {}
    total = summary.get("total", 0)
    ok = summary.get("ok", 0)
    bad = summary.get("bad") or (total - ok if total else 0)
    column = x + 2 + radar_w + 2
    room = x + width - 2 - column
    if room < 12:
        return
    rows = [
        ("TARGETS", f"{total:02d}", WHITE),
        ("SECURED", f"{ok:02d}", GREEN),
        ("CAPTURED", f"{bad:02d}", RED if bad else DIM),
    ]
    line = y + 2
    for label, value, colour in rows:
        if line > y + height - 2:
            break
        canvas.put(column, line, label, fg=DIM)
        canvas.put(column + 9, line, value, fg=colour, bold=True)
        line += 2
    gauge_y = y + height - 3
    if height >= 10 and ok and total:
        bar_w = max(4, width - 9)
        filled = max(1, round(bar_w * ok / total))
        canvas.put(x + 2, gauge_y, "\u2588" * filled, fg=GREEN, bg=PANEL)
        canvas.put(x + 2 + filled, gauge_y, "\u2591" * max(0, bar_w - filled),
                   fg=LINE, bg=PANEL)
        text = f"{round(100 * ok / total)}%"
        canvas.put(x + width - 2 - text_width(text), gauge_y, text, fg=GREEN)


def _system(canvas, state, x, y, width, height):
    canvas.box(x, y, width, height, "SYSTEM GRID", title_color=CYAN)
    physical = state.get("physical") or []
    primary = physical[0] if physical else None
    nic = f"{primary['name']}  {primary['address']}/24" if primary else "无可用物理网卡"
    tunnels = state.get("tunnels") or []
    if tunnels:
        shown = ", ".join(tunnels[:3])
        if len(tunnels) > 3:
            shown += f"  +{len(tunnels) - 3}"
    else:
        shown = "无"
    atrust = state.get("atrust") or ""
    atrust_text = f"检测到 {atrust}" if atrust else "未检测到"
    watchdog = state.get("watchdog") or {}
    daemon = watchdog.get("daemon", "unknown")
    timer = watchdog.get("timer", "unknown")
    age = watchdog.get("age")
    age_text = f"{age:.0f}s 前" if isinstance(age, (int, float)) else "无状态"
    privilege = "ADMINISTRATOR" if state.get("admin") else "STANDARD USER"
    routes = state.get("routes") or {}
    rows = [
        ("NIC", nic, WHITE),
        ("TUNNELS", shown, AMBER if tunnels else DIM),
        ("ATRUST", atrust_text, RED if atrust else DIM),
        ("PRIVILEGE", privilege, AMBER if state.get("admin") else DIM),
        ("WATCHDOG", f"daemon {daemon} \u00b7 timer {timer} \u00b7 {age_text}",
         GREEN if "active" in (daemon, timer) else DIM),
        ("ROUTES", f"{routes.get('total', 0)} 条 \u00b7 {routes.get('owned', 0)} 条 lanrf",
         INK),
    ]
    line = y + 2
    inner_w = width - 4
    for label, value, colour in rows:
        if line >= y + height - 1:
            break
        canvas.put(x + 2, line, label, fg=DIM)
        canvas.put(x + 12, line, truncate(value, inner_w - 10), fg=colour)
        line += 1


def _log_panel(canvas, state, x, y, width, height):
    canvas.box(x, y, width, height, "EVENT STREAM", title_color=MAGENTA)
    entries = list(state.get("log") or [])[-(height - 3):]
    if not entries:
        entries = [("--:--:--", "info", "就绪。s 扫描 \u00b7 f 修复 \u00b7 i 导入 SSH \u00b7 d 诊断")]
    colours = {"info": DIM, "ok": GREEN, "warn": AMBER, "fail": RED, "run": CYAN}
    line = y + 2
    for stamp, level, message in entries:
        if line >= y + height - 1:
            break
        canvas.put(x + 2, line, stamp, fg=LINE)
        canvas.put(x + 11, line, truncate(message, width - 14), fg=colours.get(level, INK))
        line += 1


def _footer(canvas, state, width, height):
    sep = height - 3
    canvas.hline(0, sep, width, fg=LINE)
    hints = "  s 扫描    f 修复    i 导入 SSH    d 诊断    w 看门狗    ? 帮助    q 退出"
    hints += "    \u2191\u2193 选择     \u21b5 详情"
    canvas.put_fit(0, height - 2, hints, width, fg=INK, bg=BG)
    status = state.get("status_line") or ""
    if not status:
        summary = state.get("summary") or {}
        status = (
            f"\u25cf  {summary.get('ok', 0)}/{summary.get('total', 0)} SECURED"
            f"  \u00b7  {state.get('error', '') or '监视中'}"
        )
    if state.get("busy"):
        status = f"\u25cf {state['busy']}\u2026  {status}"
    canvas.put_fit(0, height - 1, status, width,
                   fg=GREEN if not state.get("error") else RED, bg=BG)


def _overlay(canvas, state, width, height):
    overlay = state.get("overlay")
    if not overlay:
        return
    lines = overlay.get("lines") or []
    box_w = min(width - 6, max(40, min(96, max((text_width(line) for line in lines), default=20) + 6)))
    box_h = min(height - 4, max(8, min(len(lines) + 5, 24)))
    x = max(0, (width - box_w) // 2)
    y = max(0, (height - box_h) // 2)
    canvas.fill(x, y, box_w, box_h, " ", bg=PANEL_2)
    canvas.box(x, y, box_w, box_h, overlay.get("title", ""), border=CYAN,
               title_color=CYAN, bg=PANEL_2)
    scroll = int(overlay.get("scroll") or 0)
    visible = box_h - 3
    chunk = lines[scroll:scroll + visible]
    line = y + 1
    for text in chunk:
        colour = INK
        if text.startswith("!"):
            colour = AMBER
        elif text.startswith("\u2717"):
            colour = RED
        elif text.startswith("\u2713"):
            colour = GREEN
        canvas.put(x + 2, line, truncate(text, box_w - 4), fg=colour, bg=PANEL_2)
        line += 1
    footer = overlay.get("footer") or "Esc 返回 \u00b7 \u2191\u2193 滚动"
    canvas.put_fit(x + 1, y + box_h - 1, " " + footer + " ",
                   box_w - 2, fg=DIM, bg=PANEL_2)


def build_view(state, width, height):
    """Render the whole dashboard for a given terminal size."""
    canvas = Canvas(width, height)
    canvas.fill(0, 0, width, height, " ", bg=BG)
    if width < 60 or height < 12:
        canvas.put_fit(0, 0, " 窗口太小：至少 60x12", width, fg=AMBER, bg=BG)
        return canvas
    if width < 92 or height < 26:
        _header(canvas, state, width)
        _targets(canvas, state, 0, 3, width, max(4, height - 6))
        _footer(canvas, state, width, height)
        _overlay(canvas, state, width, height)
        return canvas

    _header(canvas, state, width)
    footer = 3
    body_y = 3
    body_h = height - body_y - footer
    left_w = max(38, min(54, int(width * 0.36)))
    right_x = left_w + 1
    right_w = width - right_x
    _targets(canvas, state, 0, body_y, left_w, body_h)
    stats_h = min(10, max(8, body_h // 3))
    system_h = min(9, max(7, body_h // 4))
    log_h = body_h - stats_h - system_h - 2
    if log_h < 5:
        stats_h = 8
        system_h = 7
        log_h = body_h - 17
    _stats(canvas, state, right_x, body_y, right_w, stats_h)
    system_y = body_y + stats_h + 1
    _system(canvas, state, right_x, system_y, right_w, system_h)
    log_y = system_y + system_h + 1
    _log_panel(canvas, state, right_x, log_y, right_w, max(3, body_h - (log_y - body_y)))
    _footer(canvas, state, width, height)
    _overlay(canvas, state, width, height)
    return canvas


# --------------------------------------------------------------------------- #
# Interactive application
# --------------------------------------------------------------------------- #

HELP_LINES = [
    "快捷键",
    "",
    "  s   扫描一次（只读，不改路由）",
    "  f   修复选中的目标；未选中时修复全部（需要授权）",
    "  i   从 ~/.ssh/config 导入局域网主机（先预演，确认后写入）",
    "  d   运行完整诊断（环境 / 路由 / 后台 / TCP 22 连通性）",
    "  w   看门狗状态：守护进程、systemd 定时器、状态文件年龄",
    "  \u2191\u2193  选择目标卡片",
    "  \u21b5  打开选中目标的详情",
    "  r   立即重新扫描",
    "  q / Ctrl-C  退出",
    "",
    "授权方式：优先请求已运行的 lan-route-fixer-daemon（无需再次弹框）；",
    "守护进程没跑时回退到 pkexec，polkit 会弹出系统授权窗口。",
]


class Tui:
    """State container + input loop; the renderer above stays pure."""

    def __init__(self, interval=5.0, config_path=None):
        self.interval = max(2.0, float(interval or 5.0))
        self.config_path = config_path
        self.state = {
            "version": __version__,
            "clock": time.strftime("%H:%M:%S"),
            "targets": [],
            "summary": {"total": 0, "ok": 0, "bad": 0},
            "physical": [],
            "tunnels": [],
            "atrust": "",
            "admin": False,
            "backend": "",
            "watchdog": {},
            "routes": {"total": 0, "owned": 0},
            "log": deque(maxlen=MAX_LOG_LINES),
            "selected": 0,
            "sweep": 0.0,
            "overlay": None,
            "busy": "",
            "status_line": "",
            "error": "",
            "config": None,
        }
        self.running = True
        self.lock = threading.Lock()
        self.results = queue.Queue()
        self.stop_event = threading.Event()
        self._config = None

    # -- data plumbing -----------------------------------------------------
    def log(self, level, message):
        self.state["log"].append((time.strftime("%H:%M:%S"), level, message))

    def _publish(self, snapshot):
        with self.lock:
            self._config = snapshot.pop("config", None)
            targets = snapshot.get("targets") or []
            self.state.update(snapshot)
            self.state["targets"] = targets
            self.state["selected"] = min(
                int(self.state.get("selected") or 0), max(0, len(targets) - 1)
            )
            self.state["status_line"] = ""
            self.state["error"] = ""
            self.state["last_scan"] = time.time()
            if not self.state.get("log"):
                self.log("info", "就绪。s 扫描 \u00b7 f 修复 \u00b7 i 导入 SSH \u00b7 d 诊断")

    def _load_once(self):
        try:
            started = time.time()
            snapshot = gather_snapshot(self.config_path)
            snapshot["elapsed"] = time.time() - started
            self.results.put(("snapshot", snapshot))
        except Exception as exception:  # noqa: BLE001 - keep the dashboard alive
            self.results.put(("error", f"扫描失败：{exception}"))

    def request_scan(self):
        if self.state.get("busy"):
            return
        self.state["busy"] = "SCANNING"
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        self._load_once()

    def _long_action(self, name, function):
        self.state["busy"] = name
        threading.Thread(target=self._run_long, args=(name, function), daemon=True).start()

    def _run_long(self, name, function):
        try:
            function()
        except Exception as exception:  # noqa: BLE001 - surface, never crash
            self.results.put(("log", ("fail", f"{name} 失败：{exception}")))
        finally:
            self.results.put(("action-done", name))

    # -- actions -----------------------------------------------------------
    def _current_config(self):
        if self._config is not None:
            return self._config
        return config_module.load_config(self.config_path)

    def action_fix(self):
        config = self._current_config()
        target = self._selected_target()
        targets = [target] if target and target.get("enabled") else config.enabled_targets
        if not targets:
            self.results.put(("log", ("warn", "没有启用的目标可修复")))
            return

        def work():
            outcome = privileged.fix_targets(targets, config=config)
            code = outcome.get("return_code", 1)
            if code == 0:
                self.results.put(("log", ("ok", "修复请求已执行；重新扫描中")))
            else:
                reason = privileged.describe_failure(code, outcome.get("stderr", ""))
                self.results.put(("log", ("fail", reason)))

        self._long_action("FIXING", work)

    def action_import(self):
        def work():
            code, output = _capture_cli(["import-ssh", "--dry-run"])
            lines = [line for line in output.splitlines() if line.strip()]
            if not lines:
                lines = ["（没有输出）"]
            overlay = {
                "title": "IMPORT SSH \u00b7 预演",
                "lines": lines[-18:],
                "scroll": 0,
                "footer": "y 写入配置 \u00b7 Esc 返回",
            }
            self.results.put(("overlay", overlay))
            self.results.put(("log", ("info", "已读取 SSH 配置，按 y 可写入")))

        self._long_action("READING SSH", work)

    def action_import_confirm(self):
        def work():
            code, output = _capture_cli(["import-ssh", "--yes"])
            for line in output.splitlines():
                if line.strip():
                    self.results.put(("log", ("ok" if code == 0 else "fail", line.strip())))
            self._load_once()

        self._long_action("IMPORTING", work)

    def action_doctor(self):
        def work():
            report = doctor_module.diagnose(probe=True)
            lines = doctor_module.format_findings(report["findings"], use_color=False)
            self.results.put(
                (
                    "overlay",
                    {
                        "title": "DIAGNOSE \u00b7 全量诊断",
                        "lines": lines.splitlines(),
                        "scroll": 0,
                        "footer": "Esc 返回 \u00b7 \u2191\u2193 滚动",
                    },
                )
            )
            worst = report.get("worst", 2)
            level = "ok" if worst == 0 else ("warn" if worst == 1 else "fail")
            self.results.put(("log", (level, f"诊断完成（{len(report['findings'])} 项）")))

        self._long_action("DIAGNOSING", work)

    def action_watchdog(self):
        status = self.state.get("watchdog") or {}
        age = status.get("age")
        lines = [
            f"守护进程     {status.get('daemon', 'unknown')}",
            f"systemd 定时器 {status.get('timer', 'unknown')}",
            f"开机启用     {status.get('enabled', 'unknown')}",
            f"状态文件     {'{:.0f} 秒前'.format(age) if isinstance(age, (int, float)) else '不存在'}",
            "",
            "要让修复在 aTrust 重连后自动补回 /32 路由：",
            "",
            "  sudo systemctl enable --now lan-route-fixer-daemon.service",
            "",
            "守护进程直接持有 rtnetlink，无需反复授权；",
            "查看日志：journalctl -u lan-route-fixer-daemon -f",
        ]
        self.results.put(
            (
                "overlay",
                {"title": "WATCHDOG", "lines": lines, "scroll": 0},
            )
        )

    def action_detail(self):
        target = self._selected_target()
        if not target:
            return
        state = STATUS_TEXT.get(target["state"], "UNKNOWN")
        lines = [
            f"名称      {target['name']}",
            f"地址      {target['address']}  (/{target.get('prefix', 32)})",
            f"状态      {state}",
            f"期望网卡  {target['desired'] or '自动'}",
            f"当前网卡  {target['current'] or '无路由'}",
            f"路由表    {target['table']}",
            f"策略路由  {'是' if target.get('policy_rule') else '否'}",
        ]
        if target.get("covering"):
            lines.append(f"覆盖路由  {', '.join(str(item) for item in target['covering'][:4])}")
        if target.get("reason"):
            lines.append("")
            for line in wrap(target["reason"], 70):
                lines.append(line)
        lines.append("")
        lines.append("按 f 修复这个目标（选中状态会被保留）。")
        self.results.put(("overlay", {"title": "TARGET", "lines": lines, "scroll": 0}))

    def _selected_target(self):
        targets = self.state.get("targets") or []
        if not targets:
            return None
        index = min(max(0, int(self.state.get("selected") or 0)), len(targets) - 1)
        return targets[index]

    # -- input -------------------------------------------------------------
    def handle_key(self, key):
        overlay = self.state.get("overlay")
        if overlay:
            if key in {"\x1b", "q"}:
                self.state["overlay"] = None
            elif key == "KEY_UP":
                overlay["scroll"] = max(0, int(overlay.get("scroll") or 0) - 1)
            elif key == "KEY_DOWN":
                overlay["scroll"] = int(overlay.get("scroll") or 0) + 1
            elif key == "y" and "IMPORT SSH" in (overlay.get("title") or ""):
                self.state["overlay"] = None
                self.action_import_confirm()
            return
        if key in {"q", "Q", "\x03"}:
            self.running = False
        elif key in {"s", "S", "r", "R"}:
            self.request_scan()
        elif key in {"f", "F"}:
            self.action_fix()
        elif key in {"i", "I"}:
            self.action_import()
        elif key in {"d", "D"}:
            self.action_doctor()
        elif key in {"w", "W"}:
            self.action_watchdog()
        elif key == "?":
            self.results.put(("overlay", {"title": "HELP", "lines": HELP_LINES, "scroll": 0}))
        elif key == "KEY_UP":
            self.state["selected"] = max(0, int(self.state.get("selected") or 0) - 1)
        elif key == "KEY_DOWN":
            self.state["selected"] = min(
                max(0, len(self.state.get("targets") or []) - 1),
                int(self.state.get("selected") or 0) + 1,
            )
        elif key in {"\r", "\n"}:
            self.action_detail()

    def _drain(self):
        changed = False
        while True:
            try:
                kind, payload = self.results.get_nowait()
            except queue.Empty:
                break
            changed = True
            if kind == "snapshot":
                self._publish(payload)
            elif kind == "error":
                self.state["error"] = str(payload)
                self.log("fail", str(payload))
                self.state["busy"] = ""
            elif kind == "log":
                level, message = payload
                self.log(level, message)
            elif kind == "overlay":
                self.state["overlay"] = payload
            elif kind == "action-done":
                self.state["busy"] = ""
        return changed

    # -- terminal loop -----------------------------------------------------
    def run(self):
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            print(
                "TUI 需要交互式终端：请在终端里运行 lan-route-fixer，"
                "或运行 lan-route-fixer status。",
                file=sys.stderr,
            )
            return 2
        if termios is None:  # pragma: no cover - Windows
            print("TUI 目前只支持 POSIX 终端。", file=sys.stderr)
            return 2
        fd = sys.stdin.fileno()
        old_attributes = termios.tcgetattr(fd)
        try:
            self.request_scan()
            _write(ALT_SCREEN_ON + CURSOR_HIDE)
            tty.setraw(fd)
            last_load = time.time()
            while self.running:
                self._drain()
                now = time.time()
                if now - last_load >= self.interval and not self.state.get("busy"):
                    last_load = now
                    self.request_scan()
                self.state["clock"] = time.strftime("%H:%M:%S")
                self.state["sweep"] = (self.state.get("sweep", 0.0) + 0.16) % 6.28318
                width, height = _terminal_size()
                canvas = build_view(self.state, width, height)
                _write(canvas.ansi())
                key = _read_key(fd, 0.12)
                if key:
                    self.handle_key(key)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_attributes)
            _write(CURSOR_SHOW + ALT_SCREEN_OFF)
        return 0


def _capture_cli(argv):
    """Run a CLI subcommand in-process and capture its output."""
    from core import cli_main  # noqa: WPS433 - core imports lanrf, so lazy

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
        try:
            code = cli_main(list(argv))
        except SystemExit as exit_error:
            code = int(exit_error.code or 0)
    return code, buffer.getvalue()


def _terminal_size():
    try:
        size = os.get_terminal_size(sys.stdout.fileno())
        return max(60, size.columns), max(12, size.lines)
    except (OSError, ValueError):
        return 120, 36


def _write(text):
    try:
        sys.stdout.write(text)
        sys.stdout.flush()
    except (OSError, ValueError):
        pass


def _read_key(fd, timeout):
    """One key, already decoded into a name (arrows) or a character."""
    if select is None:  # pragma: no cover - Windows
        return ""
    ready, _, _ = select.select([fd], [], [], timeout)
    if not ready:
        return ""
    try:
        data = os.read(fd, 32)
    except OSError:  # pragma: no cover - terminal vanished
        return ""
    if not data:
        return ""
    if data in {b"\x1b[A", b"\x1bOA"}:
        return "KEY_UP"
    if data in {b"\x1b[B", b"\x1bOB"}:
        return "KEY_DOWN"
    if data in {b"\x1b[C", b"\x1bOC", b"\x1b[D", b"\x1bOD"}:
        return ""
    text = data.decode("utf-8", "replace")
    if text.startswith("\x1b") and len(text) > 1:
        return ""
    return text


# --------------------------------------------------------------------------- #
# Probe / fallback entry points
# --------------------------------------------------------------------------- #

def probe(widths=((126, 40), (100, 30), (160, 48), (76, 20))):
    """Render the dashboard off-screen and print the plain-text frames."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    state = demo_state()
    ok = True
    for width, height in widths:
        canvas = build_view(state, width, height)
        rows = canvas.text_rows()
        widths_ok = all(text_width(row) == width for row in rows)
        print(f"size {width}x{height}  rows={len(rows)}  issues={len(canvas.issues)}"
              f"  widths_ok={widths_ok}")
        for issue in canvas.issues[:8]:
            print(f"  ! {issue}")
        ok = ok and not canvas.issues and widths_ok
        print("-" * width)
        for row in rows:
            print(row)
        print("-" * width)
    print("probe:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def run(interval=None, config_path=None):
    """Entry point used by the CLI and by the no-argument launcher."""
    return Tui(interval=interval or 5.0, config_path=config_path).run()


if __name__ == "__main__":  # pragma: no cover - manual probe
    raise SystemExit(probe())