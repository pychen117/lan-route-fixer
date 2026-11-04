"""Tech-style tkinter control deck for lan-route-fixer on Windows.

The window is one dark "deck": the left column lists the SSH targets that live
on the physical LAN, the right side shows route integrity, node status and an
event stream.  Everything is stdlib tkinter so PyInstaller can freeze it into a
single exe; the data comes from the same ``lanrf`` modules the CLI uses.

Accent colours were picked for a cold, instrument-panel look: deep blue-black
panels, cyan hairlines, green = secured, red = captured by the tunnel, amber =
needs attention.  Panels draw corner brackets, a radar sweep and a scan line so
the window feels alive without being noisy.
"""

from __future__ import annotations

import ctypes
import io
import os
import queue
import subprocess
import sys
import threading
import time
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import tkinter as tk

# -- palette ----------------------------------------------------------------

BG = "#04060b"
PANEL = "#070c14"
PANEL_2 = "#0a1119"
LINE = "#16222f"
GRID = "#0d1824"
CYAN = "#23d3ea"
CYAN_DIM = "#0e6f80"
GREEN = "#3ddc97"
RED = "#ff5c7a"
AMBER = "#f5b942"
MAGENTA = "#ff4fd8"
TEXT = "#d8ecf8"
MUTED = "#6b8194"
DIM = "#3c4c5c"

# -- fonts ------------------------------------------------------------------

F_TITLE = ("Consolas", 21, "bold")
F_H1 = ("Consolas", 12, "bold")
F_MONO_B = ("Consolas", 10, "bold")
F_MONO = ("Consolas", 9)
F_MONO_M = ("Consolas", 10)
F_MONO_S = ("Consolas", 8)
F_NUM = ("Consolas", 27, "bold")
F_UI = ("Microsoft YaHei UI", 10)
F_UI_B = ("Microsoft YaHei UI", 10, "bold")
F_UI_S = ("Microsoft YaHei UI", 9)
F_BODY = ("Microsoft YaHei UI", 9)

STATE_SECURED = (GREEN, "SECURED")
STATE_CAPTURED = (RED, "CAPTURED")
STATE_UNROUTED = (AMBER, "NO LINK")
STATE_LOST = (AMBER, "LOST")


# -- small helpers ----------------------------------------------------------


def _mix(a, b, t):
    """Linear blend of two ``#rrggbb`` colours."""
    ar, ag, ab = int(a[1:3], 16), int(a[3:5], 16), int(a[5:7], 16)
    br, bg, bb = int(b[1:3], 16), int(b[3:5], 16), int(b[5:7], 16)
    return "#%02x%02x%02x" % (
        int(ar + (br - ar) * t),
        int(ag + (bg - ag) * t),
        int(ab + (bb - ab) * t),
    )


def _round_rect(canvas, x1, y1, x2, y2, r=8, **kw):
    pts = [
        x1 + r, y1, x2 - r, y1, x2 - r, y1, x2, y1,
        x2, y1 + r, x2, y2 - r, x2, y2 - r, x2, y2,
        x2 - r, y2, x1 + r, y2, x1 + r, y2, x1, y2,
        x1, y2 - r, x1, y1 + r, x1, y1 + r, x1, y1,
    ]
    return canvas.create_polygon(pts, smooth=True, **kw)


def _brackets(canvas, x1, y1, x2, y2, color, length=12, width=1, tags=None):
    opts = {"tags": tags} if tags else {}
    for (x, y, dx, dy) in ((x1, y1, 1, 1), (x2, y1, -1, 1), (x1, y2, 1, -1), (x2, y2, -1, -1)):
        canvas.create_line(x, y, x + dx * length, y, fill=color, width=width, **opts)
        canvas.create_line(x, y, x, y + dy * length, fill=color, width=width, **opts)


def _state_of(result):
    if result.get("ok"):
        return STATE_SECURED
    if not result.get("desired"):
        return STATE_UNROUTED
    if result.get("current"):
        return STATE_CAPTURED
    return STATE_LOST


def _short(text, limit):
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


# -- widgets ----------------------------------------------------------------


class NeonButton(tk.Canvas):
    """Flat dark button with a glowing hairline and a left accent bar."""

    def __init__(self, master, text, command, accent=CYAN, width=150, height=40):
        super().__init__(
            master, width=width, height=height, bg=BG, highlightthickness=0, bd=0
        )
        self._text = text
        self._command = command
        self._accent = accent
        self._enabled = True
        self._hover = False
        self._pressed = False
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)
        self._draw()

    def set_enabled(self, enabled):
        self._enabled = bool(enabled)
        self._draw()

    def _on_enter(self, _event):
        if self._enabled:
            self._hover = True
            self.configure(cursor="hand2")
            self._draw()

    def _on_leave(self, _event):
        self._hover = False
        self._pressed = False
        self._draw()

    def _on_press(self, _event):
        if self._enabled:
            self._pressed = True
            self._draw()

    def _on_release(self, event):
        if self._enabled and self._pressed:
            self._pressed = False
            self._draw()
            if 0 <= event.x <= int(self["width"]) and 0 <= event.y <= int(self["height"]):
                self._command()

    def _draw(self):
        self.delete("all")
        w, h = int(self["width"]), int(self["height"])
        if not self._enabled:
            outline, fg, fill = DIM, DIM, BG
        elif self._hover:
            outline, fg, fill = self._accent, self._accent, _mix(self._accent, BG, 0.18)
        else:
            outline, fg, fill = _mix(self._accent, PANEL, 0.55), self._accent, PANEL_2
        _round_rect(self, 1, 1, w - 1, h - 1, 7, fill=fill, outline=outline, width=1)
        if self._hover and self._enabled:
            _round_rect(self, 3, 3, w - 3, h - 3, 6, fill=fill, outline=_mix(self._accent, BG, 0.55), width=1)
        self.create_line(12, h // 2 - 9, 12, h // 2 + 9, fill=outline, width=2)
        self.create_text(w // 2 + 7, h // 2, text=self._text, font=F_MONO_B, fill=fg)


class Panel(tk.Canvas):
    """Dark panel with corner brackets and a small mono title."""

    def __init__(self, master, title, **kw):
        super().__init__(master, bg=PANEL, highlightthickness=0, bd=0, **kw)
        self._title = title
        self._size = (0, 0)
        self.bind("<Configure>", self._on_configure)

    def _on_configure(self, event):
        if (event.width, event.height) != self._size:
            self._size = (event.width, event.height)
            self.redraw()

    def redraw(self):
        w, h = self._size
        if w < 20 or h < 20:
            return
        self.delete("all")
        _round_rect(self, 1, 1, w - 2, h - 2, 10, fill=PANEL, outline=LINE, width=1)
        _brackets(self, 1, 1, w - 2, h - 2, CYAN_DIM, length=10)
        self.create_text(20, 13, anchor="nw", text=self._title, fill=CYAN, font=F_MONO_S)
        self.create_line(20, 34, 62, 34, fill=CYAN_DIM)
        self._draw_content(w, h)


class HeaderBar(tk.Canvas):
    def __init__(self, master, height=104):
        super().__init__(master, height=height, bg=PANEL, highlightthickness=0, bd=0)
        self._state = {"admin": False, "version": "", "nic": "", "time": ""}
        self._dot = None
        self._clock = None
        self._width = 0
        self.bind("<Configure>", lambda e: self.redraw())

    def set_state(self, state):
        self._state.update(state)
        self.redraw()

    def tick(self, phase):
        if self._dot:
            if self._state.get("admin"):
                accent = GREEN
            else:
                accent = AMBER
            r = 3.5 + 1.5 * abs((phase % 40) / 20.0 - 1.0)
            cx, cy = self._state.get("dot_xy") or (0, 0)
            if cx:
                self.coords(self._dot, cx - r, cy - r, cx + r, cy + r)
        if self._clock and phase % 20 == 0:
            self.itemconfigure(self._clock, text=time.strftime("%Y-%m-%d  %H:%M:%S"))

    def redraw(self):
        w = self.winfo_width()
        if w < 50:
            return
        h = int(self["height"])
        self.delete("all")
        self.create_rectangle(0, 0, w, h, fill=PANEL, outline="")
        # faint diagonal hatch behind the status pill
        for i in range(9):
            x = w - 420 + i * 44
            self.create_line(x, 0, x - 46, h, fill="#0a141d")
        self.create_line(0, h - 1, w, h - 1, fill=LINE)

        # brand mark
        self.create_polygon(30, 24, 30, 52, 46, 38, fill=CYAN, outline="")
        self.create_text(58, 14, anchor="nw", text="LAN ROUTE FIXER", fill="#eafcff", font=F_TITLE)
        self.create_text(
            60, 70, anchor="nw", text="A T R U S T   D E F E N S E   G R I D",
            fill=CYAN_DIM, font=F_MONO_S,
        )

        # version + clock
        self.create_text(
            w - 26, 18, anchor="ne",
            text=f"v{self._state.get('version') or '?'}  //  WINDOWS",
            fill=MUTED, font=F_MONO_S,
        )
        self._clock = self.create_text(
            w - 26, 92, anchor="se", text=time.strftime("%Y-%m-%d  %H:%M:%S"),
            fill=DIM, font=F_MONO_S,
        )

        # privilege pill
        accent = GREEN if self._state.get("admin") else AMBER
        px2, py1, py2 = w - 26, 42, 76
        px1 = px2 - 238
        _round_rect(self, px1, py1, px2, py2, 17, fill=PANEL_2, outline=_mix(accent, BG, 0.45))
        cy = (py1 + py2) // 2
        self._state["dot_xy"] = (px1 + 22, cy)
        self._dot = self.create_oval(
            px1 + 18, cy - 4, px1 + 26, cy + 4, fill=accent, outline=""
        )
        self.create_text(
            px1 + 36, cy, anchor="w",
            text="ADMINISTRATOR" if self._state.get("admin") else "STANDARD USER",
            fill=accent, font=F_MONO_B,
        )


class TargetPanel(Panel):
    """Scrollable list of SSH targets, drawn as instrument cards."""

    CARD_H = 92
    GAP = 12
    TOP = 52

    def __init__(self, master, on_select):
        super().__init__(master, "SSH TARGETS")
        self._on_select = on_select
        self._results = []
        self._selected = 0
        self._hover = -1
        self._scroll = 0
        self._rects = []
        self._scan = None
        self.bind("<Button-1>", self._on_click)
        self.bind("<Motion>", self._on_motion)
        self.bind("<Leave>", lambda _e: self._set_hover(-1))
        self.bind("<MouseWheel>", self._on_wheel)

    def set_data(self, results, selected):
        self._results = list(results or [])
        self._selected = min(max(0, selected), max(0, len(self._results) - 1))
        self._scroll = 0
        self.redraw()

    def set_selected(self, index):
        self._selected = max(0, min(index, len(self._results) - 1))
        self.redraw()

    def tick(self, phase):
        if not self._scan or not self._rects:
            return
        w, h = self._size
        span = max(60, h - self.TOP - 10)
        y = self.TOP + (phase * 3) % span
        self.coords(self._scan, 16, y, w - 16, y)

    def _max_scroll(self):
        h = self._size[1]
        content = self.TOP + len(self._results) * (self.CARD_H + self.GAP) + 8
        return max(0, content - h)

    def _on_wheel(self, event):
        step = -1 if event.delta > 0 else 1
        self._scroll = max(0, min(self._scroll + step * 34, self._max_scroll()))
        self.redraw()

    def _hit(self, x, y):
        for (x1, y1, x2, y2, idx) in self._rects:
            if x1 <= x <= x2 and y1 <= y <= y2:
                return idx
        return -1

    def _on_click(self, event):
        idx = self._hit(event.x, event.y)
        if idx >= 0:
            self._selected = idx
            self.redraw()
            self._on_select(idx)

    def _on_motion(self, event):
        self._set_hover(self._hit(event.x, event.y))

    def _set_hover(self, idx):
        if idx != self._hover:
            self._hover = idx
            self.configure(cursor="hand2" if idx >= 0 else "")
            self.redraw()

    def _draw_content(self, w, h):
        self._rects = []
        self._scan = None
        if not self._results:
            self.create_text(
                w // 2, h // 2,
                text="没有目标\n用 IMPORT SSH 从 ~/.ssh/config 导入",
                fill=MUTED, font=F_UI, justify="center",
            )
            return
        self._scan = self.create_line(16, self.TOP, w - 16, self.TOP, fill="#0c2c36")
        for idx, result in enumerate(self._results):
            y1 = self.TOP + idx * (self.CARD_H + self.GAP) - self._scroll
            y2 = y1 + self.CARD_H
            if y2 < self.TOP - 4 or y1 > h - 8:
                continue
            color, badge = _state_of(result)
            selected = idx == self._selected
            hovered = idx == self._hover
            outline = CYAN if selected else (_mix(CYAN, LINE, 0.45) if hovered else LINE)
            fill = "#0b1622" if selected else PANEL_2
            _round_rect(self, 12, y1, w - 12, y2, 10, fill=fill, outline=outline, width=2 if selected else 1)
            self.create_rectangle(12, y1 + 14, 16, y2 - 14, fill=color, outline="")

            self.create_text(32, y1 + 10, anchor="nw", text=_short(result.get("name") or "?", 18), fill=TEXT, font=F_UI_B)
            self.create_text(
                32, y1 + 42, anchor="nw",
                text=_short(result.get("address") or result.get("ip") or "", 30),
                fill=CYAN, font=F_MONO_M,
            )
            desired = str(result.get("desired") or "—")
            current = str(result.get("current") or "NO ROUTE")
            self.create_text(32, y1 + 66, anchor="nw", text=desired, fill=GREEN if result.get("ok") else MUTED, font=F_MONO_S)
            arrow_x = 32 + len(desired) * 7 + 14
            arrow_y = y1 + 74
            self.create_line(arrow_x, arrow_y, arrow_x + 14, arrow_y, fill=CYAN_DIM, width=1)
            self.create_polygon(
                arrow_x + 21, arrow_y, arrow_x + 14, arrow_y - 4, arrow_x + 14, arrow_y + 4,
                fill=CYAN_DIM, outline="",
            )
            self.create_text(
                arrow_x + 30, y1 + 66, anchor="nw", text=current,
                fill=MUTED if result.get("ok") else RED, font=F_MONO_S,
            )
            self.create_text(w - 30, y1 + 18, anchor="ne", text=badge, fill=color, font=F_MONO_B)
            self._rects.append((12, y1, w - 12, y2, idx))


class StatBoard(Panel):
    """Three headline counters plus a small radar of the route table."""

    def __init__(self, master):
        super().__init__(master, "ROUTE INTEGRITY", height=158)
        self._data = None
        self._sweep = None

    def set_data(self, snapshot):
        self._data = snapshot
        self.redraw()

    def tick(self, phase):
        if self._sweep:
            self.itemconfigure(self._sweep, start=(phase * 6) % 360)

    def _draw_content(self, w, h):
        self._sweep = None
        snapshot = self._data or {}
        summary = snapshot.get("summary") or {"total": 0, "ok": 0, "bad": 0}
        results = snapshot.get("results") or []
        groups = (
            ("TARGETS", summary.get("total", 0), CYAN),
            ("SECURED", summary.get("ok", 0), GREEN),
            ("CAPTURED", summary.get("bad", 0), RED if summary.get("bad") else DIM),
        )
        x = 24
        for label, value, color in groups:
            self.create_text(x, 40, anchor="nw", text=f"{value:02d}", fill=color, font=F_NUM)
            self.create_text(x, 108, anchor="nw", text=label, fill=MUTED, font=F_MONO_S)
            self.create_line(x, 130, x + 88, 130, fill=color if value else GRID)
            x += 128

        cx, cy = w - 104, h // 2 + 8
        radius = min(54, (h - 56) // 2)
        for factor in (1.0, 0.66, 0.33):
            r = int(radius * factor)
            self.create_oval(cx - r, cy - r, cx + r, cy + r, outline=GRID)
        self.create_line(cx - radius, cy, cx + radius, cy, fill=GRID)
        self.create_line(cx, cy - radius, cx, cy + radius, fill=GRID)
        self._sweep = self.create_arc(
            cx - radius, cy - radius, cx + radius, cy + radius,
            start=0, extent=40, style="arc", outline=CYAN_DIM, width=2,
        )
        count = len(results) or 1
        for idx, result in enumerate(results):
            import math

            angle = math.radians(-90 + idx * 360.0 / count)
            color, _badge = _state_of(result)
            x1 = cx + (radius - 14) * math.cos(angle)
            y1 = cy + (radius - 14) * math.sin(angle)
            x2 = cx + (radius - 2) * math.cos(angle)
            y2 = cy + (radius - 2) * math.sin(angle)
            self.create_line(x1, y1, x2, y2, fill=color, width=2)
        self.create_text(
            cx, cy, text=f"{summary.get('ok', 0)}/{summary.get('total', 0)}",
            fill=GREEN if summary.get("bad") == 0 else AMBER, font=F_MONO_B,
        )


class SystemPanel(Panel):
    """Two-column node status readout."""

    def __init__(self, master):
        super().__init__(master, "NODE STATUS", height=176)
        self._data = None

    def set_data(self, snapshot):
        self._data = snapshot
        self.redraw()

    def _draw_content(self, w, h):
        snapshot = self._data or {}
        physical = snapshot.get("physical") or []
        tunnels = snapshot.get("tunnels") or []
        nic = ", ".join(f"{p['name']} {p['address']}".strip() for p in physical) or "none"
        tun_names = ", ".join(tunnels[:2])
        if len(tunnels) > 2:
            tun_names += f"  +{len(tunnels) - 2}"
        tun = tun_names or "none"
        rows = [
            ("NIC", nic, GREEN if physical else RED),
            ("TUNNELS", tun, AMBER if tunnels else GREEN),
            ("ATRUST", "DETECTED" if snapshot.get("atrust") else "NOT FOUND", RED if snapshot.get("atrust") else GREEN),
            ("PRIVILEGE", "ELEVATED" if snapshot.get("admin") else "STANDARD", GREEN if snapshot.get("admin") else AMBER),
            ("WATCHDOG", "TASK ACTIVE" if snapshot.get("task") else "OFFLINE", GREEN if snapshot.get("task") else MUTED),
            ("ROUTES", f"{snapshot.get('routes', 0)} rows · {snapshot.get('owned', 0)} pinned", MUTED),
        ]
        col_w = (w - 44) // 2
        for idx, (label, value, color) in enumerate(rows):
            col = idx // 3
            row = idx % 3
            x = 22 + col * col_w
            y = 50 + row * 40
            self.create_rectangle(x, y + 4, x + 8, y + 12, fill=color, outline="")
            self.create_text(x + 16, y, anchor="nw", text=label, fill=MUTED, font=F_MONO_S)
            self.create_text(
                x + 16, y + 15, anchor="nw",
                text=_short(value, 42), fill=TEXT if color != MUTED else MUTED, font=F_MONO,
            )


class LogPanel(tk.Frame):
    """Coloured event stream at the bottom of the right column."""

    def __init__(self, master):
        super().__init__(master, bg=LINE)
        inner = tk.Frame(self, bg=PANEL)
        inner.pack(fill="both", expand=True, padx=1, pady=1)
        head = tk.Frame(inner, bg=PANEL, height=40)
        head.pack(fill="x")
        head.pack_propagate(False)
        tk.Label(head, text="EVENT STREAM", bg=PANEL, fg=CYAN, font=F_MONO_S).pack(side="left", padx=18, pady=12)
        clear = tk.Label(head, text="CLEAR", bg=PANEL, fg=MUTED, font=F_MONO_S, cursor="hand2")
        clear.pack(side="right", padx=18)
        clear.bind("<Button-1>", lambda _e: self.clear())

        body = tk.Frame(inner, bg="#03070d")
        body.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.text = tk.Text(
            body, bg="#03070d", fg="#9fb6c8", bd=0, highlightthickness=0,
            font=F_BODY, wrap="word", state="disabled", padx=10, pady=8,
            insertbackground=CYAN,
        )
        self.text.pack(side="left", fill="both", expand=True)
        scroll = tk.Scrollbar(
            body, orient="vertical", command=self.text.yview,
            bg=PANEL, troughcolor=PANEL, activebackground=CYAN_DIM, bd=0,
            highlightthickness=0, width=10,
        )
        scroll.pack(side="right", fill="y")
        self.text.configure(yscrollcommand=scroll.set)
        for tag, color in (("ok", GREEN), ("err", RED), ("warn", AMBER), ("info", "#7fd7e6"), ("dim", MUTED)):
            self.text.tag_configure(tag, foreground=color)

    def add(self, stamp, message, level="info"):
        self.text.configure(state="normal")
        self.text.insert("end", f" {stamp}  ")
        self.text.insert("end", f"{message}\n", level)
        lines = int(self.text.index("end-1c").split(".")[0])
        if lines > 400:
            self.text.delete("1.0", "40.0")
        self.text.configure(state="disabled")
        self.text.see("end")

    def clear(self):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")


class TechDialog(tk.Toplevel):
    """Small dark modal used for confirmations and generated reports."""

    def __init__(self, parent, title, message="", body_text=None, ok_text="确认", cancel_text="取消", danger=False):
        super().__init__(parent, bg=BG)
        self.result = False
        self.withdraw()
        self.transient(parent)
        self.title(title)
        self.resizable(False, False)
        width = 660 if body_text is not None else 520
        height = 440 if body_text is not None else 230
        accent = RED if danger else CYAN

        head = tk.Canvas(self, height=46, bg=PANEL, highlightthickness=0)
        head.pack(fill="x")
        head.create_text(18, 14, anchor="nw", text=title, fill=accent, font=F_MONO_B)
        head.create_line(0, 45, width, 45, fill=LINE)
        _brackets(head, 1, 1, width - 2, 44, CYAN_DIM, length=8)

        if message:
            tk.Label(
                self, text=message, bg=BG, fg=TEXT, font=F_UI, justify="left",
                anchor="nw", wraplength=width - 48,
            ).pack(fill="x", padx=24, pady=16)

        if body_text is not None:
            frame = tk.Frame(self, bg="#03070d", highlightthickness=1, highlightbackground=LINE)
            frame.pack(fill="both", expand=True, padx=24, pady=(0, 8))
            txt = tk.Text(
                frame, bg="#03070d", fg="#a9c1d4", bd=0, font=F_MONO_S,
                wrap="word", padx=9, pady=9, height=10,
            )
            txt.pack(side="left", fill="both", expand=True)
            scroll = tk.Scrollbar(frame, orient="vertical", command=txt.yview)
            scroll.pack(side="right", fill="y")
            txt.configure(yscrollcommand=scroll.set)
            txt.insert("1.0", body_text)
            txt.configure(state="disabled")

        foot = tk.Frame(self, bg=BG, height=58)
        foot.pack(fill="x", side="bottom")
        foot.pack_propagate(False)
        if ok_text:
            NeonButton(
                foot, ok_text.upper(), lambda: self._close(True),
                accent=RED if danger else CYAN, width=140, height=36,
            ).pack(side="right", padx=(8, 20), pady=11)
        NeonButton(
            foot, cancel_text.upper(), lambda: self._close(False),
            accent="#4c6172", width=120, height=36,
        ).pack(side="right", pady=11)

        parent.update_idletasks()
        x = parent.winfo_rootx() + max(0, (parent.winfo_width() - width) // 2)
        y = parent.winfo_rooty() + max(0, (parent.winfo_height() - height) // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
        self.deiconify()
        self.update_idletasks()
        try:
            self.grab_set()
        except tk.TclError:
            pass
        self.focus_force()
        self.bind("<Escape>", lambda _e: self._close(False))

    def _close(self, value):
        self.result = bool(value)
        self.grab_release()
        self.destroy()

    @classmethod
    def ask(cls, parent, title, message, danger=False):
        dialog = cls(parent, title, message=message, danger=danger)
        parent.wait_window(dialog)
        return dialog.result

    @classmethod
    def report(cls, parent, title, text, ok_text=None):
        dialog = cls(parent, title, body_text=text, ok_text=ok_text, cancel_text="关闭")
        parent.wait_window(dialog)
        return dialog.result


# -- elevation --------------------------------------------------------------

SEE_MASK_NOCLOSEPROCESS = 0x00000040


class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_ulong),
        ("fMask", ctypes.c_ulong),
        ("hwnd", ctypes.c_void_p),
        ("lpVerb", ctypes.c_wchar_p),
        ("lpFile", ctypes.c_wchar_p),
        ("lpParameters", ctypes.c_wchar_p),
        ("lpDirectory", ctypes.c_wchar_p),
        ("nShow", ctypes.c_int),
        ("hInstApp", ctypes.c_void_p),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", ctypes.c_wchar_p),
        ("hkeyClass", ctypes.c_void_p),
        ("dwHotKey", ctypes.c_ulong),
        ("hIcon", ctypes.c_void_p),
        ("hProcess", ctypes.c_void_p),
    ]


def _shell_runas(exe, params):
    """Run *exe* elevated (UAC) and wait; returns ``(started, exit_code)``."""
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = SEE_MASK_NOCLOSEPROCESS
    info.lpVerb = "runas"
    info.lpFile = str(exe)
    info.lpParameters = str(params)
    info.nShow = 0
    if not shell32.ShellExecuteExW(ctypes.byref(info)):
        return False, ctypes.get_last_error()
    try:
        kernel32.WaitForSingleObject(info.hProcess, 0xFFFFFFFF)
        code = ctypes.c_ulong()
        kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
        return True, code.value
    finally:
        kernel32.CloseHandle(info.hProcess)


def _self_invocation(extra):
    """(program, parameters) that re-enters this application with *extra* args."""
    if getattr(sys, "frozen", False):
        return sys.executable, subprocess.list2cmdline(list(extra))
    entry = str(Path(__file__).resolve().with_name("gui_entry.py"))
    return sys.executable, subprocess.list2cmdline([entry] + list(extra))


# -- data -------------------------------------------------------------------


def _gather_snapshot():
    from lanrf import __version__, backends, checks
    from lanrf import config as cfgmod

    config = cfgmod.load_config()
    backend = backends.get_backend(refresh=True)
    results = checks.check_targets(config, backend=backend)
    summary = checks.summarize(results)

    tunnels = []
    try:
        tunnels = [str(t.get("name") or "") for t in backend.tunnel_interfaces()]
    except Exception:
        tunnels = []

    physical = []
    try:
        addresses = {name: addr for (name, _net, addr) in backend.local_networks(4)}
        physical = [
            {"name": name, "address": addresses.get(name, "")}
            for name in backend.list_interfaces(only_up=True)
        ]
    except Exception:
        physical = []

    routes, owned = [], 0
    try:
        routes = backend.routes() or []
        owned = sum(1 for entry in routes if entry.get("owned"))
    except Exception:
        routes, owned = [], 0

    try:
        from taskmod import task_exists

        task = task_exists()
    except Exception:
        task = False

    joined = " ".join(tunnels).lower()
    return {
        "version": __version__,
        "results": results,
        "summary": summary,
        "admin": bool(getattr(backend, "is_privileged", False)),
        "physical": physical,
        "tunnels": tunnels,
        "atrust": "atrust" in joined or "sangfor" in joined,
        "routes": len(routes),
        "owned": owned,
        "task": task,
        "config_path": str(cfgmod.CONFIG_PATH),
        "time": time.strftime("%H:%M:%S"),
    }


def _run_cli(args):
    """Run the in-process CLI with *args* and capture its text output."""
    buffer = io.StringIO()
    code = 0
    try:
        with redirect_stdout(buffer), redirect_stderr(buffer):
            from core import cli_main

            code = cli_main(list(args))
    except SystemExit as exc:  # argparse
        code = exc.code if isinstance(exc.code, int) else 2
    except Exception as exc:  # pragma: no cover - shown in the log
        buffer.write(f"\n内部错误：{exc}\n")
        code = 2
    return buffer.getvalue().strip(), code


# -- application ------------------------------------------------------------


class App:
    def __init__(self, root):
        self.root = root
        self.queue = queue.Queue()
        self.phase = 0
        self.snapshot = None
        self.busy = False
        self.selected = 0
        self._build()
        self.log("控制台启动 · 正在读取路由表与 ~/.ssh/config", "info")
        self.refresh()
        self.root.after(80, self._pump)
        self.root.after(60, self._tick)
        self.root.bind("<F5>", lambda _e: self.refresh())

    # -- layout ---------------------------------------------------------

    def _build(self):
        root = self.root
        self.header = HeaderBar(root)
        self.header.pack(fill="x", side="top")

        footer = tk.Frame(root, bg=BG, height=88)
        footer.pack(side="bottom", fill="x")
        footer.pack_propagate(False)
        bar = tk.Frame(footer, bg=BG)
        bar.pack(fill="x", pady=22)
        self.btn_scan = NeonButton(bar, "SCAN", self.refresh, accent=CYAN)
        self.btn_fix = NeonButton(bar, "FIX ROUTES", self._on_fix, accent=MAGENTA)
        self.btn_import = NeonButton(bar, "IMPORT SSH", self._on_import, accent="#2f9fb0")
        self.btn_doctor = NeonButton(bar, "DIAGNOSE", self._on_doctor, accent=AMBER)
        self.btn_task = NeonButton(bar, "WATCHDOG", self._on_task, accent=GREEN)
        self.buttons = [self.btn_scan, self.btn_fix, self.btn_import, self.btn_doctor, self.btn_task]
        for button in self.buttons:
            button.pack(side="left", padx=(16, 0))
        tk.Label(
            footer,
            text="F5 刷新  ·  写入路由表需要管理员权限  ·  aTrust 隧道会被自动绕开",
            bg=BG, fg=DIM, font=F_UI_S,
        ).pack(side="right", padx=20)

        body = tk.Frame(root, bg=BG)
        body.pack(fill="both", expand=True)
        left = tk.Frame(body, bg=BG, width=404)
        left.pack(side="left", fill="y", padx=(16, 10), pady=(6, 10))
        left.pack_propagate(False)
        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True, padx=(0, 16), pady=(6, 10))

        self.targets = TargetPanel(left, self._select)
        self.targets.pack(fill="both", expand=True)

        self.stats = StatBoard(right)
        self.stats.pack(fill="x")
        self.system = SystemPanel(right)
        self.system.pack(fill="x", pady=(10, 0))
        self.logpanel = LogPanel(right)
        self.logpanel.pack(fill="both", expand=True, pady=(10, 0))

    # -- loop -----------------------------------------------------------

    def _tick(self):
        self.phase = (self.phase + 1) % 100000
        self.header.tick(self.phase)
        self.stats.tick(self.phase)
        self.targets.tick(self.phase)
        self.root.after(60, self._tick)

    def _pump(self):
        try:
            while True:
                message = self.queue.get_nowait()
                self._handle(message)
        except queue.Empty:
            pass
        self.root.after(80, self._pump)

    def _handle(self, message):
        kind = message[0]
        if kind == "log":
            self.log(message[1], message[2] if len(message) > 2 else "info")
        elif kind == "busy":
            self._set_busy(bool(message[1]))
        elif kind == "data":
            self._apply(message[1])
        elif kind == "refresh":
            self._set_busy(False)
            self.refresh()
        elif kind == "confirm":
            _, title, text, action, danger = message
            self._set_busy(False)
            if TechDialog.ask(self.root, title, text, danger=danger) and action:
                action()
        elif kind == "preview":
            _, title, text, action = message
            self._set_busy(False)
            confirmed = TechDialog.report(self.root, title, text, ok_text="写入配置" if action else None)
            if action and confirmed:
                action()

    def log(self, message, level="info"):
        self.logpanel.add(time.strftime("%H:%M:%S"), message, level)

    def _set_busy(self, busy):
        self.busy = busy
        for button in self.buttons:
            button.set_enabled(not busy)

    # -- data flow ------------------------------------------------------

    def refresh(self):
        if self.busy:
            return
        self._set_busy(True)

        def work():
            try:
                snapshot = _gather_snapshot()
            except Exception as exc:  # pragma: no cover - environment issues
                self.queue.put(("log", f"读取失败：{exc}", "err"))
                snapshot = None
            self.queue.put(("data", snapshot))
            self.queue.put(("busy", False))

        threading.Thread(target=work, daemon=True).start()

    def _apply(self, snapshot):
        if not snapshot:
            self._set_busy(False)
            return
        self.snapshot = snapshot
        results = snapshot["results"]
        self.selected = min(self.selected, max(0, len(results) - 1))
        physical = snapshot["physical"]
        nic = f"{physical[0]['name']}  {physical[0]['address']}".strip() if physical else "no physical adapter"
        self.header.set_state(
            {
                "admin": snapshot["admin"],
                "version": snapshot["version"],
                "nic": nic,
                "time": snapshot["time"],
            }
        )
        self.stats.set_data(snapshot)
        self.system.set_data(snapshot)
        self.targets.set_data(results, self.selected)
        summary = snapshot["summary"]
        self.log(
            f"路由表：{summary['ok']}/{summary['total']} 已固定 · "
            f"{snapshot['routes']} 条 IPv4 路由 · {snapshot['owned']} 条 /32 钉住",
            "ok" if summary["bad"] == 0 else "warn",
        )

    def _select(self, index):
        self.selected = index
        results = (self.snapshot or {}).get("results") or []
        if 0 <= index < len(results):
            result = results[index]
            if not result.get("ok"):
                reason = result.get("reason") or f"当前经由 {result.get('current') or '未知网卡'}"
                self.log(f"{result.get('name')} · {result.get('address')}：{reason}", "warn")

    # -- actions --------------------------------------------------------

    def _on_fix(self):
        if self.busy:
            return
        snapshot = self.snapshot or {}
        if snapshot.get("summary", {}).get("bad", 0) == 0:
            self.log("没有需要修复的目标：所有局域网主机都已固定", "ok")
            return
        if not snapshot.get("admin"):
            self.queue.put(
                (
                    "confirm",
                    "ELEVATION REQUIRED",
                    "修改 Windows 路由表需要管理员权限。\n\n"
                    "是否以管理员身份重新启动并执行修复？UAC 会弹出确认框。",
                    self._elevate_fix,
                    False,
                )
            )
            return
        self._fix_in_process()

    def _fix_in_process(self):
        self._set_busy(True)
        self.log("正在写入 /32 主机路由…", "info")

        def work():
            try:
                from lanrf import checks, privileged
                from lanrf import config as cfgmod

                config = cfgmod.load_config()
                results = checks.check_targets(config)
                targets = [r for r in results if r.get("desired") and not r.get("ok")]
                outcome = privileged.fix_targets(targets, config=config, prefer_daemon=False)
                code = outcome.get("return_code", 1)
                if code == 0:
                    self.queue.put(("log", f"修复完成：{len(outcome.get('items') or [])} 条路由", "ok"))
                else:
                    self.queue.put(("log", f"修复失败：{outcome.get('stderr') or 'unknown error'}", "err"))
            except Exception as exc:
                self.queue.put(("log", f"修复失败：{exc}", "err"))
            self.queue.put(("refresh",))

        threading.Thread(target=work, daemon=True).start()

    def _elevate_fix(self):
        self._set_busy(True)
        self.log("请求 UAC 提权，准备以管理员身份修复…", "info")

        def work():
            exe, params = _self_invocation(["fix", "--quiet"])
            started, code = _shell_runas(exe, params)
            if not started:
                self.queue.put(("log", "提权被取消或失败", "warn"))
            else:
                self.queue.put(("log", f"提权修复进程结束（exit {code}）", "ok" if code == 0 else "err"))
            self.queue.put(("refresh",))

        threading.Thread(target=work, daemon=True).start()

    def _on_import(self):
        if self.busy:
            return
        self._set_busy(True)
        self.log("解析 ~/.ssh/config，匹配物理网段…", "info")

        def work():
            text, _code = _run_cli(["import-ssh", "--dry-run"])
            actionable = "已存在或重复" not in text and "没有需要添加" not in text
            self.queue.put(("preview", "SSH IMPORT · PREVIEW", text or "（没有输出）", self._apply_import if actionable else None))

        threading.Thread(target=work, daemon=True).start()

    def _apply_import(self):
        self._set_busy(True)
        self.log("写入配置…", "info")

        def work():
            text, code = _run_cli(["import-ssh", "--yes"])
            tail = (text.splitlines() or ["导入完成"])[-1]
            self.queue.put(("log", tail, "ok" if code == 0 else "err"))
            self.queue.put(("refresh",))

        threading.Thread(target=work, daemon=True).start()

    def _on_doctor(self):
        if self.busy:
            return
        self._set_busy(True)
        self.log("诊断网卡、路由、权限与 TCP 22…", "info")

        def work():
            try:
                from lanrf import doctor

                report = doctor.diagnose(probe=True)
                text = doctor.format_findings(report.get("findings") or [], use_color=False)
            except Exception as exc:
                text = f"诊断失败：{exc}"
            self.queue.put(("preview", "DIAGNOSTICS · REPORT", text, None))

        threading.Thread(target=work, daemon=True).start()

    def _on_task(self):
        if self.busy or not self.snapshot:
            return
        if self.snapshot.get("task"):
            self.queue.put(
                (
                    "confirm",
                    "WATCHDOG · REMOVE",
                    "将移除登录时自动修复路由的 Windows 计划任务 “LanRouteFixer”。\n\n"
                    "移除后，aTrust 再改写路由时不会自动补回。",
                    lambda: self._elevate_task("--task-uninstall"),
                    True,
                )
            )
        else:
            self.queue.put(
                (
                    "confirm",
                    "WATCHDOG · INSTALL",
                    "将注册登录计划任务 “LanRouteFixer”：以管理员权限启动，\n"
                    "登录后每 10 秒检查一次路由并自动补回 /32 主机路由。\n\n"
                    "需要 UAC 提权，是否继续？",
                    lambda: self._elevate_task("--task-install"),
                    False,
                )
            )

    def _elevate_task(self, flag):
        self._set_busy(True)
        self.log("请求 UAC 提权，正在配置计划任务…", "info")
        install = flag == "--task-install"

        def work():
            exe, params = _self_invocation([flag])
            started, code = _shell_runas(exe, params)
            if not started:
                self.queue.put(("log", "提权被取消或失败", "warn"))
            elif code == 0:
                self.queue.put(("log", "计划任务已安装（登录后自动运行）" if install else "计划任务已移除", "ok"))
            else:
                self.queue.put(("log", "计划任务配置失败（exit %s）" % code, "err"))
            self.queue.put(("refresh",))

        threading.Thread(target=work, daemon=True).start()


# -- entry ------------------------------------------------------------------


def _icon_path():
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    icon = base / "lanrf.ico"
    return str(icon) if icon.exists() else None


def probe_gui():
    """Text-mode layout probe: build the window, apply real data, dump geometry.

    Used during development because the picture cannot be inspected directly;
    it reports every canvas text item's bounding box and flags anything that
    falls outside its canvas or outside the target card that owns it.
    """
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    root = tk.Tk()
    root.title("LAN Route Fixer · probe")
    root.configure(bg=BG)
    root.geometry("1260x800+40+24")
    app = App(root)
    for _ in range(10):
        root.update()
        time.sleep(0.05)
    try:
        snapshot = _gather_snapshot()
        app._apply(snapshot)
    except Exception as exc:
        print(f"snapshot failed: {exc}")
    for _ in range(10):
        root.update()
        time.sleep(0.05)

    print(f"WINDOW {root.winfo_width()}x{root.winfo_height()}")
    widgets = [
        ("header", app.header),
        ("targets", app.targets),
        ("stats", app.stats),
        ("system", app.system),
    ]
    for name, canvas in widgets:
        w, h = canvas.winfo_width(), canvas.winfo_height()
        print(f"CANVAS {name} {w}x{h}")
        issues = 0
        for item in canvas.find_all():
            if canvas.type(item) != "text":
                continue
            bbox = canvas.bbox(item)
            text = canvas.itemcget(item, "text")
            if not bbox:
                continue
            x1, y1, x2, y2 = bbox
            out = x1 < -1 or y1 < -1 or x2 > w + 1 or y2 > h + 1
            if out:
                issues += 1
            print(f"  TEXT {'OUT ' if out else '    '}{x1},{y1}-{x2},{y2}  {text!r}")
        for (x1, y1, x2, y2, idx) in getattr(canvas, "_rects", []):
            for item in canvas.find_all():
                if canvas.type(item) != "text":
                    continue
                bbox = canvas.bbox(item)
                if not bbox:
                    continue
                if bbox[0] >= x1 and bbox[2] <= x2 and bbox[1] >= y1 - 2 and bbox[3] <= y2 + 2:
                    continue
                cx = (bbox[0] + bbox[2]) // 2
                cy = (bbox[1] + bbox[3]) // 2
                if x1 <= cx <= x2 and y1 <= cy <= y2:
                    issues += 1
                    print(f"  CARD{idx} OVERFLOW {bbox} {canvas.itemcget(item, 'text')!r}")
        print(f"  issues={issues}")
    print("LOG:")
    print(app.logpanel.text.get("1.0", "end").strip())

    print("SELFTEST")
    for args in (["status"], ["import-ssh", "--dry-run"], ["doctor", "--json"]):
        try:
            text, code = _run_cli(args)
            first = (text or "").strip().splitlines()[0][:110] if (text or "").strip() else ""
            print(f"  {' '.join(args)} -> code={code} len={len(text or '')} :: {first}")
        except Exception as exc:  # pragma: no cover - probe only
            print(f"  {' '.join(args)} -> EXC {exc!r}")
    try:
        dlg = TechDialog(root, "SELFTEST", "对话框布局检查：这条信息应该完整显示。")
        root.update()
        dlg.destroy()
        print("  dialog ok")
    except Exception as exc:  # pragma: no cover - probe only
        print(f"  dialog EXC {exc!r}")

    root.destroy()
    return 0


def run_gui():
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    root = tk.Tk()
    root.title("LAN Route Fixer · Windows")
    root.configure(bg=BG)
    root.geometry("1260x800+40+24")
    root.minsize(1120, 720)
    icon = _icon_path()
    if icon:
        try:
            root.iconbitmap(default=icon)
        except tk.TclError:
            pass
    App(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(run_gui())