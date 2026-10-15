#!/usr/bin/env python3
"""Desktop application for keeping selected LAN devices off a VPN tunnel.

Layout
------

One window, one navigation sidebar, no nested dialogs. Everything the app can do
is reachable from the sidebar, and editing happens *inside* the window:

    ┌────────────────┬─────────────────────────────────────┐
    │ 概览           │  Adw.HeaderBar + navigation title   │
    │ 修复目标       │                                     │
    │ 路由与后台     │  Adw.Clamp(PreferencesPage)         │
    │ 配置文件       │                                     │
    │ 清理           │                                     │
    │ 运行记录       │                                     │
    └────────────────┴─────────────────────────────────────┘

A previous version opened a separate ``Adw.PreferencesWindow`` for settings and
a third one for the target editor. Three stacked windows for one task is exactly
the confusion this layout removes: the sidebar keeps the user's place, and the
editor slides in as a navigation page with a back button.

The "配置文件" page is deliberate: the config file belongs to the user, so the
app shows its path, renders its raw contents, lets them edit and validate it,
and lets them delete it. Nothing is hidden.
"""

import json
import threading
import time
from datetime import datetime

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk

import core

DEFAULT_CONFIG = core.DEFAULT_CONFIG

# Sidebar entries: (key, title, icon)
SECTIONS = (
    ("overview", "概览", "go-home-symbolic"),
    ("targets", "修复目标", "network-workgroup-symbolic"),
    ("routing", "路由与后台", "network-wired-symbolic"),
    ("config", "配置文件", "document-edit-symbolic"),
    ("cleanup", "清理", "user-trash-symbolic"),
    ("log", "运行记录", "utilities-terminal-symbolic"),
)

# Status keys -> (icon, css class, label)
STATUS_STYLE = {
    "ok": ("emblem-ok-symbolic", "success", "正常"),
    "warn": ("dialog-warning-symbolic", "warning", "异常"),
    "off": ("media-playback-pause-symbolic", "", "已停用"),
    "unknown": ("dialog-question-symbolic", "", "等待检查"),
    "error": ("dialog-error-symbolic", "error", "不可用"),
}


def _find_internal_listbox(widget):
    """Depth-first search for the ListBox libadwaita hides inside a group."""
    child = widget.get_first_child()
    while child is not None:
        if isinstance(child, Gtk.ListBox):
            return child
        found = _find_internal_listbox(child)
        if found is not None:
            return found
        child = child.get_next_sibling()
    return None


def group_rows(group):
    """The rows a group is currently showing, as a list.

    ``Adw.PreferencesGroup`` keeps its rows in an internal ``Gtk.ListBox``
    (nested inside two boxes: a header area and a rows area). The rows are
    therefore *not* children of the group, so ``for row in group`` walks
    descendants and ``group.remove(row)`` fails with "tried to remove
    non-child".
    """
    listbox = _find_internal_listbox(group)
    if listbox is None:
        return []
    rows = []
    child = listbox.get_first_child()
    while child is not None:
        rows.append(child)
        child = child.get_next_sibling()
    return rows


def clear_group(group):
    """Drop every row a group shows, keeping libadwaita's scaffolding intact.

    Only the rows are removed. Yanking the internal ListBox out of the group
    *looks* like it works, but libadwaita then still believes the list exists
    and every later ``add()`` is silently dropped - which is exactly how a
    "refresh" ended up showing an empty list.
    """
    listbox = _find_internal_listbox(group)
    if listbox is None:
        return
    for row in group_rows(group):
        listbox.remove(row)


def own_cleanup_candidates(report):
    """Target-cleanup candidates that live in the config this app owns.

    ``analyze`` deliberately looks at every discovered config so routes
    belonging to another user are not mistaken for residue. A GUI running as
    one user must never *offer to edit* another user's file, so only the
    caller's own config is shown and pruned.
    """
    candidates = []
    for entry in report.get("targets", []):
        if entry.get("path") == str(core.CONFIG_PATH):
            candidates.extend(entry.get("candidates", []))
    return candidates


class TargetRow(Adw.ActionRow):
    """A target in the list, with its live route state."""

    def __init__(self, target, on_toggle, on_edit, on_delete):
        super().__init__()
        self.target = target
        self.set_activatable(True)
        # A real prefix image rather than ActionRow.set_icon_name(): the latter
        # is deprecated in libadwaita 1.6+ and cannot be updated in place.
        self.icon = Gtk.Image.new_from_icon_name("network-workgroup-symbolic")
        self.add_prefix(self.icon)
        self.connect("activated", lambda _row: on_edit(target))

        self.enabled_switch = Gtk.Switch(active=bool(target.get("enabled")),
                                         valign=Gtk.Align.CENTER)
        self.enabled_switch.set_tooltip_text("是否巡检并修复这个目标")
        self.enabled_switch.connect("notify::active", on_toggle, target)
        self.add_suffix(self.enabled_switch)

        edit_button = Gtk.Button(icon_name="document-edit-symbolic",
                                 valign=Gtk.Align.CENTER)
        edit_button.add_css_class("flat")
        edit_button.set_tooltip_text("编辑")
        edit_button.connect("clicked", lambda _button: on_edit(target))
        self.add_suffix(edit_button)

        delete_button = Gtk.Button(icon_name="user-trash-symbolic",
                                   valign=Gtk.Align.CENTER)
        delete_button.add_css_class("flat")
        delete_button.set_tooltip_text("从配置中删除")
        delete_button.connect("clicked", lambda _button: on_delete(target))
        self.add_suffix(delete_button)

        self.refresh()

    def refresh(self):
        self.set_title(self.target.get("name") or self.target.get("address") or "未命名设备")
        self.set_subtitle(self._subtitle())
        self.icon.set_from_icon_name(
            "network-workgroup-symbolic"
            if self.target.get("enabled")
            else "media-playback-pause-symbolic"
        )

    def _subtitle(self):
        parts = [self.target.get("address", "—")]
        parts.append(self.target.get("interface") or "自动选择网卡")
        if self.target.get("expand"):
            parts.append("覆盖整个本地子网")
        state = self.target.get("_state")
        if state:
            parts.append(state)
        return " · ".join(str(part) for part in parts if part)

    def set_state(self, icon_name, css_class, label, detail=""):
        self.target["_state"] = label
        self.refresh()
        if detail:
            self.set_subtitle(f"{self._subtitle()} · {detail}")


class LanRouteFixer(Adw.Application):
    def __init__(self):
        super().__init__(application_id=core.APP_ID)
        self.connect("activate", self.on_activate)
        self.config = dict(DEFAULT_CONFIG)
        self.window = None
        self.split = None
        self.content = None
        self.sidebar_list = None
        self.sidebar_rows = {}
        self.pages = {}
        self._load_config()
        self._targets = [dict(target) for target in self.config.get("targets", [])]
        self.route_results = {}
        self.cleanup_report = None
        self.cleanup_routes_check = True
        self.cleanup_targets_check = True
        self._checking = False
        self._fixing = False
        self._scanning = False
        self._cleaning = False
        self._timer_id = None
        self._building = False

    # ------------------------------------------------------------------ state

    def _load_config(self):
        loaded = core.load_config()
        self.config.update(loaded.to_dict())

    def _save_config(self):
        if not core.save_config(self.config):
            self._toast("保存配置失败")
            return False
        return True

    def _targets_from_config(self):
        self.config["targets"] = core.normalize_targets(self.config.get("targets", []))
        self._targets = [dict(target) for target in self.config["targets"]]
        return self._targets

    def _toast(self, message, timeout=4):
        overlay = getattr(self, "toast_overlay", None)
        if overlay is not None:
            overlay.add_toast(Adw.Toast(title=message, timeout=timeout))
        else:  # pragma: no cover - window not built yet
            self._log(message)

    def _log(self, message):
        if getattr(self, "log_buffer", None) is None:
            return
        stamp = datetime.now().strftime("%H:%M:%S")
        self.log_buffer.insert(self.log_buffer.get_end_iter(), f"[{stamp}] {message}\n", -1)
        # Keep the buffer from growing without bound over a long session.
        if self.log_buffer.get_line_count() > 800:
            start = self.log_buffer.get_start_iter()
            self.log_buffer.delete(start, self.log_buffer.get_iter_at_line(200))

    # -------------------------------------------------------------- activation

    def on_activate(self, _application):
        if self.window is not None:
            self.window.present()
            return
        self._build_window()
        self.window.present()
        self._refresh_all()
        if not self.config.get("targets"):
            self._show_page("targets")
            self._toast("先扫描或手动添加需要保持直连的设备")
        else:
            self._start_check()

    # ---------------------------------------------------------------- building

    def _build_window(self):
        self.window = Adw.ApplicationWindow(application=self)
        self.window.set_title(core.APP_DISPLAY_NAME)
        self.window.update_property([Gtk.AccessibleProperty.LABEL], [core.APP_DISPLAY_NAME])
        self.window.set_default_size(940, 700)
        self.window.set_size_request(560, 460)

        self.toast_overlay = Adw.ToastOverlay()
        self.split = Adw.NavigationSplitView()
        self.split.set_min_sidebar_width(200)
        self.split.set_max_sidebar_width(240)
        self.split.set_sidebar(self._build_sidebar())

        # Adw.NavigationSplitView accepts NavigationPage children only, so the
        # content stack lives inside one; each of its pages brings its own
        # header bar, which is what makes the split view look native.
        self.content = Adw.NavigationView()
        self.content.set_vexpand(True)
        content_page = Adw.NavigationPage(title=core.APP_DISPLAY_NAME)
        content_page.set_child(self.content)
        self.split.set_content(content_page)

        self.toast_overlay.set_child(self.split)
        self.window.set_content(self.toast_overlay)

        for key, _title, _icon in SECTIONS:
            self.pages[key] = self._build_page(key)
            self.content.add(self.pages[key])
        self._show_page("overview")

    def _build_sidebar(self):
        page = Adw.NavigationPage(title=core.APP_DISPLAY_NAME)
        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        header.set_show_end_title_buttons(False)
        header.set_title_widget(Adw.WindowTitle(title=core.APP_DISPLAY_NAME,
                                                subtitle="局域网路由修复"))
        toolbar.add_top_bar(header)

        self.sidebar_list = Gtk.ListBox()
        self.sidebar_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.sidebar_list.add_css_class("navigation-sidebar")
        self.sidebar_list.connect("row-selected", self._on_section_selected)

        for key, title, icon in SECTIONS:
            row = Gtk.ListBoxRow()
            row.section_key = key
            box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            box.set_margin_top(8)
            box.set_margin_bottom(8)
            box.append(Gtk.Image.new_from_icon_name(icon))
            label = Gtk.Label(label=title, xalign=0)
            label.set_hexpand(True)
            box.append(label)
            badge = Gtk.Label(label="")
            badge.add_css_class("dim-label")
            box.append(badge)
            row.set_child(box)
            row.badge = badge
            self.sidebar_rows[key] = row
            self.sidebar_list.append(row)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scrolled.set_vexpand(True)
        scrolled.set_child(self.sidebar_list)
        toolbar.set_content(scrolled)

        version = Gtk.Label(label=f"lan-route-fixer {_version()}")
        version.add_css_class("dim-label")
        version.add_css_class("caption")
        version.set_margin_top(6)
        version.set_margin_bottom(10)
        toolbar.add_bottom_bar(version)
        page.set_child(toolbar)
        return page

    def _build_page(self, key):
        builder = getattr(self, f"_build_{key}_page")
        title, toolbar_page = builder()
        page = Adw.NavigationPage(title=title)
        page.set_child(toolbar_page)
        return page

    def _scrolled_page(self, title, subtitle=None):
        """Standard content page: header bar + an Adw.PreferencesPage.

        Using the real ``Adw.PreferencesPage`` (rather than a hand-rolled box)
        is what gives the window the native look: it supplies the responsive
        clamp, the macOS-style margins and the group spacing for free.
        """
        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        header.set_title_widget(Adw.WindowTitle(title=title, subtitle=subtitle or ""))
        toolbar.add_top_bar(header)
        page = Adw.PreferencesPage()
        toolbar.set_content(page)
        return toolbar, page

    # ------------------------------------------------------------------ pages

    def _build_overview_page(self):
        toolbar, box = self._scrolled_page("概览", "所选设备会一直走物理网卡")

        summary = Adw.PreferencesGroup()
        self.overview_row = Adw.ActionRow(title="正在检查…")
        self.overview_icon = Gtk.Image.new_from_icon_name("dialog-question-symbolic")
        self.overview_row.add_prefix(self.overview_icon)
        self.overview_row.set_subtitle("把局域网设备钉在物理网卡上，避免 VPN 抢走它们的路由")
        summary.add(self.overview_row)
        box.add(summary)

        actions = Adw.PreferencesGroup(title="操作")
        self.fix_row = Adw.ActionRow(
            title="立即修复",
            subtitle="检查全部已开启目标；守护进程在运行时无需授权",
        )
        self.fix_button = Gtk.Button(label="修复")
        self.fix_button.add_css_class("suggested-action")
        self.fix_button.set_valign(Gtk.Align.CENTER)
        self.fix_button.connect("clicked", self.on_fix_now)
        self.fix_row.add_suffix(self.fix_button)
        self.fix_row.set_activatable_widget(self.fix_button)
        actions.add(self.fix_row)

        check_row = Adw.ActionRow(title="重新检查", subtitle="只读，不修改任何路由")
        check_button = Gtk.Button(label="检查")
        check_button.set_valign(Gtk.Align.CENTER)
        check_button.connect("clicked", lambda _b: self._start_check())
        check_row.add_suffix(check_button)
        check_row.set_activatable_widget(check_button)
        actions.add(check_row)
        box.add(actions)

        self.overview_group = Adw.PreferencesGroup(title="目标状态")
        box.add(self.overview_group)
        return "概览", toolbar

    def _build_targets_page(self):
        toolbar, box = self._scrolled_page(
            "修复目标", "扫描局域网，或手动填写私有地址/网段"
        )

        tools = Adw.PreferencesGroup()
        scan_row = Adw.ActionRow(
            title="自动检测局域网设备",
            subtitle="读取 ARP 邻居表；可用时通过 mDNS 显示设备名称",
        )
        self.scan_button = Gtk.Button(label="扫描局域网")
        self.scan_button.add_css_class("suggested-action")
        self.scan_button.set_valign(Gtk.Align.CENTER)
        self.scan_button.connect("clicked", self._start_scan)
        scan_row.add_suffix(self.scan_button)
        scan_row.set_activatable_widget(self.scan_button)
        tools.add(scan_row)

        add_row = Adw.ActionRow(
            title="手动添加",
            subtitle="支持 10/8、172.16/12、192.168/16 以及 ULA/链路本地 IPv6",
        )
        add_button = Gtk.Button(label="添加")
        add_button.set_valign(Gtk.Align.CENTER)
        add_button.connect("clicked", lambda _b: self._open_editor(None))
        add_row.add_suffix(add_button)
        add_row.set_activatable_widget(add_button)
        tools.add(add_row)
        box.add(tools)

        self.targets_group = Adw.PreferencesGroup(title="目标")
        box.add(self.targets_group)
        return "修复目标", toolbar

    def _build_routing_page(self):
        toolbar, box = self._scrolled_page(
            "路由与后台", "决定路由放在哪张表，以及谁来持续修复"
        )

        mode_group = Adw.PreferencesGroup(
            title="路由模式",
            description="策略路由把流量交给独立表，VPN 重写主表也抢不走",
        )
        self.mode_combo = Adw.ComboRow(title="模式")
        self.mode_combo.set_model(
            Gtk.StringList.new(["策略路由（推荐）", "主表模式（兼容 2.0.x）"])
        )
        self.mode_combo.connect("notify::selected", self._on_mode_changed)
        mode_group.add(self.mode_combo)

        self.table_row = Adw.SpinRow.new_with_range(1, 252, 1)
        self.table_row.set_value(int(self.config.get("rule_table", 168)))
        self.table_row.set_title("路由表编号")
        self.table_row.set_subtitle("1–252，默认 168；不要用 253/254/255（系统保留）")
        self.table_row.connect("notify::value", self._on_table_changed)
        mode_group.add(self.table_row)

        self.pref_row = Adw.SpinRow.new_with_range(1, 32000, 10)
        self.pref_row.set_value(int(self.config.get("rule_preference", 1200)))
        self.pref_row.set_title("ip rule 优先级")
        self.pref_row.set_subtitle("必须低于 32766（内核查主表的默认规则）")
        self.pref_row.connect("notify::value", self._on_pref_changed)
        mode_group.add(self.pref_row)
        box.add(mode_group)

        behavior = Adw.PreferencesGroup(title="行为")
        self.auto_switch = Adw.SwitchRow(
            title="自动修复",
            subtitle="检查到异常时自动修复；守护进程在运行时不会弹授权",
        )
        self.auto_switch.set_active(bool(self.config.get("auto_fix", True)))
        self.auto_switch.connect("notify::active", self.on_auto_toggled)
        behavior.add(self.auto_switch)

        self.autostart_switch = Adw.SwitchRow(
            title="登录后自动启动界面",
            subtitle="仅为当前用户写入 autostart 条目",
        )
        self.autostart_switch.set_active(bool(self.config.get("autostart", False)))
        self.autostart_switch.connect("notify::active", self._on_autostart_toggled)
        behavior.add(self.autostart_switch)

        self.expand_switch = Adw.SwitchRow(
            title="覆盖整个本地子网",
            subtitle="给目标所在的整个网段装路由，而不是只保护单个地址",
        )
        self.expand_switch.set_active(bool(self.config.get("expand_host_targets", False)))
        self.expand_switch.connect("notify::active", self._on_expand_toggled)
        behavior.add(self.expand_switch)
        box.add(behavior)

        daemon_group = Adw.PreferencesGroup(
            title="后台守护进程",
            description="订阅内核路由事件，实测约 0.33 秒内修回被抢走的路由",
        )
        self.daemon_row = Adw.ActionRow(title="状态")
        self.daemon_icon = Gtk.Image.new_from_icon_name("dialog-question-symbolic")
        self.daemon_row.add_prefix(self.daemon_icon)
        daemon_group.add(self.daemon_row)

        self.dbus_row = Adw.ActionRow(title="免授权修复接口")
        self.dbus_icon = Gtk.Image.new_from_icon_name("dialog-question-symbolic")
        self.dbus_row.add_prefix(self.dbus_icon)
        daemon_group.add(self.dbus_row)
        box.add(daemon_group)
        return "路由与后台", toolbar

    def _build_config_page(self):
        toolbar, box = self._scrolled_page("配置文件", "完全由你掌控，随时可改可删")

        paths = Adw.PreferencesGroup(
            title="位置",
            description="用户配置优先；系统级配置用于无图形界面的机器",
        )
        self.user_path_row = Adw.ActionRow(title="用户配置")
        open_user = Gtk.Button(label="打开位置", valign=Gtk.Align.CENTER)
        open_user.connect(
            "clicked", lambda _b: self._open_in_file_manager(core.CONFIG_PATH.parent)
        )
        self.user_path_row.add_suffix(open_user)
        paths.add(self.user_path_row)
        self.system_path_row = Adw.ActionRow(title="系统级配置（需要管理员）")
        paths.add(self.system_path_row)
        box.add(paths)

        editor_group = Adw.PreferencesGroup(
            title="原始内容",
            description="直接编辑 JSON；校验通过才会写入，格式错误不会破坏原文件",
        )
        self.config_view = Gtk.TextView()
        self.config_view.set_monospace(True)
        self.config_view.set_wrap_mode(Gtk.WrapMode.NONE)
        self.config_view.set_top_margin(10)
        self.config_view.set_bottom_margin(10)
        self.config_view.set_left_margin(12)
        self.config_view.set_right_margin(12)
        self.config_buffer = self.config_view.get_buffer()
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_min_content_height(280)
        scrolled.set_child(self.config_view)
        scrolled.add_css_class("card")
        editor_group.add(scrolled)

        self.config_status_row = Adw.ActionRow(
            title="尚未校验", subtitle="修改后点“校验并写入”"
        )
        editor_group.add(self.config_status_row)

        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        buttons.set_halign(Gtk.Align.CENTER)
        buttons.set_margin_top(4)
        buttons.set_margin_bottom(10)
        reload_button = Gtk.Button(label="重新载入")
        reload_button.connect("clicked", lambda _b: self._reload_config_editor())
        buttons.append(reload_button)
        validate_button = Gtk.Button(label="仅校验")
        validate_button.connect("clicked", lambda _b: self._validate_config_editor())
        buttons.append(validate_button)
        apply_button = Gtk.Button(label="校验并写入")
        apply_button.add_css_class("suggested-action")
        apply_button.connect("clicked", lambda _b: self._apply_config_editor())
        buttons.append(apply_button)
        editor_group.add(buttons)
        box.add(editor_group)

        danger = Adw.PreferencesGroup(
            title="重置",
            description="配置文件是你的：随时可以恢复默认或彻底删除",
        )
        reset_row = Adw.ActionRow(
            title="恢复默认设置",
            subtitle="清空目标与自定义选项，保留配置文件本身",
        )
        reset_button = Gtk.Button(label="恢复默认", valign=Gtk.Align.CENTER)
        reset_button.add_css_class("destructive-action")
        reset_button.connect("clicked", lambda _b: self._confirm_reset_config())
        reset_row.add_suffix(reset_button)
        danger.add(reset_row)

        delete_row = Adw.ActionRow(
            title="删除配置文件",
            subtitle="删除后所有目标都会丢失；已安装的路由可以在“清理”里回收",
        )
        delete_button = Gtk.Button(label="删除文件", valign=Gtk.Align.CENTER)
        delete_button.add_css_class("destructive-action")
        delete_button.connect("clicked", lambda _b: self._confirm_delete_config())
        delete_row.add_suffix(delete_button)
        danger.add(delete_row)
        box.add(danger)
        return "配置文件", toolbar

    def _build_cleanup_page(self):
        toolbar, box = self._scrolled_page("清理", "删掉残留的路由和早已不用的目标")

        summary = Adw.PreferencesGroup()
        self.cleanup_row = Adw.ActionRow(title="正在检查…")
        self.cleanup_icon = Gtk.Image.new_from_icon_name("user-trash-symbolic")
        self.cleanup_row.add_prefix(self.cleanup_icon)
        summary.add(self.cleanup_row)
        box.add(summary)

        refresh_row = Adw.ActionRow(
            title="重新扫描残留",
            subtitle="检查路由表里本工具装过、但已无对应目标的路由与规则",
        )
        refresh_button = Gtk.Button(label="扫描", valign=Gtk.Align.CENTER)
        refresh_button.connect("clicked", lambda _b: self._start_cleanup_scan())
        refresh_row.add_suffix(refresh_button)
        refresh_row.set_activatable_widget(refresh_button)
        refresh_group = Adw.PreferencesGroup()
        refresh_group.add(refresh_row)
        box.add(refresh_group)

        self.cleanup_routes_group = Adw.PreferencesGroup(
            title="路由与规则残留",
            description="只清理带 proto 66 标记、由本工具安装且已无目标的条目",
        )
        self.cleanup_routes_check = Gtk.CheckButton(label="同时清理路由与规则")
        self.cleanup_routes_check.set_active(True)
        self.cleanup_routes_group.add(self.cleanup_routes_check)
        box.add(self.cleanup_routes_group)

        self.cleanup_targets_group = Adw.PreferencesGroup(
            title="配置文件里早已不用的目标",
            description="只列出已停用的条目；开启中的目标永远不会被清理",
        )
        self.cleanup_targets_check = Gtk.CheckButton(label="同时清理这些配置条目")
        self.cleanup_targets_check.set_active(True)
        self.cleanup_targets_group.add(self.cleanup_targets_check)
        box.add(self.cleanup_targets_group)

        self.cleanup_apply_row = Adw.ActionRow(
            title="执行清理",
            subtitle="先在上面的列表里确认，再执行",
        )
        self.cleanup_button = Gtk.Button(label="清理选中项")
        self.cleanup_button.add_css_class("destructive-action")
        self.cleanup_button.set_valign(Gtk.Align.CENTER)
        self.cleanup_button.set_sensitive(False)
        self.cleanup_button.connect("clicked", lambda _b: self._apply_cleanup())
        self.cleanup_apply_row.add_suffix(self.cleanup_button)
        self.cleanup_apply_row.set_activatable_widget(self.cleanup_button)
        apply_group = Adw.PreferencesGroup()
        apply_group.add(self.cleanup_apply_row)
        box.add(apply_group)
        return "清理", toolbar

    def _build_log_page(self):
        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        header.set_title_widget(
            Adw.WindowTitle(title="运行记录", subtitle="本次运行做了什么")
        )
        toolbar.add_top_bar(header)

        self.log_buffer = Gtk.TextBuffer()
        view = Gtk.TextView(buffer=self.log_buffer)
        view.set_editable(False)
        view.set_cursor_visible(False)
        view.set_monospace(True)
        view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        view.set_top_margin(10)
        view.set_bottom_margin(10)
        view.set_left_margin(12)
        view.set_right_margin(12)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_min_content_height(360)
        scrolled.set_vexpand(True)
        scrolled.set_child(view)
        scrolled.add_css_class("card")

        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        buttons.set_halign(Gtk.Align.CENTER)
        clear = Gtk.Button(label="清空记录")
        clear.connect("clicked", lambda _b: self.log_buffer.set_text("", 0))
        buttons.append(clear)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        content.set_margin_top(14)
        content.set_margin_bottom(20)
        content.set_margin_start(12)
        content.set_margin_end(12)
        content.append(scrolled)
        content.append(buttons)

        clamp = Adw.Clamp(maximum_size=820, tightening_threshold=640)
        clamp.set_child(content)
        toolbar.set_content(clamp)
        return "运行记录", toolbar

    # ------------------------------------------------------------- navigation

    def _show_page(self, key, push=False):
        page = self.pages.get(key)
        if page is None:
            return
        row = self.sidebar_rows.get(key)
        if row is not None and self.sidebar_list.get_selected_row() is not row:
            self.sidebar_list.select_row(row)
        if push:
            self.content.push(page)
        else:
            self.content.replace([page])
        if key == "config":
            self._reload_config_editor()
        elif key == "cleanup" and self.cleanup_report is None:
            self._start_cleanup_scan()

    def _on_section_selected(self, _list, row):
        if row is None or self._building:
            return
        self._show_page(row.section_key)

    def _set_badge(self, key, text):
        row = self.sidebar_rows.get(key)
        if row is not None:
            row.badge.set_text(text or "")

    def _refresh_sidebar(self):
        targets = self.config.get("targets", [])
        enabled = [target for target in targets if target.get("enabled")]
        self._set_badge("targets", f"{len(enabled)}/{len(targets)}" if targets else "")
        report = self.cleanup_report
        self._set_badge("cleanup", str(report["count"]) if report and report["count"] else "")

    # -------------------------------------------------------------- target edit

    def _open_editor(self, target):
        page = Adw.NavigationPage(title="编辑目标" if target else "添加目标")
        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        header.set_title_widget(
            Adw.WindowTitle(title="编辑目标" if target else "添加目标",
                            subtitle=target.get("address", "") if target else "私有地址或网段")
        )
        back = Gtk.Button(icon_name="go-previous-symbolic")
        back.set_tooltip_text("返回")
        back.connect("clicked", lambda _b: self.content.pop())
        header.pack_start(back)
        toolbar.add_top_bar(header)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        box.set_margin_top(18)
        box.set_margin_bottom(24)
        box.set_margin_start(16)
        box.set_margin_end(16)

        group = Adw.PreferencesGroup(
            title="设备",
            description="支持私有 IPv4 地址/网段，以及 ULA 或链路本地 IPv6。",
        )
        name_row = Adw.EntryRow(title="名称（可选）")
        name_row.set_text(str(target.get("name", "")) if target else "")
        group.add(name_row)

        address_row = Adw.EntryRow(title="IP 地址或网段")
        address_row.set_text(str(target.get("address", "")) if target else "")
        group.add(address_row)

        interfaces = core.list_usable_interfaces()
        configured = str(target.get("interface", "")) if target else ""
        if configured and configured not in interfaces:
            interfaces.append(configured)
        choices = ["", *interfaces]
        combo = Adw.ComboRow(title="目标网卡")
        combo.set_model(Gtk.StringList.new(["自动（按网段/默认出口）", *interfaces]))
        combo.set_selected(choices.index(configured) if configured in choices else 0)
        group.add(combo)

        enabled_row = Adw.SwitchRow(title="启用", subtitle="参与巡检与修复")
        enabled_row.set_active(bool(target.get("enabled", True)) if target else True)
        group.add(enabled_row)

        expand_row = Adw.SwitchRow(
            title="覆盖整个本地子网",
            subtitle="给目标所在的整个网段装路由；适合家里设备经常变动的场景",
        )
        expand_row.set_active(bool(target.get("expand", False)) if target else False)
        group.add(expand_row)
        box.append(group)

        preview = Adw.PreferencesGroup(title="将要安装的路由")
        preview_row = Adw.ActionRow(title="—")
        preview.add(preview_row)
        box.append(preview)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        actions.set_halign(Gtk.Align.CENTER)
        cancel = Gtk.Button(label="取消")
        cancel.connect("clicked", lambda _b: self.content.pop())
        actions.append(cancel)
        save = Gtk.Button(label="保存目标")
        save.add_css_class("suggested-action")
        actions.append(save)
        box.append(actions)

        clamp = Adw.Clamp(maximum_size=640, tightening_threshold=520)
        clamp.set_child(box)
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scrolled.set_vexpand(True)
        scrolled.set_child(clamp)
        toolbar.set_content(scrolled)
        page.set_child(toolbar)

        def describe(*_args):
            address = address_row.get_text().strip()
            valid = core.valid_local_target(address)
            save.set_sensitive(valid)
            if not address:
                preview_row.set_title("—")
                preview_row.set_subtitle("填写地址后显示实际会安装的路由")
                return
            if not valid:
                preview_row.set_title("地址无效")
                preview_row.set_subtitle("只能是私有 IPv4 / ULA / 链路本地 IPv6")
                return
            parsed = core.parse_ip_or_cidr(address)
            family, ip, prefix = parsed
            effective = f"{ip}/{prefix}"
            if expand_row.get_active() and prefix == (32 if family == 4 else 128):
                for local_interface, network, _value in core.get_local_networks(family):
                    import ipaddress

                    if ipaddress.ip_address(ip) in network:
                        effective = f"{network.network_address}/{network.prefixlen}"
                        break
            table = self.table_row.get_value() if self.mode_combo.get_selected() == 0 else "main"
            suffix = "-6" if family == 6 else "-4"
            preview_row.set_title(f"ip {suffix} route replace {effective}")
            preview_row.set_subtitle(
                f"dev {choices[combo.get_selected()] or '自动选择'} · table {table} · proto 66"
            )

        address_row.connect("notify::text", describe)
        combo.connect("notify::selected", describe)
        expand_row.connect("notify::active", describe)
        describe()

        def save_target(_button):
            address = address_row.get_text().strip()
            if not core.valid_local_target(address):
                self._toast("请输入有效的私有地址或网段")
                return
            values = {
                "name": name_row.get_text().strip() or address,
                "address": address,
                "interface": choices[combo.get_selected()] if combo.get_selected() < len(choices) else "",
                "enabled": enabled_row.get_active(),
            }
            if expand_row.get_active():
                values["expand"] = True
            if target is None:
                self.config.setdefault("targets", []).append(values)
            else:
                for existing in self.config.get("targets", []):
                    if existing is target or existing.get("address") == target.get("address"):
                        existing.clear()
                        existing.update(values)
                        break
            self._targets_from_config()
            if self._save_config():
                self._toast("目标已保存")
                self._log(f"保存目标 {address}")
            self.content.pop()
            self._refresh_all()
            self._start_check()

        save.connect("clicked", save_target)
        self.content.push(page)

    def _delete_target(self, target):
        address = target.get("address", "")
        dialog = Adw.AlertDialog(
            heading="删除这个目标？",
            body=f"将从配置中移除 {address}。已安装的路由会在下次检查时清理。",
        )
        dialog.add_response("cancel", "取消")
        dialog.add_response("delete", "删除")
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")

        def on_response(_dialog, response):
            if response != "delete":
                return
            self.config["targets"] = [
                item
                for item in self.config.get("targets", [])
                if item.get("address") != address
            ]
            self._targets_from_config()
            if self._save_config():
                self._toast(f"已删除 {address}")
                self._log(f"删除目标 {address}")
            self._refresh_all()
            self._start_check()

        dialog.connect("response", on_response)
        dialog.present(self.window)

    # ---------------------------------------------------------------- scanning

    def _start_scan(self, _button=None):
        if self._scanning:
            return
        self._scanning = True
        self.scan_button.set_sensitive(False)
        self.scan_button.set_label("正在扫描…")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        try:
            discovered = core.detect_targets()
            error = ""
        except Exception as exception:  # noqa: BLE001 - surfaced in a toast
            discovered = []
            error = str(exception)
        GLib.idle_add(self._on_scan_done, discovered, error)

    def _on_scan_done(self, discovered, error):
        self._scanning = False
        self.scan_button.set_sensitive(True)
        self.scan_button.set_label("重新扫描")
        if error:
            self._toast(f"扫描失败：{error}")
            return GLib.SOURCE_REMOVE

        existing = {target.get("address"): target for target in self.config.get("targets", [])}
        added = 0
        for found in discovered:
            target = existing.get(found["address"])
            if target is not None:
                if not target.get("name") or target.get("name") == target.get("address"):
                    target["name"] = found.get("name", target.get("name"))
                continue
            candidate = {
                "name": found.get("name") or found["address"],
                "address": found["address"],
                "interface": "",
                "enabled": False,
            }
            self.config.setdefault("targets", []).append(candidate)
            existing[found["address"]] = candidate
            added += 1

        if added:
            self._targets_from_config()
            self._save_config()
            self._refresh_targets()
            self._refresh_sidebar()
            self._toast(f"发现 {len(discovered)} 台设备，新增 {added} 台（默认停用，需要你开启）")
            self._log(f"扫描到 {len(discovered)} 台设备，新增 {added} 台（未启用）")
        elif discovered:
            self._toast(f"已刷新 {len(discovered)} 台设备，没有新增")
        else:
            self._toast("未发现可用设备；可等待设备联网后重试，或手动添加")
        # Newly discovered entries are disabled, so the cleanup candidates change.
        self.cleanup_report = None
        return GLib.SOURCE_REMOVE

    # -------------------------------------------------------------- rendering

    def _refresh_all(self):
        self._apply_config_to_widgets()
        self._refresh_targets()
        self._refresh_sidebar()
        self._refresh_daemon()

    def _apply_config_to_widgets(self):
        self._building = True
        try:
            mode = 0 if str(self.config.get("routing_mode", "rule")) == "rule" else 1
            if self.mode_combo.get_selected() != mode:
                self.mode_combo.set_selected(mode)
            table = int(self.config.get("rule_table", 168))
            if int(self.table_row.get_value()) != table:
                self.table_row.set_value(table)
            pref = int(self.config.get("rule_preference", 1200))
            if int(self.pref_row.get_value()) != pref:
                self.pref_row.set_value(pref)
            for widget, key in (
                (self.auto_switch, "auto_fix"),
                (self.autostart_switch, "autostart"),
                (self.expand_switch, "expand_host_targets"),
            ):
                if widget.get_active() != bool(self.config.get(key, False)):
                    widget.set_active(bool(self.config.get(key, False)))
            self.table_row.set_sensitive(mode == 0)
            self.pref_row.set_sensitive(mode == 0)
        finally:
            self._building = False

    def _refresh_targets(self):
        clear_group(self.targets_group)
        targets = self.config.get("targets", [])
        enabled = sum(1 for target in targets if target.get("enabled"))
        self.targets_group.set_title(f"目标（{enabled}/{len(targets)} 已启用）")
        self.targets_group.set_description(
            "开启后的目标会被钉在物理网卡上；停用的目标不会产生任何路由"
            if targets
            else None
        )
        for target in targets:
            row = TargetRow(
                target,
                self._on_target_toggled,
                self._open_editor,
                self._delete_target,
            )
            self.targets_group.add(row)
        self.targets_group.set_description(
            (
                f"共 {len(targets)} 个目标，{enabled} 个已启用。"
                "扫描新增的结果默认停用，避免误钉住不属于局域网的地址。"
            )
            if targets
            else "还没有目标。点上面的“扫描局域网”，或手动添加一个地址。"
        )

    def _refresh_overview(self, results=None):
        if results is not None:
            self.route_results = {result["address"]: result for result in results}
        counts = {"ok": 0, "warn": 0, "off": 0, "unknown": 0}
        for target in self.config.get("targets", []):
            if not target.get("enabled"):
                counts["off"] += 1
                continue
            result = self.route_results.get(target.get("address"))
            if result is None:
                counts["unknown"] += 1
            elif result.get("ok"):
                counts["ok"] += 1
            else:
                counts["warn"] += 1

        total = sum(counts.values())
        if not total:
            self.overview_icon.set_from_icon_name("network-wired-symbolic")
            self.overview_row.set_title("还没有配置目标")
            self.overview_row.set_subtitle("到“修复目标”里扫描，或手动添加一个地址")
        elif counts["warn"] or counts["unknown"]:
            self.overview_icon.set_from_icon_name("dialog-warning-symbolic")
            self.overview_row.set_title(
                f"{counts['warn']} 个目标异常"
                + (f"，{counts['unknown']} 个等待检查" if counts["unknown"] else "")
            )
            self.overview_row.set_subtitle("点“立即修复”即可恢复；守护进程运行时会自动修回")
        else:
            self.overview_icon.set_from_icon_name("emblem-ok-symbolic")
            self.overview_row.set_title(f"{counts['ok']} 个目标全部正常")
            self.overview_row.set_subtitle(
                "这些设备会一直走物理网卡，不受 VPN 抢路由影响"
                + (f"（另有 {counts['off']} 个已停用）" if counts["off"] else "")
            )

        clear_group(self.overview_group)
        enabled = [target for target in self.config.get("targets", []) if target.get("enabled")]
        self.overview_group.set_title(f"已启用目标（{len(enabled)}）")
        for target in enabled:
            result = self.route_results.get(target.get("address"), {})
            row = Adw.ActionRow(title=target.get("name") or target.get("address"))
            state = "unknown"
            detail = "等待检查"
            if result:
                if result.get("ok"):
                    state = "ok"
                    detail = f"通过 {result.get('current')} 直连"
                elif not result.get("desired"):
                    state = "error"
                    detail = "找不到可用网卡"
                else:
                    state = "warn"
                    detail = result.get("reason") or (
                        f"当前 {result.get('current') or '未知'}，应为 {result.get('desired')}"
                    )
                    if result.get("pending"):
                        detail = f"{detail}（{result['pending']}）"
            icon_name, css, label = STATUS_STYLE[state]
            row.set_subtitle(f"{target.get('address')} · {label} · {detail}")
            row.set_icon_name(icon_name)
            hint = Gtk.Label(label=label)
            hint.add_css_class("caption")
            if css:
                hint.add_css_class(css)
            hint.set_valign(Gtk.Align.CENTER)
            row.add_suffix(hint)
            self.overview_group.add(row)
        self._refresh_sidebar()

    def _refresh_daemon(self):
        state = core.read_state()
        mode = str(self.config.get("routing_mode", "rule"))
        self.table_row.set_sensitive(mode == "rule")
        self.pref_row.set_sensitive(mode == "rule")

        dbus = core.daemon_client_status() if hasattr(core, "daemon_client_status") else None
        if dbus is None:
            self.dbus_row.set_subtitle("未检测到可用的 D-Bus 会话")
            self.dbus_icon.set_from_icon_name("dialog-question-symbolic")
        elif dbus.get("running"):
            self.dbus_row.set_subtitle("守护进程在线：点“立即修复”不会弹授权")
            self.dbus_icon.set_from_icon_name("emblem-ok-symbolic")
        else:
            self.dbus_row.set_subtitle("守护进程未运行：修复会请求管理员授权")
            self.dbus_icon.set_from_icon_name("dialog-warning-symbolic")

        if not state:
            self.daemon_row.set_subtitle("未检测到守护进程状态文件")
            self.daemon_icon.set_from_icon_name("dialog-warning-symbolic")
            return
        updated = float(state.get("updated_at") or 0)
        age = max(0.0, time.time() - updated) if updated else 0.0
        interval = float(state.get("interval_seconds") or 10)
        if age < max(60.0, 3 * interval):
            self.daemon_row.set_subtitle(
                f"运行中（pid {state.get('pid')}）· {age:.0f} 秒前检查过 · "
                f"已修回 {state.get('stats', {}).get('changes', 0)} 次"
            )
            self.daemon_icon.set_from_icon_name("emblem-ok-symbolic")
        else:
            self.daemon_row.set_subtitle(f"状态已过期（{age:.0f} 秒前），守护进程可能已停止")
            self.daemon_icon.set_from_icon_name("dialog-warning-symbolic")

    # -------------------------------------------------------------- checking

    def _start_check(self, force_fix=False):
        if self._checking or self._fixing:
            if force_fix:
                self._log("检查或修复正在进行，请稍候")
            return
        self._checking = True
        threading.Thread(target=self._check_worker, args=(force_fix,), daemon=True).start()

    def _check_worker(self, force_fix):
        try:
            results = core.check_targets(self.config)
        except Exception as exception:  # noqa: BLE001
            results = []
            GLib.idle_add(self._log, f"检查失败：{exception}")
        GLib.idle_add(self._on_check_result, results, force_fix)

    def _on_check_result(self, results, force_fix):
        self._checking = False
        self._refresh_overview(results)
        for row in list(self.targets_group):
            if isinstance(row, TargetRow):
                result = self.route_results.get(row.target.get("address"))
                if result is None:
                    continue
                if result.get("ok"):
                    icon, css, label, _ = STATUS_STYLE["ok"]
                else:
                    icon, css, label, _ = STATUS_STYLE["warn"]
                detail = (
                    f"通过 {result.get('current')} 直连"
                    if result.get("ok")
                    else result.get("reason") or "路由异常"
                )
                row.set_state(icon, css, label, detail)
        if force_fix:
            to_fix = [result for result in results if result.get("desired")]
        elif self.auto_switch.get_active():
            to_fix = [
                result for result in results if result.get("desired") and not result.get("ok")
            ]
        else:
            to_fix = []
        if to_fix:
            self._start_fix(to_fix)
        elif force_fix:
            self._log("没有需要修复的目标")
        self._refresh_daemon()
        return GLib.SOURCE_REMOVE

    def _start_fix(self, targets):
        if self._fixing:
            self._log("已有修复操作在进行")
            return
        self._fixing = True
        self.fix_button.set_sensitive(False)
        self._log(f"修复 {len(targets)} 个目标")
        threading.Thread(target=self._fix_worker, args=(targets,), daemon=True).start()

    def _fix_worker(self, targets):
        outcome = core.fix_targets(targets)
        GLib.idle_add(self._on_fix_done, outcome)

    def _on_fix_done(self, outcome):
        self._fixing = False
        self.fix_button.set_sensitive(True)
        return_code = outcome.get("return_code", -1)
        error = outcome.get("stderr", "")
        if return_code == 0:
            if outcome.get("method") == "daemon":
                self._log("已通过后台守护进程修复（无需授权）")
            applied = []
            try:
                applied = json.loads(outcome.get("stdout") or "[]")
            except (TypeError, ValueError):
                applied = []
            changed = sum(1 for item in applied if item.get("changed"))
            self._toast(
                f"修复完成，{len(applied)} 条路由"
                + (f"（{changed} 条实际改动）" if changed else "（本就正常）")
            )
            self._log(f"修复完成：{len(applied)} 条路由，{changed} 条改动")
        elif return_code == 126:
            self._toast("已取消或拒绝授权")
            self._log("已取消或拒绝授权，批量修复停止")
        elif return_code == 127:
            self._toast("无法启动特权 helper")
            self._log(f"无法启动特权 helper：{error or '策略未加载'}")
        else:
            self._toast("修复失败，详见运行记录")
            self._log(f"修复失败（退出码 {return_code}）：{error or '未知错误'}")
        self._refresh_daemon()
        GLib.timeout_add_seconds(2, self._confirm_after_fix)
        return GLib.SOURCE_REMOVE

    def _confirm_after_fix(self):
        self._start_check()
        return GLib.SOURCE_REMOVE

    def on_fix_now(self, _button):
        self._start_check(force_fix=True)

    def _tick(self):
        self._start_check()
        self._refresh_daemon()
        return GLib.SOURCE_CONTINUE

    # --------------------------------------------------------------- settings

    def _on_target_toggled(self, switch, _parameter, target):
        target["enabled"] = switch.get_active()
        self._targets_from_config()
        self._save_config()
        self._refresh_sidebar()
        self._refresh_overview()
        self.cleanup_report = None
        self._start_check()

    def _on_mode_changed(self, row, _parameter):
        if self._building:
            return
        self.config["routing_mode"] = "rule" if row.get_selected() == 0 else "main"
        self.table_row.set_sensitive(row.get_selected() == 0)
        self.pref_row.set_sensitive(row.get_selected() == 0)
        self._save_config()
        self._log(f"路由模式：{self.config['routing_mode']}")
        self._start_check()

    def _on_table_changed(self, row, _parameter):
        if self._building:
            return
        self.config["rule_table"] = int(row.get_value())
        self._save_config()
        self._start_check()

    def _on_pref_changed(self, row, _parameter):
        if self._building:
            return
        self.config["rule_preference"] = int(row.get_value())
        self._save_config()

    def _on_expand_toggled(self, switch, _parameter):
        if self._building:
            return
        self.config["expand_host_targets"] = switch.get_active()
        self._save_config()
        self._start_check()

    def _on_autostart_toggled(self, switch, _parameter):
        if self._building:
            return
        enabled = switch.get_active()
        if not core.apply_autostart(enabled):
            self._toast("无法更新开机自启设置")
            return
        self.config["autostart"] = enabled
        self._save_config()

    def on_auto_toggled(self, switch, _parameter):
        if self._building:
            return
        self.config["auto_fix"] = switch.get_active()
        self._save_config()
        self._log("自动修复已开启" if switch.get_active() else "自动修复已关闭")
        if switch.get_active():
            self._start_check()

    # -------------------------------------------------------------- config file

    def _reload_config_editor(self):
        path = core.CONFIG_PATH
        self.user_path_row.set_title("用户配置")
        self.user_path_row.set_subtitle(str(path) + ("" if path.is_file() else "（尚未创建）"))
        self.system_path_row.set_subtitle(
            str(core.SYSTEM_CONFIG_PATH)
            + ("" if core.SYSTEM_CONFIG_PATH.is_file() else "（未使用）")
        )
        try:
            text = path.read_text(encoding="utf-8") if path.is_file() else ""
        except OSError as exception:
            text = ""
            self._set_config_status(f"读取失败：{exception}", "error")
        if not text:
            text = json.dumps(core.DEFAULT_CONFIG, ensure_ascii=False, indent=2) + "\n"
        self.config_buffer.set_text(text, -1)
        self._set_config_status("已载入当前文件内容", "ok")

    def _set_config_status(self, message, kind="unknown"):
        self.config_status_row.set_subtitle(message)
        icon = {
            "ok": "emblem-ok-symbolic",
            "error": "dialog-error-symbolic",
            "unknown": "dialog-question-symbolic",
        }.get(kind, "dialog-question-symbolic")
        if self.config_status_row.get_child() is not None:
            self.config_status_row.set_child(None)
        image = Gtk.Image.new_from_icon_name(icon)
        self.config_status_row.add_prefix(image)

    def _parse_config_editor(self):
        text = self.config_buffer.get_text(
            self.config_buffer.get_start_iter(), self.config_buffer.get_end_iter(), False
        )
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exception:
            return None, f"JSON 语法错误：第 {exception.lineno} 行 {exception.msg}"
        if not isinstance(data, dict):
            return None, "顶层必须是一个 JSON 对象"
        unknown = set(data) - set(core.DEFAULT_CONFIG)
        if "targets" in data and not isinstance(data["targets"], list):
            return None, "targets 必须是数组"
        return data, ("包含未识别的键：" + "、".join(sorted(unknown))) if unknown else ""

    def _validate_config_editor(self):
        data, message = self._parse_config_editor()
        if data is None:
            self._set_config_status(message, "error")
            self._toast(message)
            return False
        if message:
            self._set_config_status(message + "（会原样保留）", "unknown")
        else:
            self._set_config_status("语法正确，可以写入", "ok")
        return True

    def _apply_config_editor(self):
        data, message = self._parse_config_editor()
        if data is None:
            self._set_config_status(message, "error")
            self._toast(message)
            return
        if not core.save_config(data):
            self._set_config_status("写入失败", "error")
            self._toast("写入配置文件失败")
            return
        self._load_config()
        self._targets_from_config()
        self._set_config_status("已写入 " + str(core.CONFIG_PATH), "ok")
        self._toast("配置文件已更新")
        self._log("通过原始编辑器更新了配置文件")
        self.cleanup_report = None
        self._refresh_all()
        self._start_check()

    def _confirm_reset_config(self):
        dialog = Adw.AlertDialog(
            heading="恢复默认设置？",
            body="会清空目标列表和所有自定义选项，配置文件本身保留。",
        )
        dialog.add_response("cancel", "取消")
        dialog.add_response("reset", "恢复默认")
        dialog.set_response_appearance("reset", Adw.ResponseAppearance.DESTRUCTIVE)

        def on_response(_dialog, response):
            if response != "reset":
                return
            if not core.save_config(dict(core.DEFAULT_CONFIG)):
                self._toast("写入失败")
                return
            self._load_config()
            self._targets_from_config()
            core.apply_autostart(False)
            self._reload_config_editor()
            self._refresh_all()
            self._toast("已恢复默认设置")

        dialog.connect("response", on_response)
        dialog.present(self.window)

    def _confirm_delete_config(self):
        dialog = Adw.AlertDialog(
            heading="删除配置文件？",
            body=f"将删除 {core.CONFIG_PATH}。所有目标都会丢失，"
            "已安装的路由可以在“清理”里回收。",
        )
        dialog.add_response("cancel", "取消")
        dialog.add_response("delete", "删除")
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)

        def on_response(_dialog, response):
            if response != "delete":
                return
            try:
                core.CONFIG_PATH.unlink(missing_ok=True)
            except OSError as exception:
                self._toast(f"删除失败：{exception}")
                return
            core.apply_autostart(False)
            self.config = dict(core.DEFAULT_CONFIG)
            self._targets_from_config()
            self.route_results = {}
            self._reload_config_editor()
            self._refresh_all()
            self._log("已删除配置文件")
            self._toast("配置文件已删除")

        dialog.connect("response", on_response)
        dialog.present(self.window)

    def _open_in_file_manager(self, path):
        try:
            launcher = Gtk.FileLauncher.new(Gio.File.new_for_path(str(path)))
            launcher.launch(self.window, None, None)
        except Exception as exception:  # noqa: BLE001 - desktop integration
            self._toast(f"无法打开文件管理器：{exception}")

    # ------------------------------------------------------------------ cleanup

    def _start_cleanup_scan(self):
        if self._cleaning:
            return
        self._cleaning = True
        self.cleanup_row.set_title("正在检查…")
        self.cleanup_row.set_subtitle("扫描路由表与配置文件")
        threading.Thread(target=self._cleanup_worker, daemon=True).start()

    def _cleanup_worker(self):
        try:
            report = core.analyze_cleanup(prune_days=self.config.get("prune_after_days"))
            error = ""
        except Exception as exception:  # noqa: BLE001
            report = None
            error = str(exception)
        GLib.idle_add(self._on_cleanup_scan_done, report, error)

    def _on_cleanup_scan_done(self, report, error):
        self._cleaning = False
        if error:
            self.cleanup_row.set_title("无法检查残留")
            self.cleanup_row.set_subtitle(error)
            return GLib.SOURCE_REMOVE
        self.cleanup_report = report

        # The checkbox is a direct child too, so keep it and drop the rest.
        for group, check in (
            (self.cleanup_routes_group, self.cleanup_routes_check),
            (self.cleanup_targets_group, self.cleanup_targets_check),
        ):
            for row in group_rows(group):
                if row is not check:
                    group.remove(row)

        routes = report["routes"]["routes"]
        route_rows = 0
        for item in routes[:50]:
            row = Adw.ActionRow(title=item["label"])
            if item["kind"] == "rule":
                row.set_subtitle("策略规则残留")
                row.set_icon_name("view-list-symbolic")
            else:
                row.set_subtitle("本工具安装的路由（proto 66），已无对应目标")
                row.set_icon_name("network-wired-symbolic")
            self.cleanup_routes_group.add(row)
            route_rows += 1
        if len(routes) > route_rows:
            more = Adw.ActionRow(title=f"…还有 {len(routes) - route_rows} 项")
            self.cleanup_routes_group.add(more)
        self.cleanup_routes_group.set_description(
            f"发现 {len(routes)} 项残留；表 {', '.join(report['routes']['tables'])}"
            if routes
            else "没有残留：路由表里没有本工具留下的孤儿条目"
        )
        self.cleanup_routes_check.set_visible(bool(routes))

        target_candidates = own_cleanup_candidates(report)
        for candidate in target_candidates[:50]:
            row = Adw.ActionRow(title=candidate.get("name") or candidate["address"])
            row.set_subtitle(f"{candidate['address']} · {candidate['detail']}")
            row.set_icon_name("user-trash-symbolic")
            self.cleanup_targets_group.add(row)
        self.cleanup_targets_group.set_description(
            f"发现 {len(target_candidates)} 条；仅限已停用的目标"
            if target_candidates
            else f"没有可清理的配置条目（保留 {report['prune_after_days']} 天内出现过的设备）"
        )
        self.cleanup_targets_check.set_visible(bool(target_candidates))

        total = len(routes) + len(target_candidates)
        if total:
            self.cleanup_icon.set_from_icon_name("user-trash-symbolic")
            self.cleanup_row.set_title(f"发现 {total} 项可清理")
            self.cleanup_row.set_subtitle("勾选要处理的部分，然后点下面的“清理选中项”")
        else:
            self.cleanup_icon.set_from_icon_name("emblem-ok-symbolic")
            self.cleanup_row.set_title("很干净")
            self.cleanup_row.set_subtitle("没有残留路由，也没有早已不用的目标")
        self.cleanup_button.set_sensitive(bool(total))
        self._refresh_sidebar()
        return GLib.SOURCE_REMOVE

    def _apply_cleanup(self):
        report = self.cleanup_report
        if not report:
            return
        do_routes = self.cleanup_routes_check.get_active() and report["routes"]["count"]
        do_targets = self.cleanup_targets_check.get_active() and bool(
            own_cleanup_candidates(report)
        )
        if not do_routes and not do_targets:
            self._toast("没有勾选任何要清理的内容")
            return

        parts = []
        if do_routes:
            parts.append(f"{report['routes']['count']} 项路由残留")
        if do_targets:
            parts.append(f"{len(own_cleanup_candidates(report))} 条配置条目")
        dialog = Adw.AlertDialog(
            heading="确认清理",
            body="将删除 " + "、".join(parts) + "。开启中的目标不受影响。",
        )
        dialog.add_response("cancel", "取消")
        dialog.add_response("clean", "清理")
        dialog.set_response_appearance("clean", Adw.ResponseAppearance.DESTRUCTIVE)

        def on_response(_dialog, response):
            if response != "clean":
                return
            self._run_cleanup(do_routes, do_targets)

        dialog.connect("response", on_response)
        dialog.present(self.window)

    def _run_cleanup(self, do_routes, do_targets):
        report = self.cleanup_report or {}
        messages = []
        if do_routes:
            # Every config that might own a route must be listed here, or its
            # routes look like residue and get deleted (see lanrf.cleanup).
            configs = list(core.collect_all_configs())
            if not any(str(path) == str(core.CONFIG_PATH) for path, _config in configs):
                configs.append((core.CONFIG_PATH, core.load_config()))
            outcome = core.prune_routes(core.get_backend(), configs)
            messages.append(f"清理 {outcome['removed_count']} 项路由残留")
            if outcome["failed"]:
                messages.append(
                    f"{outcome['failed_count']} 项没删掉（删除路由需要管理员权限，"
                    "可在终端执行 sudo lan-route-fixer prune --yes）"
                )
        if do_targets:
            config = core.load_config()
            outcome = core.prune_targets(config, own_cleanup_candidates(report))
            messages.append(f"移除 {outcome['removed_count']} 条配置条目")
            self._load_config()
            self._targets_from_config()
        self.cleanup_report = None
        self._toast("；".join(messages) or "没有改动")
        self._log("清理：" + "；".join(messages))
        self._refresh_all()
        self._start_check()
        self._start_cleanup_scan()


def _version():
    try:
        from lanrf import __version__

        return __version__
    except Exception:  # noqa: BLE001
        return ""


def main():
    Adw.init()
    return LanRouteFixer().run(None)


if __name__ == "__main__":
    raise SystemExit(main())
