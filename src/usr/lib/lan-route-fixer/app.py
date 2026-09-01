#!/usr/bin/env python3
"""Desktop application for keeping selected LAN devices off a VPN tunnel."""

import json
import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk

import core

DEFAULT_CONFIG = core.DEFAULT_CONFIG


class LanRouteFixer(Adw.Application):
    def __init__(self):
        super().__init__(application_id=core.APP_ID)
        self.connect("activate", self.on_activate)
        self.config = dict(DEFAULT_CONFIG)
        self.window = None
        self.status_group = None
        self.status_rows = {}
        self.auto_switch = None
        self.fix_button = None
        self.log_buffer = None
        self.settings_window = None
        self.settings_target_group = None
        self.settings_target_rows = []
        self.settings_targets = None
        self.settings_scan_button = None
        self.settings_auto_fix = None
        self.settings_autostart = None
        self.settings_save_button = None
        self.target_editor = None
        self.editor_name = None
        self.editor_address = None
        self.editor_interface = None
        self.editor_interfaces = []
        self.editor_save_button = None
        self._checking = False
        self._fixing = False
        self._scanning = False
        self._timer_id = None
        self._load_config()

    def _load_config(self):
        loaded = core.load_config()
        self.config.update(loaded)

    def _save_config(self):
        if not core.save_config(self.config):
            self._log("保存设置失败")
            return False
        return True

    def _apply_autostart(self, enabled):
        if not core.apply_autostart(enabled):
            self._log("更新开机自启失败")
            return False
        return True

    def _log(self, message):
        if self.log_buffer is None:
            return
        from datetime import datetime

        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_buffer.insert(
            self.log_buffer.get_end_iter(), f"[{timestamp}] {message}\n", -1
        )

    def on_activate(self, _application):
        if self.window is not None:
            self._rebuild_status_rows()
            self.window.present()
            return
        self._show_settings(first_run=(not self.config.get("targets")))
        if self.config.get("targets"):
            self._show_main_window()

    def _show_settings(self, _button=None, first_run=False, start_scan=False):
        if self.settings_window is not None:
            self.settings_window.present()
            if start_scan:
                self._start_scan()
            return

        settings = Adw.PreferencesWindow(application=self)
        settings.set_title("选择修复目标" if first_run else "设置")
        settings.set_default_size(580, 620)
        if self.window is not None:
            settings.set_transient_for(self.window)
            settings.set_modal(True)
        settings.connect("close-request", self._on_settings_closed)
        self.settings_window = settings
        self.settings_targets = [dict(target) for target in self.config["targets"]]

        page = Adw.PreferencesPage()
        target_group = Adw.PreferencesGroup(
            title="修复目标",
            description="扫描局域网后开启需要保持直连的设备；也可手动添加私有 IPv4 地址或网段。",
        )
        self.settings_target_group = target_group

        scan_row = Adw.ActionRow(
            title="自动检测局域网设备",
            subtitle="读取 ARP 邻居表；可用时通过 mDNS 显示设备名称",
        )
        self.settings_scan_button = Gtk.Button(label="扫描局域网")
        self.settings_scan_button.add_css_class("suggested-action")
        self.settings_scan_button.set_valign(Gtk.Align.CENTER)
        self.settings_scan_button.connect("clicked", self._start_scan)
        scan_row.add_suffix(self.settings_scan_button)
        scan_row.set_activatable_widget(self.settings_scan_button)
        target_group.add(scan_row)

        add_row = Adw.ActionRow(
            title="没有找到设备？",
            subtitle="手动填写设备名称、IPv4 地址/网段和目标网卡",
        )
        add_button = Gtk.Button(label="手动添加")
        add_button.set_valign(Gtk.Align.CENTER)
        add_button.connect("clicked", self._show_target_editor)
        add_row.add_suffix(add_button)
        add_row.set_activatable_widget(add_button)
        target_group.add(add_row)
        page.add(target_group)

        behavior_group = Adw.PreferencesGroup(title="行为")
        self.settings_auto_fix = Adw.SwitchRow(
            title="自动修复",
            subtitle="定期检查全部已开启目标，异常时请求管理员授权",
        )
        self.settings_auto_fix.set_active(bool(self.config.get("auto_fix", True)))
        behavior_group.add(self.settings_auto_fix)

        self.settings_autostart = Adw.SwitchRow(
            title="登录后自动启动",
            subtitle="仅为当前用户启用，可随时关闭",
        )
        self.settings_autostart.set_active(bool(self.config.get("autostart", False)))
        behavior_group.add(self.settings_autostart)
        page.add(behavior_group)

        save_group = Adw.PreferencesGroup()
        save_row = Adw.ActionRow(
            title="保存并应用",
            subtitle="目标列表仅保存在当前用户的配置目录中",
        )
        self.settings_save_button = Gtk.Button(label="保存")
        self.settings_save_button.add_css_class("suggested-action")
        self.settings_save_button.set_valign(Gtk.Align.CENTER)
        self.settings_save_button.connect("clicked", self._save_settings)
        save_row.add_suffix(self.settings_save_button)
        save_row.set_activatable_widget(self.settings_save_button)
        save_group.add(save_row)
        page.add(save_group)

        settings.add(page)
        self._rebuild_target_list()
        self._validate_settings()
        settings.present()
        if start_scan or (first_run and not self.settings_targets):
            self._start_scan()

    def _target_subtitle(self, target):
        interface = target.get("interface") or "自动选择网卡"
        details = [target.get("address", "—"), interface]
        if target.get("mac"):
            details.append(target["mac"])
        if target.get("state"):
            details.append(target["state"])
        return " · ".join(details)

    def _rebuild_target_list(self):
        if self.settings_target_group is None:
            return
        for row in self.settings_target_rows:
            self.settings_target_group.remove(row)
        self.settings_target_rows = []

        for target in self.settings_targets:
            row = Adw.ActionRow(
                title=target.get("name") or target.get("address") or "未命名设备",
                subtitle=self._target_subtitle(target),
            )
            row.set_icon_name("network-workgroup-symbolic")
            row.set_activatable(True)
            row.connect("activated", self._show_target_editor, target)

            enabled_switch = Gtk.Switch(
                active=bool(target.get("enabled")),
                valign=Gtk.Align.CENTER,
            )
            enabled_switch.set_tooltip_text("是否巡检和修复此设备")
            enabled_switch.connect("notify::active", self._on_target_toggled, target)
            row.add_suffix(enabled_switch)

            delete_button = Gtk.Button(
                icon_name="user-trash-symbolic",
                valign=Gtk.Align.CENTER,
            )
            delete_button.add_css_class("flat")
            delete_button.set_tooltip_text("删除目标")
            delete_button.connect("clicked", self._delete_target, target)
            row.add_suffix(delete_button)

            self.settings_target_group.add(row)
            self.settings_target_rows.append(row)

    def _on_target_toggled(self, switch, _parameter, target):
        target["enabled"] = switch.get_active()
        self._validate_settings()

    def _delete_target(self, _button, target):
        if target in self.settings_targets:
            self.settings_targets.remove(target)
            self._rebuild_target_list()
            self._validate_settings()

    def _start_scan(self, _button=None):
        if self._scanning or self.settings_window is None:
            return
        self._scanning = True
        self.settings_scan_button.set_sensitive(False)
        self.settings_scan_button.set_label("正在扫描…")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        try:
            discovered = core.detect_targets()
            error = ""
        except Exception as exception:
            discovered = []
            error = str(exception)
        GLib.idle_add(self._on_scan_done, discovered, error)

    def _on_scan_done(self, discovered, error):
        self._scanning = False
        if self.settings_window is None:
            return GLib.SOURCE_REMOVE
        self.settings_scan_button.set_sensitive(True)
        self.settings_scan_button.set_label("重新扫描")
        if error:
            self.settings_window.add_toast(Adw.Toast(title=f"扫描失败：{error}"))
            return GLib.SOURCE_REMOVE

        by_address = {target.get("address"): target for target in self.settings_targets}
        added = 0
        for found in discovered:
            existing = by_address.get(found["address"])
            if existing is not None:
                existing["mac"] = found.get("mac", "")
                existing["state"] = found.get("state", "")
                if not existing.get("name") or existing.get("name") == existing.get("address"):
                    existing["name"] = found["name"]
                continue
            target = dict(found)
            target["enabled"] = False
            self.settings_targets.append(target)
            by_address[target["address"]] = target
            added += 1

        self._rebuild_target_list()
        self._validate_settings()
        if not discovered:
            message = "未发现可用设备；可等待设备联网后重试，或手动添加"
        elif added:
            message = f"发现 {len(discovered)} 台设备，新增 {added} 台"
        else:
            message = f"已刷新 {len(discovered)} 台设备，没有新增设备"
        self.settings_window.add_toast(Adw.Toast(title=message))
        return GLib.SOURCE_REMOVE

    def _show_target_editor(self, _widget=None, target=None):
        if self.target_editor is not None:
            self.target_editor.present()
            return
        editing = target is not None
        original = target

        editor = Adw.PreferencesWindow(application=self)
        editor.set_title("编辑目标" if editing else "手动添加目标")
        editor.set_default_size(460, 400)
        editor.set_transient_for(self.settings_window)
        editor.set_modal(True)
        editor.connect("close-request", self._on_target_editor_closed)
        self.target_editor = editor

        page = Adw.PreferencesPage()
        group = Adw.PreferencesGroup(
            title="设备",
            description="支持 10/8、172.16/12、192.168/16 的 IPv4 地址或网段，以及 ULA/链路本地 IPv6。",
        )
        self.editor_name = Adw.EntryRow(title="名称（可选）")
        self.editor_name.set_text(str(target.get("name", "")) if editing else "")
        group.add(self.editor_name)

        self.editor_address = Adw.EntryRow(title="IP 地址或网段")
        self.editor_address.set_text(str(target.get("address", "")) if editing else "")
        self.editor_address.connect("notify::text", self._validate_target_editor)
        group.add(self.editor_address)

        interfaces = core.list_usable_interfaces()
        configured = str(target.get("interface", "")) if editing else ""
        if configured and configured not in interfaces:
            interfaces.append(configured)
        self.editor_interfaces = ["", *interfaces]
        model = Gtk.StringList.new(["自动（按网段/默认出口）", *interfaces])
        self.editor_interface = Adw.ComboRow(title="目标网卡", model=model)
        selected = self.editor_interfaces.index(configured) if configured in self.editor_interfaces else 0
        self.editor_interface.set_selected(selected)
        group.add(self.editor_interface)
        page.add(group)

        save_group = Adw.PreferencesGroup()
        save_row = Adw.ActionRow(
            title="保存目标",
            subtitle="开启后会参与定时巡检和批量修复",
        )
        self.editor_save_button = Gtk.Button(label="保存")
        self.editor_save_button.add_css_class("suggested-action")
        self.editor_save_button.set_valign(Gtk.Align.CENTER)
        self.editor_save_button.connect("clicked", self._save_target_editor, original)
        save_row.add_suffix(self.editor_save_button)
        save_row.set_activatable_widget(self.editor_save_button)
        save_group.add(save_row)
        page.add(save_group)

        editor.add(page)
        self._validate_target_editor()
        editor.present()

    def _validate_target_editor(self, *_args):
        if self.editor_save_button is not None:
            self.editor_save_button.set_sensitive(
                core.valid_local_target(self.editor_address.get_text())
            )

    def _save_target_editor(self, _button, original):
        address_text = self.editor_address.get_text().strip()
        if not core.valid_local_target(address_text):
            self.target_editor.add_toast(
                Adw.Toast(title="请输入有效的私有 IPv4 地址/网段或 IPv6 ULA/链路本地地址")
            )
            return

        selected = self.editor_interface.get_selected()
        interface = (
            self.editor_interfaces[selected]
            if selected < len(self.editor_interfaces)
            else ""
        )
        values = {
            "name": self.editor_name.get_text().strip() or address_text,
            "address": address_text,
            "interface": interface,
        }
        if original is None:
            values["enabled"] = True
            self.settings_targets.append(values)
        else:
            original.update(values)
            original.pop("mac", None)
            original.pop("state", None)

        editor = self.target_editor
        self._clear_target_editor_widgets()
        self._rebuild_target_list()
        self._validate_settings()
        editor.close()

    def _on_target_editor_closed(self, _window):
        self._clear_target_editor_widgets()
        return False

    def _clear_target_editor_widgets(self):
        self.target_editor = None
        self.editor_name = None
        self.editor_address = None
        self.editor_interface = None
        self.editor_interfaces = []
        self.editor_save_button = None

    def _validate_settings(self, *_args):
        if self.settings_save_button is None:
            return
        targets_valid = all(
            core.valid_local_target(target.get("address", ""))
            for target in self.settings_targets
        )
        has_enabled = any(
            target.get("enabled") and core.valid_local_target(target.get("address", ""))
            for target in self.settings_targets
        )
        self.settings_save_button.set_sensitive(targets_valid and has_enabled)

    def _save_settings(self, _button):
        targets = core.normalize_targets(self.settings_targets)
        if not any(target["enabled"] for target in targets):
            self.settings_window.add_toast(Adw.Toast(title="请至少开启一个修复目标"))
            return

        autostart = self.settings_autostart.get_active()
        if not self._apply_autostart(autostart):
            self.settings_window.add_toast(Adw.Toast(title="无法更新开机自启设置"))
            return

        self.config.update(
            {
                "targets": targets,
                "auto_fix": self.settings_auto_fix.get_active(),
                "autostart": autostart,
            }
        )
        if not self._save_config():
            self.settings_window.add_toast(Adw.Toast(title="无法保存配置"))
            return

        settings = self.settings_window
        self._clear_settings_widgets()
        self._show_main_window()
        if self.auto_switch.get_active() != bool(self.config["auto_fix"]):
            self.auto_switch.set_active(bool(self.config["auto_fix"]))
        self._log("设置已更新")
        self._start_check()
        settings.close()

    def _on_settings_closed(self, _window):
        self._clear_settings_widgets()
        return False

    def _clear_settings_widgets(self):
        if self.target_editor is not None:
            self.target_editor.close()
        self.settings_window = None
        self.settings_target_group = None
        self.settings_target_rows = []
        self.settings_targets = None
        self.settings_scan_button = None
        self.settings_auto_fix = None
        self.settings_autostart = None
        self.settings_save_button = None

    def _show_main_window(self):
        if self.window is not None:
            self._rebuild_status_rows()
            self.window.present()
            return

        self.window = Adw.ApplicationWindow(application=self)
        self.window.set_title(core.APP_DISPLAY_NAME)
        self.window.update_property(
            [Gtk.AccessibleProperty.LABEL], [core.APP_DISPLAY_NAME]
        )
        self.window.set_default_size(600, 580)

        header = Adw.HeaderBar()
        title = Adw.WindowTitle(
            title=core.APP_DISPLAY_NAME,
            subtitle="让所选局域网设备绕过 VPN 隧道",
        )
        header.set_title_widget(title)

        settings_button = Gtk.Button(icon_name="emblem-system-symbolic")
        settings_button.set_tooltip_text("设置")
        settings_button.connect("clicked", self._show_settings)
        header.pack_end(settings_button)

        scan_button = Gtk.Button(icon_name="view-refresh-symbolic")
        scan_button.set_tooltip_text("扫描并选择局域网设备")
        scan_button.connect(
            "clicked", lambda button: self._show_settings(button, start_scan=True)
        )
        header.pack_end(scan_button)

        self.status_group = Adw.PreferencesGroup(title="启用目标")

        self.auto_switch = Adw.SwitchRow(
            title="自动修复",
            subtitle="定期检查全部已开启目标；授权会短暂保留",
        )
        self.auto_switch.set_active(bool(self.config.get("auto_fix", True)))
        self.auto_switch.connect("notify::active", self.on_auto_toggled)
        behavior_group = Adw.PreferencesGroup(title="行为")
        behavior_group.add(self.auto_switch)

        self.fix_button = Gtk.Button(label="立即修复全部已开启目标")
        self.fix_button.add_css_class("suggested-action")
        self.fix_button.add_css_class("pill")
        self.fix_button.set_halign(Gtk.Align.CENTER)
        self.fix_button.connect("clicked", self.on_fix_now)

        log_header = Gtk.Label(label="运行记录", xalign=0)
        log_header.add_css_class("heading")
        self.log_buffer = Gtk.TextBuffer()
        log_view = Gtk.TextView(buffer=self.log_buffer)
        log_view.set_editable(False)
        log_view.set_cursor_visible(False)
        log_view.set_monospace(True)
        log_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        log_view.set_left_margin(10)
        log_view.set_right_margin(10)
        log_view.set_top_margin(8)
        log_view.set_bottom_margin(8)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_min_content_height(140)
        scrolled.set_vexpand(True)
        scrolled.set_child(log_view)
        scrolled.add_css_class("card")

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        content.set_margin_top(20)
        content.set_margin_bottom(20)
        content.set_margin_start(20)
        content.set_margin_end(20)
        content.append(self.status_group)
        content.append(behavior_group)
        content.append(self.fix_button)
        content.append(log_header)
        content.append(scrolled)

        clamp = Adw.Clamp(maximum_size=700, tightening_threshold=560)
        clamp.set_child(content)
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(header)
        toolbar.set_content(clamp)
        self.window.set_content(toolbar)
        self._rebuild_status_rows()
        self.window.present()

        interval = self._get_interval()
        self.auto_switch.set_subtitle(
            f"每 {interval} 秒检查全部已开启目标；授权会短暂保留"
        )
        if self._timer_id is None:
            self._timer_id = GLib.timeout_add_seconds(interval, self._tick)
        self._log("应用已启动")
        self._start_check()

    def _rebuild_status_rows(self):
        if self.status_group is None:
            return
        for row in self.status_rows.values():
            self.status_group.remove(row)
        self.status_rows = {}

        enabled_targets = [
            target for target in self.config["targets"] if target.get("enabled")
        ]
        self.status_group.set_title(f"启用目标（{len(enabled_targets)}）")
        for target in enabled_targets:
            interface = target.get("interface") or "自动选择网卡"
            row = Adw.ActionRow(
                title=target.get("name") or target["address"],
                subtitle=f"{target['address']} · {interface} · 等待检查",
            )
            row.set_icon_name("dialog-question-symbolic")
            self.status_group.add(row)
            self.status_rows[target["address"]] = row

    def _get_interval(self):
        try:
            return max(5, int(self.config.get("interval_seconds", 30)))
        except (TypeError, ValueError):
            return 30

    def on_auto_toggled(self, switch, _parameter):
        self.config["auto_fix"] = switch.get_active()
        self._save_config()
        self._log("自动修复已开启" if switch.get_active() else "自动修复已关闭")
        if switch.get_active():
            self._start_check()

    def on_fix_now(self, _button):
        self._start_check(force_fix=True)

    def _tick(self):
        self._start_check()
        return GLib.SOURCE_CONTINUE

    def _start_check(self, force_fix=False):
        if self._checking or self._fixing:
            if force_fix:
                self._log("检查或修复正在进行，请稍候")
            return
        self._checking = True
        threading.Thread(target=self._check_worker, args=(force_fix,), daemon=True).start()

    def _check_worker(self, force_fix):
        results = core.check_targets(self.config)
        GLib.idle_add(self._on_check_result, results, force_fix)

    def _on_check_result(self, results, force_fix):
        self._checking = False
        for result in results:
            row = self.status_rows.get(result["address"])
            if row is None:
                continue
            if not result["desired"]:
                row.set_subtitle(f"{result['address']} · 找不到可用网卡")
                row.set_icon_name("network-offline-symbolic")
            elif result["ok"]:
                row.set_subtitle(
                    f"{result['address']} · 路由正常，当前通过 {result['current']}"
                )
                row.set_icon_name("emblem-ok-symbolic")
            else:
                row.set_subtitle(
                    f"{result['address']} · 当前通过 {result['current'] or '未知'}，应通过 {result['desired']}"
                )
                row.set_icon_name("dialog-warning-symbolic")

        if force_fix:
            to_fix = [result for result in results if result["desired"]]
        elif self.auto_switch.get_active():
            to_fix = [result for result in results if result["desired"] and not result["ok"]]
        else:
            to_fix = []

        if to_fix:
            self._start_fix(to_fix)
        elif force_fix:
            self._log("没有可修复的已开启目标")
        return GLib.SOURCE_REMOVE

    def _start_fix(self, targets):
        if self._fixing:
            self._log("已有修复操作正在等待完成")
            return
        self._fixing = True
        self.fix_button.set_sensitive(False)
        self._log(f"准备修复 {len(targets)} 个已开启目标")
        threading.Thread(target=self._fix_worker, args=(targets,), daemon=True).start()

    def _fix_worker(self, targets):
        outcome = core.fix_targets(targets)
        GLib.idle_add(self._on_fix_done, outcome)

    def _on_fix_done(self, outcome):
        self._fixing = False
        self.fix_button.set_sensitive(True)
        return_code = outcome.get("return_code", -1)
        error = outcome.get("stderr", "")
        items = outcome.get("items", [])
        if return_code == 0:
            addresses = "、".join(item["address"] for item in items)
            self._log(f"修复成功：{addresses or '全部目标'}")
        elif return_code == 126:
            self._log("已取消或拒绝授权，批量修复停止")
        elif return_code == 127:
            self._log(f"无法启动特权 helper：{error or '策略未加载'}")
        else:
            self._log(f"修复失败（退出码 {return_code}）：{error or '未知错误'}")
        self._log(f"批量修复完成：共 {len(items)} 条路由")
        GLib.timeout_add_seconds(2, self._confirm_after_fix)
        return GLib.SOURCE_REMOVE

    def _confirm_after_fix(self):
        self._start_check()
        return GLib.SOURCE_REMOVE


def main():
    Adw.init()
    return LanRouteFixer().run(None)


if __name__ == "__main__":
    raise SystemExit(main())
