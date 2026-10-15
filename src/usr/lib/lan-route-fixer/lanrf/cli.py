"""Command line interface.

Command names from 2.0.x keep working. New commands expose the machinery that
makes the aTrust case fast: ``daemon`` (event driven repair), ``doctor``
(explains why a device is still unreachable) and ``status`` (what the running
daemon last saw).
"""

import argparse
import json
import os
import sys
import time

from .backends import get_backend
from .checks import check_targets, summarize
from .config import (
    CONFIG_PATH,
    DEFAULT_CONFIG,
    collect_all_configs,
    load_config,
    read_state,
)
from .discovery import detect_targets
from .privileged import describe_failure, fix_targets
from .system import status_report

STATE_COLORS = {"ok": "\033[32m", "bad": "\033[31m", "warn": "\033[33m"}
RESET = "\033[0m"


def _use_color(stream=None):
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def _print_check_results(results, json_output=False):
    if json_output:
        print(json.dumps(results, ensure_ascii=False, indent=2))
        return 0 if all(result["ok"] for result in results) else 1
    color = _use_color()
    if not results:
        print("没有启用的目标")
        return 0
    for result in results:
        state = "ok " if result["ok"] else "bad"
        desired = result["desired"] or "-"
        current = result["current"] or "-"
        prefix = STATE_COLORS.get("ok" if result["ok"] else "bad", "") if color else ""
        suffix = RESET if color else ""
        print(
            f"{prefix}{state}{suffix}\t{result['address']}\t"
            f"desired={desired}\tcurrent={current}"
            + (f"\t{result['reason']}" if not result["ok"] and result.get("reason") else "")
        )
    counts = summarize(results)
    print(f"共 {counts['total']} 个目标，正常 {counts['ok']}，异常 {counts['bad']}")
    return 0 if counts["bad"] == 0 else 1


def _print_targets(config, json_output=False):
    targets = config.targets
    if json_output:
        print(json.dumps(targets, ensure_ascii=False, indent=2))
        return
    if not targets:
        print("没有配置目标")
        return
    for target in targets:
        state = "启用" if target.get("enabled") else "停用"
        interface = target.get("interface") or "自动"
        print(f"{state}\t{target.get('address')}\t{target.get('name')}\t{interface}")


def _load_targets_with_modes(config, query):
    indices = _find_indices(config, query)
    if not indices:
        print(f"未找到目标：{query}", file=sys.stderr)
    return indices


def _find_indices(config, query):
    from .targets import find_target_indices

    return find_target_indices(config.targets, query)


def _interface_choice_error(backend, interface):
    if not interface:
        return None
    if backend.is_usable(interface):
        return None
    kind = backend.link_kind(interface)
    return f"不可用的网卡：{interface}" + (f"（类型 {kind}）" if kind else "")


def _helper_outcome_message(outcome):
    return_code = outcome.get("return_code", 0)
    if return_code == 0:
        return None
    return describe_failure(return_code, outcome.get("stderr", ""))


def build_parser():
    parser = argparse.ArgumentParser(
        prog="lan-route-fixer",
        description="Keep selected LAN devices on a physical network instead of a VPN tunnel.",
    )
    parser.add_argument("--config", help="path to config.json")
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    scan = subparsers.add_parser("scan", help="discover LAN neighbours as JSON")
    scan.add_argument("--pretty", action="store_true", help="pretty-print JSON")
    scan.add_argument("--no-names", action="store_true", help="skip mDNS lookups")

    check = subparsers.add_parser("check", help="check enabled targets")
    check.add_argument("--json", action="store_true", help="output JSON")

    fix = subparsers.add_parser("fix", help="fix all enabled targets (asks for authorization)")
    fix.add_argument("--quiet", action="store_true", help="only print errors")
    fix.add_argument(
        "--direct",
        action="store_true",
        help="skip the background daemon and authorize directly with pkexec",
    )

    run = subparsers.add_parser("run", help="foreground monitoring loop (legacy alias)")
    run.add_argument("--once", action="store_true", help="check/fix once and exit")
    run.add_argument("--interval", type=float, help="polling fallback interval in seconds")

    daemon = subparsers.add_parser(
        "daemon",
        help="event driven repair service (needs root for route changes)",
    )
    daemon.add_argument("--once", action="store_true", help="reconcile once and exit")
    daemon.add_argument("--dry-run", action="store_true", help="report, do not change")
    daemon.add_argument("--interval", type=float, default=None, help="polling fallback interval")
    daemon.add_argument("--quiet", action="store_true", help="log only problems")
    daemon.add_argument("--json", action="store_true", help="print the report as JSON")
    daemon.add_argument(
        "--dbus",
        action="store_true",
        help="also serve the D-Bus control interface so the GUI can repair "
        "without a password prompt",
    )

    status = subparsers.add_parser("status", help="show configured targets and their route state")
    status.add_argument("--json", action="store_true", help="output JSON")
    status.add_argument("--daemon", action="store_true", help="show the daemon's own state file")

    prune = subparsers.add_parser(
        "prune",
        help="clean up leftover routes/rules and forgotten targets (dry run by default)",
    )
    prune.add_argument("--yes", action="store_true", help="actually remove, not just list")
    prune.add_argument("--routes", action="store_true", help="only clean up routes and rules")
    prune.add_argument("--targets", action="store_true", help="only clean up config targets")
    prune.add_argument("--days", type=int, default=None,
                       help="a disabled target unseen for this many days is offered")
    prune.add_argument("--json", action="store_true", help="output JSON")

    doctor = subparsers.add_parser("doctor", help="explain why a LAN device is unreachable")
    doctor.add_argument("--json", action="store_true", help="output JSON")
    doctor.add_argument("--no-probe", action="store_true", help="skip active TCP probes")
    doctor.add_argument("--port", type=int, default=22, help="TCP port to probe (default 22)")
    doctor.add_argument("--no-color", action="store_true", help="disable ANSI colors")

    list_parser = subparsers.add_parser("list", help="list configured targets")
    list_parser.add_argument("--json", action="store_true", help="output JSON")

    add = subparsers.add_parser("add", help="add or update a private LAN target")
    add.add_argument("address", help="private IPv4/IPv6 address or CIDR")
    add.add_argument("--name", help="display name")
    add.add_argument("--interface", help="physical interface, or auto")
    add.add_argument("--disabled", action="store_true", help="add without enabling")
    add.add_argument(
        "--expand",
        action="store_true",
        help="install a route for the whole local subnet instead of just this host",
    )

    remove = subparsers.add_parser("remove", help="remove a target by address or name")
    remove.add_argument("query", help="address or name")

    enable = subparsers.add_parser("enable", help="enable a target")
    enable.add_argument("query", help="address or name")

    disable = subparsers.add_parser("disable", help="disable a target")
    disable.add_argument("query", help="address or name")

    set_interface = subparsers.add_parser("set-interface", help="set a target interface")
    set_interface.add_argument("query", help="address or name")
    set_interface.add_argument("interface", help="physical interface, or auto")

    config_parser = subparsers.add_parser("config", help="read or write config settings")
    config_parser.add_argument("--json", action="store_true", help="output JSON")
    config_subparsers = config_parser.add_subparsers(dest="action", metavar="ACTION")
    config_subparsers.add_parser("show", help="print the effective config")
    config_subparsers.add_parser("paths", help="print config file locations")
    config_set = config_subparsers.add_parser("set", help="set a setting")
    config_set.add_argument("key", help="setting name")
    config_set.add_argument("value", help="new value")
    config_get = config_subparsers.add_parser("get", help="read a setting")
    config_get.add_argument("key", help="setting name")

    return parser


def cli_main(argv):
    parser = build_parser()
    args = parser.parse_args(list(argv or []))

    if args.command == "scan":
        targets = detect_targets(resolve_names=not args.no_names)
        indent = 2 if args.pretty else None
        print(json.dumps(targets, ensure_ascii=False, indent=indent))
        return 0

    if args.command == "doctor":
        from .doctor import diagnose, format_findings

        report = diagnose(probe=not args.no_probe, port=args.port)
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
            return 0 if report["worst"] >= 1 else 1
        print(format_findings(report["findings"], use_color=not args.no_color))
        return 0 if report["worst"] >= 1 else 1

    if args.command == "prune":
        return _handle_prune(args)

    if args.command == "status":
        if args.daemon:
            state = read_state()
            if not state:
                print("没有守护进程状态（守护进程未运行？）")
                return 1
            if args.json:
                print(json.dumps(state, ensure_ascii=False, indent=2, default=str))
                return 0
            _print_daemon_state(state)
            return 0
        report = status_report(config_paths=[args.config] if args.config is not None else None)
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
            return 0 if report["ok"] else 1
        _print_status(report)
        return 0 if report["ok"] else 1

    if args.command == "daemon":
        from .daemon import ReconcileDaemon

        def logger(message, level="info"):
            if args.quiet and level == "info":
                return
            stream = sys.stderr if level in {"error", "warning"} else sys.stdout
            print(f"{time.strftime('%H:%M:%S')} [{level}] {message}", file=stream, flush=True)

        daemon = ReconcileDaemon(
            config_paths=[args.config] if args.config is not None else None,
            poll_interval=args.interval if args.interval else None,
            dry_run=args.dry_run,
            logger=logger,
        )
        if args.once:
            report = daemon.run_once()
            if args.json:
                print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
            return 0 if report.get("failed", 0) == 0 else 1
        if args.dbus:
            try:
                return daemon.run_glib()
            except RuntimeError as exception:
                logger(f"{exception}；将不使用 D-Bus 继续运行", "warning")
        return daemon.run()

    config = _load(args.config)

    if args.command == "check":
        return _print_check_results(check_targets(config), json_output=args.json)

    if args.command == "list":
        _print_targets(config, args.json)
        return 0

    if args.command == "config":
        return _handle_config(args, config)

    if args.command is None:
        parser.print_help()
        return 2

    if args.command in {"add", "remove", "enable", "disable", "set-interface"}:
        return _handle_mutation(args, config)

    if args.command == "fix":
        results = check_targets(config)
        to_fix = [result for result in results if result["desired"] and not result["ok"]]
        if not to_fix:
            if not args.quiet:
                print("没有需要修复的目标")
            return 0
        outcome = fix_targets(
            to_fix, config=config, prefer_daemon=not args.direct
        )
        message = _helper_outcome_message(outcome)
        if message:
            print(message, file=sys.stderr)
            return 1
        if not args.quiet:
            via = (
                "后台守护进程（无需授权）"
                if outcome.get("method") == "daemon"
                else "特权 helper"
            )
            print(f"修复完成，共 {len(outcome['items'])} 条路由（经由{via}）")
        return 0

    if args.command == "run":
        from .daemon import ReconcileDaemon

        interval = args.interval or config.interval_seconds
        daemon = ReconcileDaemon(
            config_paths=[args.config] if args.config is not None else None,
            poll_interval=interval,
            logger=lambda message, level="info": print(
                f"{time.strftime('%H:%M:%S')} [{level}] {message}",
                file=sys.stderr if level in {"error", "warning"} else sys.stdout,
                flush=True,
            ),
        )
        if args.once:
            report = daemon.run_once()
            return 0 if report.get("failed", 0) == 0 and report.get("bad", 0) == 0 else 1
        return daemon.run()

    parser.print_help()
    return 2


def _handle_prune(args):
    """List (and optionally remove) everything the tool has left behind."""
    from .backends import get_backend
    from .cleanup import analyze, keep_configs, prune_routes, prune_targets
    from .config import load_config

    paths = [args.config] if args.config is not None else None
    # The retention window lives in the config file; --days overrides it for
    # one run so the user can spot-check "what would 7 days have removed?".
    days = args.days if args.days is not None else load_config(args.config).prune_after_days
    report = analyze(config_paths=paths, prune_days=days)

    # Deleting entries from another user's config file is root's business.
    # Without an explicit --config an unprivileged run only edits the caller's
    # own file (route ownership is a separate, wider keep-set; see keep_configs).
    allowed_paths = None
    if os.geteuid() != 0:
        allowed_paths = {str(CONFIG_PATH)}
        if paths:
            allowed_paths.update(str(path) for path in paths)

    do_routes = args.routes or not args.targets
    do_targets = args.targets or not args.routes
    route_outcomes = []
    target_outcomes = []
    failures = []

    if do_routes and report["routes"]["count"]:
        if not args.json:
            print(f"路由与规则残留（表 {', '.join(report['routes']['tables'])}）：")
            for item in report["routes"]["routes"]:
                print(f"  · {item['label']}")
        if args.yes:
            # Same keep-set the report used: discovered configs plus the
            # explicit one, so a narrow --config cannot orphan a live route.
            outcome = prune_routes(get_backend(), keep_configs(paths))
            route_outcomes.append(outcome)
            failures.extend(outcome["failed"])
            if not args.json:
                print(f"  已清理 {outcome['removed_count']} 项"
                      + (f"，失败 {outcome['failed_count']} 项" if outcome["failed_count"] else ""))
                for failure in outcome["failed"]:
                    print(f"    ! {failure}")
        elif not args.json:
            print("  （删除路由与规则需要管理员权限：sudo lan-route-fixer prune --yes）")

    if do_targets:
        for entry in report["targets"]:
            if not entry["count"]:
                continue
            if allowed_paths is not None and entry["path"] not in allowed_paths:
                if not args.json:
                    print(
                        f"跳过其他用户的配置（需要 root）：{entry['path']}"
                        f"（{entry['count']} 条）"
                    )
                continue
            if not args.json:
                print(f"配置文件中可清理的条目：{entry['path']}")
                for candidate in entry["candidates"]:
                    print(f"  · {candidate['address']:<18} {candidate['detail']}")
            if args.yes:
                config = load_config(entry["path"])
                outcome = prune_targets(config, entry["candidates"])
                target_outcomes.append({"path": entry["path"], **outcome})
                if not args.json:
                    print(f"  已从配置移除 {outcome['removed_count']} 条")

    total = report["routes"]["count"] + sum(entry["count"] for entry in report["targets"])
    if args.json:
        print(
            json.dumps(
                {
                    "report": report,
                    "applied": args.yes,
                    "routes": route_outcomes,
                    "targets": target_outcomes,
                    "failed": failures,
                },
                ensure_ascii=False,
                indent=2,
                default=str,
            )
        )
    elif total == 0:
        print("没有需要清理的内容")
    elif not args.yes:
        print()
        print("以上为预演（未改动任何东西）。确认后执行：lan-route-fixer prune --yes")

    if failures:
        if not args.json:
            print(
                "有项目没有删掉：删除路由与规则需要管理员权限，请用 "
                "sudo lan-route-fixer prune --yes 重试。",
                file=sys.stderr,
            )
        return 1
    return 0


def _print_daemon_state(state):
    updated = float(state.get("updated_at") or 0)
    age = max(0.0, time.time() - updated) if updated else None
    print(f"状态文件：{state.get('_path')}")
    print(f"进程：pid={state.get('pid')} 运行中={state.get('running')}")
    print(f"模式：{state.get('routing_mode')} 表={state.get('rule_table')} 后端={state.get('backend')}")
    print(f"事件驱动：{'是' if state.get('events_supported') else '否（轮询）'}")
    if age is not None:
        print(f"最近一次检查：{age:.0f}s 前（reason={state.get('reason')}）")
    stats = state.get("stats") or {}
    print(
        "统计：检查 {passes} 次 · 内核事件 {events} 个 · 修复 {changes} 次 · 失败 {failures} 次".format(
            passes=stats.get("passes", 0),
            events=stats.get("events", 0),
            changes=stats.get("changes", 0),
            failures=stats.get("failures", 0),
        )
    )
    print(f"当前：目标 {state.get('targets', 0)} 个，异常 {state.get('bad', 0)} 个")
    for snapshot in state.get("snapshots", []):
        if snapshot.get("ok"):
            continue
        print(
            f"  ✗ {snapshot.get('name')} ({snapshot.get('address')}): "
            f"{snapshot.get('reason')}"
        )


def _print_status(report):
    color = _use_color()
    print(
        f"路由模式：{report['routing_mode']}"
        + (f"（表 {report['rule_table']}）" if report["routing_mode"] == "rule" else "")
    )
    if not report["targets"]:
        print("没有配置目标")
        return
    for snapshot in report["targets"]:
        ok = snapshot.get("ok")
        if snapshot.get("skipped"):
            mark, key = ("off", "warn") if snapshot.get("state") == "disabled" else ("inv", "bad")
        else:
            mark, key = ("ok ", "ok") if ok else ("bad", "bad")
        prefix = STATE_COLORS.get(key, "") if color else ""
        suffix = RESET if color else ""
        interface = snapshot.get("desired") or "-"
        current = snapshot.get("current") or "-"
        print(
            f"{prefix}{mark}{suffix}\t{snapshot.get('address')}\t"
            f"desired={interface}\tcurrent={current}\t{snapshot.get('name')}"
            + (f"\t{snapshot.get('reason')}" if snapshot.get("skipped") else "")
        )
    active = [snapshot for snapshot in report["targets"] if not snapshot.get("skipped")]
    disabled = len(report["targets"]) - len(active)
    print(
        f"共 {len(report['targets'])} 个目标，启用 {len(active)}，异常 {report['bad']}"
        + (f"，已停用 {disabled}" if disabled else "")
    )


def _handle_config(args, config):
    if args.action in (None, "show"):
        payload = config.to_dict()
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    if args.action == "paths":
        for path in (str(config.path), str(CONFIG_PATH)):
            print(path)
        for path, _config in collect_all_configs():
            print(path)
        return 0
    if args.action == "get":
        if args.key not in config.data and args.key not in config.unknown:
            print(f"未知设置：{args.key}", file=sys.stderr)
            return 1
        print(json.dumps(config.data.get(args.key, config.unknown.get(args.key)), ensure_ascii=False))
        return 0
    if args.action == "set":
        return _set_config_value(config, args.key, args.value)
    print("用法：lan-route-fixer config {show|paths|get|set}", file=sys.stderr)
    return 2


def _set_config_value(config, key, value):
    if key not in DEFAULT_CONFIG and key not in config.unknown:
        print(f"未知设置：{key}（可用：{', '.join(sorted(DEFAULT_CONFIG))}）", file=sys.stderr)
        return 1
    converted = value
    current = config.data.get(key, DEFAULT_CONFIG.get(key))
    if isinstance(current, bool):
        converted = str(value).strip().lower() in {"1", "true", "yes", "on", "enable", "enabled"}
    elif isinstance(current, int):
        try:
            converted = int(value)
        except ValueError:
            print(f"{key} 需要一个整数", file=sys.stderr)
            return 1
    config.data[key] = converted
    if key == "routing_mode" and converted not in {"rule", "main"}:
        print("routing_mode 只能是 rule 或 main", file=sys.stderr)
        return 1
    if not config.save():
        print(f"无法保存配置：{config.path}", file=sys.stderr)
        return 1
    print(f"{key} = {converted}")
    return 0


def _handle_mutation(args, config):
    backend = get_backend()
    targets = config.targets

    if args.command == "add":
        return _add_target(args, config, backend)

    if args.command == "set-interface":
        from .targets import normalize_interface_arg

        interface = normalize_interface_arg(args.interface)
        error = _interface_choice_error(backend, interface)
        if error:
            print(error, file=sys.stderr)
            return 1
        indices = _load_targets_with_modes(config, args.query)
        if not indices:
            return 1
        for index in indices:
            targets[index]["interface"] = interface
        if not config.save():
            print("无法保存配置", file=sys.stderr)
            return 1
        print(f"已处理 {len(indices)} 个目标：{args.command} {args.query}")
        return 0

    indices = _load_targets_with_modes(config, args.query)
    if not indices:
        return 1
    if args.command == "remove":
        for index in reversed(indices):
            targets.pop(index)
    elif args.command == "enable":
        for index in indices:
            targets[index]["enabled"] = True
    elif args.command == "disable":
        for index in indices:
            targets[index]["enabled"] = False
    if not config.save():
        print("无法保存配置", file=sys.stderr)
        return 1
    print(f"已处理 {len(indices)} 个目标：{args.command} {args.query}")
    return 0


def _add_target(args, config, backend):
    from .targets import normalize_interface_arg, valid_local_target

    address = args.address.strip()
    if not valid_local_target(address):
        print(f"无效的局域网目标：{address}", file=sys.stderr)
        return 1
    interface = normalize_interface_arg(args.interface)
    error = _interface_choice_error(backend, interface)
    if error:
        print(error, file=sys.stderr)
        return 1
    target = {
        "name": args.name.strip() if args.name else address,
        "address": address,
        "interface": interface,
        "enabled": not args.disabled,
    }
    if getattr(args, "expand", False):
        target["expand"] = True
    indices = _find_indices(config, address)
    if indices:
        stored = config.targets[indices[0]]
        stored.update(target)
        # `add` without --expand means "just this host", so an earlier override
        # has to be cleared instead of silently sticking around.
        if not target.get("expand"):
            stored.pop("expand", None)
        action = "已更新"
    else:
        config.targets.append(target)
        action = "已添加"
    if not config.save():
        print("无法保存配置", file=sys.stderr)
        return 1
    state = "启用" if target["enabled"] else "停用"
    scope = "，覆盖整个本地子网" if target.get("expand") else ""
    print(
        f"{action}目标：{target['address']}（{state}，网卡：{target['interface'] or '自动'}{scope}）"
    )
    return 0


def _load(path=None):
    return load_config(path)
