"""Diagnostics.

Answers the questions that come up when a LAN device is unreachable *while* a
VPN client is connected, and unlike the rest of the tool it tries hard to name
the culprit: which broader route is swallowing the traffic, which interface the
kernel actually picks, and whether the privileged/background machinery is
installed.

Everything here is read-only and runs unprivileged.
"""

import os
import platform
import shutil
import socket
import subprocess
import time

from . import model, netlink
from .backends import get_backend
from .config import CONFIG_PATH, SYSTEM_CONFIG_PATH, read_state
from .privileged import helper_status
from .system import status_report

SEVERITY_OK = "ok"
SEVERITY_WARN = "warn"
SEVERITY_FAIL = "fail"
SEVERITY_INFO = "info"

_SEVERITY_RANK = {
    SEVERITY_FAIL: 0,
    SEVERITY_WARN: 1,
    SEVERITY_OK: 2,
    SEVERITY_INFO: 3,
}


def _finding(severity, title, detail="", hint=""):
    return {"severity": severity, "title": title, "detail": detail, "hint": hint}


def diagnose_environment(backend=None):
    """Backend, kernel and packaging facts."""
    backend = backend or get_backend()
    findings = []
    findings.append(
        _finding(
            SEVERITY_INFO,
            f"平台后端：{backend.name}",
            f"{platform.system()} {platform.release()} · Python {platform.python_version()}",
        )
    )
    findings.append(
        _finding(
            SEVERITY_OK if backend.supports_events else SEVERITY_WARN,
            "内核路由事件通知：" + ("可用" if backend.supports_events else "不可用"),
            "RTM_NEWROUTE/RTM_DELROUTE 订阅；实测把修复延迟从最长 30s 降到约 0.33s"
            if backend.supports_events
            else "将退化为轮询，修复存在最长一个轮询周期的窗口",
        )
    )
    findings.append(
        _finding(
            SEVERITY_OK if backend.supports_policy_rules else SEVERITY_INFO,
            "策略路由（独立表 + ip rule）：" + ("可用" if backend.supports_policy_rules else "不适用"),
            "VPN 重写主路由表时，独立表 + 高优先级规则仍然生效"
            if backend.supports_policy_rules
            else "该平台只有一张路由表，依赖更长前缀 + 事件驱动修复",
        )
    )
    status = helper_status()
    if status["helper_exists"]:
        findings.append(
            _finding(
                SEVERITY_OK,
                "特权 helper 已安装",
                status["helper_path"],
            )
        )
    else:
        findings.append(
            _finding(
                SEVERITY_FAIL,
                "缺少特权 helper",
                status["helper_path"],
                "重新安装 lan-route-fixer 软件包",
            )
        )
    findings.append(
        _finding(
            SEVERITY_OK if status["pkexec_exists"] else SEVERITY_WARN,
            "pkexec：" + ("已安装" if status["pkexec_exists"] else "缺失"),
            status["pkexec_path"],
        )
    )
    interfaces = backend.list_interfaces(only_up=True)
    findings.append(
        _finding(
            SEVERITY_OK if interfaces else SEVERITY_FAIL,
            f"可用物理网卡：{len(interfaces)}",
            ", ".join(interfaces) or "未发现可承载局域网路由的网卡",
        )
    )
    tunnel = [
        name
        for name in backend.list_interfaces(only_up=False)
        if name.startswith(("utun", "tun", "wg", "tailscale", "ppp"))
        or backend.link_kind(name) in {"tun", "tap", "wireguard"}
    ]
    if tunnel:
        findings.append(
            _finding(
                SEVERITY_INFO,
                "检测到隧道/虚拟网卡",
                ", ".join(tunnel),
                "这些网卡是 VPN 抢路由的来源，本工具会把目标钉在物理网卡上",
            )
        )
    return findings


def diagnose_targets(report, backend):
    """Turn status snapshots into findings, naming the capturing route."""
    findings = []
    for snapshot in report["targets"]:
        if snapshot.get("skipped"):
            # Disabled (or invalid) targets are the user's own choice; report
            # them as information so the check count stays honest.
            findings.append(
                _finding(
                    SEVERITY_INFO,
                    f"{snapshot.get('name')} 未启用",
                    snapshot.get("reason", ""),
                    "需要保护它时执行：lan-route-fixer enable "
                    f"{snapshot.get('address')}",
                )
            )
            continue
        name = snapshot.get("name") or snapshot.get("address")
        address = snapshot.get("effective_address") or snapshot.get("address")
        if snapshot.get("ok"):
            findings.append(
                _finding(
                    SEVERITY_OK,
                    f"{name} 已固定在 {snapshot.get('desired')}",
                    f"{address}（表 {snapshot.get('table')}）",
                )
            )
            continue

        covering = snapshot.get("covering") or []
        hint = ""
        if covering:
            hint = (
                f"更宽的路由 {', '.join(covering[:3])} 正在把流量送去 "
                f"{snapshot.get('current')}；启用 routing_mode=rule 或保持守护进程运行可避免"
            )
        elif snapshot.get("current"):
            hint = "运行 `lan-route-fixer fix` 或确认守护进程正在运行"
        findings.append(
            _finding(
                SEVERITY_FAIL,
                f"{name} 状态异常：{snapshot.get('state')}",
                snapshot.get("reason", ""),
                hint,
            )
        )

    # Local-subnet coverage: a target whose subnet is not on any local NIC is
    # a configuration mistake that no amount of repair can fix.
    for snapshot in report["targets"]:
        address = snapshot.get("effective_address") or snapshot.get("address")
        if not address or "/" not in address:
            continue
        family = snapshot.get("family", 4)
        try:
            target_network = model.destination_index(address)
        except ValueError:
            continue
        covered = False
        for _interface, local_network, _local_address in backend.local_networks(family):
            try:
                if target_network in local_network:
                    covered = True
                    break
            except TypeError:  # pragma: no cover - mixed families
                continue
        if not covered:
            findings.append(
                _finding(
                    SEVERITY_WARN,
                    f"{snapshot.get('name')} 不落在任何本地网段内",
                    f"{address} 不与本机直连网段重叠",
                    "该目标必须经由网关转发，本工具只能保证它不被 VPN 抢走",
                )
            )
    return findings


def _tcp_probe(address, port=22, timeout=1.5):
    """Return ``(reachable, detail)`` for a TCP connect attempt."""
    try:
        parsed = model.normalize_destination(address)[1].rsplit("/", 1)[0]
    except ValueError:
        return None, "无法解析地址"
    try:
        with socket.create_connection((parsed, port), timeout=timeout):
            return True, f"TCP {parsed}:{port} 可连接"
    except socket.timeout:
        return False, f"TCP {parsed}:{port} 超时"
    except OSError as exception:
        return False, f"TCP {parsed}:{port} 失败：{exception}"


def _icmp_probe(address, timeout=2):
    ping = shutil.which("ping")
    if not ping:
        return None, "未安装 ping"
    try:
        parsed = model.normalize_destination(address)[1].rsplit("/", 1)[0]
    except ValueError:
        return None, "无法解析地址"
    try:
        result = subprocess.run(
            [ping, "-c", "1", "-W", str(max(1, int(timeout))), parsed],
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout + 2,
        )
    except (OSError, subprocess.SubprocessError) as exception:
        return None, f"ping 执行失败：{exception}"
    return result.returncode == 0, ("ICMP 可达" if result.returncode == 0 else "ICMP 无响应")


def diagnose_connectivity(report, backend, port=22, probe=True):
    """Optional active probe: does traffic actually reach the target?"""
    findings = []
    if not probe:
        return findings
    for snapshot in report["targets"]:
        if not snapshot.get("enabled"):
            continue
        address = snapshot.get("effective_address") or snapshot.get("address")
        if not address or snapshot.get("prefix", 32) != model.DEFAULT_PREFIXLEN.get(
            snapshot.get("family", 4)
        ):
            # Only probe bare hosts; probing a whole /24 is not meaningful.
            continue
        reachable, detail = _tcp_probe(address, port=port)
        if reachable is None:
            continue
        severity = SEVERITY_OK if reachable else SEVERITY_WARN
        findings.append(
            _finding(
                severity,
                f"{snapshot.get('name')} 连通性探测",
                detail,
                ""
                if reachable
                else f"路由指向 {snapshot.get('current') or '-'}；"
                f"若 TCP 不通但 ICMP 可达，可能是目标主机防火墙或 VPN 侧策略",
            )
        )
    return findings


def diagnose_background(backend):
    """Is something actually keeping the routes alive without user action?"""
    findings = []
    state = read_state()
    if state:
        age = max(0.0, time.time() - float(state.get("updated_at") or 0))
        fresh = age < max(60.0, 3 * float(state.get("interval_seconds") or 10))
        findings.append(
            _finding(
                SEVERITY_OK if fresh else SEVERITY_WARN,
                "后台守护进程状态文件" + ("（新鲜）" if fresh else "（已过期）"),
                f"{state.get('_path')} · {age:.0f}s 前 · reason={state.get('reason')} "
                f"· 模式={state.get('routing_mode')} · 修复={state.get('changed')}",
                "" if fresh else "守护进程可能未运行：systemctl status lan-route-fixer-daemon.service",
            )
        )
    else:
        findings.append(
            _finding(
                SEVERITY_WARN,
                "没有后台守护进程状态",
                "未找到 state.json",
                "启用 `systemctl enable --now lan-route-fixer-daemon.service`，"
                "否则路由只能靠用户手动修复或 30 秒级的 timer",
            )
        )

    timer_active = _systemctl("is-active", "lan-route-fixer.timer")
    daemon_active = _systemctl("is-active", "lan-route-fixer-daemon.service")
    if timer_active:
        findings.append(
            _finding(
                SEVERITY_INFO if daemon_active == "active" else SEVERITY_OK,
                f"systemd timer：{timer_active}",
                "作为兜底仍然有效",
            )
        )
    if daemon_active:
        findings.append(
            _finding(
                SEVERITY_OK if daemon_active == "active" else SEVERITY_WARN,
                f"事件驱动守护进程：{daemon_active}",
                "路由变化后约 0.33 秒内修复（实测）" if daemon_active == "active" else "建议启动它",
            )
        )
    elif shutil.which("systemctl"):
        findings.append(
            _finding(
                SEVERITY_WARN,
                "事件驱动守护进程未激活",
                "systemctl is-active lan-route-fixer-daemon.service = " + str(daemon_active),
                "VPN 连接瞬间到下一次轮询之间存在断网窗口；"
                "启用守护进程可把窗口从最长 30s 降到约 0.33s",
            )
        )
    return findings


def _systemctl(*args):
    if not shutil.which("systemctl"):
        return ""
    try:
        result = subprocess.run(
            ["systemctl", *args],
            capture_output=True,
            check=False,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip()


def diagnose(probe=True, port=22, config_paths=None):
    """Full diagnostic report: environment, routing, background, connectivity."""
    backend = get_backend()
    report = status_report(config_paths=config_paths, backend=backend)
    findings = []
    findings.extend(diagnose_environment(backend))
    findings.extend(diagnose_targets(report, backend))
    findings.extend(diagnose_background(backend))
    findings.extend(diagnose_connectivity(report, backend, port=port, probe=probe))
    findings.sort(key=lambda finding: _SEVERITY_RANK.get(finding["severity"], 9))
    return {
        "findings": findings,
        "status": report,
        "worst": min(
            (_SEVERITY_RANK.get(finding["severity"], 9) for finding in findings),
            default=2,
        ),
        "config_paths": {
            "user": str(CONFIG_PATH),
            "system": str(SYSTEM_CONFIG_PATH),
            "user_exists": os.path.isfile(CONFIG_PATH),
            "system_exists": os.path.isfile(SYSTEM_CONFIG_PATH),
        },
        "events": netlink.available(),
    }


def format_findings(findings, use_color=True):
    """Render findings for a terminal."""
    symbols = {
        SEVERITY_OK: "✓",
        SEVERITY_WARN: "!",
        SEVERITY_FAIL: "✗",
        SEVERITY_INFO: "·",
    }
    colors = {
        SEVERITY_OK: "\033[32m",
        SEVERITY_WARN: "\033[33m",
        SEVERITY_FAIL: "\033[31m",
        SEVERITY_INFO: "\033[36m",
    }
    reset = "\033[0m"
    lines = []
    for finding in findings:
        severity = finding["severity"]
        symbol = symbols.get(severity, "?")
        prefix = colors.get(severity, "") if use_color else ""
        suffix = reset if use_color and prefix else ""
        lines.append(f"{prefix}{symbol}{suffix} {finding['title']}")
        if finding.get("detail"):
            lines.append(f"    {finding['detail']}")
        if finding.get("hint"):
            lines.append(f"    → {finding['hint']}")
    return "\n".join(lines)
