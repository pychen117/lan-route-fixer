#!/usr/bin/env python3
"""Core, GUI-independent helpers for lan-route-fixer.

This module keeps every route/interface/configuration operation outside the
GTK layer so the same logic can be used by the desktop application, the
command-line tool, and tests.
"""

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

APP_ID = "io.github.pychen117.LanRouteFixer"
APP_DISPLAY_NAME = "局域网路由修复"
APP_DESCRIPTION = "让所选局域网设备绕过 VPN 隧道，保持直连"

CONFIG_HOME = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")).expanduser()
CONFIG_PATH = CONFIG_HOME / "lan-route-fixer/config.json"
AUTOSTART_PATH = CONFIG_HOME / "autostart/lan-route-fixer.desktop"

PACKAGED_HELPER_PATH = "/usr/libexec/lan-route-fixer/lan-route-helper"
# Keep the old path around so upgrades from the initial deskflow package still
# find a helper without reconfiguration.
LEGACY_HELPER_PATHS = (
    "/usr/libexec/deskflow-route-fixer/deskflow-route-helper",
    "/usr/local/libexec/lan-route-helper",
)
HELPER_PATH = os.environ.get("LAN_ROUTE_FIXER_HELPER") or (
    PACKAGED_HELPER_PATH
    if Path(PACKAGED_HELPER_PATH).is_file()
    else next(
        (path for path in LEGACY_HELPER_PATHS if Path(path).is_file()),
        PACKAGED_HELPER_PATH,
    )
)

IP_PATH = os.environ.get("LAN_ROUTE_FIXER_IP") or "/usr/sbin/ip"
PKEXEC_PATH = os.environ.get("LAN_ROUTE_FIXER_PKEXEC") or "/usr/bin/pkexec"
AVAHI_RESOLVE_PATH = shutil.which("avahi-resolve-address")

DEFAULT_CONFIG = {
    "targets": [],
    "interval_seconds": 30,
    "auto_fix": True,
    "autostart": False,
}

PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
ULA_NETWORK = ipaddress.ip_network("fc00::/7")

NEIGH_VALID_STATES = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"}

# Prefixes are a fast fallback. Primary classification uses the link kind
# reported by `ip -d link show`.
VIRTUAL_INTERFACE_PREFIXES = (
    "utun",
    "tun",
    "tap",
    "tailscale",
    "wg",
    "ppp",
    "ipsec",
    "ovpn",
    "zerotier",
    "gpd",
    "proton",
    "mullvad",
    "surfshark",
)
VIRTUAL_LINK_KINDS = {
    "tun",
    "tap",
    "wireguard",
    "veth",
    "dummy",
    "sit",
    "ipip",
    "gre",
    "vti",
    "ip6tnl",
    "macvlan",
    "ipvlan",
    "openvpn",
    "ppp",
    "ifb",
    "xfrm",
    "nlmon",
    "6lowpan",
    "lowpan",
}
# Link kinds that have no /sys/class/net/<iface>/device symlink but are still
# useful L2 exits on many machines.
TRUSTED_LINK_KINDS = {"bridge", "bond", "vlan"}


def run_ip(*args, timeout=5):
    """Run the ip utility and return stdout, or None on any failure."""
    try:
        result = subprocess.run(
            [IP_PATH, *args],
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def valid_private_ipv4(value):
    try:
        address = ipaddress.IPv4Address(str(value).strip())
    except (ipaddress.AddressValueError, ValueError):
        return False
    return any(address in network for network in PRIVATE_NETWORKS)


def valid_private_ipv6(value):
    try:
        address = ipaddress.IPv6Address(str(value).strip())
    except (ipaddress.AddressValueError, ValueError):
        return False
    # ULA and link-local are the reasonable "local" IPv6 families for this tool.
    return address in ULA_NETWORK or address.is_link_local


def parse_ip_or_cidr(value):
    """Return (family, address, prefix) for an IPv4/IPv6 address or CIDR.

    Family is 4 or 6. For a bare address prefix is 32 or 128.
    """
    text = str(value).strip()
    if "/" in text:
        try:
            interface = ipaddress.ip_interface(text)
        except ValueError:
            return None
        family = interface.version
        return family, str(interface.ip), interface.network.prefixlen
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    return address.version, str(address), 32 if address.version == 4 else 128


def valid_local_target(value):
    """True when value is a private IPv4 or ULA/link-local IPv6 address/CIDR."""
    parsed = parse_ip_or_cidr(value)
    if not parsed:
        return False
    family, address, prefix = parsed
    if family == 4:
        return valid_private_ipv4(address)
    return valid_private_ipv6(address)


def get_link_info():
    """Return {interface: {"kind": str, "up": bool}} from `ip -d -o link show`."""
    output = run_ip("-d", "-o", "link", "show")
    if not output:
        return {}
    info = {}
    for line in output.splitlines():
        match = re.match(r"^\d+:\s+([^:]+):\s+<([^>]*)>", line)
        if not match:
            continue
        interface = match.group(1).split("@", 1)[0]
        flags = {flag.upper() for flag in match.group(2).split(",")}
        kind_match = re.search(
            r"\b(wireguard|tun|tap|veth|bridge|bond|vlan|dummy|sit|ipip|gre|vti|ip6tnl|macvlan|ipvlan|openvpn|ppp|ifb|xfrm|nlmon|6lowpan|lowpan)\b",
            line,
            flags=re.IGNORECASE,
        )
        kind = (kind_match.group(1) if kind_match else "").lower()
        info[interface] = {"kind": kind, "up": "UP" in flags}
    return info


def is_virtual_interface(interface, kind=""):
    lower = interface.lower()
    if lower.startswith(VIRTUAL_INTERFACE_PREFIXES):
        return True
    return kind.lower() in VIRTUAL_LINK_KINDS


def is_usable_interface(interface, kind=""):
    """A non-loopback interface that is safe to use as a LAN exit."""
    if interface == "lo":
        return False
    if is_virtual_interface(interface, kind):
        return False
    # Normal physical NICs expose a device symlink. Bridges/bonds/VLANs are
    # virtual but are valid and common LAN exits, so allow them explicitly.
    if (Path("/sys/class/net") / interface / "device").exists():
        return True
    return kind in TRUSTED_LINK_KINDS


def list_usable_interfaces(only_up=False):
    """Return interface names that can carry a local route."""
    info = get_link_info()
    interfaces = []
    for interface, details in info.items():
        if not is_usable_interface(interface, details["kind"]):
            continue
        if only_up and not details["up"]:
            continue
        if interface not in interfaces:
            interfaces.append(interface)
    return interfaces


def get_local_ipv4_networks():
    """Return [(interface, network), ...] for usable IPv4 interfaces."""
    output = run_ip("-4", "-o", "addr", "show", "scope", "global")
    if not output:
        return []
    networks = []
    for line in output.splitlines():
        fields = line.split()
        if "inet" not in fields:
            continue
        index = fields.index("inet")
        if index < 1 or index + 1 >= len(fields):
            continue
        interface = fields[index - 1].split("@", 1)[0]
        try:
            network = ipaddress.ip_interface(fields[index + 1]).network
        except ValueError:
            continue
        if is_usable_interface(interface, get_link_kind(interface)):
            networks.append((interface, network))
    return networks


def get_link_kind(interface):
    return get_link_info().get(interface, {}).get("kind", "")


def get_default_interfaces():
    """Physical/usable interfaces that currently own a default route."""
    output = run_ip("-4", "-o", "route", "show", "default")
    if not output:
        return []
    candidates = []
    seen = set()
    for line in output.splitlines():
        interface_match = re.search(r"\bdev\s+(\S+)", line)
        if not interface_match:
            continue
        interface = interface_match.group(1).split("@", 1)[0]
        if interface in seen or not is_usable_interface(interface, get_link_kind(interface)):
            continue
        metric_match = re.search(r"\bmetric\s+(\d+)", line)
        metric = int(metric_match.group(1)) if metric_match else 0
        seen.add(interface)
        candidates.append((metric, interface))
    return [interface for _, interface in sorted(candidates)]


def get_default_interface():
    """Best default LAN exit: default route first, then any UP usable NIC."""
    default = get_default_interfaces()
    if default:
        return default[0]
    up_interfaces = list_usable_interfaces(only_up=True)
    return up_interfaces[0] if up_interfaces else None


def choose_interface_for_target(target):
    """Pick the interface a target should use.

    target may be an IP address or CIDR string. Prefer an interface whose local
    IPv4 subnet overlaps the target, then the default route interface.
    """
    text = str(target).strip()
    parsed = parse_ip_or_cidr(text)
    if not parsed:
        return None
    family, address, prefix = parsed
    if family != 4:
        return get_default_interface()

    try:
        if "/" in text:
            target_network = ipaddress.ip_network(text, strict=False)
        else:
            target_network = ipaddress.ip_network(f"{address}/32", strict=False)
    except ValueError:
        return None

    for interface, local_network in get_local_ipv4_networks():
        if target_network.overlaps(local_network):
            return interface
    return get_default_interface()


def get_route_info(target):
    """Return (dev, via) currently used to reach target, if resolvable."""
    output = run_ip("route", "get", str(target))
    if not output:
        return None, None
    first = output.splitlines()[0] if output.splitlines() else ""
    dev_match = re.search(r"\bdev\s+(\S+)", first)
    via_match = re.search(r"\bvia\s+(\S+)", first)
    dev = dev_match.group(1).split("@", 1)[0] if dev_match else None
    via = via_match.group(1) if via_match else None
    return dev, via


def avahi_resolve(address, timeout=2):
    if not AVAHI_RESOLVE_PATH:
        return ""
    try:
        result = subprocess.run(
            [AVAHI_RESOLVE_PATH, address],
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if result.returncode != 0:
        return ""
    fields = result.stdout.strip().split(None, 1)
    return fields[1].rstrip(".") if len(fields) == 2 else ""


def detect_targets():
    """Discover private IPv4 LAN neighbours from the neighbour table."""
    output = run_ip("-4", "neigh", "show")
    if not output:
        return []

    discovered = []
    seen = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 4 or "dev" not in fields:
            continue
        address = fields[0]
        interface_index = fields.index("dev") + 1
        if interface_index >= len(fields):
            continue
        interface = fields[interface_index].split("@", 1)[0]
        state = next(
            (field.upper() for field in fields if field.upper() in NEIGH_VALID_STATES),
            "",
        )
        if (
            address in seen
            or not valid_private_ipv4(address)
            or not is_usable_interface(interface, get_link_kind(interface))
            or not state
        ):
            continue
        mac = ""
        if "lladdr" in fields:
            mac_index = fields.index("lladdr") + 1
            if mac_index < len(fields):
                mac = fields[mac_index]
        seen.add(address)
        discovered.append(
            {
                "name": address,
                "address": address,
                "family": 4,
                "interface": interface,
                "mac": mac,
                "state": state,
            }
        )

    if discovered and AVAHI_RESOLVE_PATH:
        workers = min(8, len(discovered))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            names = executor.map(avahi_resolve, [target["address"] for target in discovered])
            for target, name in zip(discovered, names):
                if name:
                    target["name"] = name
    return discovered


def normalize_targets(targets):
    """Normalize and deduplicate a list of user/saved target dicts."""
    normalized = []
    seen = set()
    if not isinstance(targets, list):
        return normalized
    for target in targets:
        if not isinstance(target, dict):
            continue
        address = str(target.get("address", "") or target.get("ip", "")).strip()
        if not address or address in seen:
            continue
        seen.add(address)
        normalized.append(
            {
                "name": str(target.get("name", "")).strip() or address,
                "address": address,
                "interface": str(target.get("interface", "")).strip(),
                "enabled": bool(target.get("enabled", False)),
            }
        )
    return normalized


def load_config(path=None):
    config_path = Path(path) if path else CONFIG_PATH
    config = dict(DEFAULT_CONFIG)
    try:
        with config_path.open(encoding="utf-8") as config_file:
            saved = json.load(config_file)
    except (OSError, json.JSONDecodeError):
        return config
    if not isinstance(saved, dict):
        return config

    for key in ("interval_seconds", "auto_fix", "autostart"):
        if key in saved:
            config[key] = saved[key]
    if "targets" in saved:
        config["targets"] = normalize_targets(saved["targets"])
    else:
        config["targets"] = []
    return config


def save_config(config, path=None):
    config_path = Path(path) if path else CONFIG_PATH
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = config_path.with_suffix(".json.tmp")
        with temporary.open("w", encoding="utf-8") as config_file:
            json.dump(config, config_file, ensure_ascii=False, indent=2)
            config_file.write("\n")
        os.replace(temporary, config_path)
    except OSError:
        return False
    return True


def autostart_content():
    return f"""[Desktop Entry]
Type=Application
Name={APP_DISPLAY_NAME}
Comment={APP_DESCRIPTION}
Exec=/usr/bin/lan-route-fixer
Icon=network-wired
Terminal=false
X-GNOME-Autostart-enabled=true
StartupNotify=false
"""


def apply_autostart(enabled):
    try:
        if enabled:
            AUTOSTART_PATH.parent.mkdir(parents=True, exist_ok=True)
            temporary = AUTOSTART_PATH.with_suffix(".desktop.tmp")
            temporary.write_text(autostart_content(), encoding="utf-8")
            os.replace(temporary, AUTOSTART_PATH)
        else:
            AUTOSTART_PATH.unlink(missing_ok=True)
    except OSError:
        return False
    return True


def resolve_configured_interface(target, default_interface=None):
    """Return the interface a target should be routed through, or None."""
    configured = str(target.get("interface", "")).strip()
    if configured:
        return configured if is_usable_interface(configured, get_link_kind(configured)) else None
    return default_interface or choose_interface_for_target(target.get("address", ""))


def check_targets(config):
    """Return check results for all enabled, valid targets."""
    default_interface = get_default_interface()
    results = []
    for raw in config.get("targets", []):
        target = dict(raw)
        if not target.get("enabled") or not valid_local_target(target.get("address", "")):
            continue
        parsed = parse_ip_or_cidr(target["address"])
        if not parsed:
            continue
        family, address, prefix = parsed
        desired = resolve_configured_interface(target, default_interface)
        current, _ = get_route_info(address)
        results.append(
            {
                "name": target.get("name") or target["address"],
                "address": target["address"],
                "family": family,
                "ip": address,
                "prefix": prefix,
                "interface": desired,
                "desired": desired,
                "current": current,
                "ok": bool(desired and current == desired),
            }
        )
    return results



def _print_check_results(results):
    for result in results:
        state = "ok" if result["ok"] else "bad"
        desired = result["desired"] or "-"
        current = result["current"] or "-"
        print(f"{state}\t{result['address']}\tdesired={desired}\tcurrent={current}")
    return 0 if all(result["ok"] for result in results) else 1


def _find_target_indices(config, query):
    """Return indexes of targets matching an address or name."""
    query = str(query).strip()
    targets = config.get("targets", [])
    return [
        index
        for index, target in enumerate(targets)
        if target.get("address", "").strip() == query
        or str(target.get("name", "")).strip().lower() == query.lower()
    ]


def _print_targets(config, json_output=False):
    targets = config.get("targets", [])
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


def _normalize_interface_arg(value):
    interface = str(value or "").strip()
    return "" if interface.lower() == "auto" else interface


def _valid_interface_choice(interface):
    if not interface:
        return True
    return is_usable_interface(interface, get_link_kind(interface))


def cli_main(argv):
    import argparse

    parser = argparse.ArgumentParser(
        prog="lan-route-fixer",
        description="Keep selected LAN devices on a physical network instead of a VPN tunnel.",
    )
    parser.add_argument("--config", help="path to config.json")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="discover LAN neighbours as JSON")
    scan_parser.add_argument("--pretty", action="store_true", help="pretty-print JSON")

    check_parser = subparsers.add_parser("check", help="check enabled targets")
    check_parser.add_argument("--json", action="store_true", help="output JSON")

    fix_parser = subparsers.add_parser("fix", help="fix all enabled targets")
    fix_parser.add_argument("--quiet", action="store_true", help="only print errors")

    run_parser = subparsers.add_parser("run", help="run foreground monitoring loop")
    run_parser.add_argument("--once", action="store_true", help="check/fix once and exit")

    list_parser = subparsers.add_parser("list", help="list configured targets")
    list_parser.add_argument("--json", action="store_true", help="output JSON")

    add_parser = subparsers.add_parser("add", help="add or update a private LAN target")
    add_parser.add_argument("address", help="private IPv4/IPv6 address or CIDR")
    add_parser.add_argument("--name", help="display name")
    add_parser.add_argument("--interface", help="physical interface, or auto")
    add_parser.add_argument("--disabled", action="store_true", help="add without enabling")

    remove_parser = subparsers.add_parser("remove", help="remove a target by address or name")
    remove_parser.add_argument("query", help="address or name")

    enable_parser = subparsers.add_parser("enable", help="enable a target")
    enable_parser.add_argument("query", help="address or name")

    disable_parser = subparsers.add_parser("disable", help="disable a target")
    disable_parser.add_argument("query", help="address or name")

    set_if_parser = subparsers.add_parser("set-interface", help="set target interface")
    set_if_parser.add_argument("query", help="address or name")
    set_if_parser.add_argument("interface", help="physical interface, or auto")

    args = parser.parse_args(argv)

    if args.command == "scan":
        targets = detect_targets()
        indent = 2 if args.pretty else None
        print(json.dumps(targets, ensure_ascii=False, indent=indent))
        return 0

    config = load_config(args.config)

    if args.command == "check":
        results = check_targets(config)
        if args.json:
            print(json.dumps(results, ensure_ascii=False, indent=2))
            return 0 if all(result["ok"] for result in results) else 1
        return _print_check_results(results)

    if args.command == "list":
        _print_targets(config, getattr(args, "json", False))
        return 0

    if args.command in {"add", "remove", "enable", "disable", "set-interface"}:
        targets = config.setdefault("targets", [])

    if args.command == "add":
        address = args.address.strip()
        if not valid_local_target(address):
            print(f"无效的局域网目标：{address}", file=sys.stderr)
            return 1
        interface = _normalize_interface_arg(args.interface)
        if not _valid_interface_choice(interface):
            print(f"不可用的网卡：{interface}", file=sys.stderr)
            return 1
        target = {
            "name": args.name.strip() if args.name else address,
            "address": address,
            "interface": interface,
            "enabled": not args.disabled,
        }
        indices = _find_target_indices(config, address)
        if indices:
            old = targets[indices[0]]
            old.update(target)
            action = "已更新"
        else:
            targets.append(target)
            action = "已添加"
        if not save_config(config, args.config):
            print("无法保存配置", file=sys.stderr)
            return 1
        state = "启用" if target["enabled"] else "停用"
        print(f"{action}目标：{target['address']}（{state}，网卡：{target['interface'] or '自动'}）")
        return 0

    if args.command in {"remove", "enable", "disable", "set-interface"}:
        indices = _find_target_indices(config, args.query)
        if not indices:
            print(f"未找到目标：{args.query}", file=sys.stderr)
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
        else:  # set-interface
            interface = _normalize_interface_arg(args.interface)
            if not _valid_interface_choice(interface):
                print(f"不可用的网卡：{interface}", file=sys.stderr)
                return 1
            for index in indices:
                targets[index]["interface"] = interface
        if not save_config(config, args.config):
            print("无法保存配置", file=sys.stderr)
            return 1
        print(f"已处理 {len(indices)} 个目标：{args.command} {args.query}")
        return 0

    if args.command == "fix":
        results = check_targets(config)
        to_fix = [result for result in results if result["desired"] and not result["ok"]]
        if not to_fix:
            if not args.quiet:
                print("没有需要修复的目标")
            return 0
        outcome = fix_targets(to_fix, quiet=args.quiet)
        if outcome["return_code"] == 0:
            if not args.quiet:
                print(f"修复完成，共 {len(outcome['items'])} 条路由")
            return 0
        if outcome["return_code"] == 126:
            print("已取消或拒绝授权", file=sys.stderr)
        elif outcome["return_code"] == 127:
            print("无法启动特权 helper（策略可能未加载，请重新登录或重启 polkit）", file=sys.stderr)
        else:
            print(f"修复失败（退出码 {outcome['return_code']}）：{outcome['stderr']}", file=sys.stderr)
        return 1

    if args.command == "run":
        interval = max(5, int(config.get("interval_seconds", 30)))
        while True:
            results = check_targets(config)
            bad = [result for result in results if not result["ok"]]
            if bad and config.get("auto_fix", True):
                to_fix = [result for result in results if result["desired"]]
                if to_fix:
                    fix_targets(to_fix, quiet=True)
            elif bad:
                _print_check_results(bad)
            if args.once:
                return 0 if not bad else 1
            time.sleep(interval)

    parser.print_help()
    return 2

def build_route_items(targets):
    """Convert target dicts into validated helper items."""
    items = []
    for target in targets:
        address = target.get("address") or target.get("ip", "")
        parsed = parse_ip_or_cidr(address)
        if not parsed:
            continue
        family, ip, prefix = parsed
        interface = target.get("interface") or target.get("desired")
        if not interface:
            interface = resolve_configured_interface(target)
        if not interface:
            continue
        items.append(
            {
                "address": f"{ip}/{prefix}",
                "family": family,
                "interface": interface,
            }
        )
    return items


def run_helper(items, use_pkexec=True):
    """Run the privileged helper once for a batch of route items.

    The JSON payload is passed as a command-line argument instead of stdin.
    Some pkexec/PolicyKit combinations do not reliably forward stdin to the
    privileged process, which used to make the helper report exit code 64 even
    though the JSON itself was valid.
    """
    if not items:
        return {"return_code": 0, "stderr": "", "items": []}
    payload = json.dumps(items, ensure_ascii=False, separators=(",", ":"))
    if use_pkexec:
        command = [PKEXEC_PATH, HELPER_PATH, "--batch-json", payload]
    else:
        command = [HELPER_PATH, "--batch-json", payload]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=120,
        )
        return {
            "return_code": result.returncode,
            "stderr": result.stderr.strip(),
            "items": items,
        }
    except OSError as exception:
        return {"return_code": -1, "stderr": str(exception), "items": items}


def fix_targets(targets, quiet=False):
    """Fix targets from user context (uses pkexec)."""
    return run_helper(build_route_items(targets), use_pkexec=True)


def fix_targets_direct(targets):
    """Fix targets as root without pkexec (dispatcher/systemd use only)."""
    return run_helper(build_route_items(targets), use_pkexec=False)


def collect_config_paths():
    """Return system and per-user config paths that currently exist."""
    paths = []
    system_path = Path("/etc/lan-route-fixer/config.json")
    if system_path.is_file():
        paths.append(system_path)
    try:
        import pwd
    except ImportError:
        pwd = None
    if pwd is not None:
        for entry in pwd.getpwall():
            if entry.pw_uid < 1000 and entry.pw_uid != 0:
                continue
            home = entry.pw_dir or ""
            candidate = Path(home) / ".config/lan-route-fixer/config.json"
            if candidate.is_file() and candidate not in paths:
                paths.append(candidate)
    return paths


def collect_all_enabled_targets(require_auto_fix=False):
    """Collect enabled targets from all discovered configs, deduplicated.

    When require_auto_fix is true, configs whose auto_fix setting is false are
    skipped. Background system services use this so a user can turn automatic
    repair off from the GUI and have that setting actually take effect.
    """
    targets = []
    seen = set()
    for path in collect_config_paths():
        config = load_config(path)
        if require_auto_fix and not config.get("auto_fix", True):
            continue
        for target in config.get("targets", []):
            if not target.get("enabled"):
                continue
            address = target.get("address", "")
            if not address or address in seen:
                continue
            seen.add(address)
            targets.append(target)
    return targets


def apply_all_configs():
    """Check every discovered config and repair routes without pkexec.

    Returns a dict with counts for the dispatcher/systemd script to log.
    """
    targets = collect_all_enabled_targets(require_auto_fix=True)
    config = {"targets": targets, "auto_fix": True}
    results = check_targets(config)
    bad = [result for result in results if result["desired"] and not result["ok"]]
    if not bad:
        return {
            "checked": len(results),
            "fixed": 0,
            "failed": 0,
            "return_code": 0,
            "stderr": "",
            "items": [],
        }
    outcome = fix_targets_direct(bad)
    outcome["checked"] = len(results)
    outcome["fixed"] = len(outcome["items"]) if outcome["return_code"] == 0 else 0
    outcome["failed"] = len(outcome["items"]) if outcome["return_code"] != 0 else 0
    return outcome

