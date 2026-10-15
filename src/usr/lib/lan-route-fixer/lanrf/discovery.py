"""LAN neighbour discovery (ARP/NDP table plus mDNS names).

Both discovery inputs are platform specific: the neighbour table comes from the
backend, the name lookup from Avahi on Linux. The result shape is shared.
"""

import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor

from .backends import get_backend
from .linux import parse_neighbours, run_ip_ok

_AVAHI_CACHE = None


def avahi_resolve_path():
    global _AVAHI_CACHE
    if _AVAHI_CACHE is None:
        _AVAHI_CACHE = shutil.which("avahi-resolve-address") or ""
    return _AVAHI_CACHE


def avahi_resolve(address, timeout=2):
    """Reverse-resolve an address through mDNS; empty string when unknown."""
    executable = avahi_resolve_path()
    if not executable:
        return ""
    try:
        result = subprocess.run(
            [executable, str(address)],
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


def detect_targets(resolve_names=True, backend=None):
    """Discover private IPv4 LAN neighbours from the neighbour table."""
    backend = backend or get_backend()
    output = run_ip_ok("-4", "neigh", "show")
    if not output:
        return []
    discovered = parse_neighbours(output)
    if not discovered or not resolve_names:
        return discovered
    if not avahi_resolve_path():
        return discovered
    workers = max(1, min(8, len(discovered)))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        names = executor.map(avahi_resolve, [target["address"] for target in discovered])
        for target, name in zip(discovered, names):
            if name:
                target["name"] = name
    return discovered
