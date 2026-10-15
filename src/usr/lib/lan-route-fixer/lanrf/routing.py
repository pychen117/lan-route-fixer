"""Interface selection policy.

Answers one question: *which physical interface should a destination use?*
The rules, in order:

1. An explicitly configured interface, when it is still a usable LAN device.
2. An interface whose local subnet contains/overlaps the destination. This is
   what keeps a bare ``192.168.4.234/32`` on the Wi-Fi NIC that owns
   ``192.168.4.0/24``.
3. The best default-route interface.
4. Any usable interface that is up.

The chosen interface is then *sticky*: once reported, the same answer is
returned until the interface disappears. Without that, a transient routing
change (exactly what a VPN client causes) could make the tool move a LAN route
onto a different NIC and break connectivity in a new way.
"""

import ipaddress

from .backends import get_backend
from .targets import parse_ip_or_cidr


def _network_of(target):
    parsed = parse_ip_or_cidr(target)
    if not parsed:
        return None
    family, address, prefix = parsed
    try:
        return family, ipaddress.ip_network(f"{address}/{prefix}", strict=False)
    except ValueError:
        return None


class InterfaceSelector:
    """Chooses destination interfaces and remembers the previous answer."""

    def __init__(self, backend):
        self.backend = backend
        self._sticky = {}

    def clear(self):
        self._sticky.clear()

    def configured_ok(self, interface):
        interface = str(interface or "").strip()
        if not interface:
            return ""
        if self.backend.is_usable(interface):
            return interface
        return ""

    def pick(self, target, configured="", use_sticky=True):
        """Return the interface for *target*, or ``None`` when none is usable."""
        configured = self.configured_ok(configured)
        if configured:
            self._sticky[target] = configured
            return configured

        parsed = _network_of(target)
        family = parsed[0] if parsed else 4
        target_network = parsed[1] if parsed else None

        if target_network is not None:
            for interface, local_network, _address in self.backend.local_networks(family):
                try:
                    if target_network.overlaps(local_network):
                        self._sticky[target] = interface
                        return interface
                except TypeError:  # pragma: no cover - mixed families
                    continue

        defaults = self.backend.default_interfaces()
        if defaults:
            self._sticky[target] = defaults[0]
            return defaults[0]

        if use_sticky:
            previous = self._sticky.get(target)
            if previous and self.backend.is_usable(previous):
                return previous

        candidates = self.backend.list_interfaces(only_up=True)
        if candidates:
            self._sticky[target] = candidates[0]
            return candidates[0]
        return None

    def forget(self, target):
        self._sticky.pop(target, None)


def sort_targets_by_specificity(targets):
    """Broadest prefix first so a covering route never hides a host route.

    Ordering only affects how a plan reads in logs; the kernel resolves by
    longest prefix match regardless.
    """
    def key(target):
        parsed = parse_ip_or_cidr(target.get("address", ""))
        if not parsed:
            return (1, 0)
        family, _address, prefix = parsed
        return (0, (family, prefix))

    return sorted(targets, key=key)


def choose_interface_for_target(target, backend=None, configured=""):
    """Convenience wrapper: pick the interface for a destination string."""
    backend = backend or get_backend()
    selector = InterfaceSelector(backend)
    return selector.pick(str(target), configured=configured)


def get_default_interface(backend=None):
    """Best default LAN exit, or ``None``."""
    backend = backend or get_backend()
    defaults = backend.default_interfaces()
    if defaults:
        return defaults[0]
    candidates = backend.list_interfaces(only_up=True)
    return candidates[0] if candidates else None

