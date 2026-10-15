"""Windows backend skeleton.

This module exists so the port is a *fill-in* rather than a redesign. It defines
the Windows data structures and the exact API surface a real implementation must
satisfy, and it fails loudly with an actionable message instead of pretending
that routes were installed.

Porting notes
-------------

The Linux backend shells out to ``ip``. On Windows the equivalent operations are
in the IP Helper API (``iphlpapi.dll``) and ``netioapi.h``:

* ``GetIpForwardTable2`` / ``FreeMibTable`` -- enumerate the routing table
  (equivalent to ``ip route show``). Family ``AF_INET`` / ``AF_INET6``.
* ``CreateIpForwardEntry2`` / ``SetIpForwardEntry2`` /
  ``DeleteIpForwardEntry2`` -- install, update and remove a route
  (equivalent to ``ip route replace`` / ``ip route del``).
* ``InitializeIpForwardEntry`` -- fill in sane defaults before mutating a row.
* ``GetIpInterfaceTable`` / ``ConvertInterfaceLuidToNameW`` -- enumerate
  interfaces and map a row's ``InterfaceLuid`` back to a name
  (equivalent to reading ``/sys/class/net``).
* ``GetBestRoute2`` -- resolve the interface a destination currently uses
  (equivalent to ``ip route get``).
* ``NotifyRouteChange2`` -- event-driven route notifications
  (equivalent to the rtnetlink socket in :mod:`lanrf.netlink`). This is the
  Windows counterpart of the latency fix that matters most for the aTrust
  problem.
* ``GetAdaptersAddresses`` -- local addresses and subnet masks, replacing
  ``ip -o addr show``.

Two behavioural differences matter for the reconciler:

1. Windows has a single routing table. There is no policy routing and therefore
   no equivalent of the ``ip rule`` fast path, so ``supports_policy_rules``
   stays ``False``; the event monitor plus metric 0 (``MIB_IPROUTE_METRIC_MINIMUM``
   semantics: lowest metric wins) is the protection against a VPN client that
   inserts more specific routes.
2. ``CreateIpForwardEntry2`` returns ``ERROR_OBJECT_ALREADY_EXISTS`` when the
   destination/protocol/interface tuple already exists, so ``ensure_route`` has
   to fall back to ``SetIpForwardEntry2``.

The privileged side is also different: on Windows the reconciler must run as a
service under ``LocalSystem`` (or with an elevated helper task), because there
is no PolicyKit. :mod:`lanrf.reconcile` does not care *how* it got privileges,
so it can be reused unchanged.
"""

import ctypes
import sys
from ctypes import wintypes

from .backends import NetworkBackend


class LUid(ctypes.Structure):
    """``NET_LUID_LH`` -- 8 bytes, viewed as an integer."""

    _fields_ = [
        ("Value", ctypes.c_ulonglong),
    ]

    @property
    def luid(self):
        return self.Value & 0x00FFFFFFFFFFFFFF

    @property
    def if_index(self):
        return (self.Value >> 48) & 0xFFFF


class SockAddrInet(ctypes.Structure):
    """``SOCKADDR_INET`` -- only the leading family field is interpreted."""

    _fields_ = [
        ("si_family", ctypes.c_ushort),
        ("raw", ctypes.c_ubyte * 26),
    ]


class IpAddressPrefix(ctypes.Structure):
    """``IP_ADDRESS_PREFIX``."""

    _fields_ = [
        ("Prefix", SockAddrInet),
        ("PrefixLength", ctypes.c_ubyte),
    ]


class IpForwardRow2(ctypes.Structure):
    """``MIB_IPFORWARD_ROW2`` (Windows 8 / Server 2012 and newer)."""

    _fields_ = [
        ("InterfaceLuid", LUid),
        ("InterfaceIndex", wintypes.DWORD),
        ("DestinationPrefix", IpAddressPrefix),
        ("NextHop", SockAddrInet),
        ("SitePrefixLength", ctypes.c_ubyte),
        ("ValidLifetime", wintypes.DWORD),
        ("PreferredLifetime", wintypes.DWORD),
        ("Metric", wintypes.DWORD),
        ("Protocol", wintypes.DWORD),
        ("Loopback", ctypes.c_ubyte),
        ("AutoconfigureAddress", ctypes.c_ubyte),
        ("Publish", ctypes.c_ubyte),
        ("Immortal", ctypes.c_ubyte),
        ("Age", wintypes.DWORD),
        ("Origin", ctypes.c_ubyte),
    ]


# Value used by `route add -p`-style persistent entries; kept for parity with
# the Linux ROUTE_PROTOCOL stamp so garbage collection can recognise our rows.
MIB_IPPROTO_NETMGMT = 3


class WindowsBackend(NetworkBackend):
    """Skeleton backend: queries return empty results, mutations refuse."""

    name = "windows"
    supports_policy_rules = False
    supports_events = True  # available via NotifyRouteChange2 once implemented
    _implemented = False

    def __init__(self):
        if not sys.platform.startswith("win"):  # pragma: no cover - Linux runs
            self.platform = sys.platform
        self.platform = sys.platform
        self._iphlpapi = None
        if self._implemented:
            self._iphlpapi = ctypes.WinDLL("iphlpapi.dll")

    def _refuse(self, *_args, **_kwargs):
        raise NotImplementedError(
            "the Windows network backend is not implemented yet; "
            "see lanrf/windows.py for the IP Helper API mapping"
        )

    # -- queries ------------------------------------------------------------

    def link_kind(self, _interface):
        return ""

    def is_usable(self, _interface):
        return sys.platform.startswith("win")

    def list_interfaces(self, only_up=False):
        return []

    def local_networks(self, family=4):
        return []

    def default_interfaces(self):
        return []

    def route_lookup(self, _destination, family=4):
        return None

    def routes(self, table="main", family=4):
        return []

    def route_prefixes(self, table="main", family=4):
        return set()

    def rules(self, family=4):
        return []

    # -- mutations ----------------------------------------------------------

    ensure_route = _refuse
    remove_route = _refuse
    ensure_rule = _refuse
    remove_rule = _refuse
