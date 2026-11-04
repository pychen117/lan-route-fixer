"""ctypes bindings for the Windows IP Helper API.

The rest of the package never imports ``ctypes`` directly: this module is the
only place that knows the ``MIB_IPFORWARD_ROW2`` layout, the difference between
``SOCKADDR_IN`` and ``SOCKADDR_INET``, and how the IP Helper functions report
errors.  :mod:`lanrf.windows` turns the plain dicts returned here into the
backend contract, so the reconciler stays platform independent.

Importing this module must work on Linux (the test suite runs there), therefore
the DLLs are loaded lazily: nothing below touches ``iphlpapi.dll`` until a
function is actually called.  Only plain ``ctypes`` structure definitions -- and
the layout constants derived from them -- exist at import time.

Layout notes that cost real debugging time
------------------------------------------

``SOCKADDR_INET`` is a union of ``SOCKADDR_IN`` (16 bytes) and ``SOCKADDR_IN6``
(28 bytes).  Declaring it as ``(ushort, c_ubyte * 26)`` looks equivalent but is
not: the 26-byte tail gives the struct alignment 2, so every containing struct
shifts by two bytes.  The explicit field list below keeps alignment 4, which is
what makes ``IP_ADDRESS_PREFIX`` 32 bytes and ``MIB_IPFORWARD_ROW2`` 104 bytes.

``GetUnicastIpAddressTable`` is bound for completeness, but the backend sources
unicast addresses from ``GetAdaptersAddresses`` instead: on the Windows 11 build
this port was developed against, the table rows came back with an 80-byte stride
whose fields did not match ``MIB_UNICASTIPADDRESS_ROW`` (the documented 64-byte
struct), so reading it would have returned garbage.  ``GetAdaptersAddresses``
returns the same addresses plus ``OnLinkPrefixLength`` and was verified on that
machine.

Every function that calls into Windows raises ``OSError(winerror, message)`` on
a non-zero return code; ``message`` is the system text for that code when it can
be resolved, never a bare number.
"""

import ctypes
import ipaddress
import sys

# --- plain data types -------------------------------------------------------
#
# Do not use ``ctypes.c_ulong``/``wintypes.DWORD`` for the layout: on LP64
# non-Windows hosts ``c_ulong`` is 8 bytes, which would change every struct size
# the tests assert.  Fixed-width types keep the layout identical on every host.

DWORD = ctypes.c_uint32            # ULONG / DWORD / NET_IFINDEX
ULONG = ctypes.c_uint32
UINT8 = ctypes.c_uint8
BOOLEAN = ctypes.c_uint8
NET_IFINDEX = ctypes.c_uint32
NET_LUID_VALUE = ctypes.c_uint64

AF_UNSPEC = 0
AF_INET = 2
AF_INET6 = 23

ERROR_SUCCESS = 0
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_PARAMETER = 87
ERROR_NOT_SUPPORTED = 50
ERROR_BUFFER_OVERFLOW = 111
ERROR_NOT_FOUND = 1168
ERROR_OBJECT_ALREADY_EXISTS = 5010

# GetAdaptersAddresses flags (ipifcons.h)
GAA_FLAG_SKIP_UNICAST = 0x0001
GAA_FLAG_SKIP_ANYCAST = 0x0002
GAA_FLAG_SKIP_MULTICAST = 0x0004
GAA_FLAG_SKIP_DNS_SERVER = 0x0008
GAA_FLAG_INCLUDE_PREFIX = 0x0010
GAA_FLAG_SKIP_FRIENDLY_NAME = 0x0020
GAA_FLAG_INCLUDE_WINS_INFO = 0x0040
GAA_FLAG_INCLUDE_GATEWAYS = 0x0080
GAA_FLAG_INCLUDE_ALL_INTERFACES = 0x0100

# IFTYPE values (ipifcons.h).  ``IF_TYPE_TUNNEL`` is 53 on purpose: the task's
# classification uses 53 for the proprietary virtual adapters VPN clients create
# (aTrustVNIC, Tailscale, et_10_o12v all report 53 here).  ``IF_TYPE_IP_TUNNEL``
# is the older native tunnel type and is treated the same way.
IF_TYPE_OTHER = 1
IF_TYPE_ETHERNET_CSMACD = 6
IF_TYPE_PPP = 23
IF_TYPE_SOFTWARE_LOOPBACK = 24
IF_TYPE_ATM = 37
IF_TYPE_TUNNEL = 53
IF_TYPE_IEEE80211 = 71
IF_TYPE_IP_TUNNEL = 131
IF_TYPE_IEEE80216WMAN = 237

TUNNEL_IF_TYPES = frozenset({IF_TYPE_TUNNEL, IF_TYPE_IP_TUNNEL, IF_TYPE_PPP})

# MIB_IPPROTO_* values (iprtrmib.h)
MIB_IPPROTO_OTHER = 1
MIB_IPPROTO_LOCAL = 2
MIB_IPPROTO_NETMGMT = 3
MIB_IPPROTO_ICMP = 4

# "never expires" for MIB_IPFORWARD_ROW2 lifetimes (netioapi.h).
INFINITE_LIFETIME = 0xFFFFFFFF

# Rows of a MIB_*_TABLE2 start after the ULONG NumEntries and the padding needed
# to align the row (64-bit: NumEntries at 0, Table at 8).
TABLE_ROW_OFFSET = 8

FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200


# --- structures -------------------------------------------------------------


class LUID(ctypes.Structure):
    """``NET_LUID_LH`` -- the 64-bit interface identifier."""

    _fields_ = [("Value", NET_LUID_VALUE)]

    @property
    def luid(self):
        return self.Value & 0x00FFFFFFFFFFFFFF

    @property
    def if_index(self):
        return (self.Value >> 48) & 0xFFFF


class SOCKADDR_INET(ctypes.Structure):
    """The 28-byte union, laid out explicitly so its alignment is 4.

    ``si_family`` occupies the first two bytes.  For ``AF_INET`` the address
    bytes start at offset 4 (``sin_port`` is two bytes) and for ``AF_INET6`` at
    offset 8 (``sin6_port`` + ``sin6_flowinfo``), which is what the extraction
    helpers below rely on.
    """

    _fields_ = [
        ("si_family", ctypes.c_uint16),
        ("sin6_port", ctypes.c_uint16),
        ("sin6_flowinfo", ctypes.c_uint32),
        ("sin6_addr", ctypes.c_uint8 * 16),
        ("sin6_scope_id", ctypes.c_uint32),
    ]


# The two offsets an address extractor must use.  Kept as module constants
# because tests assert them and because they document why a naive ``+2`` read
# of the payload is wrong.
SOCKADDR_ADDR_V4 = 4
SOCKADDR_ADDR_V6 = 8


class IP_ADDRESS_PREFIX(ctypes.Structure):
    """``IP_ADDRESS_PREFIX`` -- address plus mask length."""

    _fields_ = [
        ("Prefix", SOCKADDR_INET),
        ("PrefixLength", UINT8),
    ]


class MIB_IPFORWARD_ROW2(ctypes.Structure):
    """``MIB_IPFORWARD_ROW2`` -- one routing table row (Windows 8+)."""

    _fields_ = [
        ("InterfaceLuid", LUID),
        ("InterfaceIndex", NET_IFINDEX),
        ("DestinationPrefix", IP_ADDRESS_PREFIX),
        ("NextHop", SOCKADDR_INET),
        ("SitePrefixLength", UINT8),
        ("ValidLifetime", ULONG),
        ("PreferredLifetime", ULONG),
        ("Metric", ULONG),
        ("Protocol", ULONG),
        ("Loopback", BOOLEAN),
        ("AutoconfigureAddress", BOOLEAN),
        ("Publish", BOOLEAN),
        ("Immortal", BOOLEAN),
        ("Age", ULONG),
        ("Origin", ULONG),
    ]


class MIB_IPFORWARD_TABLE2(ctypes.Structure):
    """Header of the table returned by ``GetIpForwardTable2``."""

    _fields_ = [
        ("NumEntries", ULONG),
        ("Table", MIB_IPFORWARD_ROW2 * 1),
    ]


class MIB_UNICASTIPADDRESS_ROW(ctypes.Structure):
    """``MIB_UNICASTIPADDRESS_ROW`` -- documented 64-byte layout.

    Defined for layout parity and for callers that really want the row type;
    :func:`get_unicast_addresses` uses the adapters API instead (see the module
    docstring for the observed reason).
    """

    _fields_ = [
        ("InterfaceLuid", LUID),
        ("InterfaceIndex", NET_IFINDEX),
        ("Address", SOCKADDR_INET),
        ("PrefixLength", UINT8),
        ("DadState", ULONG),
        ("ValidLifetime", ULONG),
        ("PreferredLifetime", ULONG),
        ("LeaseLifetime", ULONG),
        ("OnLinkPrefixLength", UINT8),
    ]


class MIB_UNICASTIPADDRESS_TABLE2(ctypes.Structure):
    _fields_ = [
        ("NumEntries", ULONG),
        ("Table", MIB_UNICASTIPADDRESS_ROW * 1),
    ]


class SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [
        ("lpSockaddr", ctypes.c_void_p),
        ("iSockaddrLength", ctypes.c_int),
    ]


class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    """``IP_ADAPTER_UNICAST_ADDRESS_LH`` including ``OnLinkPrefixLength``.

    The probe used the pre-Vista field list (ending at ``LeaseLifetime``); the
    length byte after it is what makes the subnet mask recoverable without
    parsing the prefix chain, and it verified as ``OnLinkPrefixLength`` on this
    machine (WLAN /24, Tailscale /32, loopback /8).
    """

    pass


IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ("Length", ULONG),
    ("Flags", DWORD),
    ("Next", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ("Address", SOCKET_ADDRESS),
    ("PrefixOrigin", ULONG),
    ("SuffixOrigin", ULONG),
    ("DadState", ULONG),
    ("ValidLifetime", ULONG),
    ("PreferredLifetime", ULONG),
    ("LeaseLifetime", ULONG),
    ("OnLinkPrefixLength", UINT8),
]


class IP_ADAPTER_PREFIX(ctypes.Structure):
    """``IP_ADAPTER_PREFIX_XP`` -- one entry of the adapter's prefix chain."""

    pass


IP_ADAPTER_PREFIX._fields_ = [
    ("Length", ULONG),
    ("Flags", DWORD),
    ("Next", ctypes.POINTER(IP_ADAPTER_PREFIX)),
    ("Address", SOCKET_ADDRESS),
    ("PrefixLength", ULONG),
]


class IP_ADAPTER_ADDRESSES(ctypes.Structure):
    """``IP_ADAPTER_ADDRESSES_LH`` up to (and including) ``FirstPrefix``.

    The struct Windows defines continues after ``FirstPrefix`` (link speeds,
    zone names, ...), but the layout up to that pointer is what the backend
    reads; ``ctypes.sizeof`` of this prefix is 184, matching the documented
    Windows layout for the fields in use.
    """

    pass


IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length", ULONG),
    ("IfIndex", DWORD),
    ("Next", ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ("FirstAnycastAddress", ctypes.c_void_p),
    ("FirstMulticastAddress", ctypes.c_void_p),
    ("FirstDnsServerAddress", ctypes.c_void_p),
    ("DnsSuffix", ctypes.c_wchar_p),
    ("Description", ctypes.c_wchar_p),
    ("FriendlyName", ctypes.c_wchar_p),
    ("PhysicalAddress", ctypes.c_uint8 * 8),
    ("PhysicalAddressLength", ULONG),
    ("Flags", DWORD),
    ("Mtu", ULONG),
    ("IfType", ULONG),
    ("OperStatus", DWORD),
    ("Ipv6IfIndex", DWORD),
    ("ZoneIndices", ULONG * 16),
    ("FirstPrefix", ctypes.POINTER(IP_ADAPTER_PREFIX)),
]


# --- layout facts (asserted by tests, also useful in doctor output) ---------

SOCKADDR_INET_SIZE = ctypes.sizeof(SOCKADDR_INET)
IP_ADDRESS_PREFIX_SIZE = ctypes.sizeof(IP_ADDRESS_PREFIX)
MIB_IPFORWARD_ROW2_SIZE = ctypes.sizeof(MIB_IPFORWARD_ROW2)
MIB_UNICASTIPADDRESS_ROW_SIZE = ctypes.sizeof(MIB_UNICASTIPADDRESS_ROW)
IP_ADAPTER_ADDRESSES_SIZE = ctypes.sizeof(IP_ADAPTER_ADDRESSES)
IP_ADAPTER_PREFIX_SIZE = ctypes.sizeof(IP_ADAPTER_PREFIX)
IP_ADAPTER_UNICAST_ADDRESS_SIZE = ctypes.sizeof(IP_ADAPTER_UNICAST_ADDRESS)

OFFSET_NEXT_HOP = MIB_IPFORWARD_ROW2.NextHop.offset
OFFSET_METRIC = MIB_IPFORWARD_ROW2.Metric.offset
OFFSET_PROTOCOL = MIB_IPFORWARD_ROW2.Protocol.offset
OFFSET_ORIGIN = MIB_IPFORWARD_ROW2.Origin.offset

LAYOUT = {
    "sockaddr_inet": SOCKADDR_INET_SIZE,
    "ip_address_prefix": IP_ADDRESS_PREFIX_SIZE,
    "mib_ipforward_row2": MIB_IPFORWARD_ROW2_SIZE,
    "mib_unicastipaddress_row": MIB_UNICASTIPADDRESS_ROW_SIZE,
    "ip_adapter_addresses": IP_ADAPTER_ADDRESSES_SIZE,
    "ip_adapter_prefix": IP_ADAPTER_PREFIX_SIZE,
    "ip_adapter_unicast_address": IP_ADAPTER_UNICAST_ADDRESS_SIZE,
    "offset_next_hop": OFFSET_NEXT_HOP,
    "offset_metric": OFFSET_METRIC,
    "offset_protocol": OFFSET_PROTOCOL,
    "offset_origin": OFFSET_ORIGIN,
    "sockaddr_addr_v4": SOCKADDR_ADDR_V4,
    "sockaddr_addr_v6": SOCKADDR_ADDR_V6,
}

# True when the definitions above still have the layout the port depends on.
# Computed rather than hard-coded so a ctypes/ABI change turns into a visible
# ``False`` instead of silent corruption.
LAYOUT_OK = bool(
    SOCKADDR_INET_SIZE == 28
    and IP_ADDRESS_PREFIX_SIZE == 32
    and MIB_IPFORWARD_ROW2_SIZE == 104
    and MIB_UNICASTIPADDRESS_ROW_SIZE == 64
    and IP_ADAPTER_ADDRESSES_SIZE == 184
    and IP_ADAPTER_PREFIX_SIZE == 40
    and IP_ADAPTER_UNICAST_ADDRESS_SIZE == 64
    and OFFSET_NEXT_HOP == 44
    and OFFSET_METRIC == 84
    and OFFSET_PROTOCOL == 88
    and OFFSET_ORIGIN == 100
)


# --- lazy DLL loading -------------------------------------------------------

_IPHLPAPI = None
_KERNEL32 = None
_SHELL32 = None
_ERROR_TEXT = {}


def _require_windows():
    if not sys.platform.startswith("win"):
        raise OSError(
            "the Windows IP Helper API (iphlpapi.dll) is only available on Windows"
        )


def _bind(function, restype, *argtypes):
    function.restype = restype
    function.argtypes = list(argtypes)
    return function


def _iphlpapi():
    """Return the bound iphlpapi function table, loading the DLL on first use."""
    _require_windows()
    global _IPHLPAPI
    if _IPHLPAPI is None:
        lib = ctypes.WinDLL("iphlpapi.dll")
        _IPHLPAPI = {
            "GetIpForwardTable2": _bind(
                lib.GetIpForwardTable2, ULONG, ctypes.c_uint16, ctypes.POINTER(ctypes.c_void_p)
            ),
            "GetUnicastIpAddressTable": _bind(
                lib.GetUnicastIpAddressTable, ULONG, ctypes.c_uint16, ctypes.POINTER(ctypes.c_void_p)
            ),
            "FreeMibTable": _bind(lib.FreeMibTable, None, ctypes.c_void_p),
            "InitializeIpForwardEntry": _bind(
                lib.InitializeIpForwardEntry, None, ctypes.POINTER(MIB_IPFORWARD_ROW2)
            ),
            "CreateIpForwardEntry2": _bind(
                lib.CreateIpForwardEntry2, ULONG, ctypes.POINTER(MIB_IPFORWARD_ROW2)
            ),
            "SetIpForwardEntry2": _bind(
                lib.SetIpForwardEntry2, ULONG, ctypes.POINTER(MIB_IPFORWARD_ROW2)
            ),
            "DeleteIpForwardEntry2": _bind(
                lib.DeleteIpForwardEntry2, ULONG, ctypes.POINTER(MIB_IPFORWARD_ROW2)
            ),
            "GetBestRoute2": _bind(
                lib.GetBestRoute2,
                ULONG,
                ctypes.c_void_p,
                NET_IFINDEX,
                ctypes.c_void_p,
                ctypes.POINTER(SOCKADDR_INET),
                ULONG,
                ctypes.POINTER(MIB_IPFORWARD_ROW2),
                ctypes.POINTER(SOCKADDR_INET),
            ),
            "GetAdaptersAddresses": _bind(
                lib.GetAdaptersAddresses,
                ULONG,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.POINTER(IP_ADAPTER_ADDRESSES),
                ctypes.POINTER(ULONG),
            ),
            "ConvertInterfaceIndexToLuid": _bind(
                lib.ConvertInterfaceIndexToLuid, ULONG, NET_IFINDEX, ctypes.POINTER(LUID)
            ),
            "ConvertInterfaceLuidToNameW": _bind(
                lib.ConvertInterfaceLuidToNameW,
                ULONG,
                ctypes.POINTER(LUID),
                ctypes.c_wchar_p,
                ctypes.c_size_t,
            ),
        }
    return _IPHLPAPI


def _kernel32():
    global _KERNEL32
    if _KERNEL32 is None:
        lib = ctypes.WinDLL("kernel32.dll")
        _KERNEL32 = {
            "FormatMessageW": _bind(
                lib.FormatMessageW,
                ULONG,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_wchar_p,
                ctypes.c_uint32,
                ctypes.c_void_p,
            )
        }
    return _KERNEL32


def _shell32():
    global _SHELL32
    if _SHELL32 is None:
        lib = ctypes.WinDLL("shell32.dll")
        _SHELL32 = {"IsUserAnAdmin": _bind(lib.IsUserAnAdmin, ctypes.c_int)}
    return _SHELL32


def format_error(code):
    """Return the system text for a Windows error code (best effort)."""
    code = int(code)
    cached = _ERROR_TEXT.get(code)
    if cached is not None:
        return cached
    text = ""
    if sys.platform.startswith("win"):
        try:
            buffer = ctypes.create_unicode_buffer(1024)
            length = _kernel32()["FormatMessageW"](
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                None,
                code,
                0,
                buffer,
                len(buffer),
                None,
            )
            if length:
                text = " ".join(buffer.value.split())
        except OSError:  # pragma: no cover - FormatMessage is always present
            text = ""
    if not text:
        text = f"Windows error {code}"
    _ERROR_TEXT[code] = text
    return text


def _check(return_code, context=""):
    """Raise a readable ``OSError`` for a non-zero IP Helper return code."""
    if return_code == ERROR_SUCCESS:
        return
    message = format_error(return_code)
    if context:
        message = f"{context}: {message}"
    raise OSError(int(return_code), message)


# --- address helpers --------------------------------------------------------


def sockaddr_from_ip(address):
    """Build a ``SOCKADDR_INET`` for an IPv4 or IPv6 address string."""
    value = (
        address
        if isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address))
        else ipaddress.ip_address(str(address))
    )
    sockaddr = SOCKADDR_INET()
    if value.version == 4:
        sockaddr.si_family = AF_INET
        offset, packed = SOCKADDR_ADDR_V4, value.packed
    else:
        sockaddr.si_family = AF_INET6
        offset, packed = SOCKADDR_ADDR_V6, value.packed
    ctypes.memmove(ctypes.addressof(sockaddr) + offset, packed, len(packed))
    return sockaddr


def ip_from_sockaddr(sockaddr):
    """Return the ``ipaddress`` object inside a ``SOCKADDR_INET``, or ``None``."""
    if sockaddr is None:
        return None
    family = int(sockaddr.si_family)
    base = ctypes.addressof(sockaddr)
    if family == AF_INET:
        return ipaddress.IPv4Address(ctypes.string_at(base + SOCKADDR_ADDR_V4, 4))
    if family == AF_INET6:
        return ipaddress.IPv6Address(ctypes.string_at(base + SOCKADDR_ADDR_V6, 16))
    return None


def sockaddr_text(sockaddr):
    """Human readable address of a ``SOCKADDR_INET`` (empty when unknown)."""
    value = ip_from_sockaddr(sockaddr)
    return str(value) if value is not None else ""


def _prefix_text(prefix):
    value = ip_from_sockaddr(prefix.Prefix)
    if value is None:
        return ""
    return f"{value}/{int(prefix.PrefixLength)}"


def _parse_destination(destination, family=None):
    """Return an ``ip_network`` for ``address`` or ``address/prefix``."""
    text = str(destination or "").strip()
    if not text:
        raise ValueError("empty destination")
    if "/" in text:
        parsed = ipaddress.ip_interface(text)
    else:
        address = ipaddress.ip_address(text)
        parsed = ipaddress.ip_interface(
            f"{address}/{32 if address.version == 4 else 128}"
        )
    if family is not None and parsed.version != int(family):
        raise ValueError(
            f"destination {text!r} is IPv{parsed.version}, expected IPv{int(family)}"
        )
    return parsed.network


def _forward_row_dict(row):
    """Translate a ``MIB_IPFORWARD_ROW2`` into a plain dict."""
    destination = ip_from_sockaddr(row.DestinationPrefix.Prefix)
    prefix_length = int(row.DestinationPrefix.PrefixLength)
    next_hop = ip_from_sockaddr(row.NextHop)
    return {
        "destination": str(destination) if destination is not None else "",
        "prefix": f"{destination}/{prefix_length}" if destination is not None else "",
        "prefix_length": prefix_length,
        "next_hop": str(next_hop) if next_hop is not None else "",
        "interface_index": int(row.InterfaceIndex),
        "interface_luid": int(row.InterfaceLuid.Value),
        "metric": int(row.Metric),
        "protocol": int(row.Protocol),
        "origin": int(row.Origin),
        "age": int(row.Age),
        "valid_lifetime": int(row.ValidLifetime),
        "preferred_lifetime": int(row.PreferredLifetime),
        "loopback": bool(row.Loopback),
        "immortal": bool(row.Immortal),
    }


# --- routing table ----------------------------------------------------------


def get_forward_table(family=AF_INET):
    """Return the routing table of *family* as a list of plain dicts.

    Keys: ``destination``, ``prefix``, ``prefix_length``, ``next_hop``,
    ``interface_index``, ``interface_luid``, ``metric``, ``protocol``,
    ``origin``, ``age``, ``valid_lifetime``, ``preferred_lifetime``,
    ``loopback`` and ``immortal``.
    """
    table = ctypes.c_void_p()
    _check(
        _iphlpapi()["GetIpForwardTable2"](int(family), ctypes.byref(table)),
        "GetIpForwardTable2",
    )
    try:
        count = int(ctypes.cast(table, ctypes.POINTER(ULONG)).contents.value)
        base = table.value + TABLE_ROW_OFFSET
        rows = []
        for index in range(count):
            row = MIB_IPFORWARD_ROW2.from_address(
                base + index * MIB_IPFORWARD_ROW2_SIZE
            )
            rows.append(_forward_row_dict(row))
        return rows
    finally:
        _iphlpapi()["FreeMibTable"](table)


def get_best_route_detail(destination, family=None):
    """Resolve *destination* with ``GetBestRoute2`` and return the full result.

    Returns the same keys as :func:`get_forward_table` plus ``source`` (the
    preferred local address chosen for the flow).  ``GetBestRoute2`` ignores a
    requested table: Windows has exactly one routing table.
    """
    network = _parse_destination(destination, family=family)
    dest = sockaddr_from_ip(network.network_address)
    best = MIB_IPFORWARD_ROW2()
    source = SOCKADDR_INET()
    _check(
        _iphlpapi()["GetBestRoute2"](
            None,
            0,
            None,
            ctypes.byref(dest),
            0,
            ctypes.byref(best),
            ctypes.byref(source),
        ),
        f"GetBestRoute2({destination})",
    )
    detail = _forward_row_dict(best)
    detail["source"] = sockaddr_text(source)
    return detail


def get_best_route(destination, family=None):
    """Return ``(interface_index, next_hop)`` for *destination*."""
    detail = get_best_route_detail(destination, family=family)
    return detail["interface_index"], detail["next_hop"]


# --- adapters ---------------------------------------------------------------


def _adapters_buffer(family=AF_UNSPEC):
    """Call GetAdaptersAddresses, growing the buffer on ERROR_BUFFER_OVERFLOW."""
    flags = (
        GAA_FLAG_INCLUDE_PREFIX
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER
    )
    size = ULONG(30000)
    for _attempt in range(5):
        buffer = ctypes.create_string_buffer(size.value)
        return_code = _iphlpapi()["GetAdaptersAddresses"](
            int(family),
            flags,
            None,
            ctypes.cast(buffer, ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
            ctypes.byref(size),
        )
        if return_code == ERROR_SUCCESS:
            return buffer
        if return_code != ERROR_BUFFER_OVERFLOW:
            _check(return_code, "GetAdaptersAddresses")
        # size now holds the required buffer length; retry with it.
        if size.value == 0:  # pragma: no cover - defensive
            _check(ERROR_BUFFER_OVERFLOW, "GetAdaptersAddresses")
    _check(ERROR_BUFFER_OVERFLOW, "GetAdaptersAddresses")
    return None  # pragma: no cover - unreachable


def _unicast_records(adapter):
    """Flatten one adapter's unicast address chain into dicts."""
    records = []
    current = adapter.FirstUnicastAddress
    while current:
        entry = current.contents
        if not entry.Address.lpSockaddr:
            current = entry.Next
            continue
        sockaddr = ctypes.cast(
            entry.Address.lpSockaddr, ctypes.POINTER(SOCKADDR_INET)
        ).contents
        address = ip_from_sockaddr(sockaddr)
        if address is not None:
            prefix_length = int(entry.OnLinkPrefixLength)
            if prefix_length <= 0:
                prefix_length = 32 if address.version == 4 else 128
            network = ipaddress.ip_network(
                f"{address}/{prefix_length}", strict=False
            )
            records.append(
                {
                    "interface_index": int(adapter.IfIndex),
                    "interface": adapter.FriendlyName or "",
                    "address": str(address),
                    "family": address.version,
                    "prefix_length": prefix_length,
                    "prefix": f"{network.network_address}/{network.prefixlen}",
                    "prefix_origin": int(entry.PrefixOrigin),
                    "suffix_origin": int(entry.SuffixOrigin),
                    "dad_state": int(entry.DadState),
                    "valid_lifetime": int(entry.ValidLifetime),
                    "preferred_lifetime": int(entry.PreferredLifetime),
                    "lease_lifetime": int(entry.LeaseLifetime),
                    "flags": int(entry.Flags),
                }
            )
        current = entry.Next
    return records


def _prefix_records(adapter):
    """Return the adapter's prefix chain as ``["192.168.4.0/24", ...]``."""
    prefixes = []
    current = adapter.FirstPrefix
    while current:
        entry = current.contents
        if entry.Address.lpSockaddr:
            sockaddr = ctypes.cast(
                entry.Address.lpSockaddr, ctypes.POINTER(SOCKADDR_INET)
            ).contents
            address = ip_from_sockaddr(sockaddr)
            if address is not None:
                prefixes.append(f"{address}/{int(entry.PrefixLength)}")
        current = entry.Next
    return prefixes


def _adapter_records(family=AF_UNSPEC):
    """Return every adapter (including down/loopback ones) as plain dicts."""
    buffer = _adapters_buffer(family)
    records = []
    pointer = ctypes.cast(buffer, ctypes.POINTER(IP_ADAPTER_ADDRESSES))
    while pointer:
        adapter = pointer.contents
        records.append(
            {
                "ifindex": int(adapter.IfIndex),
                "name": adapter.FriendlyName or "",
                "description": adapter.Description or "",
                "iftype": int(adapter.IfType),
                "oper_status": int(adapter.OperStatus),
                "mtu": int(adapter.Mtu),
                "unicast": _unicast_records(adapter),
                "prefixes": _prefix_records(adapter),
            }
        )
        pointer = adapter.Next
    return records


def get_adapters(family=None):
    """Return every adapter with its addresses and prefixes.

    ``family`` defaults to ``AF_UNSPEC`` (IPv4 and IPv6).  Every entry has
    ``ifindex``, ``name``, ``description``, ``iftype``, ``oper_status``,
    ``addresses`` (list of strings), ``prefixes`` (list of CIDR strings) and
    ``unicast`` (the structured records behind :func:`get_unicast_addresses`).
    Down adapters are included on purpose: the backend needs them to report
    tunnel adapters and to filter ``list_interfaces``.
    """
    wanted = AF_UNSPEC if family is None else int(family)
    adapters = []
    for record in _adapter_records(wanted):
        unicast = record["unicast"]
        adapters.append(
            {
                "ifindex": record["ifindex"],
                "name": record["name"],
                "description": record["description"],
                "iftype": record["iftype"],
                "oper_status": record["oper_status"],
                "mtu": record["mtu"],
                "addresses": [entry["address"] for entry in unicast],
                "prefixes": list(record["prefixes"]),
                "unicast": list(unicast),
            }
        )
    return adapters


def get_unicast_addresses(family=AF_INET):
    """Return local unicast addresses as plain dicts.

    Sourced from ``GetAdaptersAddresses`` (see the module docstring for why the
    unicast table is not used).  Each dict carries ``interface_index``,
    ``interface``, ``address``, ``family``, ``prefix_length``, ``prefix`` and the
    prefix/suffix/DAD origin details.
    """
    wanted = int(family)
    if wanted == AF_UNSPEC:
        versions = {4, 6}
    elif wanted == AF_INET:
        versions = {4}
    else:
        versions = {6}
    addresses = []
    for adapter in _adapter_records(wanted):
        for entry in adapter["unicast"]:
            if entry["family"] in versions:
                addresses.append(dict(entry))
    return addresses


# --- LUID helpers -----------------------------------------------------------


def luid_for_index(ifindex):
    """Return the ``LUID`` for an interface index."""
    luid = LUID()
    _check(
        _iphlpapi()["ConvertInterfaceIndexToLuid"](
            NET_IFINDEX(int(ifindex)), ctypes.byref(luid)
        ),
        f"ConvertInterfaceIndexToLuid({ifindex})",
    )
    return luid


def name_for_luid(luid):
    """Return the human readable interface name for a ``LUID`` (or ``""``)."""
    if isinstance(luid, LUID):
        value = luid
    else:
        value = LUID(int(luid))
    buffer = ctypes.create_unicode_buffer(256)
    _check(
        _iphlpapi()["ConvertInterfaceLuidToNameW"](
            ctypes.byref(value), buffer, len(buffer)
        ),
        "ConvertInterfaceLuidToNameW",
    )
    return buffer.value


# --- row construction and mutation -----------------------------------------


def build_forward_row(destination, family=None, ifindex=0, metric=0, on_link=True):
    """Build a ``MIB_IPFORWARD_ROW2`` for an on-link host route.

    The result is the /32 (or /128) row the Windows fix installs: destination
    prefix from *destination*, next hop ``0.0.0.0``/``::``, metric 0 by default,
    infinite lifetime and ``MIB_IPPROTO_NETMGMT`` as the protocol.  It is a
    plain structure: passing it to :func:`create_forward_entry` is what actually
    writes the table.
    """
    network = _parse_destination(destination, family=family)
    row_family = network.version
    row = MIB_IPFORWARD_ROW2()
    row.InterfaceLuid = luid_for_index(ifindex)
    row.InterfaceIndex = NET_IFINDEX(int(ifindex))
    row.DestinationPrefix.Prefix = sockaddr_from_ip(network.network_address)
    row.DestinationPrefix.PrefixLength = network.prefixlen
    row.SitePrefixLength = 0
    if on_link:
        row.NextHop = sockaddr_from_ip("0.0.0.0" if row_family == 4 else "::")
    row.ValidLifetime = INFINITE_LIFETIME
    row.PreferredLifetime = INFINITE_LIFETIME
    row.Metric = int(metric)
    row.Protocol = MIB_IPPROTO_NETMGMT
    row.Loopback = 0
    row.AutoconfigureAddress = 0
    row.Publish = 0
    row.Immortal = 1
    row.Age = 0
    row.Origin = 0
    return row


def create_forward_entry(row):
    """Create a route row; raises ``OSError`` when Windows refuses it."""
    _check(
        _iphlpapi()["CreateIpForwardEntry2"](ctypes.byref(row)),
        "CreateIpForwardEntry2",
    )


def set_forward_entry(row):
    """Update an existing route row; raises ``OSError`` when it does not exist."""
    _check(
        _iphlpapi()["SetIpForwardEntry2"](ctypes.byref(row)),
        "SetIpForwardEntry2",
    )


def delete_forward_entry(row):
    """Delete a route row; raises ``OSError`` when it cannot be removed."""
    _check(
        _iphlpapi()["DeleteIpForwardEntry2"](ctypes.byref(row)),
        "DeleteIpForwardEntry2",
    )


def initialize_forward_row(row):
    """Fill *row* with the IP Helper defaults (mirrors the documented call)."""
    _iphlpapi()["InitializeIpForwardEntry"](ctypes.byref(row))


# --- privilege check --------------------------------------------------------


def is_admin():
    """True when this process is running elevated (Windows Administrator)."""
    if not sys.platform.startswith("win"):
        return False
    try:
        return bool(_shell32()["IsUserAnAdmin"]())
    except OSError:  # pragma: no cover - shell32 always exists on Windows
        return False