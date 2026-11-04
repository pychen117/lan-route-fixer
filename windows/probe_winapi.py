"""Read-only probe of the Windows IP Helper API (netioapi + iphlpapi).

Purpose: confirm on a real Windows box that the structures and calls the
Windows backend wants to use actually work, and print what they return.
This script never mutates anything: it calls only Get* APIs.

Run:  python -B windows/probe_winapi.py [destination ...]
"""

import ctypes
import ipaddress
import sys
from ctypes import wintypes

iphlpapi = ctypes.WinDLL("iphlpapi.dll")
ws2_32 = ctypes.WinDLL("ws2_32.dll")

AF_INET = 2
AF_INET6 = 23
ERROR_SUCCESS = 0


class LUid(ctypes.Structure):
    _fields_ = [("Value", ctypes.c_ulonglong)]


class SockaddrInet(ctypes.Structure):
    # SOCKADDR_INET is a union of SOCKADDR_IN (16) and SOCKADDR_IN6 (28).  The
    # union's alignment is 4 (sockaddr_in6 carries a ULONG sin6_flowinfo), so
    # the fields must be laid out explicitly instead of as ushort + 26 bytes:
    # a 26-byte tail would give the struct alignment 2 and shift every later
    # field by two bytes.
    _fields_ = [
        ("si_family", ctypes.c_ushort),
        ("sin6_port", ctypes.c_ushort),
        ("sin6_flowinfo", ctypes.c_uint),
        ("sin6_addr", ctypes.c_ubyte * 16),
        ("sin6_scope_id", ctypes.c_uint),
    ]


class IpAddressPrefix(ctypes.Structure):
    _fields_ = [
        ("Prefix", SockaddrInet),
        ("PrefixLength", ctypes.c_ubyte),
    ]


class IpForwardRow2(ctypes.Structure):
    _fields_ = [
        ("InterfaceLuid", LUid),
        ("InterfaceIndex", wintypes.DWORD),
        ("DestinationPrefix", IpAddressPrefix),
        ("NextHop", SockaddrInet),
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


class IpForwardTable2(ctypes.Structure):
    _fields_ = [
        ("NumEntries", ctypes.c_ulong),
        ("Table", IpForwardRow2 * 1),
    ]


class UnicastIpAddressRow(ctypes.Structure):
    _fields_ = [
        ("InterfaceLuid", LUid),
        ("InterfaceIndex", wintypes.DWORD),
        ("Address", SockaddrInet),
        ("PrefixLength", ctypes.c_ubyte),
        ("DadState", ctypes.c_uint),
        ("ValidLifetime", wintypes.DWORD),
        ("PreferredLifetime", wintypes.DWORD),
        ("LeaseLifetime", wintypes.DWORD),
        ("OnLinkPrefixLength", ctypes.c_ubyte),
    ]


class UnicastIpAddressTable(ctypes.Structure):
    _fields_ = [
        ("NumEntries", ctypes.c_ulong),
        ("Table", UnicastIpAddressRow * 1),
    ]


class SocketAddress(ctypes.Structure):
    _fields_ = [
        ("lpSockaddr", ctypes.c_void_p),
        ("iSockaddrLength", ctypes.c_int),
    ]


class UnicastAddress(ctypes.Structure):
    pass


UnicastAddress._fields_ = [
    ("Length", wintypes.ULONG),
    ("Flags", wintypes.DWORD),
    ("Next", ctypes.POINTER(UnicastAddress)),
    ("Address", SocketAddress),
    ("PrefixOrigin", ctypes.c_uint),
    ("SuffixOrigin", ctypes.c_uint),
    ("DadState", ctypes.c_uint),
    ("ValidLifetime", wintypes.ULONG),
    ("PreferredLifetime", wintypes.ULONG),
    ("LeaseLifetime", wintypes.ULONG),
]


class AdapterAddresses(ctypes.Structure):
    pass


AdapterAddresses._fields_ = [
    ("Length", wintypes.ULONG),
    ("IfIndex", wintypes.DWORD),
    ("Next", ctypes.POINTER(AdapterAddresses)),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", ctypes.POINTER(UnicastAddress)),
    ("FirstAnycastAddress", ctypes.c_void_p),
    ("FirstMulticastAddress", ctypes.c_void_p),
    ("FirstDnsServerAddress", ctypes.c_void_p),
    ("DnsSuffix", ctypes.c_wchar_p),
    ("Description", ctypes.c_wchar_p),
    ("FriendlyName", ctypes.c_wchar_p),
    ("PhysicalAddress", ctypes.c_ubyte * 8),
    ("PhysicalAddressLength", wintypes.ULONG),
    ("Flags", wintypes.ULONG),
    ("Mtu", wintypes.ULONG),
    ("IfType", wintypes.ULONG),
    ("OperStatus", ctypes.c_uint),
    ("Ipv6IfIndex", wintypes.DWORD),
    ("ZoneIndices", wintypes.ULONG * 16),
    ("FirstPrefix", ctypes.c_void_p),
]


GetIpForwardTable2 = iphlpapi.GetIpForwardTable2
GetIpForwardTable2.restype = wintypes.ULONG
GetIpForwardTable2.argtypes = [ctypes.c_ushort, ctypes.POINTER(ctypes.c_void_p)]

GetUnicastIpAddressTable = iphlpapi.GetUnicastIpAddressTable
GetUnicastIpAddressTable.restype = wintypes.ULONG
GetUnicastIpAddressTable.argtypes = [ctypes.c_ushort, ctypes.POINTER(ctypes.c_void_p)]

GetAdaptersAddresses = iphlpapi.GetAdaptersAddresses
GetAdaptersAddresses.restype = wintypes.ULONG
GetAdaptersAddresses.argtypes = [
    wintypes.ULONG,
    wintypes.ULONG,
    ctypes.c_void_p,
    ctypes.POINTER(AdapterAddresses),
    ctypes.POINTER(wintypes.ULONG),
]

GetBestRoute2 = iphlpapi.GetBestRoute2
GetBestRoute2.restype = wintypes.ULONG
GetBestRoute2.argtypes = [
    ctypes.c_void_p,
    wintypes.ULONG,
    ctypes.c_void_p,
    ctypes.POINTER(SockaddrInet),
    wintypes.ULONG,
    ctypes.POINTER(IpForwardRow2),
    ctypes.POINTER(SockaddrInet),
]

ConvertInterfaceLuidToNameW = iphlpapi.ConvertInterfaceLuidToNameW
ConvertInterfaceLuidToNameW.restype = wintypes.ULONG
ConvertInterfaceLuidToNameW.argtypes = [ctypes.POINTER(LUid), ctypes.c_wchar_p, ctypes.c_size_t]

FreeMibTable = iphlpapi.FreeMibTable
FreeMibTable.restype = None
FreeMibTable.argtypes = [ctypes.c_void_p]


_SOCKADDR_ADDR_V4 = 4   # si_family + sin6_port
_SOCKADDR_ADDR_V6 = 8   # si_family + sin6_port + sin6_flowinfo


def _addr_text(sockaddr):
    family = sockaddr.si_family
    base = ctypes.addressof(sockaddr)
    if family == AF_INET:
        return str(ipaddress.IPv4Address(ctypes.string_at(base + _SOCKADDR_ADDR_V4, 4)))
    if family == AF_INET6:
        return str(ipaddress.IPv6Address(ctypes.string_at(base + _SOCKADDR_ADDR_V6, 16)))
    return f"<family {family}>"


def _make_sockaddr(text):
    value = ipaddress.ip_address(text)
    out = SockaddrInet()
    out.si_family = AF_INET if value.version == 4 else AF_INET6
    base = ctypes.addressof(out)
    if value.version == 4:
        ctypes.memmove(base + _SOCKADDR_ADDR_V4, value.packed, 4)
    else:
        ctypes.memmove(base + _SOCKADDR_ADDR_V6, value.packed, 16)
    return out


_ADAPTER_NAMES = {}


def _adapter_names():
    if not _ADAPTER_NAMES:
        rc, adapters = list_adapters()
        for adapter in adapters:
            _ADAPTER_NAMES[adapter["ifindex"]] = adapter["name"]
    return _ADAPTER_NAMES


def if_name(index, luid=None):
    return _adapter_names().get(index, f"idx{index}")


def list_routes():
    table = ctypes.c_void_p()
    rc = GetIpForwardTable2(AF_INET, ctypes.byref(table))
    if rc != ERROR_SUCCESS:
        return rc, []
    try:
        count = ctypes.cast(table, ctypes.POINTER(ctypes.c_ulong)).contents.value
        base = table.value + 8
        rows = []
        for index in range(count):
            row = IpForwardRow2.from_address(base + index * ctypes.sizeof(IpForwardRow2))
            rows.append(
                (
                    str(ipaddress.IPv4Network(
                        (_addr_text(row.DestinationPrefix.Prefix), row.DestinationPrefix.PrefixLength),
                        strict=False,
                    )),
                    _addr_text(row.NextHop),
                    row.InterfaceIndex,
                    if_name(row.InterfaceIndex),
                    row.Metric,
                    row.Protocol,
                )
            )
        return 0, rows
    finally:
        FreeMibTable(table)


def list_unicast():
    table = ctypes.c_void_p()
    rc = GetUnicastIpAddressTable(AF_INET, ctypes.byref(table))
    if rc != ERROR_SUCCESS:
        return rc, []
    try:
        count = ctypes.cast(table, ctypes.POINTER(ctypes.c_ulong)).contents.value
        base = table.value + 8
        out = []
        for index in range(count):
            row = UnicastIpAddressRow.from_address(base + index * ctypes.sizeof(UnicastIpAddressRow))
            out.append(
                (
                    row.InterfaceIndex,
                    if_name(row.InterfaceIndex),
                    _addr_text(row.Address),
                    row.PrefixLength,
                    row.OnLinkPrefixLength,
                    row.DadState,
                )
            )
        return 0, out
    finally:
        FreeMibTable(table)


def list_adapters():
    size = wintypes.ULONG(15000)
    for _ in range(4):
        buffer = ctypes.create_string_buffer(size.value)
        rc = GetAdaptersAddresses(
            AF_INET,
            0x0080 | 0x0040,  # GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST
            None,
            ctypes.cast(buffer, ctypes.POINTER(AdapterAddresses)),
            ctypes.byref(size),
        )
        if rc == 0:
            break
        if rc != 111:  # ERROR_BUFFER_OVERFLOW
            return rc, []
    out = []
    pointer = ctypes.cast(buffer, ctypes.POINTER(AdapterAddresses))
    while pointer:
        adapter = pointer.contents
        addresses = []
        unicast = adapter.FirstUnicastAddress
        while unicast:
            entry = unicast.contents
            addresses.append(
                (
                    _addr_text(ctypes.cast(entry.Address.lpSockaddr, ctypes.POINTER(SockaddrInet)).contents),
                    entry.Address.iSockaddrLength,
                    entry.PrefixOrigin,
                )
            )
            unicast = entry.Next
        out.append(
            {
                "ifindex": adapter.IfIndex,
                "name": adapter.FriendlyName,
                "description": adapter.Description,
                "iftype": adapter.IfType,
                "oper": adapter.OperStatus,
                "mtu": adapter.Mtu,
                "addresses": addresses,
            }
        )
        pointer = adapter.Next
    return 0, out


def best_route(text):
    source = SockaddrInet()
    destination = _make_sockaddr(text)
    row = IpForwardRow2()
    best_source = SockaddrInet()
    rc = GetBestRoute2(None, 0, None, ctypes.byref(destination), 0, ctypes.byref(row), ctypes.byref(best_source))
    if rc != ERROR_SUCCESS:
        return rc, None
    return 0, {
        "prefix": str(
            ipaddress.IPv4Network(
                (_addr_text(row.DestinationPrefix.Prefix), row.DestinationPrefix.PrefixLength),
                strict=False,
            )
        ),
        "next_hop": _addr_text(row.NextHop),
        "ifindex": row.InterfaceIndex,
        "interface": if_name(row.InterfaceIndex),
        "metric": row.Metric,
        "source": _addr_text(best_source),
        "protocol": row.Protocol,
    }


def main(argv):
    print("sizeof(IpForwardRow2) =", ctypes.sizeof(IpForwardRow2), "(expect 104)")
    print("sizeof(SockaddrInet) =", ctypes.sizeof(SockaddrInet), "(expect 28)")
    print("sizeof(IpAddressPrefix) =", ctypes.sizeof(IpAddressPrefix), "(expect 32)")
    print("sizeof(UnicastIpAddressRow) =", ctypes.sizeof(UnicastIpAddressRow), "(expect 64)")
    print("sizeof(AdapterAddresses) =", ctypes.sizeof(AdapterAddresses))
    print()

    rc, routes = list_routes()
    print(f"GetIpForwardTable2 -> rc={rc} rows={len(routes)}")
    interesting = [
        row for row in routes if row[0] in ("192.168.4.94/32", "192.168.4.0/24", "192.168.4.64/26", "0.0.0.0/0")
    ]
    for row in interesting[:20]:
        print("  ", row)

    rc, unicast = list_unicast()
    print(f"\nGetUnicastIpAddressTable -> rc={rc} rows={len(unicast)}")
    for row in unicast:
        print("  ", row)

    rc, adapters = list_adapters()
    print(f"\nGetAdaptersAddresses -> rc={rc} adapters={len(adapters)}")
    for adapter in adapters:
        print("  ", adapter)

    for destination in argv[1:] or ["192.168.4.94", "192.168.4.234", "192.168.4.19", "10.10.60.101"]:
        rc, best = best_route(destination)
        print(f"\nGetBestRoute2({destination}) -> rc={rc}")
        print("  ", best)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))