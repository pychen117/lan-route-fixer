"""Minimal rtnetlink event listener used by the Linux backend.

The whole point of this module is *latency*: a VPN client such as aTrust
installs a few hundred ``/25``..``/32`` routes the moment it connects and can
silently displace the host routes this tool installed. Polling every 30 seconds
leaves the user with a broken SSH session for up to 30 seconds. Subscribing to
the kernel's ``RTM_*ROUTE`` notifications drops that window to milliseconds.

Only the standard library is used. On non-Linux platforms the constructor
raises :class:`NotSupportedError` so the caller can fall back to polling; the
Windows port will provide an equivalent implementation backed by
``NotifyRouteChange2`` with the same interface.
"""

import os
import select
import socket
import struct

# --- rtnetlink constants (linux/rtnetlink.h, linux/netlink.h) ---------------

NETLINK_ROUTE = 0

RTM_NEWLINK = 16
RTM_DELLINK = 17
RTM_NEWADDR = 20
RTM_DELADDR = 21
RTM_NEWROUTE = 24
RTM_DELROUTE = 25
RTM_NEWRULE = 32
RTM_DELRULE = 33

RTMGRP_LINK = 0x00000001
RTMGRP_IPV4_IFADDR = 0x00000010
RTMGRP_IPV4_ROUTE = 0x00000040
RTMGRP_IPV6_IFADDR = 0x00000100
RTMGRP_IPV6_ROUTE = 0x00000400

DEFAULT_GROUPS = (
    RTMGRP_LINK
    | RTMGRP_IPV4_ROUTE
    | RTMGRP_IPV6_ROUTE
    | RTMGRP_IPV4_IFADDR
    | RTMGRP_IPV6_IFADDR
)

# nlmsghdr is 16 bytes, rtmsg 12 bytes; the family is rtmsg's first field.
_NLMSG_HEADER = struct.Struct("=IHHII")
_RTMSG = struct.Struct("=BBBBBBBBI")
# ifinfomsg / ifaddrmsg start with the address family.
HEADER_SIZE = _NLMSG_HEADER.size
PAYLOAD_SIZE = _RTMSG.size

NLMSG_NOOP = 1
NLMSG_ERROR = 2
NLMSG_DONE = 3

# Netlink attribute: 2 byte length, 2 byte type, type-encoded payload, padded
# to a 4 byte boundary.
_ATTR_HEADER = struct.Struct("=HH")
NLA_TYPE_MASK = 0x3FFF
NLA_F_NESTED = 0x8000

# linux/if_link.h
IFLA_IFNAME = 3
# linux/rtnetlink.h
RTA_DST = 1
RTA_OIF = 4
RTA_TABLE = 15

_MESSAGE_NAMES = {
    RTM_NEWLINK: "link-up",
    RTM_DELLINK: "link-down",
    RTM_NEWADDR: "addr-add",
    RTM_DELADDR: "addr-del",
    RTM_NEWROUTE: "route-add",
    RTM_DELROUTE: "route-del",
    RTM_NEWRULE: "rule-add",
    RTM_DELRULE: "rule-del",
}

# Route tables the tool cares about; anything else is noise.
MAIN_TABLE = 254
LOCAL_TABLE = 255


class NotSupportedError(RuntimeError):
    """Raised when rtnetlink monitoring is unavailable on this platform."""


def message_name(message_type):
    return _MESSAGE_NAMES.get(message_type, f"rtnl-{message_type}")


def parse_attributes(payload):
    """Return ``{type: bytes}`` for a netlink attribute block."""
    attributes = {}
    offset = 0
    length = len(payload)
    while offset + _ATTR_HEADER.size <= length:
        attr_len, attr_type = _ATTR_HEADER.unpack_from(payload, offset)
        if attr_len < _ATTR_HEADER.size or offset + attr_len > length:
            break
        value = payload[offset + _ATTR_HEADER.size : offset + attr_len]
        attributes[attr_type & NLA_TYPE_MASK] = value
        offset += (attr_len + 3) & ~3
    return attributes


def _decode_ifname(value):
    try:
        return value.split(b"\x00", 1)[0].decode("utf-8", "replace")
    except Exception:  # pragma: no cover - defensive
        return ""


def _decode_prefix(family, value, prefixlen):
    try:
        if family == socket.AF_INET and len(value) == 4:
            return f"{socket.inet_ntop(socket.AF_INET, value)}/{prefixlen}"
        if family == socket.AF_INET6 and len(value) == 16:
            return f"{socket.inet_ntop(socket.AF_INET6, value)}/{prefixlen}"
    except (OSError, ValueError):  # pragma: no cover - defensive
        return ""
    return ""


class NetlinkEvent:
    """A decoded rtnetlink notification."""

    __slots__ = ("type", "family", "table", "ifname", "prefix", "raw_size")

    def __init__(
        self,
        message_type,
        family=None,
        table=None,
        ifname="",
        prefix="",
        raw_size=0,
    ):
        self.type = message_type
        self.family = family
        self.table = table
        self.ifname = ifname
        self.prefix = prefix
        self.raw_size = raw_size

    @property
    def name(self):
        return message_name(self.type)

    @property
    def is_route(self):
        return self.type in (RTM_NEWROUTE, RTM_DELROUTE)

    @property
    def is_link(self):
        return self.type in (RTM_NEWLINK, RTM_DELLINK)

    @property
    def is_address(self):
        return self.type in (RTM_NEWADDR, RTM_DELADDR)

    @property
    def is_main_table(self):
        """True when the change affects the table the tool competes over."""
        if not self.is_route:
            return False
        return self.table in (None, 0, MAIN_TABLE)

    def __repr__(self):  # pragma: no cover - debugging aid
        return (
            f"<NetlinkEvent {self.name} family={self.family} table={self.table} "
            f"ifname={self.ifname!r} prefix={self.prefix!r}>"
        )


def decode_messages(data):
    """Decode a netlink datagram into a list of :class:`NetlinkEvent`."""
    events = []
    offset = 0
    length = len(data)
    while offset + HEADER_SIZE <= length:
        msg_len, msg_type, _flags, _seq, _pid = _NLMSG_HEADER.unpack_from(data, offset)
        if msg_len < HEADER_SIZE or offset + msg_len > length:
            break
        body = data[offset : offset + msg_len]
        offset += msg_len
        if msg_type in (NLMSG_NOOP, NLMSG_ERROR, NLMSG_DONE):
            # NLMSG_ERROR carries acks for our own (nonexistent) requests and
            # can also report asynchronous kernel errors; neither is a state
            # change we need to react to.
            continue

        family = body[HEADER_SIZE] if len(body) > HEADER_SIZE else None
        payload = body[HEADER_SIZE:]
        table = None
        prefix = ""
        ifname = ""
        if msg_type in (RTM_NEWROUTE, RTM_DELROUTE) and len(payload) >= PAYLOAD_SIZE:
            # rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type, flags
            table = payload[4]
            prefixlen = payload[1]
            attributes = parse_attributes(payload[PAYLOAD_SIZE:])
            if RTA_TABLE in attributes and len(attributes[RTA_TABLE]) == 4:
                table = struct.unpack("=I", attributes[RTA_TABLE])[0]
            if RTA_DST in attributes:
                prefix = _decode_prefix(family, attributes[RTA_DST], prefixlen)
        elif msg_type in (RTM_NEWLINK, RTM_DELLINK) and len(payload) >= 16:
            attributes = parse_attributes(payload[16:])
            if IFLA_IFNAME in attributes:
                ifname = _decode_ifname(attributes[IFLA_IFNAME])
        elif msg_type in (RTM_NEWADDR, RTM_DELADDR) and len(payload) >= 8:
            attributes = parse_attributes(payload[8:])
            if IFLA_IFNAME in attributes:
                ifname = _decode_ifname(attributes[IFLA_IFNAME])
        events.append(
            NetlinkEvent(
                msg_type,
                family=family,
                table=table,
                ifname=ifname,
                prefix=prefix,
                raw_size=msg_len,
            )
        )
    return events


class RouteMonitor:
    """Blocking rtnetlink subscription.

    Usage::

        monitor = RouteMonitor()
        while True:
            for event in monitor.wait(timeout=30):
                ...
        monitor.close()

    The socket is created with ``NETLINK_ROUTE`` and bound to the multicast
    groups for links, addresses and routes, so no privileges are required to
    observe changes (only to make them).
    """

    def __init__(self, groups=DEFAULT_GROUPS, buffer_size=1 << 18):
        if not hasattr(socket, "AF_NETLINK"):
            raise NotSupportedError("AF_NETLINK is not available on this platform")
        self.buffer_size = buffer_size
        self._socket = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE)
        try:
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        except OSError:  # pragma: no cover - depends on kernel rmem_max
            pass
        self._socket.bind((os.getpid(), groups))
        self._closed = False

    @property
    def fileno(self):
        return self._socket.fileno()

    def wait(self, timeout=None):
        """Return decoded events, blocking up to *timeout* seconds.

        An empty list means the timeout expired without any kernel event.
        """
        if self._closed:
            raise NotSupportedError("monitor is closed")
        readable, _, _ = select.select([self._socket], [], [], timeout)
        if not readable:
            return []
        try:
            data = self._socket.recv(self.buffer_size)
        except OSError:
            return []
        return decode_messages(data)

    def close(self):
        if not self._closed:
            self._closed = True
            try:
                self._socket.close()
            except OSError:  # pragma: no cover
                pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
        return False


def available():
    """True when this platform can provide rtnetlink notifications."""
    if not hasattr(socket, "AF_NETLINK"):
        return False
    try:
        with RouteMonitor():
            return True
    except (OSError, NotSupportedError):
        return False
