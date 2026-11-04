"""Windows network backend built on the IP Helper API.

Windows keeps a single routing table; there are no policy-routing rules, so the
backend reports ``supports_policy_rules = False`` and :meth:`ensure_rule` /
:meth:`remove_rule` raise ``NotImplementedError``.  The supported way to make a
LAN host bypass a VPN capture is a host route: a /32 (or /128) row with next hop
``0.0.0.0`` (on-link), metric 0, infinite lifetime, installed on the physical
adapter.  Longest-prefix lookup then prefers it over the VPN client's fragmented
``/25`` rows even though those also carry metric 0, because a /32 is more
specific.

The ctypes details live in :mod:`lanrf.winapi`; this module only maps the
returned dicts onto the backend contract.  That split keeps the API quirks (the
28-byte ``SOCKADDR_INET``, the table header padding, the friendly-name lookup
through ``GetAdaptersAddresses``) out of the reconciler's way and lets the test
suite import this module on Linux.
"""

import ipaddress
import sys

from . import model, winapi
from .backends import NetworkBackend

# IF_OPER_STATUS_UP from ipifcons.h.
_OPER_STATUS_UP = 1

# Adapter names that identify a virtual adapter Windows does not report with a
# tunnel IFTYPE.  Matched case-insensitively against friendly name and
# description; the tunnel and loopback IFTYPEs are handled before this list.
_VIRTUAL_NAME_HINTS = (
    "wi-fi direct",
    "wifi direct",
    "bluetooth",
    "pseudo",
    "virtual",
)

_PRIVILEGE_HINT = (
    "unprivileged: route changes require an elevated PowerShell "
    "(Run as Administrator)"
)


def _af(family):
    """Map the backend's 4/6 family to the AF_* constant."""
    return winapi.AF_INET if int(family) == 4 else winapi.AF_INET6


def _fmt_destination(destination):
    version, prefix = model.normalize_destination(destination)
    return version, prefix


class WindowsBackend(NetworkBackend):
    """Network backend for Windows, implemented with ``iphlpapi``."""

    name = "windows"
    supports_policy_rules = False
    # The daemon polls: NotifyRouteChange2 is not wired up yet, and a polling
    # interval is what the service already does on Windows.
    supports_events = False

    def __init__(self):
        self.platform = sys.platform
        self.is_privileged = winapi.is_admin()
        self._adapter_cache = None
        self._adapter_by_name = None
        self._adapter_by_index = None

    # -- diagnostics ---------------------------------------------------------

    @property
    def privileges_note(self):
        if self.is_privileged:
            return "elevated (Administrator)"
        return _PRIVILEGE_HINT

    def invalidate(self):
        """Drop cached adapter information (re-read on the next query)."""
        self._adapter_cache = None
        self._adapter_by_name = None
        self._adapter_by_index = None

    def tunnel_interfaces(self):
        """Diagnostic helper: tunnel and loopback adapters, including down ones.

        This is *not* part of :class:`~lanrf.backends.NetworkBackend`; the
        doctor uses it to report which adapters the backend deliberately keeps
        out of :meth:`list_interfaces` and to explain VPN capture.
        """
        result = []
        for adapter in self._adapters():
            kind = self._classify(adapter)
            if kind in ("tunnel", "loopback"):
                result.append(
                    {
                        "name": adapter["name"],
                        "ifindex": adapter["ifindex"],
                        "kind": kind,
                        "oper_status": adapter["oper_status"],
                    }
                )
        return result

    # -- adapter caching -----------------------------------------------------

    def _adapters(self):
        if self._adapter_cache is None:
            records = winapi.get_adapters()
            self._adapter_cache = records
            self._adapter_by_name = {
                record["name"]: record for record in records if record["name"]
            }
            self._adapter_by_index = {
                record["ifindex"]: record for record in records
            }
        return self._adapter_cache

    def _adapter(self, interface):
        self._adapters()
        if not interface:
            return None
        record = self._adapter_by_name.get(interface)
        if record is not None:
            return record
        # Allow "idx13" as well as an ifindex given as a string; the selector
        # and the CLI normally use friendly names only.
        text = str(interface)
        if text.isdigit():
            return self._adapter_by_index.get(int(text))
        if text.startswith("idx") and text[3:].isdigit():
            return self._adapter_by_index.get(int(text[3:]))
        return None

    def _name(self, ifindex):
        self._adapters()
        record = self._adapter_by_index.get(int(ifindex))
        return record["name"] if record is not None else ""

    def _classify(self, adapter):
        """Return the link kind: ``"tunnel"``, ``"loopback"``, ``"virtual"`` or ``""``.

        The empty string means "usable physical adapter"; other parts of the
        package (notably ``sshconfig``) rely on that convention, matching the
        Linux backend, where virtual links return their kind and physical links
        return "".
        """
        iftype = int(adapter.get("iftype") or 0)
        if iftype == winapi.IF_TYPE_SOFTWARE_LOOPBACK:
            return "loopback"
        if iftype in winapi.TUNNEL_IF_TYPES:
            return "tunnel"
        haystack = f"{adapter.get('name', '')} {adapter.get('description', '')}".lower()
        if any(hint in haystack for hint in _VIRTUAL_NAME_HINTS):
            return "virtual"
        return ""

    # -- queries -------------------------------------------------------------

    def link_kind(self, interface):
        adapter = self._adapter(interface)
        if adapter is None:
            return ""
        return self._classify(adapter)

    def is_usable(self, interface):
        adapter = self._adapter(interface)
        if adapter is None:
            return False
        if self._classify(adapter) != "":
            return False
        return int(adapter.get("oper_status") or 0) == _OPER_STATUS_UP

    def list_interfaces(self, only_up=False):
        names = []
        for adapter in self._adapters():
            if self._classify(adapter) != "":
                continue
            if only_up and int(adapter.get("oper_status") or 0) != _OPER_STATUS_UP:
                continue
            name = adapter.get("name") or f"idx{adapter.get('ifindex')}"
            names.append(name)
        return names

    def local_networks(self, family=4):
        """Return ``(interface, network, address)`` for usable local subnets."""
        version = int(family)
        wanted = 4 if version == 4 else 6
        networks = []
        for adapter in self._adapters():
            if self._classify(adapter) != "":
                continue
            if int(adapter.get("oper_status") or 0) != _OPER_STATUS_UP:
                continue
            name = adapter.get("name") or f"idx{adapter.get('ifindex')}"
            for entry in adapter.get("unicast", []):
                if int(entry.get("family") or 0) != wanted:
                    continue
                address = ipaddress.ip_address(entry["address"])
                if address.is_link_local or address.is_loopback:
                    continue
                network = ipaddress.ip_network(
                    entry["prefix"], strict=False
                )
                if network.version != wanted:
                    continue
                networks.append((name, network, address))
        return networks

    def default_interfaces(self):
        """Usable adapters carrying a default route, best metric first.

        Windows reports default routes as ``0.0.0.0/0`` rows; the lowest metric
        per adapter is used for ordering, then the adapter name breaks ties.
        """
        best = {}
        for row in winapi.get_forward_table(winapi.AF_INET):
            if row["prefix"] != "0.0.0.0/0":
                continue
            index = row["interface_index"]
            metric = int(row["metric"])
            if index not in best or metric < best[index]:
                best[index] = metric
        ranked = []
        self._adapters()
        for index, metric in best.items():
            adapter = self._adapter_by_index.get(int(index))
            if adapter is None or self._classify(adapter) != "":
                continue
            if int(adapter.get("oper_status") or 0) != _OPER_STATUS_UP:
                continue
            name = adapter.get("name") or f"idx{index}"
            ranked.append((metric, name))
        ranked.sort()
        result = []
        for _metric, name in ranked:
            if name not in result:
                result.append(name)
        return result

    def route_lookup(self, destination, family=4, table=None, fallback=True):
        """Resolve *destination* with ``GetBestRoute2``.

        Windows has one routing table, so a request for a named non-main table
        returns ``None`` (there is nothing there to inspect).  ``table`` is
        echoed back as ``requested_table`` and ``fallback`` is carried through
        for parity with the Linux backend.
        """
        requested = str(table) if table not in (None, "") else ""
        if requested not in ("", "main"):
            return None
        try:
            detail = winapi.get_best_route_detail(destination, family=family)
        except (OSError, ValueError):
            return None
        gateway = detail.get("next_hop") or ""
        if gateway in ("0.0.0.0", "::"):
            gateway = ""
        return {
            "interface": self._name(detail["interface_index"]),
            "gateway": gateway,
            "source": detail.get("source") or "",
            "table": "main",
            "requested_table": requested,
            "fallback": bool(fallback),
            "destination": detail.get("destination") or "",
            "prefix": detail.get("prefix") or "",
            "metric": int(detail.get("metric") or 0),
            "family": int(family),
        }

    @staticmethod
    def _protocol_name(protocol):
        if int(protocol) == winapi.MIB_IPPROTO_LOCAL:
            return "local"
        if int(protocol) == winapi.MIB_IPPROTO_NETMGMT:
            return "netmgmt"
        return "other"

    def routes(self, table="main", family=4):
        """Return routing table rows as :func:`lanrf.model.route_entry` dicts.

        Only the main table exists.  ``owned`` is a heuristic because Windows
        rows carry no place to mark a row as ours: a host route with metric 0,
        an on-link next hop **and** a physical adapter is the exact shape this
        backend installs, so it is reported as owned.  Requiring a physical
        adapter matters: VPN clients install the same /32 + metric 0 + on-link
        rows for their own peers (Tailscale does), and without that condition
        ``prune`` would offer to delete them.  A foreign host route on a
        physical adapter with the same shape can still look owned.
        """
        if table not in (None, "", "main"):
            return []
        version = int(family)
        entries = []
        for row in winapi.get_forward_table(_af(version)):
            prefix_length = int(row["prefix_length"])
            protocol = self._protocol_name(row["protocol"])
            interface = self._name(row["interface_index"])
            entry = model.route_entry(
                prefix=row["prefix"],
                interface=interface,
                family=version,
                table="main",
                protocol=protocol,
                source="",
                metric=int(row["metric"]),
                scope="",
            )
            on_link = row["next_hop"] in ("0.0.0.0", "::")
            if (
                prefix_length in (32, 128)
                and int(row["metric"]) == 0
                and on_link
                and self.link_kind(interface) == ""
            ):
                entry["owned"] = True
            entries.append(entry)
        return entries

    def route_prefixes(self, table="main", family=4):
        return {entry["prefix"] for entry in self.routes(table=table, family=family)}

    def rules(self, family=4):
        # Windows has no policy-routing rules.
        return []

    # -- mutations -----------------------------------------------------------

    @staticmethod
    def _check_table(table):
        if table not in (None, "", "main"):
            raise ValueError(
                "the Windows backend only supports the main routing table; "
                "set routing_mode='main'"
            )

    @staticmethod
    def _permission_error():
        return PermissionError(
            winapi.ERROR_ACCESS_DENIED,
            "writing the Windows routing table requires an elevated "
            "(Administrator) process; open PowerShell as Administrator",
        )

    def _ifindex(self, interface):
        adapter = self._adapter(interface)
        if adapter is None:
            raise ValueError(f"unknown interface {interface!r}")
        return int(adapter["ifindex"])

    def ensure_route(self, item):
        """Install an on-link host route with metric 0 on the physical adapter.

        This is the operation that stops a VPN client from capturing a LAN host:
        the /32 row is more specific than the client's /25 fragments and both
        carry metric 0, so longest-prefix matching picks the physical adapter.
        """
        table = item.get("table")
        self._check_table(table)
        interface = item.get("interface") or ""
        if not interface:
            raise ValueError("ensure_route requires an interface")
        destination = item.get("address") or item.get("destination")
        if not destination:
            raise ValueError("ensure_route requires an address")
        if not self.is_usable(interface):
            raise ValueError(f"interface {interface!r} is not a usable adapter")
        version, prefix = _fmt_destination(destination)
        family = int(item.get("family") or version)
        if family != version:
            raise ValueError(
                f"address {destination!r} is IPv{version}, expected IPv{family}"
            )
        ifindex = self._ifindex(interface)

        for row in winapi.get_forward_table(_af(version)):
            if (
                row["prefix"] == prefix
                and int(row["interface_index"]) == ifindex
                and int(row["metric"]) == 0
                and row["next_hop"] in ("0.0.0.0", "::")
            ):
                return False, f"already routed through {interface}"

        route = winapi.build_forward_row(
            prefix, family=version, ifindex=ifindex, metric=0, on_link=True
        )
        try:
            winapi.create_forward_entry(route)
        except OSError as exc:
            if exc.winerror == winapi.ERROR_ACCESS_DENIED:
                raise self._permission_error() from exc
            if exc.winerror == winapi.ERROR_OBJECT_ALREADY_EXISTS:
                try:
                    winapi.set_forward_entry(route)
                except OSError as update_error:
                    if update_error.winerror == winapi.ERROR_ACCESS_DENIED:
                        raise self._permission_error() from update_error
                    raise
                return True, f"updated {prefix} via {interface} (on-link, metric 0)"
            raise
        return True, f"added {prefix} via {interface} (on-link, metric 0)"

    def remove_route(self, item):
        """Delete the host route for ``destination`` on ``interface``.

        Returns ``False`` when no such row exists (idempotent cleanup); raises
        ``PermissionError`` when Windows denies the delete.
        """
        table = item.get("table")
        if table not in (None, "", "main"):
            return False
        interface = item.get("interface") or ""
        if not interface:
            raise ValueError("remove_route requires an interface")
        destination = item.get("address") or item.get("destination")
        if not destination:
            raise ValueError("remove_route requires an address")
        version, prefix = _fmt_destination(destination)
        ifindex = self._ifindex(interface)

        match = None
        for row in winapi.get_forward_table(_af(version)):
            if row["prefix"] == prefix and int(row["interface_index"]) == ifindex:
                match = row
                break
        if match is None:
            return False
        route = winapi.build_forward_row(
            prefix,
            family=version,
            ifindex=ifindex,
            metric=int(match["metric"]),
            on_link=match["next_hop"] in ("0.0.0.0", "::"),
        )
        try:
            winapi.delete_forward_entry(route)
        except OSError as exc:
            if exc.winerror == winapi.ERROR_ACCESS_DENIED:
                raise self._permission_error() from exc
            if exc.winerror in (
                winapi.ERROR_NOT_FOUND,
                winapi.ERROR_INVALID_PARAMETER,
            ):
                return False
            raise
        return True

    def ensure_rule(self, match, table, family=4, preference=1200):
        raise NotImplementedError(
            "Windows has no policy routing; use routing_mode='main'"
        )

    def remove_rule(self, match, table, family=4):
        raise NotImplementedError(
            "Windows has no policy routing; use routing_mode='main'"
        )