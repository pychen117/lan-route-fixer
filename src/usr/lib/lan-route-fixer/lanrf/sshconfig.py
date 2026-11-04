"""OpenSSH client-config parsing and physical-LAN filtering.

The SSH importer answers a narrow question: *which hosts in an OpenSSH config
can actually be reached over a physical LAN interface?* Only those may be
turned into :mod:`lanrf.targets` and pinned; a host that lives inside a VPN
tunnel would otherwise be pinned to the wrong NIC.

Parsing follows ``ssh_config(5)`` closely enough for that job, without pulling
in a third-party parser:

* options before the first ``Host`` block are global defaults; like OpenSSH
  they are processed first, so "the first obtained value wins";
* ``Host`` takes several whitespace-separated patterns, ``!pattern`` negates
  one, and shell-style globs (``*``/``?``/``[...]``) match like OpenSSH;
* ``Include`` files are expanded inline, relative to the including file and
  then ``~/.ssh``, at most :data:`MAX_INCLUDE_DEPTH` levels deep and only once
  per file (so a self-include cannot loop);
* comments (whole-line and trailing) and quoted arguments are handled, and
  keywords are case-insensitive;
* ``Match`` blocks are recognised but deliberately ignored: their conditions
  cannot be evaluated statically, so their directives never contribute.

Everything here is pure logic plus read-only file access, which is what makes
it testable without a real network stack.
"""

import fnmatch
import glob
import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

from .targets import family_of, parse_ip_or_cidr, valid_local_target

# OpenSSH default when a host neither sets nor inherits ``Port``.
DEFAULT_SSH_PORT = 22

# How deep Include chains are followed. OpenSSH itself allows deeper nesting
# (and uses it for drop-in directories), but four levels is plenty for a client
# config and keeps a broken include cycle bounded.
MAX_INCLUDE_DEPTH = 4

# Characters that make a Host pattern non-concrete: they cannot name one host,
# so they are never enumerated (resolution still uses them as wildcards).
_WILDCARD_CHARS = "*?["


@dataclass(frozen=True)
class SshHost:
    """One concrete host alias resolved through the SSH config.

    ``address`` is the effective ``HostName`` (or the alias itself when no
    ``HostName`` applies).  ``source_path``/``line`` point at the ``Host`` line
    that first defined the alias, for diagnostics.
    """

    name: str
    address: str
    port: int = DEFAULT_SSH_PORT
    user: str = ""
    source_path: str = ""
    line: int = 0


class _Block:
    """A ``Host`` block (patterns set) or the global option block (None)."""

    __slots__ = ("patterns", "options", "source_path", "line")

    def __init__(self, patterns=None, source_path="", line=0):
        self.patterns = patterns
        self.options = []  # [(keyword, value, line, source_path), ...]
        self.source_path = source_path
        self.line = line

    def matches(self, alias):
        """True when *alias* selects this block (negation aware)."""
        if self.patterns is None:
            return True
        positives = [p for p in self.patterns if not p.startswith("!")]
        negatives = [p[1:] for p in self.patterns if p.startswith("!")]
        if not any(fnmatch.fnmatchcase(alias, pattern) for pattern in positives):
            return False
        if any(fnmatch.fnmatchcase(alias, pattern) for pattern in negatives):
            return False
        return True


def _strip_comment(line):
    """Drop a trailing ``#`` comment, leaving quoted ``#`` characters alone."""
    quote = ""
    for index, character in enumerate(line):
        if quote:
            if character == quote:
                quote = ""
            continue
        if character in "\"'":
            quote = character
            continue
        if character == "#" and (index == 0 or line[index - 1] in " \t"):
            return line[:index]
    return line


def _split_fields(line):
    """Split an option line into fields, honouring single/double quotes."""
    fields = []
    current = []
    quote = ""
    index = 0
    while index < len(line):
        character = line[index]
        if quote:
            if character == quote:
                quote = ""
            elif character == "\\" and quote == '"' and index + 1 < len(line):
                index += 1
                current.append(line[index])
            else:
                current.append(character)
        elif character in "\"'":
            quote = character
        elif character.isspace():
            if current:
                fields.append("".join(current))
                current = []
        else:
            current.append(character)
        index += 1
    if current:
        fields.append("".join(current))
    return fields


def _default_include(pattern, base_dir):
    """Resolve one Include pattern to ``[(path, text), ...]``.

    Relative patterns are tried against the including file's directory first
    and then ``~/.ssh`` (where OpenSSH keeps user drop-in configs).  Missing
    files are ignored: a stale Include is not an error for an importer.
    """
    expanded = os.path.expanduser(str(pattern))
    candidates = []
    if os.path.isabs(expanded):
        candidates.extend(glob.glob(expanded))
    else:
        bases = []
        if base_dir:
            bases.append(Path(base_dir))
        ssh_dir = Path.home() / ".ssh"
        if ssh_dir not in bases:
            bases.append(ssh_dir)
        for base in bases:
            candidates.extend(glob.glob(str(base / expanded)))
    resolved = []
    for candidate in sorted({os.path.normcase(path) for path in candidates}):
        path = Path(candidate)
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        resolved.append((path, text))
    return resolved


class _SshParser:
    """Shared state for one (possibly multi-file) parsing run."""

    def __init__(self, source_path="", include=None):
        self.include = include or _default_include
        self.blocks = [_Block(patterns=None, source_path=source_path)]
        self._seen_files = set()
        if source_path:
            self._seen_files.add(_file_key(source_path))

    # -- text ---------------------------------------------------------------

    def parse_text(self, text, source_path="", depth=0, inherited_block=None):
        """Parse *text*; included files recurse with the current block context."""
        if depth == 0:
            current = self.blocks[0]
        else:
            current = inherited_block
        for number, raw_line in enumerate(text.splitlines(), start=1):
            line = _strip_comment(raw_line).strip()
            if not line:
                continue
            fields = _split_fields(line)
            if not fields:
                continue
            keyword = fields[0].lower()
            arguments = fields[1:]

            if keyword == "host":
                current = _Block(
                    patterns=list(arguments),
                    source_path=str(source_path or ""),
                    line=number,
                )
                self.blocks.append(current)
                continue
            if keyword == "match":
                # Conditions need a live ssh evaluation; ignore the block's
                # directives until the next Host line.
                current = None
                continue
            if keyword == "include":
                if current is None:
                    continue
                for pattern in arguments:
                    for path, included_text in self._resolve_include(
                        pattern, source_path, depth
                    ):
                        self.parse_text(
                            included_text,
                            source_path=str(path),
                            depth=depth + 1,
                            inherited_block=current,
                        )
                continue
            if current is None:
                continue
            value = " ".join(arguments) if len(arguments) > 1 else (
                arguments[0] if arguments else ""
            )
            current.options.append((keyword, value, number, str(source_path or "")))

    def _resolve_include(self, pattern, source_path, depth):
        if depth + 1 > MAX_INCLUDE_DEPTH:
            return []
        base_dir = str(Path(source_path).parent) if source_path else ""
        for path, text in self.include(pattern, base_dir):
            key = _file_key(path)
            if key in self._seen_files:
                continue
            self._seen_files.add(key)
            yield Path(path), text

    # -- resolution ---------------------------------------------------------

    def hosts(self):
        """Enumerate concrete aliases and resolve them with first-match-wins."""
        aliases = []
        defining_block = {}
        for block in self.blocks:
            if block.patterns is None:
                continue
            for pattern in block.patterns:
                if not pattern or pattern.startswith("!"):
                    continue
                if any(character in pattern for character in _WILDCARD_CHARS):
                    continue
                if pattern in defining_block:
                    continue
                defining_block[pattern] = block
                aliases.append(pattern)

        resolved = []
        for alias in aliases:
            options = self._effective_options(alias)
            address = options.get("hostname") or alias
            port = DEFAULT_SSH_PORT
            raw_port = options.get("port")
            if raw_port:
                try:
                    port = int(raw_port)
                except (TypeError, ValueError):
                    port = DEFAULT_SSH_PORT
            block = defining_block[alias]
            resolved.append(
                SshHost(
                    name=alias,
                    address=str(address),
                    port=port,
                    user=str(options.get("user") or ""),
                    source_path=block.source_path,
                    line=block.line,
                )
            )
        return resolved

    def _effective_options(self, alias):
        """First value wins, global options included (OpenSSH order)."""
        values = {}
        for block in self.blocks:
            if block.patterns is not None and not block.matches(alias):
                continue
            for keyword, value, _line, _path in block.options:
                if keyword in ("hostname", "port", "user") and keyword not in values:
                    values[keyword] = value
        return values


def _file_key(path):
    return os.path.normcase(os.path.realpath(str(path)))


def parse_ssh_config_text(text, source_path="", include=None):
    """Parse one SSH config text and return its concrete :class:`SshHost` list.

    ``source_path`` is the file the text came from: it labels diagnostics, is
    used to resolve relative ``Include`` patterns, and is registered as already
    seen so a file cannot include itself.  ``include`` is an optional
    ``callable(pattern, base_dir) -> iterable[(path, text)]`` used by tests (and
    by callers with a virtual filesystem); the default reads real files.
    """
    parser = _SshParser(source_path=str(source_path or ""), include=include)
    parser.parse_text(text or "", source_path=str(source_path or ""))
    return parser.hosts()


def default_ssh_config_paths():
    """The user's SSH client config (the only file worth importing by default)."""
    return [Path.home() / ".ssh" / "config"]


def parse_ssh_config(paths=None):
    """Parse one or more config files, first alias definition winning.

    Missing or unreadable files are skipped, so pointing the importer at a
    default path on a machine without one simply yields an empty list.
    """
    if paths is None:
        candidates = default_ssh_config_paths()
    elif isinstance(paths, (str, os.PathLike)):
        candidates = [paths]
    else:
        candidates = list(paths)

    hosts = []
    seen = set()
    for candidate in candidates:
        path = Path(os.path.expanduser(str(candidate)))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for host in parse_ssh_config_text(text, source_path=str(path)):
            if host.name in seen:
                continue
            seen.add(host.name)
            hosts.append(host)
    return hosts


# -- target helpers ----------------------------------------------------------


def host_to_target(host, interface="", name_prefix=""):
    """Turn an :class:`SshHost` into the target dict the rest of the tool uses."""
    name = f"{name_prefix}{host.name}".strip() or host.address
    return {
        "name": name,
        "address": host.address,
        "interface": str(interface or "").strip(),
        "enabled": True,
    }


def _physical_covering(backend, network, family):
    """The first usable physical ``(interface, network)`` covering *network*."""
    for interface, local_network, _address in backend.local_networks(family):
        if interface and backend.is_usable(interface) and backend.link_kind(interface) == "":
            try:
                if network.subnet_of(local_network):
                    return interface, local_network
            except (AttributeError, TypeError):
                continue
    return None


def _route_reason(backend, address, family):
    """Explain where a non-physical destination is routed right now."""
    lookup = backend.route_lookup(address, family=family)
    if not lookup:
        return "不在本机直连网段内（无匹配路由）"
    interface = str(lookup.get("interface") or "").strip()
    gateway = str(lookup.get("gateway") or "").strip()
    if not interface:
        return "不在本机直连网段内（无匹配路由）"
    if gateway:
        return f"不在本机物理网段内；当前经 {interface}（网关 {gateway}）转发"
    return f"不在本机物理网段内；当前经 {interface} 转发"


def filter_by_backend(targets, backend, include_tunnel=False):
    """Split targets into ``(kept, skipped)`` using physical LAN coverage.

    A target is kept only when its address falls inside a local network that
    :meth:`NetworkBackend.local_networks` reports for an interface that is both
    usable and not a tunnel (``link_kind() == ""``).  Backends deliberately do
    not report VPN networks here, so aTrust-style destinations are rejected by
    the coverage rule rather than by a hardcoded 10/8 exclusion.

    ``include_tunnel=True`` additionally keeps hosts whose only matching route
    leaves through a tunnel interface.  That is an explicit opt-in: pinning such
    a host to a physical NIC usually makes it unreachable, but importing it is
    occasionally useful for diagnostics.

    Each skipped entry is ``{"name", "address", "reason"}`` with a Chinese
    reason naming the interface currently capturing the address (if any).
    """
    kept = []
    skipped = []
    for target in targets or []:
        if not isinstance(target, dict):
            continue
        address = str(target.get("address") or "").strip()
        name = str(target.get("name") or address).strip() or address
        if not address or not valid_local_target(address):
            skipped.append(
                {
                    "name": name,
                    "address": address,
                    "reason": "不是有效的局域网私有地址（仅支持私有 IPv4、ULA 或链路本地地址）",
                }
            )
            continue
        family = family_of(address) or 4
        parsed = parse_ip_or_cidr(address)
        try:
            network = ipaddress.ip_network(
                f"{parsed[1]}/{parsed[2]}", strict=False
            )
        except (TypeError, ValueError):
            network = None
        if network is not None and _physical_covering(backend, network, family):
            kept.append(dict(target))
            continue
        if include_tunnel:
            lookup = backend.route_lookup(address, family=family)
            interface = str((lookup or {}).get("interface") or "").strip()
            if interface and backend.link_kind(interface):
                kept.append(dict(target))
                continue
        skipped.append(
            {
                "name": name,
                "address": address,
                "reason": _route_reason(backend, address, family),
            }
        )
    return kept, skipped