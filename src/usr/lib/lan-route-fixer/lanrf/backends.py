"""Platform backend selection.

The rest of the package talks to a backend through the small duck-typed
interface documented on :class:`NetworkBackend`. Adding Windows support means
implementing that interface with the IP Helper API (ctypes) and registering it
in :func:`get_backend`; no other module has to change.
"""

import sys

from . import model  # noqa: F401  (re-exported for convenience)


class NetworkBackend:
    """Interface every platform backend implements.

    Queries (read-only, never require privileges):

    * ``link_kind(interface) -> str``
    * ``is_usable(interface) -> bool``
    * ``list_interfaces(only_up=False) -> [str]``
    * ``local_networks(family=4) -> [(interface, network, address)]``
    * ``default_interfaces() -> [str]`` (best metric first)
    * ``route_lookup(destination, family=4) -> dict | None``
    * ``routes(table="main", family=4) -> [model.route_entry]``
    * ``route_prefixes(table="main", family=4) -> {str}``
    * ``rules(family=4) -> [dict]``

    Mutations (require privileges):

    * ``ensure_route(item) -> (changed, detail)``
    * ``remove_route(item) -> bool``
    * ``ensure_rule(match, table, family=4, preference=1200) -> (changed, detail)``
    * ``remove_rule(match, table, family=4) -> bool``

    Capability flags let the reconciler degrade gracefully:

    * ``supports_policy_rules`` -- can install ``ip rule`` style policy routing
    * ``supports_events`` -- can raise route changes without polling
    """

    name = "unsupported"
    supports_policy_rules = False
    supports_events = False


class UnsupportedBackend(NetworkBackend):
    """Placeholder backend used on platforms without an implementation.

    It answers every query with an empty result instead of raising, so the CLI
    and the GUI still start and can explain what is missing. Mutations raise so
    a bug can never silently pretend a route was installed.
    """

    name = "unsupported"

    def __init__(self, platform=None):
        self.platform = platform or sys.platform

    def _refuse(self, *_args, **_kwargs):
        raise NotImplementedError(
            f"lan-route-fixer has no network backend for {self.platform!r}"
        )

    def link_kind(self, _interface):
        return ""

    def is_usable(self, _interface):
        return False

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

    ensure_route = _refuse
    remove_route = _refuse
    ensure_rule = _refuse
    remove_rule = _refuse


_BACKEND = None


def get_backend(refresh=False):
    """Return the process-wide backend for the current platform."""
    global _BACKEND
    if _BACKEND is not None and not refresh:
        return _BACKEND
    if sys.platform.startswith("linux"):
        from .linux import LinuxBackend

        _BACKEND = LinuxBackend()
    elif sys.platform.startswith("win"):
        from .windows import WindowsBackend

        _BACKEND = WindowsBackend()
    else:
        _BACKEND = UnsupportedBackend()
    return _BACKEND


def set_backend(backend):
    """Override the active backend (used by tests)."""
    global _BACKEND
    _BACKEND = backend
    return backend
