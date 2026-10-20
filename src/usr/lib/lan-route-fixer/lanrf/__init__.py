"""Reusable, GUI-independent implementation of lan-route-fixer.

Package layout
--------------

``model``       pure data shapes: route entries, destinations, protocol stamps
``targets``     target parsing, validation, normalisation
``config``      config file load/save plus daemon state publication
``backends``    backend protocol and platform selection
``linux``       Linux backend (``ip``, sysfs) and route/rule parsing
``windows``     Windows backend skeleton (IP Helper API mapping)
``netlink``     rtnetlink event subscription used by the Linux backend
``routing``     interface selection policy
``reconcile``   the pure inspect/plan/apply engine
``checks``      read-only status for the CLI and the GUI
``discovery``   LAN neighbour discovery
``cleanup``     garbage collection for routes/rules and stale targets
``privileged``  client side of the PolicyKit boundary
``helper``      inside of the trust boundary: validation + kernel mutations
``system``      multi-config reconciliation for root-owned background paths
``daemon``      event driven repair loop
``doctor``      diagnostics
``cli``         command line interface
"""

__all__ = [
    "backends",
    "checks",
    "cleanup",
    "cli",
    "config",
    "daemon",
    "discovery",
    "doctor",
    "helper",
    "linux",
    "model",
    "netlink",
    "privileged",
    "reconcile",
    "routing",
    "system",
    "targets",
    "windows",
]

__version__ = "2.2.1"
