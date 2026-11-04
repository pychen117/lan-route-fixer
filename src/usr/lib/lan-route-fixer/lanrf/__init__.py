"""Reusable, GUI-independent implementation of lan-route-fixer.

Package layout
--------------

``model``       pure data shapes: route entries, destinations, protocol stamps
``targets``     target parsing, validation, normalisation
``config``      config file load/save plus daemon state publication
``backends``    backend protocol and platform selection
``linux``       Linux backend (``ip``, sysfs) and route/rule parsing
``winapi``      ctypes binding of the Windows IP Helper API
``windows``     Windows backend (single routing table, /32 host routes)
``netlink``     rtnetlink event subscription used by the Linux backend
``routing``     interface selection policy
``reconcile``   the pure inspect/plan/apply engine
``checks``      read-only status for the CLI and the GUI
``discovery``   LAN neighbour discovery
``sshconfig``   OpenSSH client config parser and physical-LAN filter
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
    "sshconfig",
    "system",
    "targets",
    "winapi",
    "windows",
]

__version__ = "2.3.0"
