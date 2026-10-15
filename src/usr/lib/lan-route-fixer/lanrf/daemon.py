"""Event driven reconcile daemon.

The 2.0.x design repaired routes on a 30 second systemd timer. That is far too
slow for the failure mode this tool exists to fix: a VPN client that rewrites
the routing table at connect time takes the LAN routes away, and TCP has to
retransmit for the whole gap. This daemon subscribes to rtnetlink, so a route
that appears, disappears or changes interface triggers a reconcile pass within
milliseconds.

Design notes
------------

* The daemon holds **no state of its own**. Every pass re-reads the config
  files, so a change made in the GUI (or by ``lan-route-fixer add``) is picked
  up immediately and no restart is needed.
* Events are *debounced*: a VPN client typically installs several hundred
  routes in a burst, and reconciling once at the end of the burst is both
  faster and less disruptive than reconciling 300 times.
* A poll interval is still honoured as a safety net for a missed kernel
  notification (buffer overflow, netns edge cases, a platform without events).
* Every pass publishes a state file that unprivileged tools can read, which is
  what lets the GUI show real status without asking for a password.
* A second layer watches for the *transition* of tunnel interfaces coming up,
  because that is the exact moment the table is rewritten.
"""

import json
import os
import signal
import time

from . import model, netlink
from .backends import get_backend
from .config import collect_config_paths, load_config, write_state
from .reconcile import apply_actions, build_state, finalize_outcome
from .routing import InterfaceSelector

DEFAULT_POLL_INTERVAL = 10.0  # seconds; only a fallback for missed events
DEBOUNCE_SECONDS = 0.25
MAX_DEBOUNCE_SECONDS = 2.0
STATE_MIN_INTERVAL = 1.0  # never write the state file more often than this
EVENT_POLL_TIMEOUT = 5.0

# Interface name prefixes that indicate a VPN/tunnel link. Seeing one come up
# is a strong hint that the main routing table is about to be rewritten.
TUNNEL_PREFIXES = (
    "utun",
    "tun",
    "tap",
    "wg",
    "tailscale",
    "ppp",
    "ipsec",
    "ovpn",
    "vpn",
    "zt",
    "gpd",
    "proton",
    "mullvad",
    "surfshark",
)

# Reasons recorded in the state file, in decreasing order of interest.
REASON_START = "startup"
REASON_EVENT = "route-event"
REASON_TUNNEL = "tunnel-change"
REASON_POLL = "poll"
REASON_TRIGGER = "trigger"
REASON_CONFIG = "config-change"


def is_tunnel_name(name):
    lowered = str(name or "").lower()
    return any(lowered.startswith(prefix) for prefix in TUNNEL_PREFIXES)


class ReconcileDaemon:
    """Watches the kernel and keeps every configured route in place."""

    def __init__(
        self,
        backend=None,
        config_paths=None,
        poll_interval=DEFAULT_POLL_INTERVAL,
        dry_run=False,
        logger=None,
        monitor_factory=None,
    ):
        self.backend = backend or get_backend()
        self.config_paths = list(config_paths) if config_paths is not None else None
        self.poll_interval = float(poll_interval or DEFAULT_POLL_INTERVAL)
        self.dry_run = bool(dry_run)
        self.logger = logger or (lambda message, level="info": None)
        self.selector = InterfaceSelector(self.backend)
        self._monitor_factory = monitor_factory
        self._stop = False
        self._monitor = None
        self.stats = {
            "passes": 0,
            "changes": 0,
            "failures": 0,
            "events": 0,
            "last_reason": "",
            "last_change_at": 0.0,
            "started_at": time.time(),
        }
        self._last_state_write = 0.0
        self._config_fingerprint = None
        self._last_report = {}
        # GLib-mode state (see bind_glib/run_glib).
        self._glib = None
        self._gio = None
        self._service = None
        self._loop = None
        self._debouncing = False
        self._pending_reason = None
        self._deadline = 0.0

    # -- lifecycle ----------------------------------------------------------

    def request_stop(self, *_args):
        self._stop = True
        if self._loop is not None and self._loop.is_running():
            self._loop.quit()

    def install_signal_handlers(self, glib=None):
        """Trap SIGTERM/SIGINT/SIGHUP.

        Under GLib the handler must be registered the GLib way, otherwise the
        Python-level handler is deferred until the loop happens to wake up and
        ``systemctl stop`` looks like a hang.
        """
        for signal_name in ("SIGTERM", "SIGINT", "SIGHUP"):
            number = getattr(signal, signal_name, None)
            if number is None:
                continue
            if glib is not None and self._add_glib_signal(glib, number):
                continue
            try:
                signal.signal(number, self.request_stop)
            except (ValueError, OSError):  # pragma: no cover - non-main thread
                pass

    @staticmethod
    def _add_glib_signal(glib, number):
        """Register a GLib signal source, tolerating API drift."""
        import warnings

        candidates = []
        try:  # GLib >= 2.74 moved this into GLibUnix
            from gi.repository import GLibUnix

            candidates.append(GLibUnix.signal_add)
        except (ImportError, AttributeError):  # pragma: no cover
            pass
        if hasattr(glib, "unix_signal_add"):
            candidates.append(glib.unix_signal_add)
        for candidate in candidates:
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    candidate(glib.PRIORITY_DEFAULT, number, self.request_stop)
                return True
            except Exception:  # noqa: BLE001 - fall back to signal.signal
                continue
        return False

    def _open_monitor(self):
        if self._monitor_factory is not None:
            return self._monitor_factory()
        if not netlink.available():
            return None
        return netlink.RouteMonitor()

    # -- reconciliation -----------------------------------------------------

    def _load_targets(self):
        """Re-read every config file; returns ``(targets, config, fingerprint)``."""
        from .system import collect_targets

        paths = self.config_paths if self.config_paths is not None else collect_config_paths()
        paths = list(paths or [])
        targets, config = collect_targets(paths)
        fingerprint = []
        for path in paths:
            try:
                stat = os.stat(path)
            except OSError:
                continue
            fingerprint.append((str(path), stat.st_mtime_ns, stat.st_size))
        return targets, config, tuple(fingerprint)

    def pass_once(self, reason=REASON_POLL):
        """Run one inspect/plan/apply/verify cycle and publish the result."""
        started = time.monotonic()
        targets, config, fingerprint = self._load_targets()
        if hasattr(self.backend, "invalidate"):
            self.backend.invalidate()

        if not targets:
            report = {
                "ok": True,
                "bad": 0,
                "failed": 0,
                "changed": 0,
                "unchanged": 0,
                "targets": 0,
                "elapsed_ms": 0.0,
                "snapshots": [],
                "errors": [],
                "details": [],
                "routing_mode": config.routing_mode,
                "rule_table": config.rule_table,
            }
        else:
            snapshots, actions = build_state(
                targets, config, self.backend, selector=self.selector, dry_run=self.dry_run
            )
            outcome = apply_actions(actions, self.backend, dry_run=self.dry_run)
            if actions and not self.dry_run and outcome["failed"] == 0:
                # Verify instead of trusting the plan: a VPN client may have
                # re-asserted its table the instant we finished.
                if hasattr(self.backend, "invalidate"):
                    self.backend.invalidate()
                snapshots, _extra = build_state(
                    targets, config, self.backend, selector=self.selector, dry_run=True
                )
            report = finalize_outcome(outcome, snapshots, config, dry_run=self.dry_run)
            report["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)

        self._config_fingerprint = fingerprint
        self.stats["passes"] += 1
        self.stats["last_reason"] = reason
        if report.get("changed"):
            self.stats["changes"] += 1
            self.stats["last_change_at"] = time.time()
        self.stats["failures"] += int(report.get("failed", 0))
        self._last_report = report

        for error in report.get("errors", []):
            self.logger(f"repair failed: {error}", "error")

        if reason != REASON_POLL or not report.get("ok"):
            self.logger(
                "reconcile({reason}): targets={targets} bad={bad} changed={changed} "
                "unchanged={unchanged} failed={failed} in {elapsed_ms}ms".format(
                    reason=reason,
                    targets=report.get("targets", 0),
                    bad=report.get("bad", 0),
                    changed=report.get("changed", 0),
                    unchanged=report.get("unchanged", 0),
                    failed=report.get("failed", 0),
                    elapsed_ms=report.get("elapsed_ms", 0.0),
                )
            )
        self._write_state(force=reason != REASON_POLL)
        return report

    def run_once(self, reason=REASON_TRIGGER):
        self.pass_once(reason=reason)
        return self._last_report

    # -- state --------------------------------------------------------------

    def export_state(self, reason=None):
        report = self._last_report or {}
        return {
            "version": 1,
            "pid": os.getpid(),
            "running": not self._stop,
            "reason": reason or self.stats["last_reason"],
            "started_at": self.stats["started_at"],
            "updated_at": time.time(),
            "dry_run": self.dry_run,
            "interval_seconds": self.poll_interval,
            "routing_mode": report.get("routing_mode", ""),
            "rule_table": report.get("rule_table"),
            "backend": getattr(self.backend, "name", "unknown"),
            "events_supported": bool(getattr(self.backend, "supports_events", False)),
            "stats": dict(self.stats),
            "ok": bool(report.get("ok", True)),
            "bad": int(report.get("bad", 0)),
            "targets": report.get("targets", 0),
            "changed": int(report.get("changed", 0)),
            "failed": int(report.get("failed", 0)),
            "elapsed_ms": report.get("elapsed_ms", 0.0),
            "errors": list(report.get("errors", []))[:20],
            "snapshots": [
                {
                    "name": snapshot.get("name"),
                    "address": snapshot.get("address"),
                    "state": snapshot.get("state"),
                    "ok": snapshot.get("ok"),
                    "desired": snapshot.get("desired"),
                    "current": snapshot.get("current"),
                    "reason": snapshot.get("reason"),
                }
                for snapshot in report.get("snapshots", [])
            ],
        }

    def _write_state(self, force=False):
        now = time.time()
        if not force and now - self._last_state_write < STATE_MIN_INTERVAL:
            return
        self._last_state_write = now
        write_state(self.export_state())

    # -- main loop ----------------------------------------------------------

    def _classify_events(self, events):
        """Return the reconcile reason implied by a batch of kernel events.

        A tunnel interface coming up is the moment the main table is rewritten,
        so it deserves its own label: it is the single most useful line in the
        log when a user reports "my SSH session dies when the VPN connects".
        """
        self.stats["events"] += len(events)
        reason = REASON_EVENT
        for event in events:
            if event.is_link and is_tunnel_name(event.ifname):
                reason = REASON_TUNNEL
                break
        return reason

    def run(self):
        """Blocking main loop. Returns the process exit code."""
        self.install_signal_handlers()
        self._monitor = self._open_monitor()
        if self._monitor is None:
            self.logger(
                "kernel route notifications are unavailable; "
                f"falling back to polling every {self.poll_interval:g}s",
                "warning",
            )
        else:
            self.logger("watching rtnetlink for route and link changes")

        self.pass_once(reason=REASON_START)
        deadline = time.monotonic() + self.poll_interval
        while not self._stop:
            timeout = max(0.05, min(deadline - time.monotonic(), EVENT_POLL_TIMEOUT))
            try:
                if self._monitor is not None:
                    events = self._monitor.wait(timeout=timeout)
                else:
                    time.sleep(timeout)
                    events = []
            except InterruptedError:  # pragma: no cover
                continue
            if self._stop:
                break

            if events:
                reason = self._classify_events(events)
                self._debounce()
                self.pass_once(reason=reason)
                deadline = time.monotonic() + self.poll_interval
                continue

            if time.monotonic() >= deadline:
                self.pass_once(reason=REASON_POLL)
                deadline = time.monotonic() + self.poll_interval

        self.logger("daemon stopping")
        self.stop()
        return 0

    def _debounce(self):
        """Absorb the rest of an event burst before reconciling.

        A VPN client installs several hundred routes when it connects; acting
        once at the end of that burst is both faster and less disruptive than
        acting 300 times.
        """
        if self._monitor is None:
            return
        started = time.monotonic()
        while not self._stop:
            try:
                events = self._monitor.wait(timeout=DEBOUNCE_SECONDS)
            except InterruptedError:  # pragma: no cover
                return
            if not events:
                return
            self.stats["events"] += len(events)
            if time.monotonic() - started >= MAX_DEBOUNCE_SECONDS:
                return

    # -- GLib event loop ----------------------------------------------------
    #
    # The CLI runs the loop above, which blocks in select(). Under systemd the
    # daemon instead runs inside a GLib main loop so it can also answer D-Bus
    # calls. Both paths funnel into the same pass_once(), so the routing
    # behaviour is identical; only the event source differs.

    def bind_glib(self, glib, gio, service=None):
        """Attach the daemon to a GLib main loop.

        ``service`` is the :class:`lanrf.dbus.DaemonService` used to publish
        state changes; it may be ``None`` when only the event loop is wanted.
        """
        self._glib = glib
        self._gio = gio
        self._service = service
        self._debouncing = False
        self._deadline = time.monotonic() + self.poll_interval
        self.install_signal_handlers(glib=glib)
        if self._monitor is None:
            self._monitor = self._open_monitor()
        if self._monitor is not None:
            glib.io_add_watch(
                self._monitor.fileno, glib.IOCondition.IN, self._on_monitor_ready
            )
            self.logger("watching rtnetlink for route and link changes")
        else:
            self.logger(
                "kernel route notifications are unavailable; "
                f"falling back to polling every {self.poll_interval:g}s",
                "warning",
            )
        glib.timeout_add_seconds(1, self._on_tick)
        return self

    def _on_monitor_ready(self, _fd, _condition):
        if self._stop:
            return False
        try:
            events = self._monitor.wait(timeout=0)
        except (InterruptedError, OSError):  # pragma: no cover
            return False
        if not events:
            return True
        self._pending_reason = self._classify_events(events)
        # Debounce with a short one-shot timer instead of blocking the loop:
        # a VPN client installs hundreds of routes in a burst and we want to
        # act once, at the end of it.
        if not self._debouncing:
            self._debouncing = True
            self._glib.timeout_add(
                int(DEBOUNCE_SECONDS * 1000), self._finish_debounce
            )
        return True

    def _finish_debounce(self):
        self._debouncing = False
        if self._stop:
            return False
        reason = getattr(self, "_pending_reason", REASON_EVENT)
        self._pending_reason = None
        self.run_pass(reason)
        self._deadline = time.monotonic() + self.poll_interval
        return False

    def _on_tick(self):
        if self._stop:
            self._glib.timeout_add_seconds(1, self._on_tick)
            return False
        if time.monotonic() >= self._deadline and not self._debouncing:
            self.run_pass(REASON_POLL)
            self._deadline = time.monotonic() + self.poll_interval
        return True

    def run_pass(self, reason=REASON_POLL):
        """One pass plus signal/state publication; used by the GLib loop."""
        try:
            return self.pass_once(reason=reason)
        finally:
            if self._service is not None:
                self._service.publish()

    def run_glib(self):
        """Run under a GLib main loop (systemd/D-Bus mode)."""
        from . import dbus as dbus_module

        if not dbus_module.AVAILABLE:  # pragma: no cover
            raise RuntimeError("python3-gi is required for the D-Bus daemon")
        if not getattr(self.backend, "is_privileged", True):
            # Publishing a control interface that cannot repair anything would
            # be worse than not publishing one: the GUI would call it, not get
            # its routes fixed, and fall back to a password prompt anyway.
            # Worse, owning the name would block the real root daemon from
            # answering later.
            self.logger(
                "not running as root: watching only, without the D-Bus control "
                "interface (start lan-route-fixer-daemon.service instead)",
                "warning",
            )
            return self.run()
        glib, gio = dbus_module.GLib, dbus_module.Gio
        self._loop = glib.MainLoop()
        service = dbus_module.DaemonService(self)
        self.bind_glib(glib, gio, service=service)
        service._loop = self._loop
        service.start()
        self.run_pass(REASON_START)
        dbus_module.systemd_notify("READY=1\nSTATUS=watching the routing table")
        try:
            self._loop.run()
        finally:
            service.stop()
            self.stop()
        return 0

    def stop(self):
        self._stop = True
        self._write_state(force=True)
        if self._monitor is not None:
            self._monitor.close()
            self._monitor = None


def run_once(config_paths=None, dry_run=False, reason=REASON_TRIGGER, logger=None):
    """One-shot reconciliation, used by systemd and the dispatcher."""
    daemon = ReconcileDaemon(
        config_paths=config_paths, dry_run=dry_run, logger=logger
    )
    return daemon.run_once(reason=reason)


def main(argv=None):
    """Entry point of the ``lan-route-fixer daemon`` sub-command."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="lan-route-fixer daemon",
        description="Watch the routing table and keep LAN routes pinned to the physical NIC.",
    )
    parser.add_argument("--config", action="append", default=[], help="extra config file")
    parser.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_POLL_INTERVAL,
        help="polling fallback interval in seconds",
    )
    parser.add_argument("--once", action="store_true", help="reconcile once and exit")
    parser.add_argument("--dry-run", action="store_true", help="report, do not change")
    parser.add_argument("--quiet", action="store_true", help="log only problems")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    parser.add_argument(
        "--dbus",
        action="store_true",
        help="also serve the D-Bus control interface (used by the GUI; "
        "requires python3-gi and a system bus)",
    )
    args = parser.parse_args(argv)

    def logger(message, level="info"):
        if args.quiet and level == "info":
            return
        print(f"{time.strftime('%H:%M:%S')} [{level}] {message}", flush=True)

    daemon = ReconcileDaemon(
        config_paths=args.config or None,
        poll_interval=args.interval,
        dry_run=args.dry_run,
        logger=logger,
    )
    if args.once:
        report = daemon.run_once()
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
        return 0 if report.get("failed", 0) == 0 else 1
    if args.dbus:
        try:
            return daemon.run_glib()
        except RuntimeError as exception:
            logger(f"{exception}; continuing without D-Bus", "warning")
    return daemon.run()
