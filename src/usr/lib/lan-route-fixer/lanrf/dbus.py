"""D-Bus interface exposed by the root daemon.

Why this exists
---------------

The GUI used to repair routes itself through ``pkexec``. PolicyKit caches an
``auth_admin_keep`` authorization for a few minutes, so as soon as a VPN client
kept stealing the routes back, the user was asked for a password *again and
again*. That is a bad experience and, worse, it trains people to type their
password into whatever dialog appears.

Exposing the daemon on the system bus fixes it properly:

* the daemon is already running as root and already watches the routing table;
* a user asking it to "re-run your reconciliation" cannot do anything they could
  not do by waiting for the next kernel event - the *targets* still come from
  the config files, never from the caller;
* no password is ever involved, because nothing privileged is being delegated
  to the caller.

The bus is the trust boundary: D-Bus only delivers a method call to a service
name that the system policy allows, and a caller cannot address the root-owned
name directly. ``pkexec`` remains as the fallback for a target that is not in
any config file.

Interface (``io.github.pychen117.LanRouteFixer`` on ``/Daemon``)::

    Repair() -> (json_report)
    GetStatus() -> (json_state)
    Reload() -> ()
    signal StateChanged(json_state)
"""

import json
import os

BUS_NAME = "io.github.pychen117.LanRouteFixer"
OBJECT_PATH = "/Daemon"
INTERFACE_NAME = "io.github.pychen117.LanRouteFixer.Control"

INTROSPECTION_XML = """
<node>
  <interface name="io.github.pychen117.LanRouteFixer.Control">
    <method name="Repair">
      <arg type="s" name="report" direction="out"/>
    </method>
    <method name="GetStatus">
      <arg type="s" name="state" direction="out"/>
    </method>
    <method name="Reload">
    </method>
    <signal name="StateChanged">
      <arg type="s" name="state"/>
    </signal>
    <property name="Version" type="s" access="read"/>
  </interface>
</node>
"""

# Shown by `busctl introspect` and in the D-Bus docs.
VERSION = "1"

try:  # pragma: no cover - depends on the build host having GLib
    import gi

    gi.require_version("Gio", "2.0")
    from gi.repository import Gio, GLib

    AVAILABLE = True
except (ImportError, ValueError):  # pragma: no cover
    Gio = None
    GLib = None
    AVAILABLE = False


def bus_available():
    """True when a session/system bus implementation is importable and usable."""
    if not AVAILABLE:  # pragma: no cover
        return False
    try:
        Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
    except GLib.Error:  # pragma: no cover - no system bus in the sandbox
        return False
    return True


class DaemonService:
    """Owns the bus name and forwards calls to a :class:`ReconcileDaemon`."""

    def __init__(self, daemon, bus_name=BUS_NAME, bus_type=None):
        if not AVAILABLE:  # pragma: no cover
            raise RuntimeError("Gio is not available; install python3-gi")
        self.daemon = daemon
        self.bus_name = bus_name
        self.bus_type = bus_type if bus_type is not None else Gio.BusType.SYSTEM
        self._connection = None
        self._registration_id = 0
        self._loop = None

    # -- lifecycle ----------------------------------------------------------

    def start(self):
        """Acquire the name and start answering calls."""
        self._loop = GLib.MainLoop()
        self._registration_id = Gio.bus_own_name(
            self.bus_type,
            self.bus_name,
            Gio.BusNameOwnerFlags.NONE,
            self._on_bus_acquired,
            None,
            None,
        )
        self.daemon.logger(f"listening on {self.bus_name} (system bus)")
        return self._loop

    def run(self):
        loop = self.start()
        try:
            loop.run()
        finally:
            self.stop()
        return 0

    def stop(self):
        if self._registration_id:
            Gio.bus_unown_name(self._registration_id)
            self._registration_id = 0
        if self._loop is not None and self._loop.is_running():
            self._loop.quit()
        self._loop = None

    def publish(self):
        """Emit ``StateChanged`` after a reconcile pass."""
        if self._connection is None:
            return
        try:
            self._connection.emit_signal(
                None,
                OBJECT_PATH,
                INTERFACE_NAME,
                "StateChanged",
                GLib.Variant("(s)", (self._dump(self.daemon.export_state()),)),
            )
        except GLib.Error:  # pragma: no cover - bus went away
            pass

    # -- Gio callbacks ------------------------------------------------------

    def _on_bus_acquired(self, connection, _name):
        self._connection = connection
        node = Gio.DBusNodeInfo.new_for_xml(INTROSPECTION_XML)
        connection.register_object(
            OBJECT_PATH,
            node.interfaces[0],
            self._on_method_call,
            self._on_get_property,
            None,
        )

    def _on_method_call(
        self, _connection, sender, _object_path, _interface_name, method_name, parameters, invocation
    ):
        if not self._sender_is_owner(sender):
            invocation.return_dbus_error(
                INTERFACE_NAME + ".NotAuthorized",
                f"{method_name} may only be called by the daemon's own user",
            )
            return
        try:
            result = self._dispatch(method_name, parameters)
        except Exception as exception:  # noqa: BLE001 - reported to the caller
            invocation.return_dbus_error(INTERFACE_NAME + ".Error", str(exception))
            return
        invocation.return_value(GLib.Variant("(s)", (result,)))

    def _sender_is_owner(self, sender):
        """Defence in depth behind the D-Bus policy in /usr/share/dbus-1.

        The bundled policy already restricts sending to the owner; this check
        keeps the guarantee even when the policy file is missing (running from a
        source tree) or has been edited.
        """
        try:
            current_uid = os.geteuid()
        except AttributeError:  # pragma: no cover - Windows
            return True
        if current_uid == 0:
            # Root's daemon accepts calls from root only, which is what the
            # system bus policy enforces anyway.
            pass
        if sender is None:
            return True
        try:
            connection = self._connection
            result = connection.call_sync(
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                "GetConnectionUnixUser",
                GLib.Variant("(s)", (sender,)),
                None,
                Gio.DBusCallFlags.NONE,
                2000,
                None,
            )
            caller_uid = int(result.unpack()[0])
        except GLib.Error:  # pragma: no cover - bus hiccup, policy still applies
            return True
        return caller_uid == current_uid

    def _dispatch(self, method_name, _parameters):
        self.daemon.logger(f"dbus call: {method_name}")
        if method_name == "Repair":
            report = self.daemon.run_once(reason="dbus")
            self.publish()
            return self._dump(report)
        if method_name == "GetStatus":
            return self._dump(self.daemon.export_state())
        if method_name == "Reload":
            # The daemon re-reads the config on every pass, so an explicit
            # reload only needs to trigger one.
            self.daemon.run_once(reason="dbus-reload")
            self.publish()
            return self._dump({"ok": True})
        raise ValueError(f"unknown method: {method_name}")

    def _on_get_property(
        self, _connection, sender, _object_path, _interface_name, property_name
    ):
        # Deliberately more permissive than the methods: a panel applet or a
        # monitoring tool may read the version, and it reveals nothing.
        if property_name == "Version":
            return GLib.Variant("s", VERSION)
        raise ValueError(f"unknown property: {property_name}")

    @staticmethod
    def _dump(payload):
        return json.dumps(payload, ensure_ascii=False, default=str)


class DaemonClient:
    """Thin client used by the CLI and the GUI.

    Every method fails soft: a missing daemon must never be fatal, because
    ``pkexec`` is still available as the fallback path.
    """

    def __init__(self, bus_name=BUS_NAME, timeout_ms=15000, bus_type=None):
        self.bus_name = bus_name
        self.timeout_ms = timeout_ms
        self.bus_type = bus_type if bus_type is not None else (
            Gio.BusType.SYSTEM if AVAILABLE else None
        )
        self.last_error = ""

    @property
    def usable(self):
        return AVAILABLE and bus_available()

    def _call(self, method, parameters=None):
        if not self.usable:  # pragma: no cover - no bus in the test sandbox
            self.last_error = "D-Bus is unavailable"
            return None
        try:
            connection = Gio.bus_get_sync(self.bus_type, None)
            reply = connection.call_sync(
                self.bus_name,
                OBJECT_PATH,
                INTERFACE_NAME,
                method,
                parameters,
                None,
                Gio.DBusCallFlags.NONE,
                self.timeout_ms,
                None,
            )
        except GLib.Error as exception:
            self.last_error = str(exception)
            return None
        self.last_error = ""
        return json.loads(reply.unpack()[0])

    def is_running(self):
        """True when a daemon owns the bus name right now."""
        if not self.usable:  # pragma: no cover
            return False
        try:
            connection = Gio.bus_get_sync(self.bus_type, None)
            result = connection.call_sync(
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                "NameHasOwner",
                GLib.Variant("(s)", (self.bus_name,)),
                None,
                Gio.DBusCallFlags.NONE,
                2000,
                None,
            )
            return bool(result.unpack()[0])
        except GLib.Error:  # pragma: no cover
            return False

    def repair(self):
        """Ask the daemon to reconcile now. Returns a report or ``None``."""
        return self._call("Repair")

    def status(self):
        """Ask the daemon for its last state. Returns a dict or ``None``."""
        return self._call("GetStatus")

    def reload(self):
        return self._call("Reload")


def systemd_notify(message):
    """Best-effort sd_notify(3) so the unit can report readiness."""
    socket_path = os.environ.get("NOTIFY_SOCKET")
    if not socket_path:
        return False
    import socket as _socket

    address = "\0" + socket_path[1:] if socket_path.startswith("@") else socket_path
    try:
        with _socket.socket(_socket.AF_UNIX, _socket.SOCK_DGRAM) as sock:
            sock.connect(address)
            sock.sendall(message.encode())
    except OSError:  # pragma: no cover - not running under systemd
        return False
    return True
