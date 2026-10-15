"""Configuration loading, saving and discovery.

Backwards compatible with 2.0.x config files: unknown keys are preserved on
save, missing keys fall back to :data:`DEFAULT_CONFIG`, and the historical
``ip`` alias for ``address`` still loads.
"""

import json
import os
import sys
from pathlib import Path

from .targets import normalize_targets

APP_ID = "io.github.pychen117.LanRouteFixer"
APP_DISPLAY_NAME = "局域网路由修复"
APP_DESCRIPTION = "让所选局域网设备绕过 VPN 隧道，保持直连"

CONFIG_HOME = Path(
    os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
).expanduser()
CONFIG_PATH = CONFIG_HOME / "lan-route-fixer/config.json"
AUTOSTART_PATH = CONFIG_HOME / "autostart/lan-route-fixer.desktop"
SYSTEM_CONFIG_PATH = Path(
    os.environ.get("LAN_ROUTE_FIXER_SYSTEM_CONFIG", "/etc/lan-route-fixer/config.json")
)
SYSTEM_CONFIG_DIR = SYSTEM_CONFIG_PATH.parent

# Where discovery records when each address was last seen, so targets that have
# vanished from the LAN can be offered for cleanup (see lanrf.cleanup).
DISCOVERY_CACHE_PATH = CONFIG_HOME / "lan-route-fixer/discovered.json"

# State written by the root daemon and read by unprivileged clients.
STATE_PATH = Path(
    os.environ.get("LAN_ROUTE_FIXER_STATE", "/run/lan-route-fixer/state.json")
)
FALLBACK_STATE_PATH = CONFIG_HOME / "lan-route-fixer/state.json"

DEFAULT_CONFIG = {
    "targets": [],
    # How often a polling fallback re-checks the routing table. The daemon is
    # event driven; this value only bounds how long a *missed* kernel event can
    # go unnoticed, so it is deliberately much shorter than 2.0.x's 30s.
    "interval_seconds": 10,
    "auto_fix": True,
    "autostart": False,
    # "rule": install a high-priority policy rule pointing at `rule_table` so a
    #         VPN rewriting the main table cannot displace our routes.
    # "main": legacy 2.0.x behaviour, only `ip route replace` in the main table.
    "routing_mode": "rule",
    "rule_table": 168,
    "rule_preference": 1200,
    # Expand a bare host target into its covering prefix (e.g. 192.168.4.234/32
    # -> 192.168.4.0/24). Off by default: it protects more than intended.
    "expand_host_targets": False,
    # Extra local ports to probe when diagnosing connectivity (debug aid).
    "log_level": "info",
    # Disabled targets that have not been seen on the LAN for this many days are
    # offered for cleanup. Never applied automatically.
    "prune_after_days": 30,
}

# Keys copied verbatim from a saved file when the type looks right.
_PASSTHROUGH_KEYS = (
    "interval_seconds",
    "auto_fix",
    "autostart",
    "routing_mode",
    "rule_table",
    "rule_preference",
    "expand_host_targets",
    "log_level",
    "prune_after_days",
)

VALID_ROUTING_MODES = ("rule", "main")


class Config:
    """A loaded configuration file plus the path it came from."""

    def __init__(self, data=None, path=None):
        self.data = dict(DEFAULT_CONFIG)
        self.path = Path(path) if path else CONFIG_PATH
        self.unknown = {}
        if isinstance(data, dict):
            self._merge(data)

    def _merge(self, saved):
        for key, value in saved.items():
            if key == "targets":
                continue
            if key in _PASSTHROUGH_KEYS:
                self.data[key] = value
            else:
                self.unknown[key] = value
        self.data["targets"] = normalize_targets(saved.get("targets", []))

    # -- accessors ----------------------------------------------------------

    @property
    def targets(self):
        return self.data.get("targets", [])

    @property
    def enabled_targets(self):
        return [target for target in self.targets if target.get("enabled")]

    @property
    def auto_fix(self):
        return bool(self.data.get("auto_fix", True))

    @property
    def interval_seconds(self):
        try:
            return max(2, int(self.data.get("interval_seconds", 10)))
        except (TypeError, ValueError):
            return 10

    @property
    def routing_mode(self):
        mode = str(self.data.get("routing_mode", "rule")).strip().lower()
        return mode if mode in VALID_ROUTING_MODES else "rule"

    @property
    def policy_routing(self):
        return self.routing_mode == "rule"

    @property
    def rule_table(self):
        try:
            table = int(self.data.get("rule_table", 168))
        except (TypeError, ValueError):
            return 168
        # 253/254/255 are default/main/local; the helper refuses them, so treat
        # them as invalid here rather than failing later at apply time.
        return table if 1 <= table <= 252 else 168

    @property
    def rule_preference(self):
        try:
            preference = int(self.data.get("rule_preference", 1200))
        except (TypeError, ValueError):
            return 1200
        return preference if 1 <= preference <= 32000 else 1200

    @property
    def expand_host_targets(self):
        return bool(self.data.get("expand_host_targets", False))

    @property
    def prune_after_days(self):
        try:
            days = int(self.data.get("prune_after_days", 30))
        except (TypeError, ValueError):
            return 30
        return max(1, days)

    # -- persistence --------------------------------------------------------

    def to_dict(self):
        payload = dict(self.unknown)
        payload.update(
            {
                "targets": self.targets,
                "interval_seconds": self.data.get("interval_seconds", 10),
                "auto_fix": self.data.get("auto_fix", True),
                "autostart": self.data.get("autostart", False),
                "routing_mode": self.data.get("routing_mode", "rule"),
                "rule_table": self.data.get("rule_table", 168),
                "rule_preference": self.data.get("rule_preference", 1200),
                "expand_host_targets": self.data.get("expand_host_targets", False),
                "prune_after_days": self.data.get("prune_after_days", 30),
            }
        )
        return payload

    def save(self, path=None):
        """Atomically write the config. Returns True on success."""
        config_path = Path(path) if path else self.path
        try:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = config_path.with_name(config_path.name + ".tmp")
            with temporary.open("w", encoding="utf-8") as config_file:
                json.dump(self.to_dict(), config_file, ensure_ascii=False, indent=2)
                config_file.write("\n")
                config_file.flush()
                os.fsync(config_file.fileno())
            os.replace(temporary, config_path)
        except OSError:
            return False
        return True

    def set_targets(self, targets):
        self.data["targets"] = normalize_targets(targets)
        return self.targets


def load_config(path=None):
    """Return a :class:`Config`, or a default one when the file is unreadable."""
    config_path = Path(path) if path else CONFIG_PATH
    try:
        with config_path.open(encoding="utf-8") as config_file:
            saved = json.load(config_file)
    except (OSError, json.JSONDecodeError):
        saved = {}
    if not isinstance(saved, dict):
        saved = {}
    return Config(saved, path=config_path)


def save_config(config, path=None):
    """Save either a :class:`Config` or the plain dict the GUI keeps in memory."""
    if isinstance(config, Config):
        return config.save(path)
    target_path = Path(path) if path else CONFIG_PATH
    return Config(config, path=target_path).save(target_path)


def collect_config_paths(extra_paths=()):
    """All config files that currently exist: system, then the caller's own.

    Root additionally sees every user's file, because the daemon has to protect
    targets configured by anyone. An ordinary user only gets the system config
    plus their own: reading (let alone rewriting) another user's file is not
    this tool's business, and it keeps unprivileged runs predictable.
    """
    paths = []
    for candidate in (SYSTEM_CONFIG_PATH, *(Path(p) for p in extra_paths)):
        if candidate.is_file() and candidate not in paths:
            paths.append(candidate)
    try:
        import pwd
    except ImportError:  # pragma: no cover - Windows
        pwd = None
    if pwd is not None:
        try:
            current_uid = os.geteuid()
        except AttributeError:  # pragma: no cover - non-POSIX
            current_uid = 0
        for entry in pwd.getpwall():
            if 0 < entry.pw_uid < 1000:
                continue
            if current_uid != 0 and entry.pw_uid != current_uid:
                continue
            if entry.pw_uid == current_uid:
                # The caller's own file is CONFIG_PATH, which honours
                # XDG_CONFIG_HOME; the hardcoded ~/.config path would ignore it.
                candidate = CONFIG_PATH
            else:
                candidate = Path(entry.pw_dir or "") / ".config/lan-route-fixer/config.json"
            if str(candidate) == str(SYSTEM_CONFIG_PATH):
                continue
            if candidate.is_file() and candidate not in paths:
                paths.append(candidate)
    return paths


def _discovery_source():
    """Resolve the config-path discovery callable.

    The compatibility facade ``core`` re-exports :func:`collect_config_paths`,
    and callers (plus the test suite) patch it there. Honouring that patch keeps
    the historical ``core.collect_config_paths`` seam working without making the
    real implementation depend on the facade.
    """
    module = sys.modules.get("core")
    patched = getattr(module, "collect_config_paths", None) if module is not None else None
    if patched is not None and patched is not collect_config_paths:
        return patched
    return collect_config_paths


def collect_all_enabled_targets(require_auto_fix=False, config_paths=None):
    """Enabled targets from every discovered config, deduplicated by address."""
    targets = []
    seen = set()
    paths = config_paths if config_paths is not None else _discovery_source()()
    for path in paths:
        config = load_config(path)
        if require_auto_fix and not config.auto_fix:
            continue
        for target in config.enabled_targets:
            address = str(target.get("address", ""))
            if not address or address in seen:
                continue
            seen.add(address)
            targets.append(target)
    return targets


def collect_all_configs(config_paths=None):
    """Return ``[(path, Config), ...]`` for every discovered config."""
    paths = config_paths if config_paths is not None else _discovery_source()()
    return [(Path(path), load_config(path)) for path in paths]


def read_state():
    """Read the daemon state file, newest location first."""
    for candidate in (STATE_PATH, FALLBACK_STATE_PATH):
        try:
            with candidate.open(encoding="utf-8") as state_file:
                state = json.load(state_file)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(state, dict):
            state["_path"] = str(candidate)
            return state
    return {}


def write_state(state, path=None):
    """Atomically publish daemon state (world readable, no secrets inside)."""
    state_path = Path(path) if path else STATE_PATH
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = state_path.with_name(state_path.name + ".tmp")
        with temporary.open("w", encoding="utf-8") as state_file:
            json.dump(state, state_file, ensure_ascii=False, indent=2)
            state_file.write("\n")
            state_file.flush()
            os.fsync(state_file.fileno())
        os.replace(temporary, state_path)
    except OSError:
        if path is not None:
            return False
        # /run is root-only on some systems; fall back to the user config dir.
        fallback = FALLBACK_STATE_PATH
        try:
            fallback.parent.mkdir(parents=True, exist_ok=True)
            fallback.write_text(
                json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        except OSError:
            return False
    return True


def autostart_content(exec_path="/usr/bin/lan-route-fixer"):
    return f"""[Desktop Entry]
Type=Application
Name={APP_DISPLAY_NAME}
Comment={APP_DESCRIPTION}
Exec={exec_path}
Icon=network-wired
Terminal=false
X-GNOME-Autostart-enabled=true
StartupNotify=false
"""


def apply_autostart(enabled, exec_path="/usr/bin/lan-route-fixer"):
    try:
        if enabled:
            AUTOSTART_PATH.parent.mkdir(parents=True, exist_ok=True)
            temporary = AUTOSTART_PATH.with_name(AUTOSTART_PATH.name + ".tmp")
            temporary.write_text(autostart_content(exec_path), encoding="utf-8")
            os.replace(temporary, AUTOSTART_PATH)
        else:
            AUTOSTART_PATH.unlink(missing_ok=True)
    except OSError:
        return False
    return True
