"""Entry point for the Windows GUI executable.

Three modes, decided by the argument list:

* no arguments              -> open the tkinter control deck
* ``--task-install`` / ``--task-uninstall`` -> register/remove the logon task
* anything else             -> behave exactly like the CLI (this is what the
  scheduled task runs: ``lan-route-fixer-gui.exe run --interval 10``)

A windowed PyInstaller build has no console, so ``sys.stdout``/``stderr`` may be
``None``; both are pointed at ``os.devnull`` before anything else runs.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _ensure_stdio():
    for name in ("stdout", "stderr"):
        if getattr(sys, name) is None:
            setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))


def _bootstrap_path():
    """Make ``lanrf`` importable when running from a source checkout."""
    if getattr(sys, "frozen", False):
        return
    lib = Path(__file__).resolve().parent.parent / "src" / "usr" / "lib" / "lan-route-fixer"
    if (lib / "lanrf").is_dir() and str(lib) not in sys.path:
        sys.path.insert(0, str(lib))


def _self_invocation():
    """(program, argument prefix) that re-runs this entry point."""
    if getattr(sys, "frozen", False):
        return sys.executable, ""
    return sys.executable, f'"{Path(__file__).resolve()}"'


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    _ensure_stdio()
    _bootstrap_path()

    if argv and argv[0] in ("--task-install", "--task-uninstall"):
        from taskmod import install_task, uninstall_task

        command, prefix = _self_invocation()
        try:
            if argv[0] == "--task-install":
                proc = install_task(command, f"{prefix} run --interval 10".strip())
            else:
                proc = uninstall_task()
        except Exception:  # pragma: no cover - defensive
            return 1
        return 0 if proc.returncode == 0 else 1

    if argv and argv[0] == "--gui-probe":
        from gui import probe_gui

        return probe_gui()

    if argv and argv[0] in ("--version", "-V"):
        from lanrf import __version__

        print(f"lan-route-fixer {__version__}")
        return 0

    if not argv:
        from gui import run_gui

        return run_gui()

    from core import cli_main

    return cli_main(argv)


if __name__ == "__main__":
    sys.exit(main())