"""Scheduled-task helpers for the Windows GUI.

Kept free of tkinter so ``--task-install`` / ``--task-uninstall`` work in a
plain (possibly window-less) process.
"""

from __future__ import annotations

import subprocess
import sys

TASK_NAME = "LanRouteFixer"
CREATE_NO_WINDOW = 0x08000000


def _run(args):
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=CREATE_NO_WINDOW,
    )


def task_exists():
    """True when the LanRouteFixer scheduled task is registered."""
    if not sys.platform.startswith("win"):
        return False
    try:
        return _run(["schtasks", "/Query", "/TN", TASK_NAME]).returncode == 0
    except OSError:
        return False


def _powershell(script):
    return _run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ]
    )


def install_task(command, arguments):
    """Register a logon task that runs ``command arguments`` as Administrator.

    ``command`` is the executable (the GUI exe when frozen, python.exe when run
    from a source checkout) and ``arguments`` the rest of the command line.
    """
    executable = str(command).replace("'", "''")
    cmd_args = str(arguments).replace("'", "''")
    script = f"""
$ErrorActionPreference = 'Stop'
$user = "$env:USERDOMAIN\\$env:USERNAME"
$action = New-ScheduledTaskAction -Execute '{executable}' -Argument '{cmd_args}'
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
Register-ScheduledTask -TaskName '{TASK_NAME}' -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
"""
    return _powershell(script)


def uninstall_task():
    script = f"""
$ErrorActionPreference = 'Stop'
Unregister-ScheduledTask -TaskName '{TASK_NAME}' -Confirm:$false
"""
    return _powershell(script)