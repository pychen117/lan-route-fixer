"""Command line / GUI dispatch.

The entry point has to decide, from raw ``sys.argv``, whether the user asked for
a command or for the GUI. Getting this wrong is unusually annoying: a mistyped
or mis-parsed invocation silently opens a GTK window instead of printing
something, which is exactly what happened with ``--config PATH check`` while the
option *value* was being tested as if it were a command name.

The logic lives here, away from the GTK import, so it can be unit tested.
"""

CLI_COMMANDS = frozenset(
    {
        "scan",
        "check",
        "fix",
        "run",
        "daemon",
        "status",
        "doctor",
        "prune",
        "list",
        "add",
        "remove",
        "enable",
        "disable",
        "set-interface",
        "config",
        "help",
    }
)

# Options that consume the following token as their value.
VALUE_OPTIONS = frozenset({"--config", "--helper", "--interval", "--port", "--name",
                           "--interface"})

# Flags that mean "this is the CLI" even on their own.
CLI_FLAGS = frozenset({"-h", "--help", "--version"})


def wants_cli(argv):
    """True when *argv* should be handled by the command line interface.

    Returns False for an empty argv (a desktop launch), and for any invocation
    whose first positional token is not a known command.
    """
    index = 0
    tokens = list(argv or [])
    while index < len(tokens):
        token = tokens[index]
        if token in VALUE_OPTIONS:
            # Skip the option *and* the value it consumes. Testing the value as
            # a command name is the bug this function exists to prevent.
            index += 2
            continue
        if token.startswith("-"):
            return token in CLI_FLAGS
        return token in CLI_COMMANDS
    return False
