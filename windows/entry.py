"""Entry point for the PyInstaller build of lan-route-fixer.

``windows/build-exe.cmd`` freezes this module into
``lan-route-fixer.exe``.  The frozen executable is the same command line as
``src/usr/bin/lan-route-fixer``: ``status``, ``import-ssh``, ``fix``,
``run``, ``daemon`` and ``doctor`` all work without Python installed.

``--version`` is handled here because the POSIX launcher normally answers it
before dispatch; ``core.cli_main`` installs the UTF-8 console plumbing and then
runs the argparse command line.
"""

import sys

from core import cli_main
from lanrf import __version__


def main(argv):
    if argv and argv[0] in ("--version", "-V"):
        print(f"lan-route-fixer {__version__}")
        return 0
    return cli_main(argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))