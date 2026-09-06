"""Entry point: ``python -m lanname_poker`` opens the window.

``--selftest`` builds each preset reply and, if lanname is importable, prints
what lanname reads out of it. It needs no display and no PySide6, so it doubles
as a smoke test of the wire building against the real parser.
"""

import argparse
import sys

from . import __version__, wire


def _selftest():
    from . import lanname_bridge
    # Names carry bytes the console encoding may not have, so degrade an
    # unencodable character to its escape rather than crashing the report.
    try:
        sys.stdout.reconfigure(errors="backslashreplace")
    except (AttributeError, ValueError):
        pass
    addr = "192.168.1.50"
    have = lanname_bridge.available()
    print(f"lanname importable: {have}"
          + (f" (version {lanname_bridge.version()})" if have else ""))
    for kind in wire.REPLY_KINDS:
        print(f"\n{kind}")
        for label, text, interp in wire.PRESETS:
            inject = wire.decode_input(text, interp)
            reply = wire.build_reply(kind, inject, addr)
            parsed = lanname_bridge.parse_reply(kind, reply, addr) if have else None
            note = "".join("  [" + w + "]" for w in wire.build_warnings(kind, inject))
            print(f"  {label:32} {len(reply):4d} bytes  parsed={parsed!r}{note}")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="lanname-poker",
        description="Craft the replies lanname parses, with a chosen hostname.")
    parser.add_argument("--version", action="version",
                        version=f"lanname-poker {__version__}")
    parser.add_argument("--selftest", action="store_true",
                        help="build every preset reply and print what lanname "
                             "reads, then exit; needs no display")
    args = parser.parse_args(argv)

    if args.selftest:
        return _selftest()

    from .gui import run_gui
    return run_gui(sys.argv[:1])


if __name__ == "__main__":
    sys.exit(main())
