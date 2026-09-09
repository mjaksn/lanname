"""Entry point: ``python -m lanname_harness`` opens the window.

``--selftest`` drives the same session code without a display and without
PySide6, so it doubles as a smoke test of the harness against the real
package. It builds a resolver in ``"off"`` mode over a temporary hosts file
and asks it about a handful of addresses, which sends nothing: ``"off"``
starts no threads and answers from static entries alone. The mode table it
prints is worked out from the options rather than by building a resolver in
each mode, for the same reason.
"""

import argparse
import os
import sys
import tempfile
from dataclasses import replace

from . import __version__, session

SAMPLES = ("192.168.1.10", "10.0.0.5", "8.8.8.8", "192.0.2.1",
           "224.0.0.251", "127.0.0.1", "not-an-address")

STATIC = (("192.168.1.10", "nas.lan"), ("192.168.1.11", "printer.lan"))


def _hosts_file():
    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".hosts", delete=False, encoding="utf-8")
    with handle:
        handle.write("# written by the harness self test\n")
        for addr, name in STATIC:
            handle.write(f"{addr}\t{name}\n")
    return handle.name


def _selftest():
    # Names carry bytes the console encoding may not have, so degrade an
    # unencodable character to its escape rather than crashing the report.
    try:
        sys.stdout.reconfigure(errors="backslashreplace")
    except (AttributeError, ValueError):
        pass

    have = session.available()
    print(f"lanname importable: {have}"
          + (f" (version {session.version()} from {session.location()})"
             if have else ""))
    if not have:
        print("nothing further can be checked without it")
        return 1

    print("\nmodes")
    for mode in session.modes():
        print(f"  {mode:5} {session.mode_desc(mode)}")

    print("\nceilings")
    for name, module, desc in session.CEILINGS:
        const = f"lanname.{module}.{name}"
        print(f"  {const:<38} {session.ceiling(name):>9}  {desc}")

    print("\nwhat each mode would do with an address")
    probe = session.Session()
    header = "  " + "address".ljust(16) + "kind".ljust(11)
    variants = [
        ("off", session.Options(mode="off")),
        ("dns", session.Options(mode="dns")),
        ("dns +public", session.Options(mode="dns", resolve_public=True)),
        ("all", session.Options(mode="all")),
        ("all, on link only",
         session.Options(mode="all", restrict_networks=True,
                         networks="192.168.1.0/24")),
    ]
    print(header + "".join(label.ljust(22) for label, _o in variants))
    for addr in SAMPLES:
        row = "  " + addr.ljust(16) + str(session.addr_kind(addr)).ljust(11)
        for _label, options in variants:
            probe.options = options
            looked_up, why = probe.verdict(addr)
            row += (why if looked_up else "no: " + why).ljust(22)
        print(row)

    path = _hosts_file()
    try:
        print("\na resolver in \"off\" mode over a hosts file: "
              "no threads, no traffic")
        harness = session.Session()
        options = replace(session.Options(), mode="off", hosts_files=[path])
        harness.build(options)
        print("  " + session.call_repr(options))
        print(f"  static entries loaded: {harness.static_count()}")
        for addr in SAMPLES:
            harness.watch(addr)
        for _ in range(3):
            harness.poll()
        print("  " + "address".ljust(16) + "returned".ljust(14)
              + "calls".ljust(7) + "misses")
        for watch in harness.watches:
            print("  " + watch.addr.ljust(16) + repr(watch.name).ljust(14)
                  + str(watch.calls).ljust(7) + str(watch.misses))
        print("  counters: " + ", ".join(
            f"{key}={value}" for key, value in harness.stats().items()))
        print("  local_hosts(): " + repr(harness.local_hosts()))
        harness.shutdown()
    finally:
        os.unlink(path)

    print("\nno packet was sent by any of the above")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="lanname-harness",
        description="A window for exercising lanname against a live network.")
    parser.add_argument("--version", action="version",
                        version=f"lanname-harness {__version__}")
    parser.add_argument("--selftest", action="store_true",
                        help="drive a static resolver and print what it does, "
                             "then exit; needs no display and sends nothing")
    args = parser.parse_args(argv)

    if args.selftest:
        return _selftest()

    from .gui import run_gui
    return run_gui(sys.argv[:1])


if __name__ == "__main__":
    sys.exit(main())
