"""lanname poker: craft the replies lanname parses, with a chosen hostname.

A small PySide6 tool for evaluating lanname and the NetFlow tooling that uses
it. It builds mDNS PTR and NetBIOS node status responses whose hostname is
exactly the bytes you ask for, shows what lanname reads out of them, and can
either send one to a harness or answer a live resolver's queries.

The wire building in :mod:`lanname_poker.wire` is standard library only and
imports nothing else here, so a harness can use it without a display.
"""

from .wire import (
    MDNS,
    NBSTAT,
    REPLY_KINDS,
    build_mdns_reply,
    build_nbstat_reply,
    build_reply,
    decode_input,
)

__version__ = "0.1.0"

__all__ = [
    "MDNS",
    "NBSTAT",
    "REPLY_KINDS",
    "build_mdns_reply",
    "build_nbstat_reply",
    "build_reply",
    "decode_input",
    "__version__",
]
