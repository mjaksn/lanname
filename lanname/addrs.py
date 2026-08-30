"""Which addresses are worth asking about.

A copy, deliberately. The same thirty lines of :mod:`ipaddress` classification
live in the NetFlow tooling this package was split out of, and duplicating them
is cheaper than either side taking a dependency on the other for so little.
Each stays installable with nothing but an interpreter.
"""

import ipaddress
from typing import Dict

__all__ = ["ADDR_KINDS", "MAX_ADDR_KIND_CACHE", "addr_kind"]

#: Ceiling on the classification cache. The addresses reaching this function
#: are typically read off a network, which makes the key space something other
#: hosts control rather than something bounded by anything local. Past the
#: ceiling, classification still returns the right answer and simply stops
#: being remembered.
MAX_ADDR_KIND_CACHE = 100000

_addr_kind_cache: Dict[str, str] = {}
ADDR_KINDS = ("private", "public", "multicast", "special", "unknown")


def addr_kind(addr):
    """Classify an address string as one of :data:`ADDR_KINDS`.

    "private" is RFC 1918 and its IPv6 equivalents, "special" covers loopback,
    link-local, reserved and unspecified, and "unknown" means it did not parse
    as an address at all. Both families are handled, since a caller holding a
    string will not always know which one it has.

    Cached, with a cap: an address seen once is cheap to classify again, and a
    long-running process must not grow a dictionary without bound.
    """
    if addr in _addr_kind_cache:
        return _addr_kind_cache[addr]
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        kind = "unknown"
    else:
        if ip.is_multicast:
            kind = "multicast"
        elif ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified:
            kind = "special"
        elif ip.is_private:
            kind = "private"
        else:
            kind = "public"
    if len(_addr_kind_cache) < MAX_ADDR_KIND_CACHE:
        _addr_kind_cache[addr] = kind
    return kind
