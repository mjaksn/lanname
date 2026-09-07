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

# "private" is these blocks and nothing else. ipaddress's is_private is the
# obvious test and the wrong one here: it also answers True for the
# documentation ranges (192.0.2.0/24 and its two siblings, 2001:db8::/32), the
# benchmarking range (198.18.0.0/15), 192.0.0.0/24, 0.0.0.0/8 and 2002::/16,
# and the set it covers has changed between 3.9 and 3.13. The resolver sends
# mDNS and NetBIOS probes to any address it classes private, so the class has
# to mean "a LAN this machine could be on", which is what RFC 1918 and RFC 4193
# name and nothing else. Carrier-grade NAT space (100.64.0.0/10) stays public
# on the same grounds: a provider's network, not the caller's.
_PRIVATE_V4 = tuple(ipaddress.IPv4Network(block) for block in
                    ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
_PRIVATE_V6 = (ipaddress.IPv6Network("fc00::/7"),)


def _is_private(ip):
    blocks = _PRIVATE_V4 if ip.version == 4 else _PRIVATE_V6
    return any(ip in block for block in blocks)


def addr_kind(addr):
    """Classify an address string as one of :data:`ADDR_KINDS`.

    "private" is RFC 1918 (10/8, 172.16/12, 192.168/16) and its IPv6
    equivalent, RFC 4193 (fc00::/7), and nothing else; the comment above
    ``_PRIVATE_V4`` says why the wider ``is_private`` is not used. "special"
    covers loopback, link-local, reserved and unspecified, and "unknown" means
    it did not parse as an address at all. Everything else, the documentation
    and benchmarking ranges included, is "public". Both families are handled,
    since a caller holding a string will not always know which one it has.

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
        elif _is_private(ip):
            kind = "private"
        else:
            kind = "public"
    if len(_addr_kind_cache) < MAX_ADDR_KIND_CACHE:
        _addr_kind_cache[addr] = kind
    return kind
