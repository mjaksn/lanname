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


def _is_rfc1918(ip):
    """Return True for 10/8, 172.16/12, 192.168/16 and fc00::/7.

    Deliberately excludes ip.is_private's broader set (TEST-NET, benchmarks,
    CGNAT, etc.) because the probes this gates are sent to the address, and
    those blocks are not LAN addresses the caller intended to probe.
    """
    if ip.version == 4:
        return (ipaddress.IPv4Network("10.0.0.0/8").supernet_of(
            ipaddress.IPv4Network(f"{ip}/32"))
            or ipaddress.IPv4Network("172.16.0.0/12").supernet_of(
                ipaddress.IPv4Network(f"{ip}/32"))
            or ipaddress.IPv4Network("192.168.0.0/16").supernet_of(
                ipaddress.IPv4Network(f"{ip}/32")))
    return ipaddress.IPv6Network("fc00::/7").supernet_of(
        ipaddress.IPv6Network(f"{ip}/128"))


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
        elif _is_rfc1918(ip):
            kind = "private"
        else:
            kind = "public"
    if len(_addr_kind_cache) < MAX_ADDR_KIND_CACHE:
        _addr_kind_cache[addr] = kind
    return kind
