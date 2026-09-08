"""Address to hostname lookup on a local network: reverse DNS, mDNS, NetBIOS.

For programs that hold an IP address and would rather show a name. An address
in a log line, a database row or a dashboard is much less useful a year later
than the name of the thing it was, and the three ways to find that name on a
local network are all short, all standard library, and all annoying to write
twice.

**Reverse DNS by default. The modes that probe the LAN are opt-in:**

* ``"dns"`` is the default: reverse DNS only. Passive in the sense that it
  asks the resolver the machine already uses, but it is still a query per
  address.
* ``"off"`` makes the resolver static-only. It answers from ``hosts_files``
  and nothing else: no lookups, no threads, no traffic.
* ``"all"`` is reverse DNS, then mDNS to 224.0.0.251, then a NetBIOS status
  query to the host itself. **This sends probes onto the LAN**, to addresses
  the caller hands over, which is active network behaviour that has to be
  asked for rather than inherited from a default. On some networks it will be
  noticed. ``local_networks`` narrows it to addresses inside the networks
  named there, which is worth setting where the addresses come off a wire.

::

    from lanname import Resolver

    with Resolver(mode="dns", workers=4) as resolver:
        name = resolver.lookup("192.168.1.10")     # None until it is known

Lookups run in background worker threads behind a TTL cache.
:meth:`~lanname.resolver.Resolver.lookup` only ever reads the cache and
returns immediately, so a caller reading from a socket is never blocked on
one: the first sighting of an address returns None and the name appears on a
later one. Absence means "not known yet", never "has no name".

Nothing here prints. Records go to the ``lanname`` logger, and the package
installs a NullHandler and nothing else, so they go nowhere until a handler is
configured.
"""

import logging

from .addrs import ADDR_KINDS, addr_kind
from .resolver import MODE_DESC, Resolver, mdns_reverse, netbios_name

__version__ = "0.4.0"

# A library that logs to an unconfigured root logger prints to stderr, which is
# not a library's decision to make.
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    "Resolver", "MODE_DESC",
    # the two link-local methods, callable without a Resolver
    "mdns_reverse", "netbios_name",
    # what a resolver will and will not ask about
    "addr_kind", "ADDR_KINDS",
    "__version__",
]
