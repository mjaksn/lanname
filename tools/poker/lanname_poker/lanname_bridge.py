"""A thin bridge to the lanname package under evaluation.

The preview panel wants to show not what the tool thinks it built but what
lanname itself reads out of the bytes, so this drives lanname's own
:func:`mdns_reverse` and :func:`netbios_name` with the network swapped for a
socket that hands over one canned reply. It also exposes lanname's shortening
and its address classification, so the preview can say what name is passed
along to the caller and whether "all" mode would probe the address at all.

If lanname is not importable it is taken from the checkout this tool lives
in, three directories up, which is where it sits whenever the tool runs from
the repository, then given up on: the packet building still works without it,
only the preview needs it.
"""

import os
import pathlib
import sys

_lanname = None
_loaded = False


def _load():
    global _lanname, _loaded
    if _loaded:
        return _lanname
    _loaded = True
    try:
        import lanname
        _lanname = lanname
        return _lanname
    except ImportError:
        pass
    candidates = []
    env = os.environ.get("LANNAME_REPO")
    if env:
        candidates.append(pathlib.Path(env))
    # tools/poker/lanname_poker/lanname_bridge.py -> the repository root, which
    # holds the lanname package when this runs from a checkout.
    here = pathlib.Path(__file__).resolve()
    candidates.append(here.parents[3])
    for cand in candidates:
        if (cand / "lanname" / "__init__.py").exists():
            sys.path.insert(0, str(cand))
            try:
                import lanname
                _lanname = lanname
                return _lanname
            except ImportError:
                continue
    return None


def available():
    """True if lanname could be imported, so the preview can be shown."""
    return _load() is not None


def version():
    ln = _load()
    return getattr(ln, "__version__", None) if ln else None


class _FakeSock:
    """A socket that yields one reply then times out, and sends nothing.

    The reply goes back carrying the transaction id of the query lanname sent,
    which is what a real responder echoes, so lanname's id check reads it as
    the answer to its own question. It arrives from port 5353, or from the
    host lanname connected to for NetBIOS, for the same reason: the preview
    is meant to show what lanname makes of the name, not to trip the checks
    that keep strays out.
    """

    def __init__(self, reply, timeout_cls):
        self._reply = reply
        self._timeout = timeout_cls
        self._tid = b"\x00\x00"
        self._peer = None

    def setsockopt(self, *a):
        pass

    def settimeout(self, *a):
        pass

    def connect(self, peer):
        self._peer = peer

    def sendto(self, data, *a):
        self._tid = bytes(data[:2])
        return len(data)

    def send(self, data):
        return self.sendto(data)

    def recvfrom(self, _bufsize):
        if self._reply is None:
            raise self._timeout()
        reply, self._reply = self._reply, None
        return self._tid + reply[2:], (self._peer or ("192.0.2.1", 5353))

    def recv(self, bufsize):
        return self.recvfrom(bufsize)[0]

    def close(self):
        pass


class _Shim:
    """Stands in for the socket module: real constants, fake constructor."""

    def __init__(self, real, fake):
        self._real = real
        self._fake = fake

    def socket(self, *a, **k):
        return self._fake

    def __getattr__(self, name):
        return getattr(self._real, name)


def _parse(reply, addr, mdns):
    from lanname import resolver as R
    real = R.socket
    R.socket = _Shim(real, _FakeSock(reply, real.timeout))
    try:
        if mdns:
            return R.mdns_reverse(addr, timeout=0.05)
        return R.netbios_name(addr, timeout=0.05)
    finally:
        R.socket = real


def parse_reply(kind, reply, addr):
    """The name lanname's probe pulls out of *reply*, or None.

    Runs the real lanname function against a socket that returns exactly these
    bytes, so the result includes every check lanname makes: the response bit,
    the answer count, the offsets and the name match.
    """
    from .wire import MDNS
    ln = _load()
    if ln is None:
        return None
    return _parse(reply, addr, kind == MDNS)


def shorten(name, fqdn):
    """What lanname hands the caller: the full name or just its first label."""
    ln = _load()
    if ln is None or name is None:
        return name
    resolver = ln.Resolver(mode="off")
    resolver.fqdn = fqdn
    return resolver._shorten(name)


def addr_kind(addr):
    """lanname's classification of the address, or None if lanname is absent."""
    ln = _load()
    if ln is None:
        return None
    return ln.addr_kind(addr)


def would_probe(addr):
    """Whether lanname in "all" mode would send mDNS and NetBIOS to *addr*.

    lanname only reaches those two methods for an address it classes private,
    so this mirrors the gate in its resolve path.
    """
    return addr_kind(addr) == "private"
