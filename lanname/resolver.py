"""Caching, non-blocking address to hostname lookup.

The half of this package that decides *when* to ask, remembers the answer, and
keeps the asking off the calling thread. The asking itself lives beside it in
the same module as :func:`mdns_reverse` and :func:`netbios_name`, which are
callable on their own if scheduling is not what you need.

:meth:`Resolver.lookup` only ever reads a TTL cache and returns immediately.
Misses are queued for background workers, so a caller reading from a socket is
never delayed by a name it does not have yet. The first sighting of an address
returns None and the name appears on a later one.
"""

import ipaddress
import logging
import queue
import random
import socket
import struct
import threading
import time
from collections import Counter, OrderedDict

from .addrs import addr_kind

__all__ = ["MAX_NAMES_PER_HOST", "MAX_OBSERVED_HOSTS", "MODE_DESC",
           "RESOLVER_CACHE_MAX", "Resolver", "mdns_reverse", "netbios_name"]

log = logging.getLogger(__name__)

MODE_DESC = {
    "off": "static entries only (no lookups, no threads, no traffic)",
    "dns": "reverse DNS only (passive)",
    "all": "reverse DNS, mDNS, NetBIOS (sends probes to the LAN)",
}


def dns_encode_name(name):
    out = bytearray()
    for label in name.split("."):
        if not label:
            continue
        label = label[:63]
        out.append(len(label))
        out += label.encode("ascii", "replace")
    out.append(0)
    return bytes(out)


def dns_read_name(data, off):
    """Read a possibly compressed DNS name. Returns (name, offset after the name)."""
    labels = []
    resume = None
    hops = 0
    while off < len(data):
        length = data[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[off + 1]
            if resume is None:
                resume = off + 2
            off = pointer
            hops += 1
            if hops > 16:
                break
            continue
        off += 1
        labels.append(data[off:off + length].decode("utf-8", "replace"))
        off += length
    return ".".join(labels), (resume if resume is not None else off)


def reverse_qname(addr):
    ip = ipaddress.ip_address(addr)
    if ip.version == 4:
        return ".".join(reversed(str(ip).split("."))) + ".in-addr.arpa"
    nibbles = ip.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".ip6.arpa"


def parse_ptr_response(data, want_qname):
    """Pull the first PTR rdata that answers want_qname out of a DNS response."""
    if len(data) < 12:
        return None
    _tid, flags, qdcount, ancount, _ns, _ar = struct.unpack_from("!HHHHHH", data, 0)
    if flags & 0x8000 == 0 or ancount == 0:
        return None
    off = 12
    for _ in range(qdcount):
        _name, off = dns_read_name(data, off)
        off += 4
        if off > len(data):
            return None
    want = want_qname.lower().rstrip(".")
    for _ in range(ancount):
        name, off = dns_read_name(data, off)
        if off + 10 > len(data):
            return None
        rtype, _rclass, _ttl, rdlen = struct.unpack_from("!HHIH", data, off)
        off += 10
        if off + rdlen > len(data):
            return None
        if rtype == 12 and name.lower().rstrip(".") == want:
            target, _ = dns_read_name(data, off)
            if target:
                return target
        off += rdlen
    return None


def mdns_reverse(addr, timeout=1.0):
    """Ask the local link for a PTR record.

    Uses the unicast-response bit so we do not have to join the multicast
    group. Sends to 224.0.0.251:5353 with a TTL of 1, so it stays on the link.
    """
    try:
        qname = reverse_qname(addr)
    except ValueError:
        return None
    tid = random.randrange(0, 65536)
    query = struct.pack("!HHHHHH", tid, 0x0000, 1, 0, 0, 0)
    query += dns_encode_name(qname)
    query += struct.pack("!HH", 12, 0x8001)  # PTR, class IN with the QU bit set

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        except OSError:
            pass
        sock.settimeout(timeout)
        sock.sendto(query, ("224.0.0.251", 5353))
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            sock.settimeout(remaining)
            try:
                data, _peer = sock.recvfrom(4096)
            except (socket.timeout, OSError):
                return None
            name = parse_ptr_response(data, qname)
            if name:
                return name
    finally:
        sock.close()


NB_WILDCARD = b"*" + b"\x00" * 15


def nb_encode_name(raw16):
    """First level NetBIOS name encoding: each byte becomes two nibble characters."""
    out = bytearray([32])
    for byte in raw16:
        out.append(0x41 + (byte >> 4))
        out.append(0x41 + (byte & 0x0F))
    out.append(0)
    return bytes(out)


def netbios_name(addr, timeout=1.0):
    """Ask a host directly what it calls itself. Sends UDP to its port 137."""
    tid = random.randrange(0, 65536)
    packet = struct.pack("!HHHHHH", tid, 0x0000, 1, 0, 0, 0)
    packet += nb_encode_name(NB_WILDCARD)
    packet += struct.pack("!HH", 0x0021, 0x0001)  # NBSTAT, IN

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(packet, (addr, 137))
        data, _peer = sock.recvfrom(2048)
    except OSError:
        return None
    finally:
        sock.close()

    # header 12, encoded name 34, type 2, class 2, ttl 4, rdlength 2
    off = 12 + 34 + 2 + 2 + 4 + 2
    if len(data) < off + 1:
        return None
    if struct.unpack_from("!H", data, 6)[0] < 1:  # ancount
        return None
    count = data[off]
    off += 1
    fallback = None
    for _ in range(count):
        if off + 18 > len(data):
            break
        raw = data[off:off + 15]
        suffix = data[off + 15]
        flags = struct.unpack_from("!H", data, off + 16)[0]
        off += 18
        name = raw.decode("ascii", "replace").strip().strip("\x00")
        if not name:
            continue
        group = bool(flags & 0x8000)
        if suffix == 0x00 and not group:
            return name          # unique workstation name, what we want
        if fallback is None and not group:
            fallback = name
    return fallback


RESOLVER_CACHE_MAX = 50000       # addresses held before the oldest is dropped
MAX_OBSERVED_HOSTS = 5000        # local addresses remembered for local_hosts()
MAX_NAMES_PER_HOST = 5           # names remembered for any one of them


class Resolver:
    """Non-blocking address to hostname lookup.

    :meth:`lookup` only ever reads the cache and returns immediately. Misses are
    queued for background workers, so the caller is never delayed. Call
    :meth:`shutdown` when done, or use it as a context manager.

    Public addresses are not resolved unless `resolve_public` is set: a busy
    link produces thousands of them, most resolve to something uninformative,
    and each one is a query somebody else can see.

    The default mode is "dns", reverse DNS and nothing else. "all" adds mDNS
    and NetBIOS, which put probes on the LAN, and is never reached without
    being asked for. "off" makes the resolver static-only: it answers from
    `hosts_files`, starts no threads and sends nothing.
    """

    MODES = ("off", "dns", "all")

    def __init__(self, mode="dns", hosts_files=(), workers=4,
                 resolve_public=False, fqdn=False, positive_ttl=3600,
                 negative_ttl=300, timeout=1.0):
        if mode not in self.MODES:
            raise ValueError(f"unknown resolution mode: {mode!r}")
        self.mode = mode
        self.resolve_public = resolve_public
        self.fqdn = fqdn
        self.positive_ttl = positive_ttl
        self.negative_ttl = negative_ttl
        self.timeout = timeout

        self.static = {}
        for path in hosts_files:
            self._load_hosts(path)

        # Ordered so the oldest entry can be dropped when the cache is full.
        # Clearing the whole cache instead would send every active host back
        # through resolution at the same moment, which under "all" means a
        # burst of mDNS and NetBIOS probes onto the LAN.
        self._cache = OrderedDict()
        # Every name ever seen for a local address, oldest first, kept apart
        # from the cache: the cache expires and evicts, and this is meant to
        # answer "what did you see all session" long after either has happened.
        self._observed = OrderedDict()
        self._pending = set()
        self._lock = threading.Lock()
        self._queue = queue.Queue(maxsize=4096)
        self._stop = threading.Event()
        self.stats = Counter()

        self._worker_count = max(1, workers)
        self._threads = []
        if mode != "off":
            self._start_workers()

    def _start_workers(self):
        """Bring the lookup threads up, once.

        A resolver constructed with mode "off" has none, so switching mode
        later has to start them or the queue would fill with work nobody does.
        """
        if self._threads:
            return
        for _ in range(self._worker_count):
            thread = threading.Thread(target=self._worker, daemon=True,
                                      name="lanname-resolver")
            thread.start()
            self._threads.append(thread)

    def set_mode(self, mode):
        """Change resolution mode while running."""
        if mode not in self.MODES:
            raise ValueError(f"unknown resolution mode: {mode!r}")
        self.mode = mode
        if mode != "off":
            self._start_workers()

    def set_fqdn(self, fqdn):
        """Switch between full and short names.

        Every cached entry was shortened on the way in, so the cache says
        nothing about what the names would look like under the other setting
        and has to go. This is the one case where emptying it wholesale is
        right rather than a thundering herd.
        """
        if fqdn == self.fqdn:
            return
        self.fqdn = fqdn
        with self._lock:
            self._cache.clear()

    # == static hosts file ==================================================

    def _load_hosts(self, path):
        """Read a hosts-format file. First entry for an address wins."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    line = line.split("#", 1)[0].strip()
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    try:
                        addr = str(ipaddress.ip_address(parts[0]))
                    except ValueError:
                        continue
                    if addr not in self.static:
                        self.static[addr] = parts[1]
        except OSError as exc:
            # Logged, not raised: a missing optional hosts file should not stop
            # the program that asked for it.
            log.warning("could not read hosts file %s: %s", path, exc)

    # == public API =========================================================

    def _shorten(self, name):
        if not name:
            return None
        name = name.rstrip(".")
        if not self.fqdn:
            name = name.split(".")[0]
        return name or None

    def lookup(self, addr):
        """Return a cached hostname or None. Never blocks.

        None means "not known yet", not "has no name". Ask again the next
        time the address turns up.
        """
        if not addr:
            return None

        static = self.static.get(addr)
        if static:
            name = self._shorten(static)
            self._observe(addr, name)
            return name

        if self.mode == "off":
            return None

        kind = addr_kind(addr)
        if kind in ("multicast", "special", "unknown"):
            return None
        if kind == "public" and not self.resolve_public:
            return None

        now = time.monotonic()
        with self._lock:
            entry = self._cache.get(addr)
            if entry is not None:
                name, expires = entry
                if now < expires:
                    self._cache.move_to_end(addr)
                    self.stats["hits"] += 1
                    return name
                del self._cache[addr]
            if addr in self._pending:
                return None
            self._pending.add(addr)

        try:
            self._queue.put_nowait(addr)
        except queue.Full:
            with self._lock:
                self._pending.discard(addr)
            self.stats["dropped"] += 1
        return None

    def _observe(self, addr, name):
        """Remember that this local address answered to this name.

        Only addresses on the local network are worth listing, and only a
        handful of names for any one of them: a name that keeps changing is
        interesting for the last few changes and no further back than that.
        """
        if not name or addr_kind(addr) != "private":
            return
        with self._lock:
            names = self._observed.get(addr)
            if names is None:
                names = self._observed[addr] = []
            elif names[-1] == name:
                # The usual case by far: the same host answering as before.
                self._observed.move_to_end(addr)
                return
            elif name in names:
                names.remove(name)      # seen before, but not most recently
            names.append(name)
            del names[:-MAX_NAMES_PER_HOST]
            self._observed.move_to_end(addr)
            while len(self._observed) > MAX_OBSERVED_HOSTS:
                self._observed.popitem(last=False)

    def local_hosts(self):
        """Every local address seen with a name, and the names it answered to.

        Sorted by address, with each address's names most recent first, so the
        one a row leads with is the one to believe.
        """
        with self._lock:
            snapshot = [(addr, list(reversed(names)))
                        for addr, names in self._observed.items() if names]

        def order(entry):
            try:
                return (0, int(ipaddress.ip_address(entry[0])))
            except ValueError:
                return (1, 0)

        return sorted(snapshot, key=order)

    def shutdown(self):
        """Ask the worker threads to finish. They are daemons, so this is a
        courtesy rather than a requirement, but it stops probes going out
        after the caller thinks it has stopped."""
        self._stop.set()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.shutdown()
        return False

    # == workers ============================================================

    def _worker(self):
        while not self._stop.is_set():
            try:
                addr = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            name = None
            try:
                name = self._resolve(addr)
            except Exception:
                log.debug("lookup of %s failed", addr, exc_info=True)
                name = None
            finally:
                if name:
                    name = self._shorten(name)
                    if name:
                        self._observe(addr, name)
                ttl = self.positive_ttl if name else self.negative_ttl
                with self._lock:
                    self._cache[addr] = (name, time.monotonic() + ttl)
                    self._cache.move_to_end(addr)
                    self._pending.discard(addr)
                    while len(self._cache) > RESOLVER_CACHE_MAX:
                        self._cache.popitem(last=False)
                        self.stats["evicted"] += 1
                self.stats["resolved" if name else "missed"] += 1
                self._queue.task_done()

    def _resolve(self, addr):
        """Return a raw (unshortened) name or None. The caller shortens it
        under the lock so a concurrent set_fqdn() cannot race a cache write."""
        # 1. reverse DNS
        try:
            name = socket.gethostbyaddr(addr)[0]
            if name:
                self.stats["via_dns"] += 1
                return name
        except (OSError, UnicodeError):
            pass

        if self.mode != "all":
            return None
        if addr_kind(addr) != "private":
            return None

        # 2. mDNS
        name = mdns_reverse(addr, timeout=self.timeout)
        if name:
            self.stats["via_mdns"] += 1
            return name

        # 3. NetBIOS
        name = netbios_name(addr, timeout=self.timeout)
        if name:
            self.stats["via_netbios"] += 1
            return name

        return None
