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


# The DNS limits on a name: 63 bytes to a label, 253 to the whole in text form,
# 255 on the wire. A reply past any of them is refused rather than trimmed,
# since the only host that sends one is trying something.
_MAX_LABEL_BYTES = 63
_MAX_NAME_BYTES = 253
_MAX_WIRE_NAME_BYTES = 255


def dns_read_name(data, off):
    """Read a possibly compressed DNS name. Returns (name, offset after the name).

    The name is None, and the offset the end of the data, once its labels add
    up to more than 255 bytes. A compression pointer may point backwards, so a
    reply can make each of the 16 permitted hops re-read every label before
    it and assemble tens of thousands of characters out of a few kilobytes;
    the bound is on the bytes read into the name, which no pointer can inflate.
    Nothing after a refused name is worth reading, hence the offset.
    """
    labels = []
    resume = None
    hops = 0
    total = 0
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
        total += length
        if total > _MAX_WIRE_NAME_BYTES:
            return None, len(data)
        labels.append(data[off:off + length].decode("utf-8", "replace"))
        off += length
    return ".".join(labels), (resume if resume is not None else off)


def _checked_name(name, allow_space=False):
    """The name if it is fit to hand on, else None.

    A name from mDNS or NetBIOS is whatever the answering host chose, and the
    caller is likely to print it. So a name is refused if it carries any code
    point below 0x21 or equal to 0x7f: those are the characters that move a
    cursor, forge a second log line or hide the rest of a name. A NetBIOS
    name may hold a space, since its field is space padded and the padding is
    stripped before the check, so 0x20 is allowed there and nowhere else. A
    label over 63 bytes or a whole over 253 is refused as well, measured in
    UTF-8 bytes rather than characters so that a multibyte name cannot slip
    under the DNS limits. Everything above 0x7f passes, lookalikes and
    bidirectional controls included: they are legal in a name, and judging
    them is the caller's business, as the README says under Limitations.

    A name that is nothing but dots is refused too: it would shorten to
    nothing, and a result that is nothing should not count as found.
    """
    if not name or not name.rstrip("."):
        return None
    floor = 0x20 if allow_space else 0x21
    for char in name:
        code = ord(char)
        if code < floor or code == 0x7F:
            return None
    if len(name.encode("utf-8")) > _MAX_NAME_BYTES:
        return None
    for label in name.split("."):
        if len(label.encode("utf-8")) > _MAX_LABEL_BYTES:
            return None
    return name


def reverse_qname(addr):
    ip = ipaddress.ip_address(addr)
    if ip.version == 4:
        return ".".join(reversed(str(ip).split("."))) + ".in-addr.arpa"
    nibbles = ip.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".ip6.arpa"


def parse_ptr_response(data, want_qname, tid=None):
    """Pull the first PTR rdata that answers want_qname out of a DNS response.

    With *tid* given, a response carrying any other transaction id is not an
    answer to the query that id was sent with, and is refused. Sixteen bits
    against a blind spoofer is a filter for stray and stale replies, not
    authentication; the README's "names are not verified" still stands.
    """
    if len(data) < 12:
        return None
    got_tid, flags, qdcount, ancount, _ns, _ar = struct.unpack_from("!HHHHHH", data, 0)
    if tid is not None and got_tid != tid:
        return None
    if flags & 0x8000 == 0 or ancount == 0:
        return None
    off = 12
    for _ in range(qdcount):
        name, off = dns_read_name(data, off)
        off += 4
        if name is None or off > len(data):
            return None
    want = want_qname.lower().rstrip(".")
    for _ in range(ancount):
        name, off = dns_read_name(data, off)
        if name is None or off + 10 > len(data):
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

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return None
    try:
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        except OSError:
            pass
        sock.settimeout(timeout)
        try:
            sock.sendto(query, ("224.0.0.251", 5353))
        except OSError:
            # No route to the group, which is what a host with no default
            # route reports. This used to raise out of _resolve() before it
            # reached NetBIOS, so such a host named nothing under "all".
            return None
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            sock.settimeout(remaining)
            try:
                data, peer = sock.recvfrom(4096)
            except (socket.timeout, OSError):
                return None
            # An mDNS responder answers from port 5353. A datagram from any
            # other port is a stray or a spoof aimed at the ephemeral port
            # this socket happens to hold, and so is a reply with the wrong
            # transaction id; both are skipped rather than ending the wait,
            # since the real answer may still be on its way.
            if peer[1] != 5353:
                continue
            name = parse_ptr_response(data, qname, tid)
            if name is None:
                continue
            return _checked_name(name)
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

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return None
    try:
        sock.settimeout(timeout)
        # connect() rather than sendto(): a connected UDP socket only hands
        # over datagrams from the address it was connected to, so a stray or
        # spoofed reply from anywhere else never reaches the parser below.
        sock.connect((addr, 137))
        sock.send(packet)
        data = sock.recv(2048)
    except OSError:
        return None
    finally:
        sock.close()

    if len(data) < 12:
        return None
    got_tid, flags, _qdcount, ancount = struct.unpack_from("!HHHH", data, 0)
    # The reply has to carry the id the query went out with and the response
    # bit, or it is not the reply to this query. One datagram is read, so a
    # wrong one costs the lookup rather than being skipped as mDNS does.
    if got_tid != tid or flags & 0x8000 == 0 or ancount < 1:
        return None
    # header 12, encoded name 34, type 2, class 2, ttl 4, rdlength 2
    off = 12 + 34 + 2 + 2 + 4 + 2
    if len(data) < off + 1:
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
        # Only the protocol's own padding comes off: the field is 15 bytes,
        # padded with spaces and by some implementations with NUL. A bare
        # strip() would take a trailing tab or newline with it, so a name
        # ending in one would be tidied into an acceptable name instead of
        # being refused as every other control character is.
        name = _checked_name(raw.decode("ascii", "replace").strip(" \x00"),
                             allow_space=True)
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


def _parse_networks(networks):
    """Normalise the `local_networks` argument, or None for no restriction.

    Checked at construction for the reason the TTLs are: this decides where
    probes are allowed to go, and a typo in it should fail in the caller's
    hands rather than quietly widening or closing the gate on a worker thread
    later. `strict=False` so that an interface address with a prefix on it,
    "192.168.1.7/24", is read as the network it sits in, which is what an
    operator copying a line out of `ip addr` will hand over.

    An empty iterable is kept as an empty tuple rather than turned back into
    None: it means "probe nothing", which is a reasonable thing to ask for and
    a different answer from "probe anywhere".
    """
    if networks is None:
        return None
    parsed = []
    for entry in networks:
        try:
            parsed.append(ipaddress.ip_network(entry, strict=False))
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"local_networks entry is not a network: {entry!r}") from exc
    return tuple(parsed)


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

    `local_networks` narrows what "all" mode is willing to probe. Private is
    not the same as on-link: 10/8, 172.16/12 and 192.168/16 are three very
    large blocks, and an address out of one of them can arrive from anywhere
    that can put a packet in front of the caller, spoofed source included. A
    NetBIOS query goes straight to the address, so an address nobody here can
    reach still sends a datagram towards it, over a VPN or a WAN link if that
    is where the route leads. Given a list of networks, probes go only to
    addresses inside one of them. The default, None, is no restriction, which
    is what every earlier version did.
    """

    MODES = ("off", "dns", "all")

    def __init__(self, mode="dns", hosts_files=(), workers=4,
                 resolve_public=False, fqdn=False, positive_ttl=3600,
                 negative_ttl=300, timeout=1.0, local_networks=None):
        if mode not in self.MODES:
            raise ValueError(f"unknown resolution mode: {mode!r}")
        for label, ttl in (("positive_ttl", positive_ttl),
                           ("negative_ttl", negative_ttl)):
            # Checked here because the worker adds a TTL to a clock reading
            # with nothing around it to catch a TypeError, and a value that
            # is wrong should fail where it was given, not on a daemon thread
            # some time later. A bool is an int, and True as a TTL is a
            # mistake rather than a second.
            if isinstance(ttl, bool) or not isinstance(ttl, (int, float)):
                raise TypeError(f"{label} must be a number of seconds, not {ttl!r}")
            if ttl < 0:
                raise ValueError(f"{label} must not be negative: {ttl!r}")
        self.mode = mode
        self.resolve_public = resolve_public
        self.fqdn = fqdn
        self.positive_ttl = positive_ttl
        self.negative_ttl = negative_ttl
        self.timeout = timeout
        self.local_networks = _parse_networks(local_networks)

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
        """Bring the lookup threads up, once, and never after shutdown().

        A resolver constructed with mode "off" has none, so switching mode
        later has to start them or the queue would fill with work nobody
        does. Under the lock, so that two set_mode() calls at once cannot
        start two pools; and a no-op once stopped, since a thread started
        then would find its loop condition already false and exit at once.
        """
        with self._lock:
            if self._threads or self._stop.is_set():
                return
            for _ in range(self._worker_count):
                thread = threading.Thread(target=self._worker, daemon=True,
                                          name="lanname-resolver")
                thread.start()
                self._threads.append(thread)

    def set_mode(self, mode):
        """Change resolution mode while running.

        Going to "off" drops the work already queued as well as refusing
        new work. After shutdown() the mode still changes but no workers
        start: a resolver is not restartable.
        """
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

        The flag flips under the same lock the worker shortens under, so a
        lookup in flight lands in the new form or is cleared with the rest,
        and is never written back in the old one after the clear.
        """
        with self._lock:
            if fqdn == self.fqdn:
                return
            self.fqdn = fqdn
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
            # After shutdown() nothing drains the queue, so an address added
            # to _pending here would stay there and answer None for ever. The
            # cache above still answers, since reading it costs nothing.
            if self._stop.is_set() or addr in self._pending:
                return None
            # Queued under the same lock the stop check just ran under, and
            # shutdown() sets the event under it too, so a shutdown landing
            # between the two cannot return and then have this thread put
            # work on a queue nobody will drain. Lock order is this lock and
            # then the queue's own; put_nowait() never blocks, and a worker
            # has let go of the queue's lock before it takes this one, so the
            # pair has no way to deadlock.
            self._pending.add(addr)
            try:
                self._queue.put_nowait(addr)
            except queue.Full:
                self._pending.discard(addr)
                self.stats["dropped"] += 1
        return None

    def _observe(self, addr, name):
        """Remember that this local address answered to this name."""
        with self._lock:
            self._note_name(addr, name)

    def _note_name(self, addr, name):
        """The body of _observe(), for a caller already holding the lock.

        Only addresses on the local network are worth listing, and only a
        handful of names for any one of them: a name that keeps changing is
        interesting for the last few changes and no further back than that.
        """
        if not name or addr_kind(addr) != "private":
            return
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
        """Ask the worker threads to finish, and take no more work.

        The threads are daemons, so this is a courtesy rather than a
        requirement, but it stops probes going out after the caller thinks
        it has stopped: queued addresses are dropped unresolved, a probe in
        flight is the last one, and lookup() answers from static entries and
        the cache only. A resolver is not restartable; set_mode() after this
        starts nothing.
        """
        # Set under the lock that lookup() checks it under, so that a lookup
        # cannot pass the check and then queue an address after this call has
        # returned and the caller believes the resolver has stopped.
        with self._lock:
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
            try:
                self._work(addr)
            except Exception:
                # _work() catches what _resolve() raises, so this only fires
                # on a failure in the bookkeeping after it. WARNING because
                # that is a bug rather than a lookup that failed, and caught
                # so that one bug does not retire a daemon thread for the
                # rest of the process.
                log.warning("resolver worker failed on %s", addr, exc_info=True)
            finally:
                self._queue.task_done()

    def _work(self, addr):
        """Resolve one queued address and record the outcome."""
        # Work queued before a set_mode("off") or shutdown() is dropped here
        # rather than done: a resolver that still sends the queries it had
        # lined up has not stopped. No cache entry is written, so the address
        # is looked up afresh if the mode comes back.
        if self._stop.is_set() or self.mode == "off":
            with self._lock:
                self._pending.discard(addr)
            return
        raw = None
        try:
            raw = self._resolve(addr)
        except Exception:
            log.debug("lookup of %s failed", addr, exc_info=True)
        with self._lock:
            # The discard comes first, so that nothing below can fail in a
            # way that leaves the address pending, and so unanswerable, for
            # ever.
            self._pending.discard(addr)
            # Shortened here, under the lock, rather than in _resolve(): a
            # set_fqdn() landing between the two would clear the cache and
            # then have the old form written straight back into it, to sit
            # there for positive_ttl looking like the new one.
            name = self._shorten(raw)
            ttl = self.positive_ttl if name else self.negative_ttl
            self._cache[addr] = (name, time.monotonic() + ttl)
            self._cache.move_to_end(addr)
            while len(self._cache) > RESOLVER_CACHE_MAX:
                self._cache.popitem(last=False)
                self.stats["evicted"] += 1
            if name:
                self._note_name(addr, name)
            # Counted under the lock as well. Anything waiting for the work
            # to finish watches _pending, which is read under this lock, so a
            # count published outside it could still be catching up at the
            # moment the resolver first looks idle.
            self.stats["resolved" if name else "missed"] += 1

    def _may_probe(self):
        """Whether an mDNS or NetBIOS probe may go out right now.

        Read again before each probe rather than once at the top of
        _resolve(): a probe waits up to `timeout`, and a set_mode("off") or
        shutdown() during that wait has to stop the next one going out.
        """
        return self.mode == "all" and not self._stop.is_set()

    def _on_link(self, addr):
        """Whether `local_networks` allows a probe to this address.

        True for everything when no networks were given, which is the default
        and what every version before this one did. Anything that does not
        parse is refused: this gate only ever narrows, so the safe answer for
        an address nobody can classify is not to send it a datagram.
        """
        if self.local_networks is None:
            return True
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        # A network of the other family answers False rather than raising, so
        # a mixed list needs no sorting by version here.
        return any(ip in network for network in self.local_networks)

    def _resolve(self, addr):
        """Find a name for the address, or None. Runs on a worker thread.

        The name comes back as the method gave it, full and unshortened; the
        worker shortens it under the lock, for the reason given there. Every
        result goes through _checked_name() here as well as inside the two
        probes, reverse DNS included: a PTR record is somebody else's bytes
        as much as a probe reply is, and this is the one place all three
        paths pass before a name reaches the cache and local_hosts().
        """
        # 1. reverse DNS
        try:
            name = _checked_name(socket.gethostbyaddr(addr)[0])
        except (OSError, UnicodeError):
            name = None
        if name:
            self.stats["via_dns"] += 1
            return name

        if not self._may_probe() or addr_kind(addr) != "private":
            return None
        if not self._on_link(addr):
            self.stats["off_link"] += 1
            return None

        # Steps 2 and 3 share one deadline, rather than taking `timeout` each.
        # The cost of an address is what an attacker controls: a host that
        # floods the caller with addresses that answer nothing holds a worker
        # for the whole of both waits, and four workers at two seconds an
        # address get through about two addresses a second between them,
        # which is slow enough that real hosts go unnamed for as long as the
        # flood lasts. One deadline halves the worst case and leaves the best
        # one alone.
        #
        # mDNS gets at most half, so that a silent link cannot spend the whole
        # budget before NetBIOS is tried; an mDNS miss is the ordinary case
        # for the Windows hosts NetBIOS is there to name. Whatever mDNS leaves
        # goes to NetBIOS, which is all of the second half and more when the
        # multicast send fails outright. A responder that is going to answer
        # answers in tens of milliseconds, so the shortened wait is only ever
        # spent on an address that was not going to answer at all.
        deadline = time.monotonic() + self.timeout

        # 2. mDNS
        name = _checked_name(mdns_reverse(addr, timeout=self.timeout / 2.0))
        if name:
            self.stats["via_mdns"] += 1
            return name

        # 3. NetBIOS
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not self._may_probe():
            return None
        name = _checked_name(netbios_name(addr, timeout=remaining),
                             allow_space=True)
        if name:
            self.stats["via_netbios"] += 1
            return name

        return None
