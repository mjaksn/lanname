"""Driving a live lanname resolver, without Qt.

Everything the window does to the package happens here: building a
:class:`~lanname.Resolver` from a set of options, changing the two things that
can change while it runs, asking it about addresses on a repeating tick,
reading its counters and its observed hosts, moving the module level ceilings,
and calling the two probe functions on their own.

Qt free and importable without a display, so the suite can exercise the whole
of it and ``--selftest`` can run in CI. Nothing here sends a packet by itself:
the traffic, when there is any, is whatever lanname decides to send for the
mode and the addresses it is given.

If lanname is not importable it is taken from the checkout this tool lives in,
three directories up, which is where it sits whenever the tool runs from the
repository.
"""

import ipaddress
import itertools
import os
import pathlib
import sys
import time
from dataclasses import dataclass, field, replace
from typing import List, Optional, Tuple

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
    # tools/harness/lanname_harness/session.py -> the repository root, which
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
    """True if lanname could be imported. Nothing here works without it."""
    return _load() is not None


def version():
    ln = _load()
    return getattr(ln, "__version__", None) if ln else None


def location():
    """The directory the imported lanname came from, for the status line.

    Worth showing rather than assuming: an installed copy and the checkout
    beside this tool are both plausible, and a harness reporting on the wrong
    one is worse than no harness.
    """
    ln = _load()
    if ln is None or not getattr(ln, "__file__", None):
        return None
    return str(pathlib.Path(ln.__file__).parent)


def modes():
    """The three mode names, in the order the package lists them."""
    ln = _load()
    return list(ln.Resolver.MODES) if ln else ["off", "dns", "all"]


def mode_desc(mode):
    """lanname's own one line account of a mode, from its MODE_DESC."""
    ln = _load()
    if ln is None:
        return ""
    return ln.MODE_DESC.get(mode, "")


def addr_kinds():
    ln = _load()
    return list(ln.ADDR_KINDS) if ln else []


def addr_kind(addr):
    """lanname's classification of an address, or None without lanname."""
    ln = _load()
    return ln.addr_kind(addr) if ln else None


# The counters the README documents, in its order, so the display is stable
# and a key that has not happened yet reads 0 rather than being absent.
STAT_KEYS = ("hits", "resolved", "missed", "via_dns", "via_mdns",
             "via_netbios", "dropped", "evicted", "off_link")

STAT_DESC = {
    "hits": "answered from the cache",
    "resolved": "a worker found a name",
    "missed": "a worker found nothing",
    "via_dns": "named by reverse DNS",
    "via_mdns": "named by mDNS",
    "via_netbios": "named by NetBIOS",
    "dropped": "discarded, the work queue was full",
    "evicted": "cache entries dropped to stay under the ceiling",
    "off_link": "probes not sent, outside local_networks",
}

# The module qualified constants the README lists under "Ceilings", each with
# the module that owns it. They are read as module globals every time they are
# used, so moving one here moves it for a resolver already running, which is
# the only practical way to watch an eviction happen.
CEILINGS = (
    ("RESOLVER_CACHE_MAX", "resolver", "cached names"),
    ("MAX_OBSERVED_HOSTS", "resolver", "addresses kept for local_hosts()"),
    ("MAX_NAMES_PER_HOST", "resolver", "names kept for one address"),
    ("MAX_ADDR_KIND_CACHE", "addrs", "cached address classifications"),
)

#: The work queue lanname builds, for the note beside the feed control. Not a
#: constant the package exports, so it is read off the live resolver's queue
#: rather than named twice.
DEFAULT_QUEUE_SIZE = 4096

MDNS = "mDNS"
NETBIOS = "NetBIOS"
PROBE_KINDS = (MDNS, NETBIOS)


def ceiling(name):
    """Read one of the module level ceilings, or None without lanname."""
    ln = _load()
    if ln is None:
        return None
    for const, module, _desc in CEILINGS:
        if const == name:
            return getattr(getattr(ln, module), const)
    raise KeyError(name)


def set_ceiling(name, value):
    """Move one of the ceilings on the module that owns it.

    On ``lanname.resolver`` or ``lanname.addrs``, never on the ``lanname``
    package: the worker reads ``RESOLVER_CACHE_MAX`` as a global of its own
    module, so rebinding the re-exported copy would leave the real one alone
    and the harness would be reporting on a change it had not made.
    """
    ln = _load()
    if ln is None:
        raise RuntimeError("lanname is not importable")
    for const, module, _desc in CEILINGS:
        if const == name:
            setattr(getattr(ln, module), const, int(value))
            return
    raise KeyError(name)


def probe(kind, addr, timeout):
    """Call mdns_reverse or netbios_name directly. Blocks up to *timeout*.

    **This sends a packet.** mDNS goes to the multicast group with a TTL of 1,
    NetBIOS straight to the address itself. Both answer None rather than
    raising when nothing comes back or the reply does not parse.
    """
    ln = _load()
    if ln is None:
        raise RuntimeError("lanname is not importable")
    if kind == MDNS:
        return ln.mdns_reverse(addr, timeout=timeout)
    return ln.netbios_name(addr, timeout=timeout)


def parse_networks(text):
    """Split a comma or whitespace separated list of networks and check it.

    Returns a list, possibly empty, and raises ValueError naming the entry
    that did not parse. lanname checks this itself at construction, and would
    raise the same way; doing it here as well is what lets the field report a
    typo as it is typed rather than only when the build button is pressed.
    """
    out = []
    for entry in text.replace(",", " ").split():
        # strict=False, as lanname parses it: an interface address with a
        # prefix on it, "192.168.1.7/24", reads as the network it sits in.
        out.append(ipaddress.ip_network(entry, strict=False))
    return out


def split_addrs(text):
    """Addresses out of a line of text, comma or whitespace separated."""
    return [part for part in text.replace(",", " ").split() if part]


def feed_addresses(network, count):
    """*count* host addresses from *network*, for filling the work queue.

    A generator rather than a list: a /8 asked for a few thousand addresses
    should not materialise sixteen million first.
    """
    net = ipaddress.ip_network(network, strict=False)
    return itertools.islice((str(host) for host in net.hosts()), count)


@dataclass
class Options:
    """Everything Resolver.__init__ takes, as the window holds it.

    `mode` and `fqdn` are the two that can change on a running resolver; the
    rest are construction only, which is why the window offers a rebuild.
    `local_networks` keeps lanname's three states apart: None for no
    restriction, an empty list for probe nothing, and a list for the usual
    case. A text field alone cannot say which of the first two is meant, so
    the restriction is a separate flag.
    """

    mode: str = "dns"
    workers: int = 4
    resolve_public: bool = False
    fqdn: bool = False
    positive_ttl: float = 3600.0
    negative_ttl: float = 300.0
    timeout: float = 1.0
    restrict_networks: bool = False
    networks: str = ""
    hosts_files: List[str] = field(default_factory=list)

    def local_networks(self):
        """The `local_networks` argument these options mean."""
        if not self.restrict_networks:
            return None
        return parse_networks(self.networks)

    def rebuild_needed(self, other):
        """Whether going from *other* to these options needs a new resolver.

        Mode and fqdn are excluded because set_mode() and set_fqdn() do them
        on the resolver already running.
        """
        here = replace(self, mode="", fqdn=False)
        there = replace(other, mode="", fqdn=False)
        return here != there


def call_repr(options):
    """The ``Resolver(...)`` call *options* stand for, as Python.

    Every argument, named, in the order the signature takes them, rather than
    only the ones that differ from a default. A harness is a place to read the
    whole signature off the screen, and a line that can be pasted into an
    interpreter is worth more than a shorter one that cannot.
    """
    try:
        networks = options.local_networks()
    except ValueError:
        networks = "<invalid>"
    if isinstance(networks, list):
        networks = repr([str(network) for network in networks])
    else:
        networks = repr(networks)
    parts = [
        f"mode={options.mode!r}",
        "hosts_files=" + repr(list(options.hosts_files)),
        f"workers={options.workers}",
        f"resolve_public={options.resolve_public}",
        f"fqdn={options.fqdn}",
        f"positive_ttl={options.positive_ttl:g}",
        f"negative_ttl={options.negative_ttl:g}",
        f"timeout={options.timeout:g}",
        "local_networks=" + networks,
    ]
    return "Resolver(" + ", ".join(parts) + ")"


@dataclass
class Watch:
    """One address the harness keeps asking about, and how that has gone.

    The counts are the point of the thing. lookup() answers None until a
    worker has been round, so a row that reads 4 calls and 3 misses before a
    name appeared is the package's central behaviour made visible, and calls
    climbing with no misses after that is the cache being hit.
    """

    addr: str
    calls: int = 0
    misses: int = 0
    name: Optional[str] = None
    added: float = field(default_factory=time.monotonic)
    first_answer: Optional[float] = None

    def latency(self):
        """Seconds between the first ask and the first name, or None."""
        if self.first_answer is None:
            return None
        return self.first_answer - self.added


#: Ceiling on the watch table. The rows are polled and redrawn on a timer, so
#: this is a limit on the harness rather than on lanname; feed the queue
#: instead when the point is volume.
MAX_WATCHES = 200


class Session:
    """One resolver at a time, and the state the window draws around it."""

    def __init__(self):
        self.resolver = None
        self.options = Options()
        self.built_with = None
        self.watches: List[Watch] = []
        self.shut_down = False

    # == the resolver =======================================================

    def build(self, options):
        """Construct a resolver from *options*, retiring any current one.

        Lets TypeError and ValueError out: a TTL that is not a number and a
        network that does not parse are both raised by lanname at
        construction, on purpose, and the window shows the message rather
        than the harness second-guessing the check.
        """
        ln = _load()
        if ln is None:
            raise RuntimeError("lanname is not importable")
        local_networks = options.local_networks()
        built = ln.Resolver(
            mode=options.mode,
            hosts_files=list(options.hosts_files),
            workers=options.workers,
            resolve_public=options.resolve_public,
            fqdn=options.fqdn,
            positive_ttl=options.positive_ttl,
            negative_ttl=options.negative_ttl,
            timeout=options.timeout,
            local_networks=local_networks,
        )
        # Only once the new one exists: a construction that raised leaves the
        # old resolver running rather than the harness holding nothing.
        self.shutdown()
        self.resolver = built
        self.options = replace(options)
        self.built_with = replace(options)
        self.shut_down = False
        self.reset_watch_counts()
        return built

    def shutdown(self):
        """Stop the current resolver, if there is one. Safe to repeat."""
        if self.resolver is not None:
            self.resolver.shutdown()
            self.shut_down = True

    def set_mode(self, mode):
        """Change mode on the running resolver, as set_mode() does.

        After a shutdown the mode still changes and no workers start, which
        is what the package documents; the window says so rather than hiding
        the control.
        """
        self.options = replace(self.options, mode=mode)
        if self.built_with is not None:
            self.built_with = replace(self.built_with, mode=mode)
        if self.resolver is not None:
            self.resolver.set_mode(mode)

    def set_fqdn(self, fqdn):
        """Change the name form on the running resolver. Empties its cache."""
        self.options = replace(self.options, fqdn=fqdn)
        if self.built_with is not None:
            self.built_with = replace(self.built_with, fqdn=fqdn)
        if self.resolver is not None:
            self.resolver.set_fqdn(fqdn)

    def running(self):
        return self.resolver is not None and not self.shut_down

    def needs_rebuild(self):
        """Whether the form has moved past what the live resolver was built with."""
        if self.built_with is None:
            return False
        return self.options.rebuild_needed(self.built_with)

    def static_count(self):
        """How many entries the hosts files supplied, for the status line."""
        return len(self._static())

    def _static(self):
        """The live resolver's static entries, or an empty mapping.

        Through getattr for the reason queue_size() is: `static` carries no
        underscore and the package's own notes describe it, but it is not in
        the README's table of the public API, and a window must not fail to
        open because something it only reports on was renamed.
        """
        return getattr(self.resolver, "static", {}) or {}

    def queue_size(self):
        """The bound on the work queue of the live resolver.

        Read off the resolver where it can be, since a number the harness
        prints should be the one in force rather than the one that was true
        when this was written, and fallen back to the documented 4,096 when
        it cannot: the queue itself is an internal, and a harness must not
        stop working because an internal was renamed.
        """
        queue = getattr(self.resolver, "_queue", None)
        return getattr(queue, "maxsize", None) or DEFAULT_QUEUE_SIZE

    # == asking about addresses =============================================

    def watch(self, addr):
        """Start asking about an address. Returns the row, new or existing."""
        for existing in self.watches:
            if existing.addr == addr:
                return existing
        if len(self.watches) >= MAX_WATCHES:
            raise ValueError(
                f"the watch list holds {MAX_WATCHES} addresses; use the feed "
                "to put volume through the queue")
        watch = Watch(addr)
        self.watches.append(watch)
        return watch

    def unwatch(self, addr):
        self.watches = [w for w in self.watches if w.addr != addr]

    def clear_watches(self):
        self.watches = []

    def reset_watch_counts(self):
        """Start the counts again, so a rebuild is not read as a cache hit."""
        now = time.monotonic()
        for watch in self.watches:
            watch.calls = 0
            watch.misses = 0
            watch.name = None
            watch.added = now
            watch.first_answer = None

    def poll(self):
        """Call lookup() once for every watched address and record what came back.

        This is the loop the package is written for: a caller that asks again
        the next time an address turns up, rather than waiting for the first
        answer. A name can go back to None here, which is not a bug: the
        entry's TTL ran out and the address is queued afresh.
        """
        if self.resolver is None:
            return self.watches
        now = time.monotonic()
        for watch in self.watches:
            name = self.resolver.lookup(watch.addr)
            watch.calls += 1
            watch.name = name
            if name is None:
                watch.misses += 1
            elif watch.first_answer is None:
                watch.first_answer = now
        return self.watches

    def feed(self, addresses):
        """Push addresses through lookup() once each, without watching them.

        For filling the work queue. Returns how many were passed on. In "off"
        mode lookup() returns before it queues anything, and a resolver
        already holding an address pending will not queue it twice, so the
        number here is what was offered rather than what was sent.
        """
        if self.resolver is None:
            return 0
        count = 0
        for addr in addresses:
            self.resolver.lookup(addr)
            count += 1
        return count

    # == what the resolver will do with an address ==========================

    def verdict(self, addr) -> Tuple[bool, str]:
        """Whether this address would be looked up, and in short what happens.

        Mirrors the gate at the top of Resolver.lookup() and the one in
        _resolve(), against the options as they stand. The package is the
        authority; this exists so the window can say what will happen before
        an address is added rather than only after nothing happened.
        """
        ln = _load()
        if ln is None:
            return False, "no lanname"
        if self._static().get(addr):
            return True, "static"
        options = self.options
        if options.mode == "off":
            return False, "mode off"
        kind = ln.addr_kind(addr)
        if kind in ("multicast", "special", "unknown"):
            return False, kind
        if kind == "public" and not options.resolve_public:
            return False, "public"
        if options.mode != "all" or kind != "private":
            # Probes are only ever tried for a private address, whatever
            # resolve_public says: both methods are link-local.
            return True, "dns"
        try:
            networks = options.local_networks()
        except ValueError:
            networks = None
        if networks is None:
            return True, "dns, mDNS, NetBIOS"
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return True, "dns (off link)"
        if any(ip in network for network in networks):
            return True, "dns, mDNS, NetBIOS"
        return True, "dns (off link)"

    # == what it has found ==================================================

    def stats(self):
        """Every documented counter, zero where it has not happened yet."""
        if self.resolver is None:
            return {key: 0 for key in STAT_KEYS}
        counter = self.resolver.stats
        out = {key: counter[key] for key in STAT_KEYS}
        for key, value in counter.items():
            out.setdefault(key, value)
        return out

    def local_hosts(self):
        """Every private address seen with a name, newest name first."""
        if self.resolver is None:
            return []
        return self.resolver.local_hosts()
