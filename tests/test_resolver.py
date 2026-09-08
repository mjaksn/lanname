"""The resolver: off unless asked, and never blocking when on.

No test here touches the network. `_resolve` is replaced with a canned answer,
which is the whole point of the split between "how do I find a name" and
"how do I cache and schedule finding one".

The ceiling is patched on `resolver_mod` rather than on the package, because
the worker reads it as a module global and rebinding the re-exported copy
would leave the real one in place. The tests that exercise the two probes
swap `resolver_mod.socket` for `FakeSocketModule` the same way, so the real
parsing code runs over bytes the test built and nothing reaches a socket.
"""

import ipaddress
import pathlib
import re
import socket
import struct
import threading
import time
import unittest
from collections import OrderedDict

from lanname import Resolver, addr_kind
from lanname import resolver as resolver_mod


def canned(self, addr):
    return "host-" + addr.replace(".", "-")


def addr(i):
    return "10.0.%d.%d" % (i // 256, i % 256)


def drain(resolver, deadline=15.0):
    """Wait for the worker queue to empty. True if it did."""
    end = time.time() + deadline
    while time.time() < end:
        with resolver._lock:
            idle = not resolver._pending
        if idle and resolver._queue.empty():
            return True
        time.sleep(0.01)
    return False


class FakeSocket:
    """A datagram socket that sends nothing and hands back canned replies.

    Each recvfrom() or recv() yields the next of `replies`, a list of
    (data, peer) pairs, with the transaction id of the last query sent written
    into its first two bytes, which is what a real responder does. `skew_tid`
    writes the wrong id instead. When the replies run out it raises
    socket.timeout, which is what a silent link looks like.
    """

    def __init__(self, replies=(), skew_tid=False, refuse_send=False):
        self.replies = list(replies)
        self.skew_tid = skew_tid
        self.refuse_send = refuse_send
        self.sent = []
        self.peer = None

    def setsockopt(self, *args):
        pass

    def settimeout(self, *args):
        pass

    def close(self):
        pass

    def connect(self, peer):
        self.peer = peer

    def sendto(self, data, peer):
        if self.refuse_send:
            raise OSError(101, "Network is unreachable")
        self.sent.append((data, peer))
        return len(data)

    def send(self, data):
        return self.sendto(data, self.peer)

    def recvfrom(self, _size):
        if not self.replies:
            raise socket.timeout()
        data, peer = self.replies.pop(0)
        tid = struct.unpack_from("!H", self.sent[-1][0], 0)[0]
        if self.skew_tid:
            tid ^= 1
        return struct.pack("!H", tid) + data[2:], peer

    def recv(self, size):
        return self.recvfrom(size)[0]


class FakeSocketModule:
    """Stands in for `resolver_mod.socket`: real constants, fake connections.

    `fake` is the socket every socket() call returns, or a list of them handed
    out in order when a test needs the two probes to see different ones.
    `hosts` is what gethostbyaddr() answers; anything else is unknown.
    """

    def __init__(self, fake=None, refuse_open=False, hosts=None):
        self.fake = fake
        self.refuse_open = refuse_open
        self.hosts = hosts or {}

    def socket(self, *args, **kwargs):
        if self.refuse_open:
            raise OSError(24, "Too many open files")
        if isinstance(self.fake, list):
            return self.fake.pop(0)
        return self.fake

    def gethostbyaddr(self, addr):
        try:
            return self.hosts[addr], [], [addr]
        except KeyError:
            raise socket.herror(1, "Unknown host") from None

    def __getattr__(self, name):
        return getattr(socket, name)


def fake_network(test, **kwargs):
    """Swap the resolver's socket module for a fake until the test ends."""
    module = FakeSocketModule(**kwargs)
    resolver_mod.socket = module
    test.addCleanup(setattr, resolver_mod, "socket", socket)
    return module


def labels(*parts, end=b"\x00"):
    """DNS wire labels, exactly as given: no truncation, no sanitising."""
    return b"".join(bytes([len(part)]) + part for part in parts) + end


QNAME = "1.0.0.10.in-addr.arpa"


def mdns_reply(target, tid=0, qname=QNAME):
    """A PTR response answering `qname` with `target`, built as a responder would."""
    header = struct.pack("!HHHHHH", tid, 0x8400, 0, 1, 0, 0)
    rdata = labels(*(part.encode("utf-8") for part in target.split(".")))
    answer = resolver_mod.dns_encode_name(qname)
    answer += struct.pack("!HHIH", 12, 1, 120, len(rdata)) + rdata
    return header + answer


def nbstat_reply(name, tid=0, response=True):
    """A node status response naming one unique workstation, `name`."""
    header = struct.pack("!HHHHHH", tid, 0x8400 if response else 0, 0, 1, 0, 0)
    rrname = resolver_mod.nb_encode_name(resolver_mod.NB_WILDCARD)
    raw = name.encode("ascii", "replace")[:15].ljust(15, b" ")
    rdata = bytes([1]) + raw + b"\x00" + struct.pack("!H", 0)
    return header + rrname + struct.pack("!HHIH", 0x21, 1, 0, len(rdata)) + rdata


class Modes(unittest.TestCase):
    def test_the_default_mode_is_reverse_dns(self):
        resolver = Resolver()
        self.addCleanup(resolver.shutdown)
        self.assertEqual(resolver.mode, "dns")

    def test_the_probing_mode_is_never_the_default(self):
        # "all" puts mDNS and NetBIOS on the wire, to addresses the caller
        # hands over, on a network they may not own. Reaching it has to be a
        # deliberate act rather than something inherited from a default.
        resolver = Resolver()
        self.addCleanup(resolver.shutdown)
        self.assertNotEqual(resolver.mode, "all")

    def test_off_starts_no_threads(self):
        resolver = Resolver(mode="off")
        self.addCleanup(resolver.shutdown)
        self.assertEqual(resolver._threads, [])

    def test_off_answers_none_without_looking(self):
        resolver = Resolver(mode="off")
        self.addCleanup(resolver.shutdown)
        self.assertIsNone(resolver.lookup("192.168.1.1"))
        self.assertTrue(resolver._queue.empty())

    def test_an_unknown_mode_is_refused_at_construction(self):
        with self.assertRaises(ValueError):
            Resolver(mode="everything")

    def test_switching_mode_starts_the_workers(self):
        resolver = Resolver(mode="off", workers=1)
        self.addCleanup(resolver.shutdown)
        resolver.set_mode("dns")
        self.assertEqual(len(resolver._threads), 1)


class StaticHosts(unittest.TestCase):
    def test_a_static_entry_answers_even_with_lookups_off(self):
        import os
        import tempfile
        handle, path = tempfile.mkstemp(suffix=".hosts", text=True)
        with os.fdopen(handle, "w") as out:
            out.write("# a comment\n"
                      "192.168.1.5   nas   nas.local\n"
                      "\n"
                      "not-an-address  junk\n"
                      "192.168.1.6\n")
        self.addCleanup(os.unlink, path)

        resolver = Resolver(mode="off", hosts_files=[path])
        self.addCleanup(resolver.shutdown)
        self.assertEqual(resolver.lookup("192.168.1.5"), "nas")
        self.assertEqual(resolver.static, {"192.168.1.5": "nas"})

    def test_a_missing_hosts_file_is_logged_not_raised(self):
        with self.assertLogs("lanname.resolver", "WARNING"):
            resolver = Resolver(mode="off", hosts_files=["nonesuch.hosts"])
        self.addCleanup(resolver.shutdown)
        self.assertEqual(resolver.static, {})


class CacheBehaviour(unittest.TestCase):
    """The cache must drop its oldest entry, not all of them.

    Clearing it wholesale would send every active host back through resolution
    at the same moment, which in "all" mode is a burst of probes onto the LAN.
    """

    def setUp(self):
        self._real_resolve = Resolver._resolve
        self._real_max = resolver_mod.RESOLVER_CACHE_MAX
        Resolver._resolve = canned
        resolver_mod.RESOLVER_CACHE_MAX = 100

    def tearDown(self):
        Resolver._resolve = self._real_resolve
        resolver_mod.RESOLVER_CACHE_MAX = self._real_max

    def test_the_cache_is_capped_not_emptied(self):
        r = Resolver(mode="dns", workers=2)
        self.addCleanup(r.shutdown)
        for i in range(300):
            r.lookup(addr(i))
        self.assertTrue(drain(r), "lookups did not complete")
        self.assertIsInstance(r._cache, OrderedDict)
        self.assertEqual(len(r._cache), 100)
        self.assertEqual(r.stats["evicted"], 200)

    def test_the_newest_survive_and_the_oldest_go(self):
        r = Resolver(mode="dns", workers=2)
        self.addCleanup(r.shutdown)
        for i in range(300):
            r.lookup(addr(i))
        self.assertTrue(drain(r))
        self.assertIn(addr(299), r._cache)
        self.assertNotIn(addr(0), r._cache)

    def test_names_are_actually_cached(self):
        r = Resolver(mode="dns", workers=2)
        self.addCleanup(r.shutdown)
        r.lookup("10.0.0.7")
        self.assertTrue(drain(r))
        self.assertEqual(r.lookup("10.0.0.7"), "host-10-0-0-7")
        self.assertEqual(r.stats["hits"], 1)

    def test_a_hit_moves_an_entry_to_the_young_end(self):
        r = Resolver(mode="dns", workers=2)
        self.addCleanup(r.shutdown)
        for i in range(100):
            r.lookup(addr(i))
        self.assertTrue(drain(r))

        hot = addr(0)
        self.assertEqual(r.lookup(hot), "host-10-0-0-0")
        for i in range(100, 150):
            r.lookup(addr(i))
        self.assertTrue(drain(r))

        self.assertIn(hot, r._cache, "a used entry outlived 50 newer ones")
        self.assertNotIn(addr(1), r._cache, "its untouched neighbour did not")
        self.assertEqual(len(r._cache), 100)

    def test_an_expired_entry_is_dropped_on_read(self):
        r = Resolver(mode="dns", workers=1, positive_ttl=0.05,
                     negative_ttl=0.05)
        self.addCleanup(r.shutdown)
        r.lookup("10.0.0.1")
        self.assertTrue(drain(r))
        self.assertEqual(r.lookup("10.0.0.1"), "host-10-0-0-1")
        time.sleep(0.1)
        self.assertIsNone(r.lookup("10.0.0.1"), "an expired name was served")


class WhatIsWorthLookingUp(unittest.TestCase):
    def setUp(self):
        self._real = Resolver._resolve
        Resolver._resolve = canned

    def tearDown(self):
        Resolver._resolve = self._real

    def test_the_first_sighting_returns_none_without_blocking(self):
        # The caller may be reading from a socket. Anything that stalls that
        # loop costs it packets, so a miss must answer immediately.
        r = Resolver(mode="dns", workers=1)
        self.addCleanup(r.shutdown)
        started = time.monotonic()
        self.assertIsNone(r.lookup("10.0.0.1"))
        self.assertLess(time.monotonic() - started, 0.1)

    def test_multicast_and_special_addresses_are_not_looked_up(self):
        r = Resolver(mode="dns", workers=1)
        self.addCleanup(r.shutdown)
        for address in ("224.0.0.251", "127.0.0.1", "169.254.1.1", "junk"):
            self.assertIsNone(r.lookup(address))
        self.assertTrue(r._queue.empty())

    def test_public_addresses_are_left_alone_unless_asked(self):
        r = Resolver(mode="dns", workers=1)
        self.addCleanup(r.shutdown)
        r.lookup("8.8.8.8")
        self.assertTrue(r._queue.empty())

        r2 = Resolver(mode="dns", workers=1, resolve_public=True)
        self.addCleanup(r2.shutdown)
        r2.lookup("8.8.8.8")
        drain(r2)
        self.assertEqual(r2.lookup("8.8.8.8"), "host-8-8-8-8")

    def test_a_pending_address_is_not_queued_twice(self):
        # Built "off" so that no worker starts, then switched by hand rather
        # than through set_mode(), which would start one. What is under test
        # is lookup()'s own dedupe, and a live worker racing to drain the
        # queue would make the assertion a coin toss.
        #
        # Passing workers=0 does not achieve the same thing: __init__ floors
        # the count at 1, so a resolver that queues work always has someone
        # to do it. That floor is deliberate and is not what this test is
        # about.
        r = Resolver(mode="off", workers=1)
        self.addCleanup(r.shutdown)
        self.assertEqual(r._threads, [])
        r.mode = "dns"
        for _ in range(5):
            r.lookup("10.0.0.99")
        self.assertEqual(r._queue.qsize(), 1)
        self.assertEqual(r._pending, {"10.0.0.99"})

    def test_local_hosts_records_what_answered(self):
        r = Resolver(mode="dns", workers=1)
        self.addCleanup(r.shutdown)
        r.lookup("10.0.0.1")
        self.assertTrue(drain(r))
        self.assertEqual(r.local_hosts(), [("10.0.0.1", ["host-10-0-0-1"])])

    def test_it_works_as_a_context_manager(self):
        with Resolver(mode="dns", workers=1) as r:
            self.assertIsNone(r.lookup("10.0.0.1"))
        self.assertTrue(r._stop.is_set())


def gated_resolve(test):
    """Replace _resolve with one that blocks until released and logs its calls.

    Restored when the test ends. Returns the gate and the list of addresses
    the replacement was asked about, in order.
    """
    gate = threading.Event()
    calls = []

    def slow(_self, addr):
        calls.append(addr)
        gate.wait(5)
        return "nas.lan"

    real = Resolver._resolve
    Resolver._resolve = slow
    test.addCleanup(setattr, Resolver, "_resolve", real)
    return gate, calls


def wait_until(condition, deadline=5.0):
    """Poll until the condition holds. True if it did within the deadline."""
    end = time.time() + deadline
    while time.time() < end:
        if condition():
            return True
        time.sleep(0.01)
    return False


class StoppingWork(unittest.TestCase):
    """#13: set_mode("off") and shutdown() stop the work already queued,
    nothing takes new work after shutdown(), and a worker outlives a bug."""

    def test_off_drops_the_queue_rather_than_draining_it(self):
        gate, calls = gated_resolve(self)
        r = Resolver(mode="dns", workers=1)
        self.addCleanup(r.shutdown)
        for i in range(20):
            r.lookup(addr(i))
        self.assertTrue(wait_until(lambda: calls), "the worker never started")
        r.set_mode("off")
        gate.set()
        self.assertTrue(drain(r), "the queue was not emptied")
        # One address was in flight and finished; the other nineteen were
        # dropped without a lookup or a cache entry, so a later "dns" asks
        # about them afresh.
        self.assertEqual(calls, [addr(0)])
        self.assertEqual(len(r._cache), 1)
        self.assertEqual(r.stats["resolved"], 1)

    def test_shutdown_ends_with_the_work_in_flight(self):
        gate, calls = gated_resolve(self)
        r = Resolver(mode="dns", workers=1)
        for i in range(20):
            r.lookup(addr(i))
        self.assertTrue(wait_until(lambda: calls))
        r.shutdown()
        gate.set()
        for thread in r._threads:
            thread.join(5)
        self.assertFalse(any(t.is_alive() for t in r._threads))
        self.assertEqual(calls, [addr(0)], "a worker kept resolving after shutdown")

    def test_a_probe_is_skipped_once_the_mode_drops_mid_lookup(self):
        # The mDNS wait can be a second long; a set_mode("off") during it
        # must stop the NetBIOS probe going out. Both probes are replaced,
        # reverse DNS is faked, and _resolve is called directly on a resolver
        # with no threads, so nothing reaches the network.
        fake_network(self)
        r = Resolver(mode="off")
        r.mode = "all"
        probed = []

        def mdns(addr, timeout):
            r.mode = "dns"
            return None

        def netbios(addr, timeout):
            probed.append(addr)
            return "NAS"

        for name, stub in (("mdns_reverse", mdns), ("netbios_name", netbios)):
            self.addCleanup(setattr, resolver_mod, name, getattr(resolver_mod, name))
            setattr(resolver_mod, name, stub)
        self.assertIsNone(r._resolve("10.0.0.1"))
        self.assertEqual(probed, [])

    def test_lookup_after_shutdown_queues_nothing(self):
        r = Resolver(mode="dns", workers=1)
        r.shutdown()
        self.assertIsNone(r.lookup("10.0.0.5"))
        self.assertTrue(r._queue.empty())
        self.assertEqual(r._pending, set())

    def test_static_entries_and_the_cache_still_answer_after_shutdown(self):
        self.addCleanup(setattr, Resolver, "_resolve", Resolver._resolve)
        Resolver._resolve = canned
        r = Resolver(mode="dns", workers=1)
        r.static["10.0.0.8"] = "nas"
        r.lookup("10.0.0.7")
        self.assertTrue(drain(r))
        r.shutdown()
        self.assertEqual(r.lookup("10.0.0.7"), "host-10-0-0-7")
        self.assertEqual(r.lookup("10.0.0.8"), "nas")

    def test_set_mode_after_shutdown_starts_no_threads(self):
        r = Resolver(mode="off")
        r.shutdown()
        r.set_mode("dns")
        self.assertEqual(r._threads, [])

    def test_ttls_are_validated_at_construction(self):
        for bad in ("60", None, True):
            with self.assertRaises(TypeError):
                Resolver(mode="off", positive_ttl=bad)
        with self.assertRaises(ValueError):
            Resolver(mode="off", negative_ttl=-1)
        Resolver(mode="off", positive_ttl=0.5, negative_ttl=0)

    def test_a_worker_survives_a_failure_in_its_bookkeeping(self):
        self.addCleanup(setattr, Resolver, "_resolve", Resolver._resolve)
        Resolver._resolve = canned
        real = Resolver._note_name
        self.addCleanup(setattr, Resolver, "_note_name", real)

        def broken(_self, addr, name):
            raise RuntimeError("bookkeeping bug")

        Resolver._note_name = broken
        r = Resolver(mode="dns", workers=1)
        self.addCleanup(r.shutdown)
        with self.assertLogs("lanname.resolver", "WARNING"):
            r.lookup("10.0.0.1")
            self.assertTrue(drain(r))
        self.assertNotIn("10.0.0.1", r._pending, "the address was pinned")
        Resolver._note_name = real
        r.lookup("10.0.0.2")
        self.assertTrue(drain(r), "the worker did not survive")
        self.assertEqual(r.lookup("10.0.0.2"), "host-10-0-0-2")


class ShorteningRace(unittest.TestCase):
    """#14: the form a name is cached in is decided when it is written, under
    the lock, so a set_fqdn() during a lookup cannot be undone by it."""

    def test_a_lookup_in_flight_lands_in_the_new_form(self):
        gate, calls = gated_resolve(self)
        r = Resolver(mode="dns", workers=1)
        self.addCleanup(r.shutdown)
        r.lookup("10.0.0.1")
        self.assertTrue(wait_until(lambda: calls), "the lookup never started")
        r.set_fqdn(True)
        gate.set()
        self.assertTrue(drain(r))
        self.assertEqual(r.lookup("10.0.0.1"), "nas.lan")
        self.assertEqual(r.local_hosts(), [("10.0.0.1", ["nas.lan"])])

        r.set_fqdn(False)
        self.assertIsNone(r.lookup("10.0.0.1"), "the cache was not cleared")
        self.assertTrue(drain(r))
        self.assertEqual(r.lookup("10.0.0.1"), "nas")


class Packaging(unittest.TestCase):
    """#16: the two hand-maintained version strings agree.

    The release workflow compares them, but only on a tag, which also has to
    be on main; so a bump that edited one file has already merged before
    anything notices. Checked here so it fails in the pull request instead.
    """

    def test_pyproject_and_the_package_agree_on_the_version(self):
        from lanname import __version__
        # A regex rather than tomllib, which arrived in 3.11 and this package
        # still runs on 3.9.
        pyproject = pathlib.Path(__file__).resolve().parents[1] / "pyproject.toml"
        found = re.search(r'^version = "([^"]+)"$',
                          pyproject.read_text(encoding="utf-8"), re.M)
        self.assertIsNotNone(found, "no version line in pyproject.toml")
        self.assertEqual(found.group(1), __version__)


class AddrKinds(unittest.TestCase):
    """#17: "private" means a LAN this machine could be on and nothing else,
    because it is the gate on what "all" mode probes."""

    def test_the_four_lan_blocks_are_private(self):
        for address in ("10.0.0.1", "172.16.0.1", "172.31.255.254",
                        "192.168.1.1", "fc00::1", "fd12::1"):
            self.assertEqual(addr_kind(address), "private", address)

    def test_documentation_benchmark_and_cgnat_ranges_are_public(self):
        # Every one of these is True for ip.is_private on some Python, and
        # none is a LAN. "public" means left alone unless resolve_public is
        # set, and never probed.
        for address in ("192.0.2.1", "198.51.100.7", "203.0.113.9", "198.18.0.1",
                        "192.0.0.1", "0.1.2.3", "100.64.0.1", "172.32.0.1",
                        "2001:db8::1", "2002::1"):
            self.assertEqual(addr_kind(address), "public", address)

    def test_such_an_address_is_never_probed(self):
        # The resolver's gate on mDNS and NetBIOS is addr_kind() == "private".
        # 192.0.2.1 used to pass it, and a NetBIOS query went out through the
        # default route to a documentation address. Both probes are stubbed
        # and reverse DNS is faked, so nothing here reaches the network.
        fake_network(self)
        probed = []
        for name in ("mdns_reverse", "netbios_name"):
            self.addCleanup(setattr, resolver_mod, name, getattr(resolver_mod, name))
            setattr(resolver_mod, name, lambda addr, timeout: probed.append(addr))
        r = Resolver(mode="off", resolve_public=True)
        r.mode = "all"
        for address in ("192.0.2.1", "198.18.0.1"):
            self.assertIsNone(r._resolve(address))
        self.assertEqual(probed, [])
        r._resolve("10.0.0.1")
        self.assertEqual(probed, ["10.0.0.1", "10.0.0.1"])


class ProbeReplies(unittest.TestCase):
    """#10: a probe only takes the reply to the query it sent.

    Both probes run here over the fake socket module, so nothing is sent. The
    fake stamps each reply with the id it saw go out, as a responder would, so
    the id check passes unless a test asks for it not to.
    """

    ADDR = "10.0.0.1"

    def test_mdns_takes_a_reply_from_port_5353(self):
        fake = FakeSocket([(mdns_reply("nas.local"), (self.ADDR, 5353))])
        fake_network(self, fake=fake)
        self.assertEqual(resolver_mod.mdns_reverse(self.ADDR), "nas.local")
        self.assertEqual(fake.sent[0][1], ("224.0.0.251", 5353))

    def test_mdns_skips_a_reply_from_another_port_and_keeps_waiting(self):
        fake = FakeSocket([(mdns_reply("evil.local"), (self.ADDR, 40000)),
                           (mdns_reply("nas.local"), (self.ADDR, 5353))])
        fake_network(self, fake=fake)
        self.assertEqual(resolver_mod.mdns_reverse(self.ADDR), "nas.local")

    def test_mdns_skips_a_reply_with_the_wrong_transaction_id(self):
        fake = FakeSocket([(mdns_reply("evil.local"), (self.ADDR, 5353))],
                          skew_tid=True)
        fake_network(self, fake=fake)
        self.assertIsNone(resolver_mod.mdns_reverse(self.ADDR))

    def test_netbios_connects_to_the_host_and_reads_its_reply(self):
        fake = FakeSocket([(nbstat_reply("NAS"), (self.ADDR, 137))])
        fake_network(self, fake=fake)
        self.assertEqual(resolver_mod.netbios_name(self.ADDR), "NAS")
        self.assertEqual(fake.peer, (self.ADDR, 137))

    def test_netbios_refuses_the_wrong_transaction_id(self):
        fake = FakeSocket([(nbstat_reply("NAS"), (self.ADDR, 137))],
                          skew_tid=True)
        fake_network(self, fake=fake)
        self.assertIsNone(resolver_mod.netbios_name(self.ADDR))

    def test_netbios_refuses_a_query_echoed_back(self):
        fake = FakeSocket([(nbstat_reply("NAS", response=False), (self.ADDR, 137))])
        fake_network(self, fake=fake)
        self.assertIsNone(resolver_mod.netbios_name(self.ADDR))


class ProbeFailures(unittest.TestCase):
    """#12: a probe that cannot send answers None, and the next one still runs.

    A host with no default route has no route to 224.0.0.251 either, and the
    multicast send used to raise out of `_resolve()` before NetBIOS was tried.
    """

    ADDR = "10.0.0.1"

    def test_mdns_answers_none_when_the_send_fails(self):
        fake_network(self, fake=FakeSocket(refuse_send=True))
        self.assertIsNone(resolver_mod.mdns_reverse(self.ADDR))

    def test_both_probes_answer_none_when_no_socket_can_be_opened(self):
        fake_network(self, refuse_open=True)
        self.assertIsNone(resolver_mod.mdns_reverse(self.ADDR))
        self.assertIsNone(resolver_mod.netbios_name(self.ADDR))

    def test_a_failed_multicast_send_still_reaches_netbios(self):
        fake_network(self, fake=[
            FakeSocket(refuse_send=True),
            FakeSocket([(nbstat_reply("NAS"), (self.ADDR, 137))]),
        ])
        r = Resolver(mode="all", workers=1)
        self.addCleanup(r.shutdown)
        r.lookup(self.ADDR)
        self.assertTrue(drain(r))
        self.assertEqual(r.lookup(self.ADDR), "NAS")
        self.assertEqual(r.stats["via_netbios"], 1)


class ProbeGate(unittest.TestCase):
    """#23: `local_networks` decides where a probe is allowed to go.

    Private is a very large space and says nothing about what is reachable
    here, so an address arriving with a spoofed 10/8 source used to send a
    NetBIOS query straight to it, wherever the route led. These tests run over
    the fake socket module, so "was a probe sent" is answered by looking at
    what the fake was handed rather than by watching a link.
    """

    INSIDE = "10.0.0.1"
    OUTSIDE = "10.9.9.9"
    NETWORKS = ("10.0.0.0/24",)

    def probing_resolver(self, **kwargs):
        r = Resolver(mode="all", workers=1, **kwargs)
        self.addCleanup(r.shutdown)
        return r

    def test_an_address_outside_the_networks_is_never_probed(self):
        fake = FakeSocket([(nbstat_reply("NAS"), (self.OUTSIDE, 137))])
        fake_network(self, fake=fake)
        r = self.probing_resolver(local_networks=self.NETWORKS)
        r.lookup(self.OUTSIDE)
        self.assertTrue(drain(r))
        self.assertEqual(fake.sent, [])
        self.assertIsNone(r.lookup(self.OUTSIDE))
        self.assertEqual(r.stats["off_link"], 1)
        self.assertEqual(r.stats["missed"], 1)

    def test_an_address_inside_the_networks_is_probed(self):
        fake_network(self, fake=[
            FakeSocket(refuse_send=True),
            FakeSocket([(nbstat_reply("NAS"), (self.INSIDE, 137))]),
        ])
        r = self.probing_resolver(local_networks=self.NETWORKS)
        r.lookup(self.INSIDE)
        self.assertTrue(drain(r))
        self.assertEqual(r.lookup(self.INSIDE), "NAS")
        self.assertEqual(r.stats["off_link"], 0)

    def test_the_default_probes_anywhere_private(self):
        """The gate is opt-in; without it nothing about "all" mode moves."""
        fake_network(self, fake=[
            FakeSocket(refuse_send=True),
            FakeSocket([(nbstat_reply("NAS"), (self.OUTSIDE, 137))]),
        ])
        r = self.probing_resolver()
        self.assertIsNone(r.local_networks)
        r.lookup(self.OUTSIDE)
        self.assertTrue(drain(r))
        self.assertEqual(r.lookup(self.OUTSIDE), "NAS")

    def test_an_empty_list_probes_nothing(self):
        """Distinct from None: "nowhere" is a thing to ask for, "anywhere" is
        what leaving the argument out means."""
        fake = FakeSocket([(nbstat_reply("NAS"), (self.INSIDE, 137))])
        fake_network(self, fake=fake)
        r = self.probing_resolver(local_networks=[])
        self.assertEqual(r.local_networks, ())
        r.lookup(self.INSIDE)
        self.assertTrue(drain(r))
        self.assertEqual(fake.sent, [])
        self.assertEqual(r.stats["off_link"], 1)

    def test_an_interface_address_with_a_prefix_is_read_as_its_network(self):
        r = self.probing_resolver(local_networks=["10.0.0.7/24"])
        self.assertEqual([str(net) for net in r.local_networks], ["10.0.0.0/24"])
        self.assertTrue(r._on_link(self.INSIDE))
        self.assertFalse(r._on_link(self.OUTSIDE))

    def test_both_families_can_be_listed_together(self):
        r = self.probing_resolver(local_networks=["10.0.0.0/24", "fd00::/64"])
        self.assertTrue(r._on_link("fd00::5"))
        self.assertTrue(r._on_link(self.INSIDE))
        self.assertFalse(r._on_link("fd01::5"))

    def test_an_address_that_does_not_parse_is_refused(self):
        r = self.probing_resolver(local_networks=self.NETWORKS)
        self.assertFalse(r._on_link("not-an-address"))

    def test_a_bad_entry_fails_at_construction(self):
        """Where the TTLs fail, and for the same reason: a typo that widened
        or closed this gate would otherwise show up as traffic, or none."""
        with self.assertRaises(ValueError):
            Resolver(mode="off", local_networks=["10.0.0.0/33"])
        with self.assertRaises(ValueError):
            Resolver(mode="off", local_networks=[None])

    def test_one_network_need_not_be_wrapped_in_a_list(self):
        """A string is iterable over its characters, so iterating first would
        answer a perfectly good network with a complaint about "1"."""
        r = self.probing_resolver(local_networks="10.0.0.0/24")
        self.assertEqual([str(net) for net in r.local_networks], ["10.0.0.0/24"])
        self.assertTrue(r._on_link(self.INSIDE))
        self.assertFalse(r._on_link(self.OUTSIDE))

    def test_a_bare_network_object_is_one_network_not_its_addresses(self):
        """`ipaddress` networks iterate over every address they hold, so a /8
        passed on its own would build sixteen million single-address networks
        before the constructor returned, if it ever did."""
        r = self.probing_resolver(
            local_networks=ipaddress.ip_network("10.0.0.0/8"))
        self.assertEqual([str(net) for net in r.local_networks], ["10.0.0.0/8"])
        self.assertTrue(r._on_link(self.OUTSIDE))

    def test_something_that_is_not_networks_at_all_fails_at_construction(self):
        with self.assertRaises(TypeError):
            Resolver(mode="off", local_networks=24)


class FakeClock:
    """`time` for the resolver, with a monotonic that only a test moves.

    A probe that spent its budget is the case worth checking, and sleeping
    for it would make the assertion a race against the clock's granularity
    rather than a statement about the budget: on Windows `time.monotonic()`
    can read a 0.1 second sleep as slightly less than 0.1. Everything else on
    the module, `sleep` included, is the real thing.
    """

    def __init__(self, start=1000.0):
        self.now = start

    def monotonic(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds

    def __getattr__(self, name):
        return getattr(time, name)


class ProbeDeadline(unittest.TestCase):
    """#23: the two probes share one deadline instead of taking `timeout` each.

    The probes are replaced rather than faked at the socket, since what is
    being checked is the budget each is handed, not what either does with it.
    """

    ADDR = "10.0.0.1"
    TIMEOUT = 0.2

    def setUp(self):
        self.clock = FakeClock()
        self.addCleanup(setattr, resolver_mod, "time", resolver_mod.time)
        resolver_mod.time = self.clock

    def record_probes(self, mdns=None, netbios=None, mdns_spends=False):
        """Swap both probes for recorders. Returns the timeouts they were given."""
        seen = []

        def fake_mdns(addr, timeout=1.0):
            seen.append(("mdns", timeout))
            if mdns_spends:
                self.clock.advance(timeout)
            return mdns

        def fake_netbios(addr, timeout=1.0):
            seen.append(("netbios", timeout))
            return netbios

        for name, func in (("mdns_reverse", fake_mdns),
                           ("netbios_name", fake_netbios)):
            self.addCleanup(setattr, resolver_mod, name,
                            getattr(resolver_mod, name))
            setattr(resolver_mod, name, func)
        return seen

    def resolve_once(self, seen):
        r = Resolver(mode="all", workers=1, timeout=self.TIMEOUT)
        self.addCleanup(r.shutdown)
        fake_network(self)
        r.lookup(self.ADDR)
        self.assertTrue(drain(r))
        return r, dict(seen)

    def test_mdns_gets_half_the_budget(self):
        r, seen = self.resolve_once(self.record_probes())
        self.assertEqual(seen["mdns"], self.TIMEOUT / 2.0)
        self.assertIsNone(r.lookup(self.ADDR))

    def test_netbios_still_runs_after_an_mdns_miss(self):
        """The regression a naive deadline would introduce. An mDNS miss is
        the ordinary case for the hosts NetBIOS is there to name, so spending
        the whole budget on it would leave them nameless."""
        r, seen = self.resolve_once(self.record_probes(netbios="NAS"))
        self.assertIn("netbios", seen)
        self.assertGreater(seen["netbios"], 0)
        self.assertEqual(r.lookup(self.ADDR), "NAS")

    def test_a_mdns_that_spends_its_half_leaves_netbios_the_rest(self):
        r, seen = self.resolve_once(
            self.record_probes(netbios="NAS", mdns_spends=True))
        # mDNS took its whole half, so what is left is the other half and no
        # more. The pair are bounded by `timeout` however the first one goes.
        # Compared approximately because the budget is a difference of two
        # clock readings, and binary floating point leaves a few parts in
        # 10^16 on it; the assertion is about the half, not the residue.
        self.assertAlmostEqual(seen["netbios"], self.TIMEOUT / 2.0, places=6)
        self.assertEqual(r.lookup(self.ADDR), "NAS")

    def test_netbios_is_skipped_once_the_deadline_has_passed(self):
        seen = self.record_probes(netbios="NAS")

        def spendthrift(addr, timeout=1.0):
            seen.append(("mdns", timeout))
            self.clock.advance(self.TIMEOUT)
            return None

        resolver_mod.mdns_reverse = spendthrift
        r, seen = self.resolve_once(seen)
        self.assertNotIn("netbios", seen)
        self.assertIsNone(r.lookup(self.ADDR))

    def test_an_mdns_answer_skips_netbios_entirely(self):
        r, seen = self.resolve_once(self.record_probes(mdns="nas.local"))
        self.assertNotIn("netbios", seen)
        self.assertEqual(r.lookup(self.ADDR), "nas")


class NameChecks(unittest.TestCase):
    """#11: a name off the link is refused if it could do anything on a
    terminal, and bounded at the DNS limits, before it reaches the cache."""

    ADDR = "10.0.0.1"

    def test_control_characters_are_refused(self):
        for bad in ("\x1b[2Kgateway", "nas\nforged", "nas\x00hidden", "nas\x7f",
                    "nas\tx", "\x1b]8;;http://evil.example/\x07nas"):
            self.assertIsNone(resolver_mod._checked_name(bad), repr(bad))

    def test_ordinary_and_non_ascii_names_pass(self):
        # A Cyrillic lookalike, a right-to-left override and the replacement
        # character all pass: legal in a name, and the caller's to judge.
        for good in ("router", "printer.workshop.lan", "r\u043euter",
                     "invoice\u202egpj.exe", "nas\ufffd", "n" * 63):
            self.assertEqual(resolver_mod._checked_name(good), good)

    def test_a_name_that_is_only_dots_is_refused(self):
        # "." would shorten to nothing yet count as found, and stop "all"
        # mode trying the probes for the address.
        self.assertIsNone(resolver_mod._checked_name("."))
        self.assertIsNone(resolver_mod._checked_name("..."))
        self.assertEqual(resolver_mod._checked_name("nas."), "nas.")

    def test_a_space_passes_only_where_netbios_allows_it(self):
        self.assertIsNone(resolver_mod._checked_name("my host"))
        self.assertEqual(resolver_mod._checked_name("my host", allow_space=True),
                         "my host")

    def test_the_limits_are_measured_in_bytes(self):
        check = resolver_mod._checked_name
        self.assertIsNone(check("n" * 64))
        self.assertIsNone(check("\u00e9" * 32), "32 characters but 64 bytes")
        whole = ".".join(["x" * 63] * 4)[:253]
        self.assertEqual(check(whole), whole)
        self.assertIsNone(check(whole + "x"))

    def test_dns_read_name_refuses_a_name_past_255_bytes(self):
        data = labels(b"w" * 63, b"x" * 63, b"y" * 63, b"z" * 63, b"v" * 10)
        name, off = resolver_mod.dns_read_name(data, 0)
        self.assertIsNone(name)
        self.assertEqual(off, len(data))

    def test_a_pointer_loop_cannot_inflate_a_name(self):
        # The rdata is 240 bytes of labels ending in a pointer back to its
        # own start, so every permitted hop re-reads all of them. Refused on
        # the bytes read, whatever the hop count.
        header = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)
        answer = resolver_mod.dns_encode_name(QNAME)
        start = len(header) + len(answer) + 10
        rdata = labels(b"a" * 60, b"b" * 60, b"c" * 60, b"d" * 60,
                       end=struct.pack("!H", 0xC000 | start))
        data = header + answer + struct.pack("!HHIH", 12, 1, 120, len(rdata)) + rdata
        self.assertIsNone(resolver_mod.parse_ptr_response(data, QNAME))

    def test_mdns_refuses_a_name_with_a_newline(self):
        fake_network(self, fake=FakeSocket(
            [(mdns_reply("nas\nforged"), (self.ADDR, 5353))]))
        self.assertIsNone(resolver_mod.mdns_reverse(self.ADDR))

    def test_netbios_refuses_a_control_character(self):
        fake_network(self, fake=FakeSocket(
            [(nbstat_reply("NAS\x1bX"), (self.ADDR, 137))]))
        self.assertIsNone(resolver_mod.netbios_name(self.ADDR))

    def test_netbios_padding_is_stripped_but_nothing_else(self):
        # The 15 byte field is space padded, so the padding has to come off
        # before the check or every name would carry it. Stripping whitespace
        # rather than padding would take the newline here off too and turn a
        # refusable name into "NAS".
        fake_network(self, fake=FakeSocket(
            [(nbstat_reply("NAS\n"), (self.ADDR, 137))]))
        self.assertIsNone(resolver_mod.netbios_name(self.ADDR))

    def test_reverse_dns_results_are_checked_too(self):
        fake_network(self, hosts={self.ADDR: "nas\x1b[2J.lan"})
        r = Resolver(mode="dns", workers=1)
        self.addCleanup(r.shutdown)
        r.lookup(self.ADDR)
        self.assertTrue(drain(r))
        self.assertIsNone(r.lookup(self.ADDR))
        self.assertEqual(r.stats["via_dns"], 0)
        self.assertEqual(r.stats["missed"], 1)


if __name__ == "__main__":
    unittest.main()
