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

import socket
import struct
import time
import unittest
from collections import OrderedDict

from lanname import Resolver
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
