"""The resolver: off unless asked, and never blocking when on.

No test here touches the network. `_resolve` is replaced with a canned answer,
which is the whole point of the split between "how do I find a name" and
"how do I cache and schedule finding one".

The ceiling is patched on `resolver_mod` rather than on the package, because
the worker reads it as a module global and rebinding the re-exported copy
would leave the real one in place.
"""

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


class OffByDefault(unittest.TestCase):
    def test_the_default_mode_is_off(self):
        # It probes the LAN in its widest mode. A library that did that
        # without being asked would be doing something the caller did not
        # sanction on a network they may not own.
        resolver = Resolver()
        self.addCleanup(resolver.shutdown)
        self.assertEqual(resolver.mode, "off")

    def test_off_starts_no_threads(self):
        resolver = Resolver()
        self.addCleanup(resolver.shutdown)
        self.assertEqual(resolver._threads, [])

    def test_off_answers_none_without_looking(self):
        resolver = Resolver()
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
        r = Resolver(mode="dns", workers=0)
        self.addCleanup(r.shutdown)
        for _ in range(5):
            r.lookup("10.0.0.99")
        self.assertEqual(r._queue.qsize(), 1)

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


if __name__ == "__main__":
    unittest.main()
