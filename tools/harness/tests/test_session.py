"""Tests for the session, the half of the harness that touches lanname.

**No test here sends a packet.** Two ways of arranging that, both taken from
lanname's own suite. Most tests build the resolver in ``"off"`` mode, which
starts no threads and answers from static entries alone. The few that need a
name to appear replace ``Resolver._resolve``, the only method that touches the
network, with :func:`canned` *before* the resolver is built, so no lookup ever
reaches ``gethostbyaddr`` or a socket.

The window itself is not exercised: it needs PySide6 and a display, and it
holds no resolver logic of its own to test.
"""

import os
import tempfile
import time
import unittest
from dataclasses import replace

from lanname_harness import session

lanname = session._load()
if lanname is not None:
    from lanname import Resolver
    from lanname import resolver as resolver_mod
else:                                   # pragma: no cover - covered by skip
    resolver_mod = Resolver = None

needs_lanname = unittest.skipIf(lanname is None, "lanname is not importable")


def canned(self, addr):
    """Stand in for Resolver._resolve: a name from the address, no network."""
    return "host-" + addr.replace(".", "-") + ".lan"


def hosts_file(entries):
    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".hosts", delete=False, encoding="utf-8")
    with handle:
        for addr, name in entries:
            handle.write(f"{addr} {name}\n")
    return handle.name


def poll_until(harness, done, deadline=15.0):
    """Poll the way the window does until *done*, or give up. True if it did.

    Polling rather than sleeping for a fixed period, and asking the harness
    rather than reaching into the resolver's queue: this is the loop the
    window runs, so a test that waits this way waits the way the tool does.
    """
    end = time.time() + deadline
    while time.time() < end:
        harness.poll()
        if done():
            return True
        time.sleep(0.01)
    return False


class Options(unittest.TestCase):

    def test_only_mode_and_fqdn_change_without_a_rebuild(self):
        base = session.Options()
        self.assertFalse(base.rebuild_needed(replace(base, mode="all")))
        self.assertFalse(base.rebuild_needed(replace(base, fqdn=True)))
        self.assertTrue(base.rebuild_needed(replace(base, workers=8)))
        self.assertTrue(base.rebuild_needed(replace(base, timeout=2.0)))
        self.assertTrue(base.rebuild_needed(replace(base, networks="10/8")))

    def test_the_three_states_of_local_networks_stay_apart(self):
        # None is no restriction and an empty list is "probe nothing", which
        # a text field alone cannot tell apart. Hence the separate flag.
        self.assertIsNone(session.Options().local_networks())
        self.assertEqual(
            session.Options(restrict_networks=True).local_networks(), [])
        self.assertEqual(
            len(session.Options(restrict_networks=True,
                                networks="192.168.1.0/24 10.0.0.0/8"
                                ).local_networks()), 2)

    def test_host_bits_are_allowed_in_a_network(self):
        # As lanname parses it: a line copied out of `ip addr` reads as the
        # network the interface sits in.
        networks = session.parse_networks("192.168.1.7/24")
        self.assertEqual(str(networks[0]), "192.168.1.0/24")

    def test_a_network_that_does_not_parse_is_refused(self):
        with self.assertRaises(ValueError):
            session.parse_networks("192.168.1.0/24 not-a-network")

    def test_the_call_shows_every_argument(self):
        text = session.call_repr(session.Options(
            mode="all", restrict_networks=True, networks="192.168.1.0/24"))
        for argument in ("mode=", "hosts_files=", "workers=", "resolve_public=",
                         "fqdn=", "positive_ttl=", "negative_ttl=", "timeout=",
                         "local_networks="):
            self.assertIn(argument, text)
        self.assertIn("'192.168.1.0/24'", text)

    def test_the_call_says_so_rather_than_raising_on_a_bad_network(self):
        text = session.call_repr(session.Options(
            restrict_networks=True, networks="nonsense"))
        self.assertIn("<invalid>", text)


class Parsing(unittest.TestCase):

    def test_addresses_split_on_commas_or_whitespace(self):
        self.assertEqual(session.split_addrs("10.0.0.1, 10.0.0.2  10.0.0.3"),
                         ["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        self.assertEqual(session.split_addrs("   "), [])

    def test_the_feed_takes_host_addresses_from_the_network(self):
        addrs = list(session.feed_addresses("10.99.0.0/16", 3))
        self.assertEqual(addrs, ["10.99.0.1", "10.99.0.2", "10.99.0.3"])

    def test_the_feed_does_not_materialise_the_whole_network(self):
        # A /8 asked for three addresses must not build sixteen million.
        started = time.monotonic()
        self.assertEqual(len(list(session.feed_addresses("10.0.0.0/8", 3))), 3)
        self.assertLess(time.monotonic() - started, 1.0)


@needs_lanname
class Ceilings(unittest.TestCase):

    def setUp(self):
        self.saved = {name: session.ceiling(name)
                      for name, _module, _desc in session.CEILINGS}

    def tearDown(self):
        for name, value in self.saved.items():
            session.set_ceiling(name, value)

    def test_a_ceiling_moves_on_the_module_that_owns_it(self):
        # On lanname.resolver and lanname.addrs, never on the lanname package:
        # the worker reads the constant as a global of its own module, so
        # rebinding the re-exported copy would change nothing that matters.
        session.set_ceiling("RESOLVER_CACHE_MAX", 123)
        self.assertEqual(resolver_mod.RESOLVER_CACHE_MAX, 123)
        self.assertEqual(session.ceiling("RESOLVER_CACHE_MAX"), 123)

        session.set_ceiling("MAX_ADDR_KIND_CACHE", 7)
        from lanname import addrs as addrs_mod
        self.assertEqual(addrs_mod.MAX_ADDR_KIND_CACHE, 7)

    def test_an_unknown_ceiling_is_a_key_error(self):
        with self.assertRaises(KeyError):
            session.set_ceiling("NO_SUCH_CEILING", 1)


@needs_lanname
class StaticResolver(unittest.TestCase):
    """A resolver in "off" mode: no threads, no traffic, static entries only."""

    def setUp(self):
        self.path = hosts_file([("192.168.1.10", "nas.lan"),
                                ("192.168.1.11", "printer.lan")])
        self.addCleanup(os.unlink, self.path)
        self.harness = session.Session()
        self.addCleanup(self.harness.shutdown)
        self.harness.build(session.Options(mode="off", hosts_files=[self.path]))

    def test_the_hosts_file_is_read_at_construction(self):
        self.assertEqual(self.harness.static_count(), 2)

    def test_a_static_entry_answers_on_the_first_ask(self):
        watch = self.harness.watch("192.168.1.10")
        self.harness.poll()
        self.assertEqual(watch.name, "nas")
        self.assertEqual(watch.misses, 0)
        self.assertIsNotNone(watch.latency())

    def test_fqdn_changes_the_form_without_a_rebuild(self):
        watch = self.harness.watch("192.168.1.10")
        self.harness.poll()
        self.assertEqual(watch.name, "nas")
        self.harness.set_fqdn(True)
        self.harness.poll()
        self.assertEqual(watch.name, "nas.lan")
        self.assertFalse(self.harness.needs_rebuild())

    def test_nothing_else_is_looked_up_in_off_mode(self):
        watch = self.harness.watch("192.168.1.99")
        self.harness.poll()
        self.harness.poll()
        self.assertIsNone(watch.name)
        self.assertEqual(watch.misses, 2)

    def test_a_static_address_reaches_local_hosts(self):
        self.harness.watch("192.168.1.10")
        self.harness.poll()
        self.assertEqual(self.harness.local_hosts(),
                         [("192.168.1.10", ["nas"])])

    def test_every_documented_counter_is_reported(self):
        stats = self.harness.stats()
        self.assertEqual(sorted(stats), sorted(session.STAT_KEYS))
        self.assertEqual(set(stats.values()), {0})


@needs_lanname
class WatchList(unittest.TestCase):

    def setUp(self):
        self.harness = session.Session()
        self.addCleanup(self.harness.shutdown)
        self.harness.build(session.Options(mode="off"))

    def test_an_address_is_watched_once(self):
        first = self.harness.watch("10.0.0.1")
        again = self.harness.watch("10.0.0.1")
        self.assertIs(first, again)
        self.assertEqual(len(self.harness.watches), 1)

    def test_the_watch_list_is_bounded(self):
        for i in range(session.MAX_WATCHES):
            self.harness.watch(f"10.0.{i // 256}.{i % 256}")
        with self.assertRaises(ValueError):
            self.harness.watch("10.9.9.9")

    def test_forgetting_an_address(self):
        self.harness.watch("10.0.0.1")
        self.harness.watch("10.0.0.2")
        self.harness.unwatch("10.0.0.1")
        self.assertEqual([w.addr for w in self.harness.watches], ["10.0.0.2"])
        self.harness.clear_watches()
        self.assertEqual(self.harness.watches, [])

    def test_a_rebuild_starts_the_counts_again(self):
        watch = self.harness.watch("10.0.0.1")
        self.harness.poll()
        self.assertEqual(watch.calls, 1)
        self.harness.build(session.Options(mode="off"))
        self.assertEqual(watch.calls, 0)
        self.assertEqual(watch.misses, 0)


@needs_lanname
class Verdicts(unittest.TestCase):
    """What the harness says a resolver would do, before it does it."""

    def setUp(self):
        self.harness = session.Session()
        self.addCleanup(self.harness.shutdown)

    def verdict(self, addr, **options):
        self.harness.options = session.Options(**options)
        return self.harness.verdict(addr)

    def test_off_mode_looks_nothing_up(self):
        self.assertEqual(self.verdict("192.168.1.1", mode="off"),
                         (False, "mode off"))

    def test_public_addresses_wait_for_resolve_public(self):
        self.assertEqual(self.verdict("8.8.8.8", mode="dns"),
                         (False, "public"))
        self.assertEqual(
            self.verdict("8.8.8.8", mode="dns", resolve_public=True),
            (True, "dns"))

    def test_the_kinds_that_are_never_looked_up(self):
        for addr, kind in (("224.0.0.251", "multicast"),
                           ("127.0.0.1", "special"),
                           ("nonsense", "unknown")):
            self.assertEqual(self.verdict(addr, mode="all"), (False, kind))

    def test_probes_are_private_only_even_with_resolve_public(self):
        self.assertEqual(
            self.verdict("8.8.8.8", mode="all", resolve_public=True),
            (True, "dns"))

    def test_local_networks_narrows_what_is_probed(self):
        inside = self.verdict("192.168.1.5", mode="all", restrict_networks=True,
                              networks="192.168.1.0/24")
        outside = self.verdict("10.0.0.5", mode="all", restrict_networks=True,
                               networks="192.168.1.0/24")
        self.assertEqual(inside, (True, "dns, mDNS, NetBIOS"))
        self.assertEqual(outside, (True, "dns (off link)"))

    def test_an_empty_restriction_probes_nothing(self):
        self.assertEqual(
            self.verdict("192.168.1.5", mode="all", restrict_networks=True),
            (True, "dns (off link)"))

    def test_a_static_entry_answers_whatever_the_mode(self):
        path = hosts_file([("192.168.1.10", "nas.lan")])
        self.addCleanup(os.unlink, path)
        self.harness.build(session.Options(mode="off", hosts_files=[path]))
        self.assertEqual(self.harness.verdict("192.168.1.10"), (True, "static"))


@needs_lanname
class Lifecycle(unittest.TestCase):

    def setUp(self):
        self.harness = session.Session()
        self.addCleanup(self.harness.shutdown)

    def test_a_build_that_raises_leaves_the_old_resolver_alone(self):
        self.harness.build(session.Options(mode="off"))
        first = self.harness.resolver
        with self.assertRaises(ValueError):
            self.harness.build(session.Options(mode="off", positive_ttl=-1))
        self.assertIs(self.harness.resolver, first)
        self.assertTrue(self.harness.running())

    def test_a_network_that_does_not_parse_stops_the_build(self):
        with self.assertRaises(ValueError):
            self.harness.build(session.Options(
                mode="off", restrict_networks=True, networks="nonsense"))
        self.assertIsNone(self.harness.resolver)

    def test_shutdown_is_reported_and_repeatable(self):
        self.harness.build(session.Options(mode="off"))
        self.assertTrue(self.harness.running())
        self.harness.shutdown()
        self.harness.shutdown()
        self.assertFalse(self.harness.running())

    def test_the_form_moving_on_asks_for_a_rebuild(self):
        self.harness.build(session.Options(mode="off"))
        self.assertFalse(self.harness.needs_rebuild())
        self.harness.options = replace(self.harness.options, workers=8)
        self.assertTrue(self.harness.needs_rebuild())
        # Mode and fqdn are not among them: those two change in place.
        self.harness.options = replace(self.harness.options, workers=4)
        self.harness.set_mode("dns")
        self.assertFalse(self.harness.needs_rebuild())

    def test_the_tick_stops_asking_once_the_resolver_is_shut_down(self):
        # The window asks on a timer. Left running after a shutdown it shows
        # counts climbing against a resolver the caller has stopped, which
        # reads as a resolver that did not stop.
        self.harness.build(session.Options(mode="off"))
        watch = self.harness.watch("192.168.1.10")
        self.harness.tick()
        self.assertEqual(watch.calls, 1)
        self.harness.shutdown()
        self.harness.tick()
        self.harness.tick()
        self.assertEqual(watch.calls, 1)

    def test_asking_deliberately_still_works_after_a_shutdown(self):
        # lookup() is legal after shutdown() and answers from static entries
        # and the cache, which is worth being able to see on purpose.
        path = hosts_file([("192.168.1.10", "nas.lan")])
        self.addCleanup(os.unlink, path)
        self.harness.build(session.Options(mode="off", hosts_files=[path]))
        watch = self.harness.watch("192.168.1.10")
        self.harness.shutdown()
        self.harness.poll()
        self.assertEqual(watch.calls, 1)
        self.assertEqual(watch.name, "nas")

    def test_a_shutdown_resolver_says_it_looks_nothing_up(self):
        path = hosts_file([("192.168.1.10", "nas.lan")])
        self.addCleanup(os.unlink, path)
        self.harness.build(session.Options(mode="off", hosts_files=[path]))
        self.assertEqual(self.harness.verdict("192.168.1.11"),
                         (False, "mode off"))
        self.harness.shutdown()
        # The shutdown is what the table should report, ahead of the mode:
        # it is the more final of the two and the one just asked for.
        self.assertEqual(self.harness.verdict("192.168.1.11"),
                         (False, "shut down"))
        # Except a static entry, which is read before the cache and queues
        # nothing, so it answers after a shutdown like any other time.
        self.assertEqual(self.harness.verdict("192.168.1.10"), (True, "static"))

    def test_the_queue_bound_is_reported(self):
        self.harness.build(session.Options(mode="off"))
        self.assertEqual(self.harness.queue_size(), session.DEFAULT_QUEUE_SIZE)


@needs_lanname
class ThroughTheWorkers(unittest.TestCase):
    """The whole loop, with the one method that touches the network replaced.

    Resolver._resolve is swapped before any resolver is built, so a mode that
    would otherwise call gethostbyaddr never reaches it and nothing is sent.
    """

    def setUp(self):
        self.real_resolve = Resolver._resolve
        Resolver._resolve = canned
        self.addCleanup(self.restore)
        self.harness = session.Session()
        self.addCleanup(self.harness.shutdown)

    def restore(self):
        Resolver._resolve = self.real_resolve

    def test_the_first_ask_misses_and_a_later_one_has_the_name(self):
        self.harness.build(session.Options(mode="dns", workers=2))
        watch = self.harness.watch("192.168.1.50")
        self.harness.poll()
        self.assertIsNone(watch.name)
        self.assertEqual(watch.misses, 1)
        self.assertTrue(poll_until(self.harness, lambda: watch.name),
                        "the name never appeared")
        self.assertEqual(watch.name, "host-192-168-1-50")
        self.assertIsNotNone(watch.latency())

    def test_fqdn_keeps_the_whole_name(self):
        self.harness.build(session.Options(mode="dns", workers=2, fqdn=True))
        watch = self.harness.watch("192.168.1.50")
        self.assertTrue(poll_until(self.harness, lambda: watch.name))
        self.assertEqual(watch.name, "host-192-168-1-50.lan")

    def test_asking_again_after_the_name_is_known_is_a_cache_hit(self):
        self.harness.build(session.Options(mode="dns", workers=2))
        watch = self.harness.watch("192.168.1.50")
        self.assertTrue(poll_until(self.harness, lambda: watch.name))
        before = self.harness.stats()["hits"]
        self.harness.poll()
        self.assertEqual(self.harness.stats()["hits"], before + 1)

    def test_the_feed_puts_addresses_through_without_watching_them(self):
        self.harness.build(session.Options(mode="dns", workers=4))
        offered = self.harness.feed(session.feed_addresses("10.99.0.0/16", 50))
        self.assertEqual(offered, 50)
        self.assertEqual(self.harness.watches, [])
        self.assertTrue(
            poll_until(self.harness,
                       lambda: self.harness.stats()["resolved"] >= 50),
            "the fed addresses were not resolved")
        self.assertEqual(len(self.harness.local_hosts()), 50)

    def test_the_feed_queues_nothing_in_off_mode(self):
        self.harness.build(session.Options(mode="off"))
        self.harness.feed(session.feed_addresses("10.99.0.0/16", 20))
        self.assertEqual(self.harness.stats()["resolved"], 0)

    def test_lowering_the_cache_ceiling_evicts(self):
        saved = session.ceiling("RESOLVER_CACHE_MAX")
        self.addCleanup(session.set_ceiling, "RESOLVER_CACHE_MAX", saved)
        session.set_ceiling("RESOLVER_CACHE_MAX", 10)
        self.harness.build(session.Options(mode="dns", workers=4))
        self.harness.feed(session.feed_addresses("10.99.0.0/16", 40))
        self.assertTrue(
            poll_until(self.harness,
                       lambda: self.harness.stats()["evicted"] >= 30),
            "the cache did not evict down to its ceiling")


if __name__ == "__main__":
    unittest.main()
