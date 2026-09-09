# lanname harness

A PySide6 window for driving a real [`lanname`](../../README.md) resolver and
watching what it does. Every argument the constructor takes has a control,
every counter it keeps has a row, and the addresses you give it are asked
about again on a tick, so the miss on the first ask and the name on a later
one are both visible rather than inferred.

Where the [poker tool](../poker/README.md) beside it crafts the replies
`lanname` parses, this drives the package itself. The two go together: build a
resolver here in `"all"` mode, run the poker responder on the same link, and
the name you composed there arrives here through the whole path.

## What it exposes

Everything in the package's public API that a window can reach.

* **A resolver built from the full signature.** `mode`, `hosts_files`,
  `workers`, `resolve_public`, `fqdn`, `positive_ttl`, `negative_ttl`,
  `timeout` and `local_networks`, with the rows named after the arguments
  rather than prose. The equivalent `Resolver(...)` call is shown as you
  change them and can be copied into an interpreter or a test.
* **The two things that change on a running resolver.** `set_mode()` and
  `set_fqdn()` are applied as you touch them; everything else is construction
  only, and the window says so when the form has moved past what the live
  resolver was built with.
* **Build and shutdown**, the two halves of the `with` block. Asking on the
  tick stops at a shutdown, so nothing goes on climbing against a resolver you
  have stopped, and the rows say `shut down` rather than what they would have
  done. **Ask once** still asks, and still gets an answer from a static entry
  or an unexpired cache entry, which is what `shutdown()` leaves working. A
  resolver is not restartable, so building again builds a new one.
* **Addresses asked about on a tick.** Each row shows what `lanname` classes
  the address as, what the resolver as built would do with it (the form is
  only a proposal until you rebuild, and the column follows the resolver),
  what `lookup()` returned this time, how many asks have been made, how many of
  them missed, and how long the first name took to arrive. Names are shown as
  a repr, so one carrying a control character cannot rearrange the table.
* **A feed for the work queue.** Some number of addresses out of a network,
  offered to `lookup()` once each and not watched. This is how to see
  `dropped` climb, since the queue holds 4,096 and drops rather than blocking.
* **Every counter**, from `hits` through to `off_link`, refreshed on the same
  tick.
* **`local_hosts()`**, the private addresses seen with a name all session and
  the names each answered to, newest first.
* **The ceilings**, `RESOLVER_CACHE_MAX`, `MAX_OBSERVED_HOSTS`,
  `MAX_NAMES_PER_HOST` and `MAX_ADDR_KIND_CACHE`, moved on the modules that
  own them. They are read afresh every time they are used, so lowering one
  applies to the resolver already running: set the cache to 10, feed a few
  hundred addresses, and watch `evicted`. `MAX_ADDR_KIND_CACHE` is the one
  with nothing to watch, since it decides whether a classification is
  remembered and evicts nothing. Values apply when the box is left or
  stepped rather than as each digit is typed, so that a ceiling on its way to
  20,000 does not pass through 2 and take the session's record with it.
* **`mdns_reverse()` and `netbios_name()` on their own**, against an address
  and a timeout of your choosing, off the GUI thread so the window keeps
  painting while they wait.
* **The `lanname` logger**, with a level selector. The package installs a
  NullHandler and nothing else, so this is the only thing that will show you a
  hosts file that could not be read or a lookup that raised.

## Installing and running

Python 3.10 or newer.

```
pip install --require-hashes -r requirements.txt
python -m lanname_harness
```

If `lanname` is not installed, the checkout this tool lives in is used, two
directories up from here, so running it from this repository needs nothing
arranged. Point `LANNAME_REPO` at another checkout to drive that one instead.
The window says which one it imported and where from.

No display and no PySide6 needed for a quick check:

```
python -m lanname_harness --selftest
```

That prints the modes and their descriptions, the ceilings, a table of what
each mode would do with an address of each kind, and then builds a resolver in
`"off"` mode over a temporary hosts file and asks it about a handful of
addresses. It sends nothing: `"off"` starts no threads and answers from static
entries alone.

## A tour in five minutes

1. Press **Samples** to put one address of each kind on the table, then
   **Build resolver** with the default `"dns"` mode. The private addresses go
   from `None` to a name or to a cached miss; the multicast, loopback and
   unparseable ones are never looked up at all, and the "Would do" column says
   why before it happens.
2. Turn on **fqdn**. The cache empties, every row misses once more, and the
   names come back with their domain on.
3. Set `positive_ttl` to 10 and rebuild. The names disappear and are fetched
   again ten seconds later, which is the TTL doing its job.
4. Set `RESOLVER_CACHE_MAX` to 10 and feed 200 addresses. `evicted` climbs and
   the cache stays at its ceiling rather than emptying itself.
5. Set `workers` to 1 and feed 5,000. `dropped` climbs: the queue is bounded
   on purpose, because the alternative to dropping work is growing memory
   without limit. Every address that does get through is a real query in
   `"dns"` mode, so pick the size with that in mind.

## Safety

In `"all"` mode, a private address that reverse DNS did not name, and that
`local_networks` allows, gets an mDNS query on the link and a NetBIOS query
sent straight to it. The probe buttons send a packet whatever mode the
resolver is in, and to any address you give them. `"dns"` mode is one
query per address to the resolver the machine already uses. Use this on a
network you own or are authorised to test, and set `local_networks` when the
addresses come from anywhere you do not control.

Nothing here is a load generator. The feed exists to fill a bounded queue, and
in `"all"` mode it asks first.
