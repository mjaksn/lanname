# lanname

[![CI](https://github.com/mjaksn/lanname/actions/workflows/ci.yml/badge.svg)](https://github.com/mjaksn/lanname/actions/workflows/ci.yml)
[![Release](https://github.com/mjaksn/lanname/actions/workflows/release.yml/badge.svg)](https://github.com/mjaksn/lanname/actions/workflows/release.yml)
[![PyPI](https://img.shields.io/pypi/v/lanname)](https://pypi.org/project/lanname/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/mjaksn/lanname/blob/main/LICENSE)

Address to hostname lookup on a local network: reverse DNS, mDNS and NetBIOS,
cached and never blocking the caller. Standard library only, no dependencies,
Python 3.9 and up.

```python
from lanname import Resolver

with Resolver(mode="dns", workers=4) as resolver:
    name = resolver.lookup("192.168.1.10")     # None until it is known
```

An IP address in a log line, a database row or a dashboard is much less useful
a year later than the name of the thing it was. The three ways to find that
name on a local network are all short, all standard library, and all annoying
enough to get right that nobody wants to write them twice.

Two things are worth stating before anything else. The first is why you would
reach for this rather than call `socket.gethostbyaddr` yourself. The second is
the one place it will do something you did not ask for if you let it.

**It never blocks.** `lookup()` reads a cache and returns, always. Misses are
queued for background workers. A caller draining a socket cannot afford to
wait on a DNS round trip, and UDP in particular has no backpressure, so
anything that stalls the read loop loses packets silently.

**The widest mode probes the LAN, and is not the default.** Installing this
says you want names. It does not say you want multicast queries and NetBIOS
requests going to hosts you happened to see an address for, on a network you
may not own. The default asks the resolver your machine already uses and
nothing more. `"all"` is a switch you throw deliberately.

---

## Contents

- [Installing](#installing)
- [Modes](#modes)
- [Resolver](#resolver)
- [What gets looked up](#what-gets-looked-up)
- [Where probes are allowed to go](#where-probes-are-allowed-to-go)
- [Static hosts files](#static-hosts-files)
- [What answered, over a session](#what-answered-over-a-session)
- [Counters](#counters)
- [Ceilings](#ceilings)
- [Logging](#logging)
- [The three methods on their own](#the-three-methods-on-their-own)
- [Crafting replies to test against](#crafting-replies-to-test-against)
- [Limitations](#limitations)
- [Licence](#licence)

---

## Installing

```
pip install lanname
```

Or from a checkout with `pip install .`, or by copying the `lanname/`
directory somewhere on the path. There is nothing to build and nothing to
install alongside it.

```python
import lanname
lanname.__version__          # "0.3.0"
```

---

## Modes

| mode | |
| --- | --- |
| `"off"` | static entries only. No lookups, no threads, no traffic. |
| `"dns"` | **the default.** Reverse DNS only. Passive in the sense that it asks the resolver the machine already uses, but it is still a query per address. |
| `"all"` | reverse DNS, then mDNS to 224.0.0.251, then a NetBIOS status query to the host itself. **This sends probes onto the LAN.** |

The order matters and is not configurable: reverse DNS answers for anything
with a real record, mDNS catches the Apple and Linux hosts that publish over
multicast, and NetBIOS catches the Windows machines that answer to nothing
else. Each step only runs because the one before it came back empty.

`mode` can be changed on a running resolver with `set_mode()`, which starts the
worker threads if the resolver was constructed `"off"` and never had any.
Going back to `"off"` stops new work being queued and drops what was already
queued, unresolved, so nothing is sent for it; a probe in flight is the last
one. The threads stay parked on an empty queue; `shutdown()` is what retires
them, and after it the resolver is not restartable: `set_mode()` still changes
the mode but starts nothing.

`MODE_DESC` is exported with the rest: a dict from each mode name to the one
line description of it used above, so a program that offers the choice can say
what it is offering without writing its own account of the three.

---

## Resolver

```python
Resolver(mode="dns", hosts_files=(), workers=4, resolve_public=False,
         fqdn=False, positive_ttl=3600, negative_ttl=300, timeout=1.0,
         local_networks=None)
```

| argument | |
| --- | --- |
| `mode` | one of the three above, default `"dns"`. `ValueError` for anything else. |
| `hosts_files` | paths to hosts-format files, read once at construction. See [below](#static-hosts-files). |
| `workers` | background lookup threads. They are daemons, and none are started at all while the mode is `"off"`. |
| `resolve_public` | look up public addresses too, default `False`. See [what gets looked up](#what-gets-looked-up). |
| `fqdn` | keep the full name rather than the first label. `False` gives `nas`, `True` gives `nas.local`. |
| `positive_ttl` | seconds a found name is cached, default 3600. Anything but a number is a `TypeError`, a negative one a `ValueError`, raised here rather than on a worker thread later. |
| `negative_ttl` | seconds a failure is cached, default 300, so a host that does not answer is not asked again on every sighting. Checked the same way. |
| `timeout` | seconds for the mDNS and NetBIOS pair together, default 1.0, not for each. mDNS takes at most half and NetBIOS whatever is left. Reverse DNS uses the system resolver's own timeout, which this does not bound. |
| `local_networks` | networks a probe may be sent to, default `None` for no restriction. Anything `ipaddress.ip_network` accepts, with the host bits allowed, so `"192.168.1.7/24"` reads as `192.168.1.0/24`. An empty list means probe nothing. See [below](#where-probes-are-allowed-to-go). |

| method | |
| --- | --- |
| `lookup(addr)` | the name, or `None`. Never blocks. |
| `set_mode(mode)` | change mode while running, starting workers if needed. `"off"` drops queued work. Never starts anything after `shutdown()`. |
| `set_fqdn(fqdn)` | change the name form. Empties the cache, since every entry in it was shortened on the way in; a lookup in flight lands in the new form. |
| `local_hosts()` | every private address seen with a name, and the names it answered to. See [below](#what-answered-over-a-session). |
| `shutdown()` | ask the workers to stop and take no more work. Also `__exit__`, so a `with` block does it. |

`lookup()` returning `None` means "not known yet", never "has no name". Ask
again the next time the address turns up; the answer appears once a worker has
been round. The first sighting of any address is always a miss, by design.

`shutdown()` is a courtesy rather than a requirement, since the workers are
daemon threads and the interpreter will not wait for them. What it buys is
that probes stop going out at the point the caller thinks it has stopped:
queued addresses are dropped unresolved, a probe in flight is the last one,
and `lookup()` answers from static entries and the cache only, queueing
nothing. A resolver is not restartable; build another.

---

## What gets looked up

Not everything is worth a query, and two of the categories are worth refusing
outright.

| kind | looked up |
| --- | --- |
| private | yes, by every mode. This is what the package is for. |
| public | only with `resolve_public=True` |
| multicast | never |
| loopback, link-local, reserved, unspecified | never |
| not an address at all | never |

`private` means 10/8, 172.16/12, 192.168/16 and fc00::/7, and nothing else.
`ipaddress`'s `is_private` would also say yes to the documentation ranges
(192.0.2.0/24 and its two siblings, 2001:db8::/32), the benchmarking range
(198.18.0.0/15) and a few more, and its answer has changed between Python
versions; none of those is a LAN, and since this class is the gate on what
`"all"` mode probes, it is drawn tightly. Those ranges, and carrier-grade NAT
space (100.64.0.0/10), count as public: left alone unless `resolve_public` is
set, and never probed.

Public addresses are skipped by default because a busy link produces thousands
of them, most resolve to something uninformative like a cloud provider's
generic reverse record, and every one is a query somebody else can see. Turn
them on when the public side is the interesting half.

mDNS and NetBIOS are only ever tried for private addresses, whatever
`resolve_public` says. Both are link-local methods, and sending either to an
address off the local network is at best pointless and at worst rude. Private
is a weaker guarantee than on-link, though, so read the next section before
turning `"all"` on anywhere that matters.

`addr_kind(addr)` is exported if the same classification is useful elsewhere.
It returns one of `ADDR_KINDS`.

---

## Where probes are allowed to go

Private is not the same as on-link. 10/8, 172.16/12 and 192.168/16 are three
very large blocks, and an address out of one of them says only that some
network somewhere uses it, not that it is on a network this machine is
attached to. The addresses handed to `lookup()` typically come off a wire,
which makes them somebody else's choice: a host that can put a packet in
front of the caller, with a source address it picked, decides which addresses
`"all"` mode probes. The mDNS query goes to the multicast group with a TTL of
1 and stays on the link whatever the address in it, but the NetBIOS query
goes to the address itself, so it leaves by whatever route the machine has,
over a VPN or a WAN link included.

`local_networks` is the answer to that. Given a list, `"all"` mode probes only
addresses inside one of the networks on it:

```python
Resolver(mode="all", local_networks=["192.168.1.0/24"])
```

The default is `None`, which is no restriction and what every version before
this one did. An address turned away is counted in `stats["off_link"]`, and is
otherwise treated as a miss: reverse DNS was still tried for it, and the
failure is cached for `negative_ttl` like any other.

There is no automatic discovery of the machine's own networks. Nothing in
`socket` or `ipaddress` reports an interface prefix, and the calls that do,
`getifaddrs` and `GetAdaptersAddresses`, are per-platform and would each need
their own `ctypes` struct layout, right on every platform or the gate is
wrong in one direction or the other. That is a decision to take on its own
rather than in passing, so for now the networks have to be given, and until
they are, `"all"` mode behaves as it always has.

---

## Static hosts files

```python
Resolver(mode="off", hosts_files=["/etc/hosts", "static.hosts"])
```

Standard hosts format: an address, whitespace, a name, and `#` starts a
comment. The first entry for an address wins, and files are read in the order
given. Lines that do not parse are skipped rather than raising, and a file
that cannot be read at all is logged as a warning, on the grounds that a
missing optional file should not stop the program that asked for it.

Static entries answer **even in `"off"` mode**, and they answer without a
cache lookup or a queue round trip. A resolver constructed `"off"` with a
hosts file is a pure static mapping that starts no threads and sends no
traffic, which is a reasonable way to run this in an environment where active
lookups are not welcome.

---

## What answered, over a session

```python
for addr, names in resolver.local_hosts():
    print(addr, names[0], names[1:] or "")
```

Every private address that has ever resolved to a name, sorted by address,
each with its names most recent first. This is kept separately from the cache
and outlives it: the cache expires and evicts, and this is meant to answer
"what did you see all session" long after either has happened.

A host whose name changes keeps both, newest first, up to
`MAX_NAMES_PER_HOST`. That is usually a DHCP lease moving or a machine being
renamed, and the last few changes are the interesting part.

---

## Counters

`resolver.stats` is a `collections.Counter`, safe to read at any time.

| key | |
| --- | --- |
| `hits` | answered from the cache |
| `resolved` | a worker found a name |
| `missed` | a worker found nothing, and the failure was cached for `negative_ttl` |
| `via_dns`, `via_mdns`, `via_netbios` | which method produced the name, for the ones that were found |
| `dropped` | lookups discarded because the work queue was full |
| `evicted` | cache entries dropped to stay under the ceiling |
| `off_link` | probes not sent because the address was outside `local_networks` |

`dropped` climbing means addresses are arriving faster than `workers` threads
can resolve them, and those addresses simply go unresolved for now. Raise
`workers`, or accept it: the queue is bounded on purpose, because the
alternative to dropping work is growing memory without limit.

What a lookup can cost sets the rate those threads work at, and an address
that answers nothing costs the most. In `"all"` mode the probes add at most
`timeout` to it, for the pair rather than for each, so four threads spend at
worst four seconds a second of wall clock on probing and the rest on reverse
DNS, which the system resolver bounds and this package does not. Whoever is
sending the addresses decides how many of them go unanswered, which is why
the two probes share one deadline: taking `timeout` each doubled the cost of
exactly the address an attacker supplies for free.

---

## Ceilings

Everything keyed by address has a bound. The addresses reaching this package
come off a network, so anything keyed by one and never evicted is a memory
leak that other hosts can pull on.

| constant | default | what it bounds | on overflow |
| --- | --- | --- | --- |
| `lanname.resolver.RESOLVER_CACHE_MAX` | 50,000 | cached names | least recently used evicted, counted in `stats["evicted"]` |
| `lanname.resolver.MAX_OBSERVED_HOSTS` | 5,000 | addresses remembered for `local_hosts()` | least recently seen evicted |
| `lanname.resolver.MAX_NAMES_PER_HOST` | 5 | names remembered for any one address | oldest forgotten |
| `lanname.addrs.MAX_ADDR_KIND_CACHE` | 100,000 | cached address classifications | stops caching |

The work queue holds 4,096 addresses and drops rather than blocking, counted
in `stats["dropped"]`.

The cache drops its oldest entry rather than emptying itself, and that
distinction is the whole reason it is an `OrderedDict`. Clearing it wholesale
would send every active host back through resolution at the same moment, which
in `"all"` mode is a burst of mDNS and NetBIOS probes onto the LAN, from a
program that was supposed to be quiet.

---

## Logging

Everything goes to the `lanname` logger. The package installs a `NullHandler`
and nothing else, so records go nowhere until you configure a handler.

```python
import logging
logging.basicConfig(level=logging.INFO)
```

| logger | what |
| --- | --- |
| `lanname.resolver` | WARNING for a hosts file that could not be read, and for a worker that failed after a lookup (a bug rather than a lookup that failed; the worker carries on). DEBUG for a lookup that raised |

Nothing here is logged per address at INFO or above. A resolver watching a
busy link would drown any log it shared.

---

## The three methods on their own

The scheduling and the asking are separable, and the asking is exported:

```python
from lanname import mdns_reverse, netbios_name

mdns_reverse("192.168.1.10", timeout=1.0)    # str or None
netbios_name("192.168.1.10", timeout=1.0)    # str or None
```

Both send one packet and wait for one answer, both block for up to `timeout`,
and both answer `None` rather than raising when a probe goes unanswered or a
reply does not parse, and likewise when no socket can be opened or the send
itself fails, as it does on a host with no route to the multicast group. A
failure in one method is never a reason for `"all"` mode to skip the next.
Reverse DNS has no wrapper here, because `socket.gethostbyaddr` already is
one.

`mdns_reverse` sends a PTR query to 224.0.0.251:5353 with the unicast-response
bit set and a multicast TTL of 1, so it stays on the link and there is no
group to join. `netbios_name` sends a NBSTAT query straight to the host's port
137 and prefers the unique workstation name out of the answer.

Each takes only the reply to the query it sent. `mdns_reverse` ignores a
datagram from any port but 5353 or carrying another transaction id, and keeps
waiting; `netbios_name` connects to the host so that nothing else can answer,
then checks the id and the response bit. A sixteen bit id is a filter for
strays and stale replies, not authentication; see
[Limitations](#limitations) for what is and is not checked about the name
itself.

---

## Crafting replies to test against

A name from mDNS or NetBIOS is whatever the answering host chose, so the
behaviour worth testing in anything downstream is what it does with a name
that is not a tidy label: a control sequence, a newline, an embedded NUL,
bytes that are not UTF-8, a lookalike, or a name far longer than a real host
would send.

The repository carries a small tool for producing exactly those, under
[`tools/poker`](https://github.com/mjaksn/lanname/tree/main/tools/poker). It
builds the two replies with the hostname chosen byte for byte, shows what this
package reads out of them, and can answer a live resolver's queries on the
link so that a whole application sees the name you picked. It is a separate
program beside the package, with a window that needs PySide6; the package
itself keeps no dependencies. Its README says how to run it and, since it
puts spoofed traffic on a network, where not to.

---

## Limitations

- **The first answer is always `None`.** That is the design, not a bug. A
  caller that genuinely needs the name before it can proceed wants
  `socket.gethostbyaddr` and the blocking that comes with it.
- **mDNS and NetBIOS are IPv4 only.** Both open an `AF_INET` socket. Reverse
  DNS works for either family, so an IPv6 address gets one method rather than
  three.
- **NetBIOS is a Windows convention and a fading one.** Recent Windows can
  have it disabled, and non-Windows hosts answer only if they run Samba.
  It is the last method tried for exactly that reason.
- **Names are checked, not verified.** A host answering NetBIOS or mDNS says
  what it likes, and nothing here checks the claim against a forward lookup.
  Treat a name from `"all"` mode as a label a host chose for itself, not as
  identity. What is checked is that the name is fit to print: one holding any
  character below 0x21 (a space is allowed inside a NetBIOS name) or equal to
  0x7f is refused, since those move a cursor, forge a second log line or hide
  the rest of a name; so is a label over 63 bytes or a name over 253, the DNS
  limits; and a name is abandoned past 255 bytes on the wire, so a reply
  built to loop its compression pointers cannot inflate one. Everything above
  0x7f passes: a lookalike or a right-to-left override is legal in a name and
  yours to judge. A reverse DNS result goes through the same check, and a
  refused name is cached as a miss like any other.
- **One resolver, one cache.** Two resolvers in a process do not share
  anything, including the worker threads and the queue.

`lookup()` is safe to call from any thread; the cache and the observed-host
table are both behind a lock.

---

## Licence

MIT. See [LICENSE](https://github.com/mjaksn/lanname/blob/main/LICENSE).
