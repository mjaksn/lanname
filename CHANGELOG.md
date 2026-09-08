# Changelog

Notable changes to lanname. Versions follow [semantic
versioning](https://semver.org/spec/v2.0.0.html): while the major version is 0
the public API may still change, and any such change is called out here under
**Changed** rather than assumed to be obvious from the version number.

The public API is what [the README](README.md) documents, which is everything
reachable from `lanname.__all__` plus the module-qualified constants listed
under [Ceilings](README.md#ceilings). Internals not named there may move
without notice.

## [Unreleased]

### Added

- **`Resolver(local_networks=...)`, the networks `"all"` mode is allowed to
  probe.** "private" is three very large blocks and says nothing about what
  this machine is attached to, so an address arriving with a chosen source,
  from a LAN neighbour or through an edge that does not filter inbound
  private sources, decided where a NetBIOS query went: straight to that
  address, over a VPN or a WAN link if that is where the route led, once per
  address per `negative_ttl`. Given a network, or an iterable of them, probes
  go only to addresses inside one, and an address turned away is counted in the
  new `stats["off_link"]` and otherwise treated as a miss. The default,
  `None`, is no restriction, so nothing about `"all"` mode moves unless the
  argument is given. There is no automatic discovery of the machine's own
  prefixes: nothing in `socket` or `ipaddress` reports an interface prefix,
  and the per-platform calls that do would each need their own `ctypes`
  struct layout. A bad entry is a `ValueError` at construction, where the
  TTLs are checked and for the same reason. (#23)

### Changed

- **`timeout` now bounds the mDNS and NetBIOS pair together rather than each
  of them.** An address that answers nothing held a worker for both waits in
  series, so four workers named about two addresses a second while a flood of
  unanswerable addresses lasted, and the addresses arrive from whoever is
  sending them. The pair now share one deadline: mDNS takes at most half and
  NetBIOS whatever is left, which is the other half when mDNS spends its own
  and more when the multicast send fails outright. The worst case an address
  can cost is halved, and a responder that was going to answer answers in
  tens of milliseconds either way. Callers who relied on a full `timeout`
  reaching each probe should double the value. (#23)

## [0.3.0] - 2026-09-08

### Added

- A reply crafting tool under `tools/poker`, for feeding the mDNS and NetBIOS
  parsers a hostname chosen byte for byte and seeing what comes out. It is a
  separate program beside the package, with its own README and its own
  dependency on PySide6 for the window; the package itself still has none.
- PyCharm run configurations under `.idea/runConfigurations/` and VS Code
  ones under `.vscode/`, for the test suite, ruff, mypy, and the poker
  tool's window, suite and self test. Repository tooling: neither set
  reaches the wheel or anyone who installs the package.

### Changed

- **`addr_kind()` classes fewer addresses as `"private"`, so `"all"` mode
  probes fewer.** It used `ipaddress`'s `is_private`, which also says yes to
  the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
  2001:db8::/32), the benchmarking range (198.18.0.0/15), 192.0.0.0/24,
  0.0.0.0/8 and 2002::/16, and whose answer differs between 3.9 and 3.13. A
  NetBIOS query to 192.0.2.1 went out through the default route, which the
  README said the package refused to do. `"private"` is now 10/8, 172.16/12,
  192.168/16 and fc00::/7 and nothing else, the same on every Python version.
  Everything it no longer covers is `"public"`: not looked up unless
  `resolve_public` is set, and never probed. A caller that relied on a
  reverse DNS lookup of one of those ranges under the default
  `resolve_public=False` now has to set it. Carrier-grade NAT space
  (100.64.0.0/10) was already public and stays so. (#17)

### Fixed

- The two probes now take only the reply to the query they sent.
  `mdns_reverse` ignored the source of a datagram and the transaction id in
  it, so any host that guessed the ephemeral port could answer; it now skips a
  reply from any port but 5353 or with another id and keeps waiting.
  `netbios_name` used `sendto()` and read one datagram from anywhere, checking
  only the answer count, so a stray ended the lookup and the miss was cached;
  it now connects to the host, so nothing else can answer, and checks the id
  and the response bit. (#10)
- Names off the link are checked before they reach the cache and
  `local_hosts()`. `dns_read_name()` never bounded a name, and a reply that
  looped its compression pointers could assemble a 65,000 character name out
  of four kilobytes; `netbios_name()` stripped whitespace and NUL and passed
  everything else on, escape sequences included. A name holding any character
  below 0x21 (a space is allowed inside a NetBIOS name) or equal to 0x7f is
  now refused, as is a label over 63 bytes or a name over 253, and reading
  stops past 255 bytes on the wire. Reverse DNS results go through the same
  check. Characters above 0x7f still pass; the README says why under
  Limitations. (#11)
- A multicast send that failed raised out of `mdns_reverse()`, and so out of
  the worker before NetBIOS was tried, which on a host with no route to
  224.0.0.251 (one with no default route, typically) meant `"all"` mode named
  nothing at all. The send is now caught, as is a failure to open the socket
  in either probe, and each answers `None` as the README always said they
  did. (#12)
- `set_mode("off")` and `shutdown()` now stop the work already queued, as the
  README said they did. A worker used to resolve every address it dequeued
  whatever the mode, and checked the mode only once, before mDNS, so after
  `set_mode("off")` up to 4,096 queued addresses still got a reverse DNS
  query and after `shutdown()` a probe already under way went on through
  mDNS and NetBIOS. Queued work is now dropped unresolved, with no cache
  entry, and the mode is read again before each probe. `lookup()` after
  `shutdown()` used to keep queueing addresses nobody would drain, pinning
  each as `None` for ever; it now answers from static entries and the cache
  and queues nothing, and `set_mode()` after `shutdown()` starts no threads.
  A failure in the worker's bookkeeping after a lookup, which nothing there
  can cause today, would have retired the thread; it is now logged at
  WARNING and the worker carries on, and `positive_ttl` and `negative_ttl`
  are validated at construction. (#13)
- A `set_fqdn()` landing while a lookup was in flight could be undone by it:
  the worker shortened the name under the old setting, `set_fqdn()` cleared
  the cache, and the old form was then written back to sit there for
  `positive_ttl`. The name is now shortened under the lock, at the moment it
  is written, and `set_fqdn()` flips the setting under the same lock. (#14)
- The release workflow checked for a changelog section only after the upload
  to PyPI, so a tag without one was already published, and beyond recall,
  when it failed. The check now runs in the build job with the other guards,
  before anything is uploaded, and the release job takes the notes from an
  artifact rather than a checkout. (#15)
- The test suite now checks that `pyproject.toml` and `lanname.__version__`
  agree, so a version bump that edits one file fails in its pull request
  rather than at the tag. (#16)

## [0.2.1] - 2026-08-26

### Documentation

- The README now carries the same badge set as the sibling projects: CI,
  Release, PyPI version, and licence. Released so that the badges appear on the
  PyPI project page, which is rendered from the README inside the uploaded
  distribution and cannot be edited in place.

No code changed in this release.

## [0.2.0] - 2026-08-25

### Changed

- **`Resolver()` now resolves.** The default mode was `"off"`, which made a
  resolver built without arguments inert: no threads, no traffic, and
  `lookup()` answering None for everything but a static entry. It is now
  `"dns"`, so the same call starts its workers and puts a reverse DNS query on
  the network for each private address handed to `lookup()`.

  Nothing raises and nothing warns, so code written against 0.1.0 keeps
  running and quietly starts doing something it did not do before. **If you
  were relying on a bare `Resolver()` being silent, pass `mode="off"`
  explicitly.** That behaves exactly as 0.1.0 did, and it is now the
  documented way to ask for a static-only resolver: it answers from
  `hosts_files`, starts no threads and sends nothing.

  `"all"`, the mode that sends mDNS and NetBIOS probes onto the LAN, is
  unaffected and is still reached only by asking for it.

  The reason for the change: the old default made sense when this code was an
  optional module inside a NetFlow collector, where nobody had installed it on
  purpose. Installing lanname is an unambiguous request for name lookup, so
  starting from "does nothing" was answering a question nobody had asked.

### Fixed

- The README argued for the old default on grounds that stopped applying when
  this became its own package, describing the risk as a library probing the
  LAN "inside a daemon somebody installed for an unrelated reason". The
  argument now rests where it belongs, on the mode rather than the package.

## [0.1.0] - 2026-08-24

First release. Reverse DNS, mDNS and NetBIOS lookup behind a bounded TTL cache
and a pool of background workers, so that a caller holding an address is never
made to wait for a name. Standard library only, no dependencies, Python 3.9
and up.

[Unreleased]: https://github.com/mjaksn/lanname/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/mjaksn/lanname/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/mjaksn/lanname/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/mjaksn/lanname/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mjaksn/lanname/releases/tag/v0.1.0
