# Changelog

Notable changes to lanname. Versions follow [semantic
versioning](https://semver.org/spec/v2.0.0.html): while the major version is 0
the public API may still change, and any such change is called out here under
**Changed** rather than assumed to be obvious from the version number.

The public API is what [the README](README.md) documents, which is everything
reachable from `lanname.__all__` plus the module-qualified constants listed
under [Ceilings](README.md#ceilings). Internals not named there may move
without notice.

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

[0.2.0]: https://github.com/mjaksn/lanname/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mjaksn/lanname/releases/tag/v0.1.0
