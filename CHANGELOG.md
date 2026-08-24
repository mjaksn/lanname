# Changelog

Notable changes to lanname. Versions follow [semantic
versioning](https://semver.org/spec/v2.0.0.html): while the major version is 0
the public API may still change, and any such change is called out here under
**Changed** rather than assumed to be obvious from the version number.

The public API is what [the README](README.md) documents, which is everything
reachable from `lanname.__all__` plus the module-qualified constants listed
under [Ceilings](README.md#ceilings). Internals not named there may move
without notice.

## [0.1.0] - 2026-08-24

First release. Reverse DNS, mDNS and NetBIOS lookup behind a bounded TTL cache
and a pool of background workers, so that a caller holding an address is never
made to wait for a name. Standard library only, no dependencies, Python 3.9
and up.

[0.1.0]: https://github.com/mjaksn/lanname/releases/tag/v0.1.0
