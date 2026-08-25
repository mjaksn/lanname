# AGENTS.md

Guidance for coding agents working in this repository.

## What this is

`lanname` turns an IP address into a hostname on a local network. It has
three ways of asking, tried in a fixed order: reverse DNS, then mDNS to
224.0.0.251, then a NetBIOS status query sent straight to the host. Lookups
run on background worker threads behind a TTL cache, so `Resolver.lookup()`
only ever reads the cache and returns at once.

Read `README.md` before changing behaviour. It is the definition of the
public API, and `CHANGELOG.md` says so explicitly: the public API is
everything in `lanname.__all__` plus the module-qualified constants listed
under "Ceilings".

## Layout

| path | |
| --- | --- |
| `lanname/__init__.py` | re-exports, `__version__`, the package NullHandler |
| `lanname/resolver.py` | the `Resolver`, plus `mdns_reverse` and `netbios_name` and the wire format helpers they use |
| `lanname/addrs.py` | `addr_kind()`, which decides whether an address is worth asking about |
| `tests/test_resolver.py` | the whole suite, 19 tests |

## Commands

Run from the repository root. Nothing needs installing to run the suite:
the package has no dependencies and the tests reach no network.

```
python -m unittest discover          # 19 tests, about a quarter of a second
python -m unittest discover -v       # what CI runs
python -m ruff check .               # lint, configured in pyproject.toml
python -m mypy lanname               # types, configured in pyproject.toml
```

A single test, a single class, or a single module:

```
python -m unittest tests.test_resolver.CacheBehaviour.test_names_are_actually_cached
python -m unittest tests.test_resolver.Modes
python -m unittest tests.test_resolver
```

`ruff` and `mypy` are not declared anywhere as dev dependencies, since there
is no dev extra; CI installs them with `pip install ruff mypy`.

Packaging is checked by CI (`python -m build`, then `twine check dist/*`,
then a wheel installed into a throwaway venv and imported from another
directory). To reproduce that job locally, install the two tools it needs
first, since neither is present by default:

```
pip install build twine
python -m build
twine check dist/*
```

## Constraints that must not be broken

**No dependencies.** Standard library only, and this is a decision rather
than an accident: the comment above the empty `dependencies` list in
`pyproject.toml` says a package whose whole job is turning an address into a
name should not be the reason anything else has to be audited or upgraded.
Do not add a runtime dependency, and do not add a test dependency either;
the suite is `unittest` for the same reason.

**Python 3.9 is the floor.** No `X | None` unions, no builtin generics such
as `dict[str, str]`; use `typing.Dict` and `typing.Optional`, as
`addrs.py` already does. The ruff rule selection (`E`, `F`, `W`, `I`, `B`)
deliberately leaves out the pyupgrade rules for exactly this reason, so lint
passing is not evidence that the syntax is old enough.

**Line lengths.** 88 columns for Python, enforced by ruff. 80 columns for
markdown prose, matching `README.md` and `CHANGELOG.md`; tables and code
blocks run as long as they need to.

**Modes stay as they are unless the change is deliberate and documented.**
`"dns"` has been the default since 0.2.0, `"off"` is static entries only and
starts no threads, and `"all"` is the mode that puts mDNS and NetBIOS probes
on the LAN. `"all"` must stay opt-in. The 0.2.0 entry in `CHANGELOG.md`
records what changing a default costs, and any further change to one belongs
under **Changed** there.

## How the pieces fit

The split worth understanding is between deciding *when* to ask and doing
the asking.

`Resolver.lookup()` never blocks and never resolves. It answers from
`self.static` (hosts file entries, which answer even in `"off"` mode), then
from the TTL cache, and otherwise puts the address on a bounded queue and
returns `None`. `None` means "not known yet", never "has no name". The first
sighting of any address is always a miss, by design, because the intended
caller is draining a socket and cannot wait on a round trip.

`Resolver._resolve()` runs on a worker thread and is the only place that
touches the network. It tries reverse DNS, and only under `"all"`, and only
for private addresses, goes on to `mdns_reverse()` and `netbios_name()`.

Everything keyed by an address is bounded, because those keys come off a
network and are therefore controlled by other hosts: `RESOLVER_CACHE_MAX`,
`MAX_OBSERVED_HOSTS`, `MAX_NAMES_PER_HOST`, `MAX_ADDR_KIND_CACHE`, and the
4,096 slot work queue that drops rather than blocking. The cache is an
`OrderedDict` so it can evict its oldest entry instead of clearing itself:
clearing it would send every active host back through resolution at once,
which under `"all"` is a burst of probes onto the LAN. `set_fqdn()` is the
one place that clears it wholesale, and only because every cached name was
shortened on the way in.

`_cache` and `_observed` are both behind `self._lock`, and `lookup()` is
safe to call from any thread. `self.stats` is a `Counter` and is safe to
read at any time.

## Testing

**No test in this suite may send a real packet.** The tests replace
`Resolver._resolve` with `canned()`, a function that fabricates a name from
the address, and restore it in `tearDown`. Any new test must do the same.
This is not a style preference: the package's widest mode sends multicast
DNS queries and NetBIOS requests to whatever address it is handed, so a test
that let a real lookup through would put traffic on the machine's network,
on CI runners as much as on a developer's LAN.

Two things to copy from the existing tests rather than reinvent:

- Patch module globals on `lanname.resolver`, not on the `lanname` package.
  The worker reads `RESOLVER_CACHE_MAX` as a module global, so rebinding the
  re-exported copy leaves the real one in place and the test proves nothing.
- Wait for workers with the `drain()` helper, which polls `_pending` and the
  queue, rather than sleeping for a fixed period.

Threads are daemons, so a leaked resolver will not hang the suite, but every
test still registers `self.addCleanup(resolver.shutdown)`.

## CI and branches

`.github/workflows/ci.yml` runs lint and types once, the suite across five
Python versions on Ubuntu and four on Windows (3.9 on Windows is excluded
deliberately, with the reasoning in the file), and a build and install
check. The `gate` job is the single check branch protection requires, and it
fails if any of the three upstream jobs did anything other than succeed.

CI runs on pull requests, on pushes to `main`, and on manual dispatch, but
not on ordinary branch pushes. `main` takes changes only through a pull
request, so work on a branch and open one; a dispatched run does not enter a
pull request's status check rollup and therefore cannot satisfy the gate.

Releases are tag driven. `.github/workflows/release.yml` fires on `v*` tags
and refuses to publish unless the tag, the version in `pyproject.toml`, and
`lanname.__version__` all agree, so a version bump means editing both places
and adding a `CHANGELOG.md` entry.

## Prose conventions

The existing prose argues for its decisions rather than only stating them,
which is why the comments in `pyproject.toml`, the workflow files and the
test module are as long as they are. When changing something those comments
justify, update the argument, do not just leave it pointing at the old
behaviour. British spelling is used throughout ("behaviour", "licence" for
the noun).
