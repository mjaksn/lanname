# AGENTS.md

Guidance for coding agents working in this repository.

## What this is

`lanname-harness` is a PySide6 window for driving a live `lanname` resolver.
It builds one from every argument the constructor takes, asks it about
addresses on a repeating tick so the first miss and the later name are both
visible, shows the counters and `local_hosts()` as they move, moves the module
level ceilings, calls the two probe functions on their own, and shows what the
package logs.

It exists because the package's central behaviour is a schedule rather than a
value. `lookup()` returning `None` and then a name two ticks later, a cache
entry ageing out, a counter climbing, a queue dropping work: none of that is
visible from a single call, and a window that ticks shows all of it.

## Layout

| path | |
| --- | --- |
| `lanname_harness/session.py` | everything that touches `lanname`: the loader, the options, the watch list and its poll, the ceilings, the probes. No Qt |
| `lanname_harness/gui.py` | the PySide6 window; holds no resolver logic of its own |
| `lanname_harness/__main__.py` | `python -m lanname_harness`, and `--selftest` |
| `tests/test_session.py` | the session, over resolvers that send nothing |

## Commands

Run from this directory, `tools/harness`.

```
python -m unittest discover                 # the suite
python -m lanname_harness --selftest        # drive a static resolver, print what it does
python -m lanname_harness                   # open the window (needs PySide6)
pip install --require-hashes -r requirements.txt   # install PySide6
```

The suite and the self test both reach for `lanname`. If it is not installed
they use the checkout this directory lives in, so nothing needs arranging when
running from the repository. Set `LANNAME_REPO` to drive another checkout
instead. Tests that need the package are skipped, not failed, when it cannot
be found.

## Constraints that must not be broken

**No test sends a packet, and neither does the self test.** Two ways of
arranging that, both taken from `lanname`'s own suite, and any new test must
use one of them. Either build the resolver in `"off"` mode, which starts no
threads and answers from static entries alone, or replace `Resolver._resolve`,
the only method that touches the network, with the suite's `canned()` **before**
the resolver is built and restore it after. A resolver built in `"dns"` mode
without that replacement calls `gethostbyaddr`, which is a real query, and one
in `"all"` mode puts multicast and NetBIOS traffic on the machine's network.
The window is where real traffic belongs, on a person's deliberate press.

**`session.py` stays Qt free.** The whole of the harness's behaviour lives
there so that the suite can exercise it without a display and `--selftest` can
run in CI. It must not import PySide6, and `gui.py` must not grow logic of its
own: a rule the window applies but the session does not know about is a rule
no test can reach.

**The ceilings move on the module that owns them**, `lanname.resolver` or
`lanname.addrs`, never on the `lanname` package. The worker reads
`RESOLVER_CACHE_MAX` as a global of its own module, so rebinding the
re-exported copy would change nothing and the harness would be reporting a
change it had not made.

**Prefer the public API.** This tool is a demonstration of what the package
offers, so reaching past `__all__` and the documented ceilings undercuts the
point of it. Two internals are read and both are guarded: `resolver.static`
for the count of hosts file entries, and `_queue.maxsize` through `getattr`,
falling back to the documented 4,096, so a rename in the package cannot stop
the window opening. Nothing else, and nothing that writes.

**The window never blocks.** `mdns_reverse` and `netbios_name` wait for up to
their timeout, so they run on a thread and report back through a Signal. Log
records arrive from the worker threads and go through a Signal for the same
reason: touching a widget from another thread is how a Qt program crashes.

**Python 3.10 is the floor**, matching the PySide6 wheels, which are
`cp310-abi3` and declare `>=3.10`. The package under test still supports 3.9;
this tool does not have to, and the two are separate programs.

**Dependencies are pinned by version and hash** in `requirements.txt`, and
nothing is added that was released in the last seven days.

## Prose conventions

British spelling, matching the `lanname` repository ("behaviour", "licence"
for the noun). Do not use an em dash or a double hyphen as punctuation; a
comma, a colon or two sentences instead. A long option on a command line keeps
its two leading hyphens, and hyphens joining words are ordinary spelling.

The window's own text is documentation and rots the same way. When the package
changes what a mode does, what a counter counts or where a probe may go, the
notes under each box are as much a part of the change as the README.

## Safety

`"all"` mode and the probe buttons put traffic on the network the machine is
on, and `"dns"` mode is a query per address to the machine's own resolver. The
banner says so and changes when `"all"` mode goes live; keep that warning
present and accurate. The feed asks before offering addresses to a resolver in
`"all"` mode.
