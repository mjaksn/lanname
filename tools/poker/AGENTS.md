# AGENTS.md

Guidance for coding agents working in this repository.

## What this is

`lanname-poker` is a small PySide6 tool for evaluating `lanname` and the
NetFlow tooling that uses it. It builds the two replies `lanname` reads a name
out of, an mDNS PTR response and a NetBIOS node status response, with the
hostname content chosen byte for byte, and then either shows what `lanname`
makes of them, sends one at an endpoint, or answers a live resolver's queries.

The reason it exists is that a name from the link is attacker controlled, and
the interesting behaviour of anything downstream is how it copes with a name
that is not a tidy label: a control character, a newline, an embedded NUL,
bytes that are not valid UTF-8, a lookalike, or a name far longer than a real
host would send. This tool produces exactly those, on demand.

## Layout

| path | |
| --- | --- |
| `lanname_poker/wire.py` | the pure encoders and the query reader, standard library only, no Qt |
| `lanname_poker/lanname_bridge.py` | drives `lanname`'s own parser over a fake socket, and its shortening and classification, for the preview |
| `lanname_poker/responder.py` | answers `lanname`'s live queries; standard library sockets and threads, Qt free |
| `lanname_poker/net.py` | sends one crafted datagram to a chosen endpoint |
| `lanname_poker/gui.py` | the PySide6 window; holds no wire or socket logic of its own |
| `lanname_poker/__main__.py` | `python -m lanname_poker`, and `--selftest` |
| `tests/test_wire.py` | the encoders, the query reader and the round trip through `lanname`'s parser |
| `tests/test_responder.py` | the responder's matching and reply logic, over fake sockets |

## Commands

Run from this directory, `tools/poker`.

```
python -m unittest discover                 # the suite
python -m lanname_poker --selftest          # build every preset, print what lanname reads
python -m lanname_poker                      # open the window (needs PySide6)
pip install --require-hashes -r requirements.txt   # install PySide6
```

The suite and the self test both reach for `lanname`. If it is not installed
they use the checkout this directory lives in, so nothing needs arranging when
running from the repository. Set `LANNAME_REPO` to evaluate another checkout
instead. The round-trip tests are skipped, not failed, when `lanname` cannot be
found, and the packet building is tested either way.

## Constraints that must not be broken

**No test sends a packet, and neither does the self test.** The preview and the
tests feed crafted bytes to `lanname`'s parser through a fake socket. A test
that opened a real socket would put crafted multicast or unicast traffic on the
machine's network, which is the one thing a test must never do here. The live
responder and the send button do put traffic on the link, on purpose, and are
never exercised by the suite.

**The encoders never sanitise.** The whole point is to place bytes `lanname`
would reject or mangle, so `wire.decode_input` and the builders pass everything
through. Any cleaning belongs in `lanname`, not here. If a class of content
cannot survive a path, say so in the UI (as the NetBIOS ASCII note does) rather
than quietly fixing it.

**`wire.py` stays Qt free and import light.** A harness imports it to build test
bytes without a display, so it must not import PySide6, the responder, or
`lanname`.

**Python 3.10 is the floor**, matching the PySide6 wheels, which are
`cp310-abi3` and declare `>=3.10`.

**Dependencies are pinned by version and hash** in `requirements.txt`, and
nothing is added that was released in the last seven days.

## Prose conventions

British spelling, matching the `lanname` repository ("behaviour", "licence"
for the noun). Do not use an em dash or a double hyphen as punctuation; a comma,
a colon or two sentences instead. A long option on a command line keeps its two
leading hyphens, and hyphens joining words are ordinary spelling.

## Safety

Starting the responder or pressing send puts spoofed link traffic onto the
network the machine is on. It is a testing tool for a network you own or are
authorised to test. The window says so; keep that warning present and accurate.
