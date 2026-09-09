# lanname poker

A small PySide6 tool for feeding [`lanname`](../../README.md) the replies it
parses, with the hostname content chosen byte for byte. It is for evaluating
`lanname` and the NetFlow tooling built on it, both in a test harness and
against a running application.

`lanname` turns a local address into a name three ways: reverse DNS, an mDNS
PTR query to the link, and a NetBIOS status query to the host. The mDNS and
NetBIOS answers come from whatever host chooses to reply, so the name is
attacker controlled. This tool builds those two answers with a name that is
exactly the bytes you ask for, so you can see how `lanname` and everything
downstream handle a name that is not a plain label.

## What it does

* **Compose** an mDNS PTR reply or a NetBIOS name reply, entering the hostname
  directly or with escapes for bytes you cannot type: `\xHH` for a raw byte,
  `\uHHHH` for a code point, `\n \r \t \0`, and `\\` for a backslash.
* **See the exact bytes** `lanname` would receive, and copy them as hex or as a
  Python bytes literal to drop into a test.
* **See what `lanname` does with them**: the name its own parser reads out,
  or `None` where it refused the reply (it refuses a name holding a control
  character, and one past the DNS length limits), the shortened name it
  passes to the caller with and without `fqdn`, and whether it would probe the
  address at all in `"all"` mode. Names are shown as a repr, so what survives
  is visible byte for byte.
* **Send one datagram** to a host and port of your choosing, for a harness
  listening on a UDP socket.
* **Answer a live resolver.** The responder listens for `lanname`'s real
  queries and replies with the composed name, so an end application resolves
  the name you chose. mDNS is answered on 224.0.0.251:5353; NetBIOS on UDP 137.
  A configurable delay holds each answer back before it goes out, so a reply
  can be made to arrive after `lanname` has stopped waiting for it.
* **Read a log** of everything the tool does, in one pane: sends, presets, the
  responder's lifecycle, and every query it answers, each line timestamped. A
  level selector filters what shows, from `DEBUG` for the fullest detail up to
  `ERROR`.

A dozen presets cover the content worth testing: an ANSI erase sequence, a
newline that forges a second log line, an embedded NUL, an OSC 8 terminal
hyperlink, a right-to-left override, a Cyrillic lookalike, invalid UTF-8, a
maximum length label, and an oversize name split across many labels.

## Installing and running

Python 3.10 or newer.

```
pip install --require-hashes -r requirements.txt
python -m lanname_poker
```

The packet building and the parse preview want `lanname` importable. If it is
not installed, the tool uses the checkout it lives in, two directories up, so
running it from this repository needs nothing arranged. Point `LANNAME_REPO` at
another checkout to evaluate that one instead. The byte view and the builders
work without `lanname`; only the preview needs it.

No display and no PySide6 needed for a quick check:

```
python -m lanname_poker --selftest
```

That builds every preset reply and prints what `lanname` reads out of each,
which is also a smoke test of the wire building against the real parser.

## Two ways to use it

**In a harness.** Compose a reply, copy the bytes, and assert on them in a test
of `lanname` or of code that consumes its names. `lanname_poker.wire` is
standard library only and imports nothing else, so a test can build the bytes
itself:

```python
from lanname_poker import wire
reply = wire.build_reply(wire.MDNS, wire.decode_input(r"nas\x1b[2K", True),
                         "192.168.1.50")
```

**Against an application.** Run the application with `lanname` in `"all"` mode,
start the responder here on the same link, and each address the application
looks up comes back with the name you set. Change the name and the next query
takes the new one. The log pane shows each query as it is answered, and the
delay lets you answer late on purpose: `lanname` gives mDNS half of its timeout
and NetBIOS the rest, so a delay past that budget is a reply it has already
given up on, which is worth seeing an application cope with.

## Limits worth knowing

* A NetBIOS name is 15 bytes of ASCII. Longer input is cut, and a byte over
  0x7f arrives as the replacement character, because that is how `lanname`
  decodes it. Use the mDNS path for full byte and Unicode fidelity. The window
  flags this as you type.
* The NetBIOS responder binds UDP 137, which on Windows the operating system
  usually holds for its own NetBIOS service, so it may fail to bind. It reports
  that plainly. mDNS uses 5353, which `lanname` leaves free by asking for
  unicast answers, so that path binds.
* The NetBIOS responder can only answer for the host it runs on, since
  `lanname` sends that query straight to the address it is naming. The mDNS
  responder sees every query on the link and can answer for any address, so it
  defaults to answering only the address you entered.
* Reverse DNS is resolved by the operating system, not from a packet on the
  link, so it is not something this tool crafts.
* While the responder waits out a delay it is not reading the socket, so a
  second query arriving during the wait is answered only once the first is
  done. That suits the one-host case the tool is built around, and the wait is
  interruptible, so stopping the responder does not block on it.

## Safety

The responder and the send button put spoofed link traffic onto the network the
machine is on. Use them only on a network you own or are authorised to test.
