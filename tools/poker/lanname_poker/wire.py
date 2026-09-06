"""Building the packets lanname parses, with the hostname content chosen byte
for byte.

Nothing here touches the network or imports lanname. These are the pure
encoders: given a hostname and a target address, they produce the exact bytes
of an mDNS PTR response or a NetBIOS node status response that lanname's
:func:`mdns_reverse` and :func:`netbios_name` will read a name out of. The
point of the tool is to control that name completely, so the encoders take
raw bytes and never sanitise: a control character, an ANSI escape, a byte that
is not valid UTF-8 or a name far longer than anything a real host would send
all pass straight through.

There is also a small reader used by the live responder to pull the
transaction id and the queried name back out of a query lanname sent.
"""

import string
import struct

MDNS = "mDNS PTR reply"
NBSTAT = "NetBIOS name reply"
REPLY_KINDS = (MDNS, NBSTAT)

# A fixed id for the offline preview, so the same inputs give the same bytes.
# The responder ignores this and echoes the id of the query it is answering.
DEFAULT_TID = 0x1234

_HEX = set(string.hexdigits)


def decode_input(text, interpret_escapes):
    """Turn the hostname field into the exact bytes to inject.

    With escapes off the text is taken literally and encoded as UTF-8. With
    escapes on, a backslash introduces one of a small set of sequences so that
    bytes which cannot be typed can still be placed exactly:

      ``\\xHH``    one raw byte, so ``\\xff`` injects an octet that is not valid
                   UTF-8 and exercises lanname's ``"replace"`` decoding
      ``\\uHHHH``  the UTF-8 encoding of a code point, for lookalikes and bidi
                   controls such as ``\\u202e``
      ``\\n \\r \\t \\0``  newline, carriage return, tab, NUL
      ``\\\\``       a literal backslash

    An incomplete or unknown sequence is left as the literal characters typed,
    so nothing is silently swallowed.
    """
    if not interpret_escapes:
        return text.encode("utf-8")
    out = bytearray()
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch != "\\":
            out += ch.encode("utf-8")
            i += 1
            continue
        if i + 1 >= n:
            out += b"\\"
            i += 1
            continue
        esc = text[i + 1]
        if esc == "x" and i + 4 <= n and text[i + 2] in _HEX and text[i + 3] in _HEX:
            out.append(int(text[i + 2:i + 4], 16))
            i += 4
        elif esc == "u" and i + 6 <= n and all(c in _HEX for c in text[i + 2:i + 6]):
            out += chr(int(text[i + 2:i + 6], 16)).encode("utf-8")
            i += 6
        elif esc == "n":
            out.append(0x0A)
            i += 2
        elif esc == "r":
            out.append(0x0D)
            i += 2
        elif esc == "t":
            out.append(0x09)
            i += 2
        elif esc == "0":
            out.append(0x00)
            i += 2
        elif esc == "\\":
            out.append(0x5C)
            i += 2
        else:
            out += ("\\" + esc).encode("utf-8")
            i += 2
    return bytes(out)


def encode_dns_labels(namebytes):
    """Length-prefix a name into DNS wire labels, splitting on a dot byte.

    Each label is capped at 63 bytes, because a length octet of 64 or more has
    its top bits set and would be read as a compression pointer rather than a
    label. To build a name longer than 63 bytes, use several dot-separated
    labels. Empty labels are dropped, so a trailing dot is ignored, matching
    what lanname's own encoder does.
    """
    out = bytearray()
    for label in namebytes.split(b"."):
        if not label:
            continue
        label = label[:63]
        out.append(len(label))
        out += label
    out.append(0)
    return bytes(out)


def label_warnings(namebytes, limit=63):
    """Note where :func:`encode_dns_labels` had to truncate, for the UI."""
    warnings = []
    for idx, label in enumerate(namebytes.split(b".")):
        if len(label) > limit:
            warnings.append(
                f"label {idx} is {len(label)} bytes and was cut to {limit}")
    return warnings


def nb_encode_name(raw16):
    """First level NetBIOS name encoding: each byte becomes two nibbles.

    A copy of lanname's own encoder. The 16 byte input becomes 34 bytes on the
    wire, which is the fixed width lanname's parser skips over before reading
    the node status entries.
    """
    out = bytearray([32])
    for byte in raw16:
        out.append(0x41 + (byte >> 4))
        out.append(0x41 + (byte & 0x0F))
    out.append(0)
    return bytes(out)


def reverse_qname(addr):
    """The in-addr.arpa or ip6.arpa name lanname asks a PTR query for.

    A local copy so the tool can build a query name without lanname installed.
    Kept identical to lanname's, so the name in the crafted answer matches the
    one lanname compares against.
    """
    import ipaddress
    ip = ipaddress.ip_address(addr)
    if ip.version == 4:
        return ".".join(reversed(str(ip).split("."))) + ".in-addr.arpa"
    nibbles = ip.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".ip6.arpa"


def build_mdns_reply(qname, inject_bytes, tid=DEFAULT_TID):
    """An mDNS PTR response answering *qname* with *inject_bytes* as the name.

    The header sets the response and authoritative bits and one answer with no
    question, which is what lanname's parser expects. The answer name is the
    queried name so lanname accepts the match, and the PTR rdata is the chosen
    bytes, encoded as labels with no sanitising.
    """
    header = struct.pack("!HHHHHH", tid & 0xFFFF, 0x8400, 0, 1, 0, 0)
    answer = encode_dns_labels(qname.encode("ascii", "replace"))
    rdata = encode_dns_labels(inject_bytes)
    answer += struct.pack("!HHIH", 12, 0x0001, 120, len(rdata)) + rdata
    return header + answer


def build_nbstat_reply(inject_bytes, tid=DEFAULT_TID):
    """A NetBIOS node status response whose one name is *inject_bytes*.

    lanname reads the name from a fixed offset, so the record name and the
    trailing statistics are placeholders. The name field is 15 bytes: longer
    input is cut, and because lanname decodes it as ASCII with ``"replace"``,
    any byte over 127 arrives as a replacement character. A unique workstation
    entry (suffix zero, group bit clear) is the one lanname returns.
    """
    name15 = inject_bytes[:15]
    name15 = name15 + b"\x20" * (15 - len(name15))
    header = struct.pack("!HHHHHH", tid & 0xFFFF, 0x8400, 0, 1, 0, 0)
    rrname = nb_encode_name(b"*" + b"\x00" * 15)
    entry = name15 + b"\x00" + struct.pack("!H", 0x0000)
    rdata = bytes([1]) + entry
    rr = rrname + struct.pack("!HHIH", 0x0021, 0x0001, 0, len(rdata)) + rdata
    return header + rr


def nbstat_warnings(inject_bytes):
    """Note NetBIOS specific losses, for the UI."""
    warnings = []
    if len(inject_bytes) > 15:
        warnings.append(
            f"NetBIOS name is 15 bytes; {len(inject_bytes)} given, rest dropped")
    if any(b > 0x7F for b in inject_bytes[:15]):
        warnings.append(
            "bytes over 0x7f become the replacement character; NetBIOS is ASCII")
    return warnings


def build_reply(kind, inject_bytes, addr, tid=DEFAULT_TID):
    """Dispatch to the right builder. *addr* supplies the mDNS query name."""
    if kind == MDNS:
        return build_mdns_reply(reverse_qname(addr), inject_bytes, tid)
    if kind == NBSTAT:
        return build_nbstat_reply(inject_bytes, tid)
    raise ValueError(f"unknown reply kind: {kind!r}")


def build_warnings(kind, inject_bytes):
    """The encoding caveats for a reply, so the UI can show what was lost."""
    if kind == MDNS:
        return label_warnings(inject_bytes)
    if kind == NBSTAT:
        return nbstat_warnings(inject_bytes)
    return []


def _read_dns_name(data, off):
    """Read a possibly compressed DNS name from a query. Returns (name, off)."""
    labels = []
    resume = None
    hops = 0
    while off < len(data):
        length = data[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[off + 1]
            if resume is None:
                resume = off + 2
            off = pointer
            hops += 1
            if hops > 16:
                break
            continue
        off += 1
        labels.append(data[off:off + length].decode("ascii", "replace"))
        off += length
    return ".".join(labels), (resume if resume is not None else off)


def parse_query(kind, data):
    """Pull what the responder needs out of a query lanname sent.

    Returns a dict with ``is_query`` (the QR bit clear), ``tid``, and for mDNS
    the questioned ``qname`` and ``qtype``. Returns None if the packet is too
    short to be a query at all.
    """
    if len(data) < 12:
        return None
    tid, flags, qd, _an, _ns, _ar = struct.unpack_from("!HHHHHH", data, 0)
    info = {"tid": tid, "is_query": (flags & 0x8000) == 0}
    if kind == MDNS and qd >= 1:
        qname, off = _read_dns_name(data, 12)
        info["qname"] = qname
        if off + 2 <= len(data):
            info["qtype"] = struct.unpack_from("!H", data, off)[0]
    return info


def hexdump(data):
    """A classic offset, hex and printable-ASCII dump for the byte view."""
    lines = []
    for base in range(0, len(data), 16):
        chunk = data[base:base + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        hexpart = f"{hexpart:<47}"
        asciipart = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{base:04x}  {hexpart}  {asciipart}")
    return "\n".join(lines) if lines else "(empty)"


def python_bytes_literal(data):
    """The bytes as a Python literal, for pasting straight into a test."""
    return repr(bytes(data))


#: Ready-made payloads. Each is (label, text, interpret_escapes). They lean on
#: the classes of content a name from the link should never be trusted to be:
#: terminal control, log forgery, embedded NUL, invalid UTF-8, lookalikes and
#: oversize. Handy for driving an evaluation quickly.
PRESETS = (
    ('Plain short name', r"router", False),
    ('Fully qualified name', r"printer.workshop.lan", False),
    ('ANSI erase line', r"\x1b[2K\rgateway", True),
    ('Newline log forgery', r"nas\nWARNING lanname: root login from 10.0.0.9", True),
    ('Embedded NUL', r"nas\x00hidden", True),
    ('OSC 8 terminal hyperlink',
     r"\x1b]8;;http://evil.example/\x07nas\x1b]8;;\x07", True),
    ('Right-to-left override', r"invoice\u202egpj.exe", True),
    ('Cyrillic lookalike of router', r"r\u043euter", True),
    ('Invalid UTF-8 bytes', r"nas\xff\xfe", True),
    ("Maximum 63-byte label", "n" * 63, False),
    ("Oversize name in many labels", ".".join(["label"] * 40), False),
)
