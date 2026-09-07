"""Tests for the wire building, including a round trip through lanname itself.

No test sends a packet. The round-trip tests feed crafted bytes to lanname's
own parser through a fake socket, exactly as the preview panel does, and are
skipped if lanname cannot be imported. Non-ASCII code points are built with
chr() so this source stays plain ASCII and readable.
"""

import struct
import unittest

from lanname_poker import lanname_bridge, wire

E_ACUTE = chr(0xE9)       # e with an acute accent
RLO = chr(0x202E)         # right-to-left override
REPLACEMENT = chr(0xFFFD)  # what invalid UTF-8 decodes to


class DecodeInput(unittest.TestCase):

    def test_literal_is_utf8(self):
        self.assertEqual(wire.decode_input("router", False), b"router")

    def test_unicode_literal(self):
        text = "caf" + E_ACUTE
        self.assertEqual(wire.decode_input(text, False), text.encode("utf-8"))

    def test_hex_escape_is_one_raw_byte(self):
        self.assertEqual(wire.decode_input(r"a\xffb", True), b"a\xffb")

    def test_unicode_escape(self):
        expected = b"a" + RLO.encode("utf-8") + b"b"
        self.assertEqual(wire.decode_input(r"a\u202eb", True), expected)

    def test_named_escapes(self):
        self.assertEqual(wire.decode_input(r"\n\r\t\0", True),
                         b"\x0a\x0d\x09\x00")

    def test_double_backslash(self):
        self.assertEqual(wire.decode_input(r"a\\b", True), b"a\\b")

    def test_incomplete_escape_is_literal(self):
        self.assertEqual(wire.decode_input(r"a\x", True), b"a\\x")

    def test_escapes_off_keeps_backslash(self):
        self.assertEqual(wire.decode_input(r"a\xff", False), b"a\\xff")


class EncodeLabels(unittest.TestCase):

    def test_simple(self):
        self.assertEqual(wire.encode_dns_labels(b"ab.cd"),
                         b"\x02ab\x02cd\x00")

    def test_empty_labels_dropped(self):
        self.assertEqual(wire.encode_dns_labels(b"a..b."),
                         b"\x01a\x01b\x00")

    def test_label_capped_at_63(self):
        encoded = wire.encode_dns_labels(b"x" * 100)
        self.assertEqual(encoded[0], 63)
        self.assertEqual(len(encoded), 1 + 63 + 1)

    def test_label_warning(self):
        self.assertTrue(wire.label_warnings(b"x" * 100))
        self.assertFalse(wire.label_warnings(b"short"))


class BuildStructure(unittest.TestCase):

    def test_mdns_header_is_a_response_with_one_answer(self):
        reply = wire.build_mdns_reply("1.2.3.4.in-addr.arpa", b"router")
        _tid, flags, qd, an, _ns, _ar = struct.unpack_from("!HHHHHH", reply, 0)
        self.assertTrue(flags & 0x8000)
        self.assertEqual(qd, 0)
        self.assertEqual(an, 1)

    def test_nbstat_answer_count_and_offset(self):
        reply = wire.build_nbstat_reply(b"NAS")
        self.assertEqual(struct.unpack_from("!H", reply, 6)[0], 1)   # ancount
        self.assertEqual(reply[56], 1)                               # name count

    def test_nbstat_warns_on_unicode_and_length(self):
        self.assertTrue(wire.nbstat_warnings(("caf" + E_ACUTE).encode("utf-8")))
        self.assertTrue(wire.nbstat_warnings(b"x" * 20))
        self.assertFalse(wire.nbstat_warnings(b"NAS"))


class ParseQuery(unittest.TestCase):

    def _lanname_style_mdns_query(self, qname, tid=0x4242):
        query = struct.pack("!HHHHHH", tid, 0x0000, 1, 0, 0, 0)
        query += wire.encode_dns_labels(qname.encode("ascii"))
        query += struct.pack("!HH", 12, 0x8001)
        return query

    def test_reads_tid_qname_and_type(self):
        qname = "50.1.168.192.in-addr.arpa"
        query = self._lanname_style_mdns_query(qname, tid=0x4242)
        info = wire.parse_query(wire.MDNS, query)
        self.assertTrue(info["is_query"])
        self.assertEqual(info["tid"], 0x4242)
        self.assertEqual(info["qname"], qname)
        self.assertEqual(info["qtype"], 12)

    def test_response_bit_marks_not_a_query(self):
        data = struct.pack("!HHHHHH", 1, 0x8000, 0, 1, 0, 0)
        self.assertFalse(wire.parse_query(wire.MDNS, data)["is_query"])

    def test_too_short_returns_none(self):
        self.assertIsNone(wire.parse_query(wire.MDNS, b"\x00\x01"))


@unittest.skipUnless(lanname_bridge.available(),
                     "lanname not importable; run from a checkout or set LANNAME_REPO")
class RoundTripThroughLanname(unittest.TestCase):
    """The point of the tool: what lanname makes of exactly the chosen content.

    A name it accepts comes back byte for byte. A name it refuses, one holding
    a control character or past the DNS length limits, comes back as None, and
    the tests here pin down which is which so a change on lanname's side shows
    up as a failure on this one.
    """

    ADDR = "192.168.1.50"

    def _parse_mdns(self, text, interp):
        inject = wire.decode_input(text, interp)
        reply = wire.build_reply(wire.MDNS, inject, self.ADDR)
        return lanname_bridge.parse_reply(wire.MDNS, reply, self.ADDR)

    def _parse_nbstat(self, text, interp):
        inject = wire.decode_input(text, interp)
        reply = wire.build_reply(wire.NBSTAT, inject, self.ADDR)
        return lanname_bridge.parse_reply(wire.NBSTAT, reply, self.ADDR)

    def test_plain_name_exact(self):
        self.assertEqual(self._parse_mdns("router", False), "router")

    def test_fqdn_preserved(self):
        self.assertEqual(self._parse_mdns("a.b.c", False), "a.b.c")

    def test_ansi_escape_is_refused(self):
        self.assertIsNone(self._parse_mdns(r"\x1b[2Kx", True))

    def test_newline_is_refused(self):
        self.assertIsNone(self._parse_mdns(r"nas\nforged", True))

    def test_nul_is_refused(self):
        self.assertIsNone(self._parse_mdns(r"nas\x00hidden", True))

    def test_invalid_utf8_becomes_replacement(self):
        self.assertIn(REPLACEMENT, self._parse_mdns(r"nas\xff", True))

    def test_bidi_override_survives(self):
        # Above 0x7f, so lanname lets it through: legal in a name, and the
        # caller's to judge. This is the case the tool exists to show.
        self.assertIn(RLO, self._parse_mdns(r"a\u202eb", True))

    def test_nbstat_plain_name(self):
        self.assertEqual(self._parse_nbstat("NAS", False), "NAS")

    def test_nbstat_control_char_is_refused(self):
        self.assertIsNone(self._parse_nbstat(r"nas\x1bx", True))

    # The presets lanname refuses outright, all for a control character. The
    # rest come back as sent, replacement characters and lookalikes included.
    REFUSED = {"ANSI erase line", "Newline log forgery", "Embedded NUL",
               "OSC 8 terminal hyperlink"}

    def test_every_preset_is_read_or_refused_as_expected(self):
        for label, text, interp in wire.PRESETS:
            with self.subTest(preset=label):
                parsed = self._parse_mdns(text, interp)
                if label in self.REFUSED:
                    self.assertIsNone(parsed)
                else:
                    self.assertIsNotNone(parsed)


if __name__ == "__main__":
    unittest.main()
