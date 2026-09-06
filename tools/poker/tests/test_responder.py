"""Tests for the responder's answer logic, without opening a socket.

The listening loop and its real sockets are never exercised here; only
:meth:`Responder._handle` is, with a captured send, so the transaction id
echo, the address restriction and the query-type filter are checked against
lanname's own parser without a packet leaving anything.
"""

import struct
import unittest

from lanname_poker import lanname_bridge, wire
from lanname_poker.responder import Responder


def mdns_query(qname, tid=0x4242):
    q = struct.pack("!HHHHHH", tid, 0x0000, 1, 0, 0, 0)
    q += wire.encode_dns_labels(qname.encode("ascii"))
    q += struct.pack("!HH", 12, 0x8001)
    return q


def nbstat_query(tid=0x4242):
    q = struct.pack("!HHHHHH", tid, 0x0000, 1, 0, 0, 0)
    q += wire.nb_encode_name(b"*" + b"\x00" * 15)
    q += struct.pack("!HH", 0x0021, 0x0001)
    return q


class _CaptureSock:
    def __init__(self):
        self.sent = []

    def sendto(self, data, peer):
        self.sent.append((data, peer))
        return len(data)


class MdnsResponder(unittest.TestCase):

    ADDR = "192.168.1.50"

    def _responder(self, payload, restrict=None):
        r = Responder(on_log=lambda _m: None)
        r._kind = wire.MDNS
        r._sock = _CaptureSock()
        r.set_payload(payload)
        r.set_restrict(restrict)
        return r

    def test_answers_with_the_payload_and_echoes_tid(self):
        r = self._responder(wire.decode_input(r"nas\x1bx", True))
        qname = wire.reverse_qname(self.ADDR)
        r._handle(mdns_query(qname, tid=0x1357), ("10.0.0.9", 5353))
        self.assertEqual(len(r._sock.sent), 1)
        reply, peer = r._sock.sent[0]
        self.assertEqual(peer, ("10.0.0.9", 5353))
        self.assertEqual(struct.unpack_from("!H", reply, 0)[0], 0x1357)
        if lanname_bridge.available():
            name = lanname_bridge.parse_reply(wire.MDNS, reply, self.ADDR)
            self.assertIn("\x1b", name)

    def test_restrict_blocks_other_addresses(self):
        r = self._responder(b"router", restrict="192.168.1.50")
        other = wire.reverse_qname("192.168.1.99")
        r._handle(mdns_query(other), ("10.0.0.9", 5353))
        self.assertEqual(r._sock.sent, [])

    def test_restrict_allows_the_named_address(self):
        r = self._responder(b"router", restrict="192.168.1.50")
        r._handle(mdns_query(wire.reverse_qname("192.168.1.50")),
                  ("10.0.0.9", 5353))
        self.assertEqual(len(r._sock.sent), 1)

    def test_ignores_a_response_rather_than_a_query(self):
        r = self._responder(b"router")
        response = struct.pack("!HHHHHH", 1, 0x8000, 0, 1, 0, 0)
        r._handle(response, ("10.0.0.9", 5353))
        self.assertEqual(r._sock.sent, [])


class NbstatResponder(unittest.TestCase):

    def _responder(self, payload):
        r = Responder(on_log=lambda _m: None)
        r._kind = wire.NBSTAT
        r._sock = _CaptureSock()
        r.set_payload(payload)
        return r

    def test_answers_and_echoes_tid(self):
        r = self._responder(b"NAS")
        r._handle(nbstat_query(tid=0x2468), ("10.0.0.9", 137))
        self.assertEqual(len(r._sock.sent), 1)
        reply, _peer = r._sock.sent[0]
        self.assertEqual(struct.unpack_from("!H", reply, 0)[0], 0x2468)
        if lanname_bridge.available():
            self.assertEqual(
                lanname_bridge.parse_reply(wire.NBSTAT, reply, "192.168.1.50"),
                "NAS")


if __name__ == "__main__":
    unittest.main()
