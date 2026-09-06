"""Sending one crafted reply to a chosen endpoint.

Separate from the responder because it is a different job: not answering a
query lanname sent, but pushing a datagram at an address and port of your
choosing. That suits a harness listening on a UDP socket, or replaying a reply
at a capture. A live lanname resolver will not pick a lone datagram up, since
it matches answers to the query it sent on its own socket; use the responder
for that.
"""

import socket

from . import wire


def send_once(kind, inject_bytes, dest_host, dest_port, addr=None,
              tid=wire.DEFAULT_TID):
    """Build the reply and send it as one UDP datagram. Returns bytes sent.

    *addr* supplies the queried name for an mDNS reply and is unused for
    NetBIOS. Raises OSError if the send fails and ValueError if an mDNS reply
    is asked for without a usable address.
    """
    if kind == wire.MDNS:
        if not addr:
            raise ValueError("an mDNS reply needs the address it answers for")
        reply = wire.build_mdns_reply(wire.reverse_qname(addr), inject_bytes, tid)
    else:
        reply = wire.build_nbstat_reply(inject_bytes, tid)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return sock.sendto(reply, (dest_host, int(dest_port)))
    finally:
        sock.close()
