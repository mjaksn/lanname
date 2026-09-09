"""Answering the queries lanname actually sends, so a live instance resolves
the name you chose.

The offline preview shows what lanname would read out of a reply. To see an
end application take the name, something has to be on the link when lanname
asks. That is what this does: it listens for lanname's mDNS PTR queries on the
multicast group and for its NetBIOS status queries on UDP 137, and answers each
one with the composed reply, echoing the query's transaction id so the answer
matches even once lanname starts checking it.

This puts crafted answers onto the local link. Run it only on a network you
own or are authorised to test. It is Qt free on purpose: it reports what it
does through the standard logging module, on the ``lanname_poker.responder``
logger, and takes a single state callback for start, stop and failure, so it
can be tested and driven from anything.

Two honest limits, both reported through the log rather than hidden:

* On Windows the operating system usually holds UDP 137 for its own NetBIOS
  service, so the NetBIOS responder may fail to bind. mDNS uses 5353, which
  lanname leaves free by asking for unicast answers, so that path binds.
* The NetBIOS responder can only answer for the host it runs on, because
  lanname sends that query straight to the address it is naming. The mDNS
  responder sees every query on the link and can answer for any address.
"""

import logging
import socket
import struct
import threading

from . import wire

log = logging.getLogger(__name__)

MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353
NBNS_PORT = 137


class Responder:
    """Listens for lanname's queries and answers them with a chosen name.

    Each answered query and each notable event is written to the module
    logger, ``lanname_poker.responder``, so attach a handler to see them.
    *on_state* is called with (running, reason) when the responder starts,
    stops or fails; it may be called from the listening thread, so a GUI
    should marshal it onto its own thread. Log records are emitted from that
    thread too, and a GUI handler must do the same.
    """

    def __init__(self, on_state=None):
        self._on_state = on_state or (lambda _running, _reason: None)
        self._thread = None
        self._sock = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._kind = None
        self._payload = b""
        self._restrict_qname = None
        self._delay = 0.0

    # == configuration, safe to call while running

    def set_payload(self, payload):
        """The bytes to place as the name in every answer from now on."""
        with self._lock:
            self._payload = bytes(payload)

    def set_restrict(self, addr):
        """Limit mDNS answers to queries for *addr*, or None to answer all.

        Answering every PTR query on a link names every address the querier
        looks up, which is powerful and blunt. Restricting to one address is
        the safe default for evaluating a single host.
        """
        if addr:
            try:
                self._restrict_qname = wire.reverse_qname(addr).lower().rstrip(".")
                return
            except ValueError:
                log.warning("cannot restrict to %r: not an address", addr)
        self._restrict_qname = None

    def set_delay(self, seconds):
        """Wait *seconds* before answering each query from now on.

        A slow answer is worth crafting: lanname gives mDNS half of its
        timeout and NetBIOS the rest, so a reply that arrives late enough is
        one it has already given up on, and the tool should be able to sit on
        that edge deliberately. Zero, the default, answers at once as before.
        Negative values are clamped to zero. The wait is interruptible, so a
        stop during it drops the pending answer rather than holding shutdown.
        """
        with self._lock:
            self._delay = max(0.0, float(seconds))

    # == lifecycle

    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    def start(self, kind, payload, restrict_addr=None, delay=0.0):
        if self.is_running():
            return
        self._kind = kind
        self.set_payload(payload)
        self.set_restrict(restrict_addr)
        self.set_delay(delay)
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="lanname-poker-responder", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        thread = self._thread
        if thread and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        self._thread = None

    # == the listening loop

    def _run(self):
        try:
            self._sock = self._open()
        except OSError as exc:
            self._on_state(False, self._bind_hint(exc))
            return
        self._on_state(True, f"listening for {self._kind}")
        try:
            self._loop()
        except Exception as exc:              # noqa: BLE001 report and exit
            self._on_state(False, f"stopped on error: {exc}")
        finally:
            try:
                self._sock.close()
            except OSError:
                pass

    def _open(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        if self._kind == wire.MDNS:
            sock.bind(("", MDNS_PORT))
            mreq = struct.pack("=4sl", socket.inet_aton(MDNS_GROUP),
                               socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        else:
            sock.bind(("", NBNS_PORT))
        sock.settimeout(0.5)
        return sock

    def _bind_hint(self, exc):
        if self._kind == wire.NBSTAT:
            return (f"could not bind UDP {NBNS_PORT}: {exc}. On Windows the "
                    "NetBIOS service usually holds this port; stop it or test "
                    "NetBIOS through the byte view instead.")
        return f"could not bind UDP {MDNS_PORT}: {exc}"

    def _loop(self):
        while not self._stop.is_set():
            try:
                data, peer = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    return
                raise
            self._handle(data, peer)

    def _handle(self, data, peer):
        info = wire.parse_query(self._kind, data)
        if not info or not info["is_query"]:
            return
        with self._lock:
            payload = self._payload
            restrict = self._restrict_qname
            delay = self._delay
        origin = f"{peer[0]}:{peer[1]}"
        if self._kind == wire.MDNS:
            if info.get("qtype") != 12 or "qname" not in info:
                log.debug("mDNS query from %s ignored, not a PTR lookup", origin)
                return
            qname = info["qname"]
            if restrict is not None and qname.lower().rstrip(".") != restrict:
                log.debug("mDNS query for %s from %s ignored, not the "
                          "restricted address", qname, origin)
                return
            reply = wire.build_mdns_reply(qname, payload, info["tid"])
            what = f"mDNS query for {qname} from {origin}"
        else:
            reply = wire.build_nbstat_reply(payload, info["tid"])
            what = f"NetBIOS query from {origin}"

        # The wait comes after building the reply and after the filters, so a
        # query we would ignore costs nothing, and it uses the stop event so a
        # stop() during it drops this answer rather than making shutdown wait.
        # It blocks the loop, which for a tool answering one host is what is
        # wanted; a flood of queriers is not the case this serves.
        if delay:
            log.info("%s, answering in %.2f s", what, delay)
            if self._stop.wait(delay):
                log.info("%s abandoned, stopped during the delay", what)
                return

        self._sock.sendto(reply, peer)
        tail = f" after {delay:.2f} s" if delay else ""
        log.info("%s answered with %s%s", what, self._show(payload), tail)

    @staticmethod
    def _show(payload):
        try:
            return repr(payload.decode("utf-8"))
        except UnicodeDecodeError:
            return repr(payload)
