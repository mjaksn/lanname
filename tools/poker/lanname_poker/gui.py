"""The PySide6 window.

One window, top to bottom: compose a reply, see the exact bytes, see what
lanname reads and passes on, and then deliver it either as a single datagram to
an endpoint of your choosing or by answering lanname's live queries. The window
holds no wire-format or socket logic of its own: it drives :mod:`wire`,
:mod:`net`, :mod:`responder` and :mod:`lanname_bridge`.
"""

import ipaddress

try:
    from PySide6.QtCore import Qt, Signal
    from PySide6.QtGui import QFont, QGuiApplication
    from PySide6.QtWidgets import (
        QApplication,
        QCheckBox,
        QComboBox,
        QFormLayout,
        QFrame,
        QGroupBox,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QMessageBox,
        QPlainTextEdit,
        QPushButton,
        QScrollArea,
        QVBoxLayout,
        QWidget,
    )
    HAVE_QT = True
except ImportError:
    HAVE_QT = False


def _mono():
    font = QFont()
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setFamily("monospace")
    return font


def _valid_addr(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


if HAVE_QT:

    from . import lanname_bridge, net, wire
    from .responder import Responder

    class MainWindow(QWidget):

        _log_line = Signal(str)
        _responder_state = Signal(bool, str)

        def __init__(self):
            super().__init__()
            self.setWindowTitle("lanname poker")
            self.responder = Responder(
                on_log=self._log_line.emit,
                on_state=lambda running, reason:
                    self._responder_state.emit(running, reason))
            self._log_line.connect(self._append_log)
            self._responder_state.connect(self._on_responder_state)
            self._build()
            self._refresh()

        # == construction

        def _build(self):
            outer = QVBoxLayout(self)

            banner = QLabel(
                "This tool crafts spoofed link traffic and can transmit it. "
                "Use it only on a network you own or are authorised to test.")
            banner.setWordWrap(True)
            banner.setStyleSheet(
                "background:#5a1d1d;color:#fff;padding:6px;border-radius:4px;")
            outer.addWidget(banner)

            # The five boxes are taller than the viewport on a small or a
            # high-DPI screen: at 300% scale a maximised 4K panel is only about
            # 1280x752 logical pixels, less than these need. Put them in a
            # scroll area so they keep their natural height and scroll, rather
            # than being crushed together. The banner stays outside it, pinned
            # so the warning is always in view.
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QFrame.Shape.NoFrame)
            scroll.setHorizontalScrollBarPolicy(
                Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
            content = QWidget()
            inner = QVBoxLayout(content)
            inner.setContentsMargins(0, 0, 0, 0)
            inner.addWidget(self._compose_box())
            inner.addWidget(self._bytes_box())
            inner.addWidget(self._preview_box())
            inner.addWidget(self._send_box())
            inner.addWidget(self._responder_box())
            inner.addStretch(1)
            scroll.setWidget(content)
            outer.addWidget(scroll)

        def _compose_box(self):
            box = QGroupBox("Compose a reply")
            form = QFormLayout(box)

            self.kind = QComboBox()
            self.kind.addItems(list(wire.REPLY_KINDS))
            self.kind.currentIndexChanged.connect(self._refresh)
            form.addRow("Reply type", self.kind)

            self.addr = QLineEdit("192.168.1.50")
            self.addr.textChanged.connect(self._refresh)
            form.addRow("Address it answers for", self.addr)

            self.preset = QComboBox()
            self.preset.addItem("Load a preset...")
            for label, _text, _interp in wire.PRESETS:
                self.preset.addItem(label)
            self.preset.currentIndexChanged.connect(self._load_preset)
            form.addRow("Preset", self.preset)

            self.hostname = QLineEdit("router")
            self.hostname.textChanged.connect(self._refresh)
            form.addRow("Hostname to inject", self.hostname)

            self.escapes = QCheckBox("interpret backslash escapes")
            self.escapes.toggled.connect(self._refresh)
            form.addRow("", self.escapes)

            help_text = QLabel(
                "Split into DNS labels on '.'. With escapes on: \\xHH a raw "
                "byte, \\uHHHH a code point, \\n \\r \\t \\0, \\\\ a backslash. "
                "NetBIOS names are 15 bytes of ASCII.")
            help_text.setWordWrap(True)
            help_text.setStyleSheet("color:#777;")
            form.addRow("", help_text)
            return box

        def _bytes_box(self):
            box = QGroupBox("Bytes lanname would receive")
            layout = QVBoxLayout(box)
            self.bytes_view = QPlainTextEdit(readOnly=True)
            self.bytes_view.setFont(_mono())
            # Eight hexdump lines cover every preset but the oversize one, which
            # scrolls inside the pane. Kept short so the window scrolls less.
            self.bytes_view.setFixedHeight(112)
            layout.addWidget(self.bytes_view)
            row = QHBoxLayout()
            copy_hex = QPushButton("Copy hex")
            copy_hex.clicked.connect(self._copy_hex)
            copy_lit = QPushButton("Copy Python bytes")
            copy_lit.clicked.connect(self._copy_literal)
            row.addWidget(copy_hex)
            row.addWidget(copy_lit)
            row.addStretch(1)
            layout.addLayout(row)
            return box

        def _preview_box(self):
            box = QGroupBox("What lanname does with it")
            layout = QVBoxLayout(box)
            self.parsed_label = QLabel()
            self.parsed_label.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse)
            self.parsed_label.setWordWrap(True)
            self.passed_label = QLabel()
            self.passed_label.setWordWrap(True)
            self.kind_label = QLabel()
            self.warn_label = QLabel()
            self.warn_label.setWordWrap(True)
            self.warn_label.setStyleSheet("color:#b8860b;")
            for widget in (self.parsed_label, self.passed_label,
                           self.kind_label, self.warn_label):
                layout.addWidget(widget)
            return box

        def _send_box(self):
            box = QGroupBox("Send one datagram")
            layout = QVBoxLayout(box)
            note = QLabel(
                "For a harness listening on a UDP socket. A live lanname will "
                "not accept a lone datagram; use the responder for that.")
            note.setWordWrap(True)
            note.setStyleSheet("color:#777;")
            layout.addWidget(note)
            row = QHBoxLayout()
            self.dest_host = QLineEdit("127.0.0.1")
            self.dest_port = QLineEdit("5353")
            self.dest_port.setFixedWidth(70)
            send = QPushButton("Send once")
            send.clicked.connect(self._send_once)
            row.addWidget(QLabel("to"))
            row.addWidget(self.dest_host)
            row.addWidget(QLabel("port"))
            row.addWidget(self.dest_port)
            row.addWidget(send)
            layout.addLayout(row)
            self.send_result = QLabel()
            self.send_result.setStyleSheet("color:#777;")
            layout.addWidget(self.send_result)
            return box

        def _responder_box(self):
            box = QGroupBox("Live responder")
            layout = QVBoxLayout(box)
            note = QLabel(
                "Answers lanname's real queries with the composed name so an "
                "end application resolves it. mDNS listens on 224.0.0.251:5353; "
                "NetBIOS listens on UDP 137 and may be blocked on Windows.")
            note.setWordWrap(True)
            note.setStyleSheet("color:#777;")
            layout.addWidget(note)

            self.restrict = QCheckBox(
                "Only answer mDNS queries for the address above")
            self.restrict.setChecked(True)
            self.restrict.toggled.connect(self._push_responder_config)
            layout.addWidget(self.restrict)

            row = QHBoxLayout()
            self.start_btn = QPushButton("Start responder")
            self.start_btn.clicked.connect(self._start_responder)
            self.stop_btn = QPushButton("Stop")
            self.stop_btn.clicked.connect(self._stop_responder)
            self.stop_btn.setEnabled(False)
            self.responder_status = QLabel("stopped")
            self.responder_status.setStyleSheet("color:#777;")
            row.addWidget(self.start_btn)
            row.addWidget(self.stop_btn)
            row.addWidget(self.responder_status)
            row.addStretch(1)
            layout.addLayout(row)

            self.log_view = QPlainTextEdit(readOnly=True)
            self.log_view.setFont(_mono())
            # Six lines of the running log, which scrolls as it fills. Kept
            # short so the window scrolls less.
            self.log_view.setFixedHeight(98)
            layout.addWidget(self.log_view)
            return box

        # == state

        def _current_kind(self):
            return self.kind.currentText()

        def _current_inject(self):
            return wire.decode_input(self.hostname.text(),
                                     self.escapes.isChecked())

        def _current_reply(self):
            kind = self._current_kind()
            inject = self._current_inject()
            if kind == wire.MDNS:
                if not _valid_addr(self.addr.text()):
                    return None, inject
                return wire.build_mdns_reply(
                    wire.reverse_qname(self.addr.text()), inject), inject
            return wire.build_nbstat_reply(inject), inject

        def _load_preset(self, index):
            if index <= 0:
                return
            _label, text, interp = wire.PRESETS[index - 1]
            self.hostname.blockSignals(True)
            self.escapes.blockSignals(True)
            self.hostname.setText(text)
            self.escapes.setChecked(interp)
            self.hostname.blockSignals(False)
            self.escapes.blockSignals(False)
            self.preset.blockSignals(True)
            self.preset.setCurrentIndex(0)
            self.preset.blockSignals(False)
            self._refresh()

        def _refresh(self):
            kind = self._current_kind()
            reply, inject = self._current_reply()
            if reply is None:
                self.bytes_view.setPlainText(
                    "(enter a valid address to build an mDNS reply)")
            else:
                self.bytes_view.setPlainText(wire.hexdump(reply))

            warnings = wire.build_warnings(kind, inject)
            self.warn_label.setText(
                "  ".join("warning: " + w for w in warnings))

            if not lanname_bridge.available():
                self.parsed_label.setText(
                    "lanname not importable; install it or place its checkout "
                    "beside this repository to preview parsing")
                self.passed_label.setText("")
                self.kind_label.setText("")
            elif reply is None:
                self.parsed_label.setText("")
                self.passed_label.setText("")
                self.kind_label.setText("")
            else:
                addr = self.addr.text()
                parsed = lanname_bridge.parse_reply(kind, reply, addr)
                self.parsed_label.setText("lanname parses: " + repr(parsed))
                short = lanname_bridge.shorten(parsed, False)
                full = lanname_bridge.shorten(parsed, True)
                self.passed_label.setText(
                    f"passes to caller: {short!r} (fqdn off)  "
                    f"{full!r} (fqdn on)")
                if _valid_addr(addr):
                    kind_name = lanname_bridge.addr_kind(addr)
                    probe = "yes" if lanname_bridge.would_probe(addr) else "no"
                    self.kind_label.setText(
                        f"address kind: {kind_name}   probed by mDNS and "
                        f"NetBIOS in \"all\" mode: {probe}")
                else:
                    self.kind_label.setText("")

            if self.responder.is_running():
                self._push_responder_config()

        # == actions

        def _copy_hex(self):
            reply, _inject = self._current_reply()
            if reply is not None:
                QGuiApplication.clipboard().setText(reply.hex())

        def _copy_literal(self):
            reply, _inject = self._current_reply()
            if reply is not None:
                QGuiApplication.clipboard().setText(
                    wire.python_bytes_literal(reply))

        def _send_once(self):
            kind = self._current_kind()
            inject = self._current_inject()
            try:
                sent = net.send_once(
                    kind, inject, self.dest_host.text(), self.dest_port.text(),
                    addr=self.addr.text())
                self.send_result.setText(
                    f"sent {sent} bytes to {self.dest_host.text()}:"
                    f"{self.dest_port.text()}")
            except (OSError, ValueError) as exc:
                self.send_result.setText(f"send failed: {exc}")

        def _start_responder(self):
            kind = self._current_kind()
            restrict = self.addr.text() if self.restrict.isChecked() else None
            self.responder.start(kind, self._current_inject(), restrict)
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.responder_status.setText("starting...")

        def _stop_responder(self):
            self.responder.stop()
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.responder_status.setText("stopped")

        def _push_responder_config(self):
            self.responder.set_payload(self._current_inject())
            restrict = self.addr.text() if self.restrict.isChecked() else None
            self.responder.set_restrict(restrict)

        def _append_log(self, line):
            self.log_view.appendPlainText(line)

        def _on_responder_state(self, running, reason):
            self.responder_status.setText(reason)
            self.start_btn.setEnabled(not running)
            self.stop_btn.setEnabled(running)
            if not running and reason.startswith("could not bind"):
                QMessageBox.warning(self, "Responder could not start", reason)

        def closeEvent(self, event):
            self.responder.stop()
            super().closeEvent(event)


def run_gui(argv=None):
    """Launch the window. Returns the process exit code."""
    if not HAVE_QT:
        raise SystemExit(
            "PySide6 is not installed. Install it with:\n"
            "  pip install --require-hashes -r requirements.txt")
    app = QApplication.instance() or QApplication(argv or [])
    window = MainWindow()
    # Open at a comfortable size, but never taller or wider than the screen
    # will hold, so the window fits on first open before it is maximised. The
    # margins leave room for the title bar and taskbar that the available area
    # does not already account for. The floor stops those margins shrinking the
    # window below a usable size, and then yields to the screen in turn, since a
    # floor larger than the display would defeat the point of the clamp. The
    # scroll area handles anything the height then cannot show.
    # availableGeometry is in the same logical pixels as resize, so this reads
    # correctly at any display scale.
    screen = window.screen() or app.primaryScreen()
    avail = screen.availableGeometry()
    width = min(760, avail.width() - 40)
    height = min(900, avail.height() - 60)
    width = min(max(width, 480), avail.width())
    height = min(max(height, 360), avail.height())
    window.resize(width, height)
    window.show()
    return app.exec()
