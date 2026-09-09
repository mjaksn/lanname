"""The PySide6 window.

One window and no tabs. The left column is the resolver: every argument its
constructor takes, the two that can be changed while it runs, the module level
ceilings, and the two probe functions called on their own. The right column is
what comes back: the addresses being asked about and how each ask went, the
counters, the hosts seen all session, and the log records of the package
and of the harness itself on one pane.

The window holds no resolver logic of its own. It reads and drives
:mod:`session`, which is where lanname is actually touched.
"""

import logging
import threading

from . import session

try:
    from PySide6.QtCore import Qt, QTimer, Signal
    from PySide6.QtGui import QFont, QGuiApplication
    from PySide6.QtWidgets import (
        QAbstractItemView,
        QApplication,
        QCheckBox,
        QComboBox,
        QDoubleSpinBox,
        QFileDialog,
        QFormLayout,
        QFrame,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QMessageBox,
        QPlainTextEdit,
        QPushButton,
        QScrollArea,
        QSpinBox,
        QTableWidget,
        QTableWidgetItem,
        QVBoxLayout,
        QWidget,
    )
    HAVE_QT = True
except ImportError:
    HAVE_QT = False

# Addresses worth having on the table before anything else is typed: one from
# each class lanname sorts addresses into, including the two that ipaddress
# calls private and lanname does not. 192.0.2.1 is the documentation range and
# 127.0.0.1 is loopback; neither is a LAN, and this class is the gate on what
# "all" mode probes.
SAMPLE_ADDRESSES = (
    "192.168.1.1",
    "10.0.0.5",
    "172.16.4.9",
    "8.8.8.8",
    "192.0.2.1",
    "224.0.0.251",
    "127.0.0.1",
    "not-an-address",
)

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

POLL_INTERVALS = (
    ("off", 0),
    ("100 ms", 100),
    ("250 ms", 250),
    ("500 ms", 500),
    ("1 s", 1000),
    ("2 s", 2000),
)

WATCH_COLUMNS = ("Address", "Kind", "Would do", "lookup() returned",
                 "Calls", "Misses", "First name after")

MUTED = "color:#777;"


def _mono():
    font = QFont()
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setFamily("monospace")
    return font


if HAVE_QT:

    class _LogBridge(logging.Handler):
        """Hands log records to the window from any thread.

        The records that matter most here come off the worker threads, so the
        handler does nothing but call a Signal's emit, which Qt queues onto the
        GUI thread. Touching a widget from here directly would be the classic
        way to crash a Qt program.

        The thread's name is in the line because four workers resolve at once
        and their records interleave: without it a query and the reply to it
        cannot be told from two different addresses being asked about.
        """

        def __init__(self, sink):
            super().__init__()
            self._sink = sink
            self.setFormatter(logging.Formatter(
                "%(asctime)s %(levelname)s %(threadName)s %(name)s: "
                "%(message)s",
                datefmt="%H:%M:%S"))

        def emit(self, record):
            try:
                self._sink(self.format(record))
            except Exception:       # pragma: no cover - handler of last resort
                self.handleError(record)

    class MainWindow(QWidget):

        _log_line = Signal(str)
        _probe_done = Signal(str)

        def __init__(self):
            super().__init__()
            self.session = session.Session()
            self.setWindowTitle("lanname harness")
            self._log_line.connect(self._append_log)
            self._probe_done.connect(self._on_probe_done)
            # The view exists before the handler that writes to it. _build()
            # asks the session which lanname it imported, which is the first
            # line either logger writes, so a pane built after the handler was
            # attached would be handed a record with no widget behind it.
            self.log_view = self._make_log_view()
            self._handler = _LogBridge(self._log_line.emit)
            # Both loggers on the one pane, and in one timeline: the harness
            # says what was asked for and lanname says what it did about it,
            # and the two only make sense read together.
            self._loggers = [logging.getLogger("lanname"),
                             logging.getLogger("lanname_harness")]
            for logger in self._loggers:
                logger.addHandler(self._handler)
                logger.setLevel(logging.DEBUG)
            self._timer = QTimer(self)
            self._timer.timeout.connect(self._tick)
            self._local_hosts_shown = None
            self._build()
            self._on_option_changed()
            self._set_interval(self.interval.currentIndex())

        # == construction ===================================================

        def _build(self):
            outer = QVBoxLayout(self)

            self.banner = QLabel()
            self.banner.setWordWrap(True)
            outer.addWidget(self.banner)

            self.where = QLabel()
            self.where.setWordWrap(True)
            self.where.setStyleSheet(MUTED)
            outer.addWidget(self.where)

            # Two columns in a scroll area, for the same reason the poker tool
            # has one: at a high display scale the boxes are taller than the
            # viewport, and they should keep their natural height and scroll
            # rather than be crushed together. The banner stays outside it, so
            # the warning about what "all" mode sends is always in view.
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QFrame.Shape.NoFrame)
            content = QWidget()
            columns = QHBoxLayout(content)
            columns.setContentsMargins(0, 0, 0, 0)

            left = QVBoxLayout()
            left.addWidget(self._resolver_box())
            left.addWidget(self._ceilings_box())
            left.addWidget(self._probe_box())
            left.addStretch(1)

            right = QVBoxLayout()
            right.addWidget(self._addresses_box())
            right.addWidget(self._stats_box())
            right.addWidget(self._hosts_box())
            right.addWidget(self._log_box())

            columns.addLayout(left, 3)
            columns.addLayout(right, 4)
            scroll.setWidget(content)
            outer.addWidget(scroll)

        def _resolver_box(self):
            box = QGroupBox("Resolver")
            layout = QVBoxLayout(box)
            form = QFormLayout()
            form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
            layout.addLayout(form)

            # Rows carry the argument names rather than prose, so that what is
            # on the screen and what goes in the call are the same words.
            self.mode = QComboBox()
            self.mode.addItems(session.modes())
            self.mode.setCurrentText("dns")
            self.mode.currentIndexChanged.connect(self._on_mode_changed)
            form.addRow("mode", self.mode)
            self.mode_desc = QLabel()
            self.mode_desc.setWordWrap(True)
            self.mode_desc.setStyleSheet(MUTED)
            form.addRow("", self.mode_desc)

            self.fqdn = QCheckBox("keep the whole name")
            self.fqdn.setToolTip(
                "False gives 'nas', True gives 'nas.local'. Changing it "
                "empties the cache, since every entry was shortened on the "
                "way in.")
            self.fqdn.toggled.connect(self._on_fqdn_changed)
            form.addRow("fqdn", self.fqdn)

            self.workers = QSpinBox()
            self.workers.setRange(1, 64)
            self.workers.setValue(4)
            self.workers.valueChanged.connect(self._on_option_changed)
            form.addRow("workers", self.workers)

            self.resolve_public = QCheckBox("public addresses too")
            self.resolve_public.setToolTip(
                "A busy link produces thousands of them, most resolve to "
                "something uninformative, and each one is a query somebody "
                "else can see. Never probed either way.")
            self.resolve_public.toggled.connect(self._on_option_changed)
            form.addRow("resolve_public", self.resolve_public)

            self.positive_ttl = self._seconds(3600.0, 0.0, 1000000.0)
            form.addRow("positive_ttl", self.positive_ttl)
            self.negative_ttl = self._seconds(300.0, 0.0, 1000000.0)
            form.addRow("negative_ttl", self.negative_ttl)
            self.timeout = self._seconds(1.0, 0.0, 60.0)
            form.addRow("timeout", self.timeout)

            self.restrict = QCheckBox("restrict where probes go")
            self.restrict.setToolTip(
                "Private is not the same as on-link. Off is no restriction; "
                "on with an empty field means probe nothing.")
            self.restrict.toggled.connect(self._on_option_changed)
            form.addRow("local_networks", self.restrict)
            self.networks = QLineEdit()
            self.networks.setPlaceholderText(
                "192.168.1.0/24 10.2.0.0/16   (empty means probe nothing)")
            self.networks.textChanged.connect(self._on_option_changed)
            form.addRow("", self.networks)

            self.hosts_files = QPlainTextEdit()
            self.hosts_files.setFixedHeight(52)
            self.hosts_files.setPlaceholderText("one path per line")
            self.hosts_files.textChanged.connect(self._on_option_changed)
            form.addRow("hosts_files", self.hosts_files)
            browse = QPushButton("Add a file...")
            browse.clicked.connect(self._browse_hosts)
            form.addRow("", browse)

            self.call = QPlainTextEdit(readOnly=True)
            self.call.setFont(_mono())
            self.call.setFixedHeight(72)
            layout.addWidget(self.call)

            row = QHBoxLayout()
            self.build_btn = QPushButton("Build resolver")
            self.build_btn.clicked.connect(self._build_resolver)
            self.stop_btn = QPushButton("Shutdown")
            self.stop_btn.clicked.connect(self._shutdown_resolver)
            self.stop_btn.setEnabled(False)
            copy_call = QPushButton("Copy the call")
            copy_call.clicked.connect(
                lambda: QGuiApplication.clipboard().setText(
                    self.call.toPlainText()))
            row.addWidget(self.build_btn)
            row.addWidget(self.stop_btn)
            row.addWidget(copy_call)
            row.addStretch(1)
            layout.addLayout(row)

            self.resolver_status = QLabel()
            self.resolver_status.setWordWrap(True)
            layout.addWidget(self.resolver_status)
            return box

        def _seconds(self, value, low, high):
            spin = QDoubleSpinBox()
            spin.setRange(low, high)
            spin.setDecimals(2)
            spin.setSingleStep(0.5)
            spin.setSuffix(" s")
            spin.setValue(value)
            spin.valueChanged.connect(self._on_option_changed)
            return spin

        def _ceilings_box(self):
            box = QGroupBox("Ceilings")
            layout = QVBoxLayout(box)
            note = QLabel(
                "Module globals, read afresh every time they are used, so "
                "lowering one applies to the resolver already running. Set "
                "RESOLVER_CACHE_MAX small and feed the queue to watch "
                "evictions. MAX_ADDR_KIND_CACHE is the exception: it gates "
                "whether a classification is remembered and evicts nothing, "
                "so lowering it shows up nowhere here. A value applies when "
                "the box is left or stepped, not as each digit is typed: a "
                "ceiling on its way to 20000 would otherwise pass through 2 "
                "and evict almost everything first.")
            note.setWordWrap(True)
            note.setStyleSheet(MUTED)
            layout.addWidget(note)
            form = QFormLayout()
            layout.addLayout(form)
            self.ceilings = {}
            for name, module, desc in session.CEILINGS:
                spin = QSpinBox()
                spin.setRange(1, 100000000)
                # Without this a value is emitted per keystroke, so typing
                # 20000 passes 2, 20, 200 and 2000 through the running
                # resolver on the way. For MAX_OBSERVED_HOSTS that is not a
                # transient: the entries local_hosts() has already lost are
                # gone, and widening the ceiling is exactly when it happens.
                spin.setKeyboardTracking(False)
                current = session.ceiling(name)
                spin.setValue(current if current is not None else 1)
                spin.setToolTip(f"lanname.{module}.{name}: {desc}")
                spin.valueChanged.connect(
                    lambda value, key=name: self._set_ceiling(key, value))
                form.addRow(f"{module}.{name}", spin)
                self.ceilings[name] = spin
            return box

        def _probe_box(self):
            box = QGroupBox("Probe one address, without a resolver")
            layout = QVBoxLayout(box)
            note = QLabel(
                "mdns_reverse() and netbios_name(), the two methods called on "
                "their own. Each sends one packet and waits for one answer, "
                "whatever mode the resolver above is in, and answers None "
                "rather than raising when nothing comes back.")
            note.setWordWrap(True)
            note.setStyleSheet(MUTED)
            layout.addWidget(note)

            row = QHBoxLayout()
            self.probe_addr = QLineEdit("192.168.1.1")
            self.probe_timeout = QDoubleSpinBox()
            self.probe_timeout.setRange(0.05, 30.0)
            self.probe_timeout.setValue(1.0)
            self.probe_timeout.setSuffix(" s")
            self.probe_timeout.setFixedWidth(90)
            row.addWidget(QLabel("addr"))
            row.addWidget(self.probe_addr)
            row.addWidget(self.probe_timeout)
            layout.addLayout(row)

            buttons = QHBoxLayout()
            self.probe_buttons = []
            for kind in session.PROBE_KINDS:
                button = QPushButton(f"Send {kind}")
                button.clicked.connect(
                    lambda _checked=False, k=kind: self._probe(k))
                buttons.addWidget(button)
                self.probe_buttons.append(button)
            buttons.addStretch(1)
            layout.addLayout(buttons)

            self.probe_result = QLabel()
            self.probe_result.setWordWrap(True)
            self.probe_result.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse)
            layout.addWidget(self.probe_result)
            return box

        def _addresses_box(self):
            box = QGroupBox("Addresses")
            layout = QVBoxLayout(box)
            note = QLabel(
                "Each row is asked again on every tick, which is how a caller "
                "is meant to use lookup(): the first ask always misses, and "
                "the name turns up on a later one. Calls climbing with no new "
                "misses after that is the cache being hit; a static entry "
                "answers from the first ask and never reaches the cache, so "
                "it misses nothing and counts no hits either.")
            note.setWordWrap(True)
            note.setStyleSheet(MUTED)
            layout.addWidget(note)

            row = QHBoxLayout()
            self.add_addr = QLineEdit()
            self.add_addr.setPlaceholderText(
                "192.168.1.10 192.168.1.11   (space or comma separated)")
            self.add_addr.returnPressed.connect(self._add_addresses)
            add = QPushButton("Watch")
            add.clicked.connect(self._add_addresses)
            samples = QPushButton("Samples")
            samples.setToolTip(
                "One address of each kind in ADDR_KINDS: "
                + ", ".join(session.addr_kinds())
                + ". Two of them are private to ipaddress and not to "
                "lanname.")
            samples.clicked.connect(self._add_samples)
            row.addWidget(self.add_addr)
            row.addWidget(add)
            row.addWidget(samples)
            layout.addLayout(row)

            self.watch_table = self._table(WATCH_COLUMNS)
            self.watch_table.setFixedHeight(220)
            layout.addWidget(self.watch_table)

            row = QHBoxLayout()
            row.addWidget(QLabel("ask every"))
            self.interval = QComboBox()
            for label, _ms in POLL_INTERVALS:
                self.interval.addItem(label)
            self.interval.setCurrentIndex(2)
            self.interval.currentIndexChanged.connect(self._set_interval)
            row.addWidget(self.interval)
            once = QPushButton("Ask once")
            once.setToolTip(
                "One lookup() for every row, whatever the interval says and "
                "whether or not the resolver has been shut down.")
            once.clicked.connect(self._ask_once)
            drop = QPushButton("Forget selected")
            drop.clicked.connect(self._forget_selected)
            clear = QPushButton("Forget all")
            clear.clicked.connect(self._forget_all)
            row.addWidget(once)
            row.addWidget(drop)
            row.addWidget(clear)
            row.addStretch(1)
            layout.addLayout(row)

            self.asking_note = QLabel()
            self.asking_note.setWordWrap(True)
            self.asking_note.setStyleSheet(MUTED)
            layout.addWidget(self.asking_note)

            feed = QHBoxLayout()
            self.feed_count = QSpinBox()
            self.feed_count.setRange(1, 100000)
            self.feed_count.setValue(500)
            self.feed_network = QLineEdit("10.99.0.0/16")
            self.feed_network.setFixedWidth(130)
            feed_btn = QPushButton("Feed the queue")
            feed_btn.clicked.connect(self._feed)
            feed.addWidget(QLabel("feed"))
            feed.addWidget(self.feed_count)
            feed.addWidget(QLabel("from"))
            feed.addWidget(self.feed_network)
            feed.addWidget(feed_btn)
            feed.addStretch(1)
            layout.addLayout(feed)

            self.feed_note = QLabel()
            self.feed_note.setWordWrap(True)
            self.feed_note.setStyleSheet(MUTED)
            layout.addWidget(self.feed_note)
            return box

        def _stats_box(self):
            box = QGroupBox("Counters")
            layout = QVBoxLayout(box)
            grid = QGridLayout()
            grid.setColumnStretch(2, 1)
            layout.addLayout(grid)
            self.stat_labels = {}
            for row, key in enumerate(session.STAT_KEYS):
                grid.addWidget(QLabel(key), row, 0)
                value = QLabel("0")
                value.setFont(_mono())
                grid.addWidget(value, row, 1)
                desc = QLabel(session.STAT_DESC[key])
                desc.setWordWrap(True)
                desc.setStyleSheet(MUTED)
                grid.addWidget(desc, row, 2)
                self.stat_labels[key] = value
            return box

        def _hosts_box(self):
            box = QGroupBox("local_hosts()")
            layout = QVBoxLayout(box)
            note = QLabel(
                "Every private address that has ever answered to a name, kept "
                "apart from the cache and outliving it, newest name first.")
            note.setWordWrap(True)
            note.setStyleSheet(MUTED)
            layout.addWidget(note)
            self.hosts_table = self._table(("Address", "Name", "Earlier names"))
            self.hosts_table.setFixedHeight(160)
            layout.addWidget(self.hosts_table)
            self.hosts_note = QLabel()
            self.hosts_note.setStyleSheet(MUTED)
            layout.addWidget(self.hosts_note)
            return box

        def _make_log_view(self):
            """The pane itself, built early so a record always has somewhere
            to land. Bounded, because a resolver at DEBUG under a feed writes
            faster than anyone reads."""
            view = QPlainTextEdit(readOnly=True)
            view.setFont(_mono())
            view.setFixedHeight(120)
            view.setMaximumBlockCount(2000)
            return view

        def _log_box(self):
            box = QGroupBox("Log records from lanname and from this harness")
            layout = QVBoxLayout(box)
            row = QHBoxLayout()
            row.addWidget(QLabel("level"))
            self.level = QComboBox()
            self.level.addItems(LOG_LEVELS)
            self.level.setCurrentText("DEBUG")
            self.level.currentTextChanged.connect(self._set_level)
            row.addWidget(self.level)
            clear = QPushButton("Clear")
            clear.clicked.connect(lambda: self.log_view.setPlainText(""))
            row.addWidget(clear)
            row.addStretch(1)
            layout.addLayout(row)
            layout.addWidget(self.log_view)
            note = QLabel(
                "DEBUG is where the detail is: every query sent, every reply "
                "read, what was queued, cached and evicted, and what this "
                "harness asked for, from both loggers on one timeline with "
                "the thread that wrote each line. Nothing is logged per "
                "address above DEBUG, and a cache hit is not logged at all: "
                "the watch table and the hits counter are where a repeated "
                "answer belongs. A hosts file that cannot be read is a "
                "WARNING.")
            note.setWordWrap(True)
            note.setStyleSheet(MUTED)
            layout.addWidget(note)
            return box

        def _table(self, headers):
            table = QTableWidget(0, len(headers))
            table.setHorizontalHeaderLabels(list(headers))
            table.verticalHeader().setVisible(False)
            table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            table.setSelectionBehavior(
                QAbstractItemView.SelectionBehavior.SelectRows)
            table.horizontalHeader().setSectionResizeMode(
                QHeaderView.ResizeMode.ResizeToContents)
            table.horizontalHeader().setStretchLastSection(True)
            return table

        # == options ========================================================

        def _read_options(self):
            paths = [line.strip()
                     for line in self.hosts_files.toPlainText().splitlines()
                     if line.strip()]
            return session.Options(
                mode=self.mode.currentText(),
                workers=self.workers.value(),
                resolve_public=self.resolve_public.isChecked(),
                fqdn=self.fqdn.isChecked(),
                positive_ttl=self.positive_ttl.value(),
                negative_ttl=self.negative_ttl.value(),
                timeout=self.timeout.value(),
                restrict_networks=self.restrict.isChecked(),
                networks=self.networks.text(),
                hosts_files=paths,
            )

        def _on_option_changed(self):
            self.session.options = self._read_options()
            self._refresh_status()

        def _on_mode_changed(self):
            self.session.options = self._read_options()
            self.session.set_mode(self.mode.currentText())
            self._refresh_status()

        def _on_fqdn_changed(self):
            self.session.options = self._read_options()
            self.session.set_fqdn(self.fqdn.isChecked())
            self._refresh_status()

        def _browse_hosts(self):
            path, _filter = QFileDialog.getOpenFileName(
                self, "Choose a hosts file")
            if path:
                text = self.hosts_files.toPlainText()
                self.hosts_files.setPlainText(
                    (text + "\n" + path).strip() if text else path)

        def _set_ceiling(self, name, value):
            if session.available():
                session.set_ceiling(name, value)

        def _refresh_status(self):
            options = self.session.options
            self.mode_desc.setText(session.mode_desc(options.mode))
            self.call.setPlainText(session.call_repr(options))
            self.networks.setEnabled(options.restrict_networks)

            version = session.version()
            where = session.location()
            self.where.setText(
                f"lanname {version} from {where}" if version
                else "lanname is not importable; nothing here will work")

            live = self.session.running()
            probing = live and options.mode == "all"
            if probing:
                self.banner.setText(
                    "\"all\" mode is live. A private address that reverse "
                    "DNS does not name, and that local_networks allows, gets "
                    "an mDNS query on the link and a NetBIOS query sent "
                    "straight to it. Use this only on a network you own or "
                    "are authorised to test.")
                self.banner.setStyleSheet(
                    "background:#5a1d1d;color:#fff;padding:6px;"
                    "border-radius:4px;")
            else:
                self.banner.setText(
                    "This harness drives the real package. \"all\" mode puts "
                    "mDNS and NetBIOS probes on the LAN, \"dns\" mode asks the "
                    "system resolver once per address, and the probe buttons "
                    "send a packet whatever the mode.")
                self.banner.setStyleSheet(
                    "background:#4a3c10;color:#fff;padding:6px;"
                    "border-radius:4px;")

            if self.session.resolver is None:
                state = "no resolver built yet"
            elif self.session.shut_down:
                state = ("shut down: queued work was dropped, lookup() answers "
                         "from static entries and the cache only. Build again "
                         "to restart; a resolver is not restartable.")
            else:
                static = self.session.static_count()
                state = (f"running, mode {options.mode!r}, "
                         f"{self.session.built_with.workers} workers, "
                         f"{static} static entries")
                if self.session.needs_rebuild():
                    state += ("   [the options above have moved past what this "
                              "one was built with; only mode and fqdn change "
                              "on a running resolver, so rebuild to apply the "
                              "rest]")
            self.resolver_status.setText(state)
            if self.session.resolver is None:
                self.asking_note.setText(
                    "Nothing is asked until a resolver is built.")
            elif self.session.shut_down:
                self.asking_note.setText(
                    "Asking on the tick has stopped, because the resolver has "
                    "been shut down. \"Ask once\" still works and still "
                    "answers, from static entries and from cache entries that "
                    "have not expired; nothing new is looked up and nothing "
                    "is queued.")
            else:
                self.asking_note.setText("")
            self.build_btn.setText(
                "Build resolver" if self.session.resolver is None
                else "Rebuild resolver")
            self.stop_btn.setEnabled(live)
            self.feed_note.setText(
                f"One lookup() each, not watched. The work queue holds "
                f"{self.session.queue_size()}, so more than that at once is "
                f"where \"dropped\" starts climbing. In \"off\" mode nothing "
                f"is queued, and an address already pending is not queued "
                f"twice.")

        # == the resolver ===================================================

        def _build_resolver(self):
            options = self._read_options()
            try:
                self.session.build(options)
            except (TypeError, ValueError, RuntimeError) as exc:
                QMessageBox.warning(
                    self, "Resolver not built",
                    f"{type(exc).__name__}: {exc}")
                self._refresh_status()
                return
            self._local_hosts_shown = None
            self._refresh_status()
            self._tick()

        def _shutdown_resolver(self):
            self.session.shutdown()
            self._refresh_status()

        # == addresses ======================================================

        def _add_addresses(self):
            self._watch_all(session.split_addrs(self.add_addr.text()))
            self.add_addr.clear()

        def _add_samples(self):
            self._watch_all(SAMPLE_ADDRESSES)

        def _watch_all(self, addrs):
            for addr in addrs:
                try:
                    self.session.watch(addr)
                except ValueError as exc:
                    QMessageBox.information(self, "Watch list full", str(exc))
                    break
            self._sync_watch_rows()
            self._tick()

        def _forget_selected(self):
            rows = {index.row() for index in
                    self.watch_table.selectionModel().selectedRows()}
            for row in sorted(rows, reverse=True):
                item = self.watch_table.item(row, 0)
                if item is not None:
                    self.session.unwatch(item.text())
            self._sync_watch_rows()

        def _forget_all(self):
            self.session.clear_watches()
            self._sync_watch_rows()

        def _feed(self):
            if not self.session.running():
                QMessageBox.information(
                    self, "No resolver", "Build a resolver first.")
                return
            count = self.feed_count.value()
            if self.session.options.mode == "all":
                answer = QMessageBox.question(
                    self, "Feed in \"all\" mode",
                    f"This offers {count} addresses to a resolver in \"all\" "
                    "mode. Every private one that reverse DNS does not name "
                    "gets an mDNS query on the link and a NetBIOS query sent "
                    "to it. Go on?")
                if answer != QMessageBox.StandardButton.Yes:
                    return
            try:
                addrs = session.feed_addresses(self.feed_network.text(), count)
                # The count goes in the log from session.feed(), so the line
                # lands in its place in the record rather than being written
                # to the widget from here and jumping the queue.
                self.session.feed(addrs)
            except ValueError as exc:
                QMessageBox.warning(self, "Not a network", str(exc))
                return
            self._tick()

        # == the probes =====================================================

        def _probe(self, kind):
            addr = self.probe_addr.text().strip()
            if not addr:
                return
            timeout = self.probe_timeout.value()
            for button in self.probe_buttons:
                button.setEnabled(False)
            self.probe_result.setText(f"{kind} to {addr}, waiting up to "
                                      f"{timeout:g} s...")
            # On a thread of its own: both functions block until an answer or
            # the timeout, and a window that stops repainting for a second is
            # a window that looks broken.
            thread = threading.Thread(
                target=self._probe_worker, args=(kind, addr, timeout),
                daemon=True, name="harness-probe")
            thread.start()

        def _probe_worker(self, kind, addr, timeout):
            try:
                name = session.probe(kind, addr, timeout)
                line = f"{kind} to {addr} returned {name!r}"
            except Exception as exc:
                line = f"{kind} to {addr} raised {type(exc).__name__}: {exc}"
            self._probe_done.emit(line)

        def _on_probe_done(self, line):
            self.probe_result.setText(line)
            for button in self.probe_buttons:
                button.setEnabled(True)

        # == the tick =======================================================

        def _set_interval(self, index):
            _label, ms = POLL_INTERVALS[index]
            if ms:
                self._timer.start(ms)
            else:
                self._timer.stop()

        def _tick(self):
            # tick() rather than poll(): the timer's ask stops at a shutdown,
            # so the counts do not go on climbing against a resolver the
            # caller has stopped. "Ask once" is the way to ask after one.
            self.session.tick()
            self._refresh_watch_rows()
            self._refresh_stats()
            self._refresh_hosts()

        def _ask_once(self):
            self.session.poll()
            self._refresh_watch_rows()
            self._refresh_stats()
            self._refresh_hosts()

        def _sync_watch_rows(self):
            """Match the table's rows to the watch list, then fill them in."""
            table = self.watch_table
            table.setRowCount(len(self.session.watches))
            for row, watch in enumerate(self.session.watches):
                for column in range(len(WATCH_COLUMNS)):
                    if table.item(row, column) is None:
                        table.setItem(row, column, QTableWidgetItem(""))
                table.item(row, 0).setText(watch.addr)
            self._refresh_watch_rows()

        def _refresh_watch_rows(self):
            table = self.watch_table
            if table.rowCount() != len(self.session.watches):
                self._sync_watch_rows()
                return
            for row, watch in enumerate(self.session.watches):
                kind = session.addr_kind(watch.addr) or ""
                looked_up, why = self.session.verdict(watch.addr)
                latency = watch.latency()
                # A name is shown as a repr rather than as itself: it is
                # whatever the answering host chose, and one carrying a
                # control character or a right-to-left override would
                # otherwise rearrange the table it is printed in.
                cells = (watch.addr, kind, why if looked_up else f"no: {why}",
                         repr(watch.name), str(watch.calls), str(watch.misses),
                         "-" if latency is None else f"{latency:.2f} s")
                for column, text in enumerate(cells):
                    item = table.item(row, column)
                    if item.text() != text:
                        item.setText(text)

        def _refresh_stats(self):
            stats = self.session.stats()
            for key, label in self.stat_labels.items():
                text = str(stats.get(key, 0))
                if label.text() != text:
                    label.setText(text)

        def _refresh_hosts(self):
            hosts = self.session.local_hosts()
            # Capped, and only redrawn when something moved: this table is
            # thousands of rows long after a feed, and rebuilding it four
            # times a second would spend the whole tick on it.
            shown = hosts[:200]
            # The total goes out before the early return, or it would freeze
            # at whatever it read the last time the visible rows changed. The
            # list is sorted by address, so past the cap every new host lands
            # beyond the window and the rows stop moving while the count is
            # still climbing.
            self.hosts_note.setText(
                f"{len(hosts)} addresses"
                + (f", showing the first {len(shown)}" if len(hosts) > len(shown)
                   else ""))
            if shown == self._local_hosts_shown:
                return
            self._local_hosts_shown = shown
            table = self.hosts_table
            table.setRowCount(len(shown))
            for row, (addr, names) in enumerate(shown):
                cells = (addr, repr(names[0]),
                         ", ".join(repr(name) for name in names[1:]))
                for column, text in enumerate(cells):
                    item = table.item(row, column)
                    if item is None:
                        table.setItem(row, column, QTableWidgetItem(text))
                    elif item.text() != text:
                        item.setText(text)

        # == logging ========================================================

        def _set_level(self, name):
            for logger in self._loggers:
                logger.setLevel(getattr(logging, name))

        def _append_log(self, line):
            self.log_view.appendPlainText(line)

        def closeEvent(self, event):
            self._timer.stop()
            for logger in self._loggers:
                logger.removeHandler(self._handler)
            self.session.shutdown()
            super().closeEvent(event)


def run_gui(argv=None):
    """Launch the window. Returns the process exit code."""
    if not HAVE_QT:
        raise SystemExit(
            "PySide6 is not installed. Install it with:\n"
            "  pip install --require-hashes -r requirements.txt")
    app = QApplication.instance() or QApplication(argv or [])
    window = MainWindow()
    # Open at a comfortable size, but never larger than the screen will hold,
    # so the window fits before it is maximised. The floor stops the margins
    # shrinking it below a usable size and then yields to the screen in turn.
    # availableGeometry is in the same logical pixels as resize, so this reads
    # correctly at any display scale, and the scroll area takes whatever the
    # height cannot show.
    screen = window.screen() or app.primaryScreen()
    avail = screen.availableGeometry()
    width = min(max(min(1180, avail.width() - 40), 640), avail.width())
    height = min(max(min(960, avail.height() - 60), 420), avail.height())
    window.resize(width, height)
    window.show()
    return app.exec()
