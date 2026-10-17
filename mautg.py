#!/usr/bin/env python3
# - - - - - - - - - - - - - - - - - - - - - - - -
# mautg.py  by ewald@jeitler.cc 2026 https://www.jeitler.cc
# - - - - - - - - - - - - - - - - - - - - - - - -
# When I wrote this code, only God and I knew how it worked.
# Now only God and the AI know it.
# And since the AI helped write it… good luck to all of us.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

VERSION = "1.48"
AUTHOR = "Ewald Jeitler"
URL = "https://www.jeitler.cc"
CREDIT = f"by {AUTHOR} - {URL}"


def _pad_credit(room):
    """Padding for the rest of a status bar, with the credit right-aligned if it fits."""
    room = max(0, room)
    c = _credit(room)
    return ' ' * (room - len(c) - (1 if c else 0)) + c + (' ' if c else '')


def _credit(room):
    """Longest credit text that fits into `room` columns (with one blank on each side)."""
    for t in (CREDIT, f"by {AUTHOR}", URL):
        if len(t) + 2 <= room:
            return t
    return ''

import socket
import struct
import sys
import time
import json
import errno
import argparse
import threading
import csv
import zlib
import functools
import os
import signal
import shutil
import select
import selectors
from datetime import datetime
from pathlib import Path
from collections import defaultdict, OrderedDict
from typing import NamedTuple, Optional

# --- Output encoding ----------------------------------------------------------
# Unicode only when the locale says UTF-8; otherwise (e.g. Cisco Guest Shell,
# LANG=C) plain ASCII so nothing is garbled. Force with --ascii / MAUTG_ASCII=1.
import codecs

_ASCII_MAP = {
    '\u00b5': 'u', '\u2013': '-', '\u2014': '-', '\u2026': '...', '\u2192': '->',
    '\u2298': 'x', '\u2299': '(i)', '\u24d8': '(i)', '\u2500': '-', '\u2502': '|',
    '\u250c': '+', '\u2510': '+', '\u2514': '+', '\u2518': '+', '\u2550': '=',
    '\u2551': '|', '\u2554': '+', '\u255a': '+', '\u2557': '+', '\u255d': '+',
    '\u26a0': '!', '\u2713': 'OK', '\u2717': 'X', '\u00b0': 'deg', '\u00b1': '+/-',
    '\u00d7': 'x', '\u2022': '*', '\u2191': '^', '\u2193': 'v', '\u2190': '<-',
    '\u2264': '<=', '\u2265': '>=', '\u2248': '~', '\u00b7': '.',
    '\u2018': "'", '\u2019': "'", '\u201c': '"', '\u201d': '"',
    '\U0001f680': '', '\u2588': '#', '\u2591': '.', '\u25cf': '*', '\u25cb': 'o',
}


def _ascii_handler(err):
    bad = err.object[err.start:err.end]
    return (''.join(_ASCII_MAP.get(ch, '?') for ch in bad), err.end)


codecs.register_error('mautg', _ascii_handler)


def _locale_utf8():
    # Python 3.7+ coerces a C locale to LC_CTYPE=C.UTF-8 in its own environment;
    # that says nothing about the terminal, so it is ignored here.
    ct = os.environ.get('LC_CTYPE')
    if ct and ct.lower() == 'c.utf-8':
        ct = None
    enc = (os.environ.get('LC_ALL') or ct or os.environ.get('LANG') or '').lower()
    return 'utf-8' in enc or 'utf8' in enc


_ASCII_OUT = bool('--ascii' in sys.argv[1:] or os.environ.get('MAUTG_ASCII')
                  or (sys.platform != 'win32' and not _locale_utf8()))

# --- Python 3.6 support (e.g. the Cisco IOS-XE Guest Shell) -----------------------
if sys.version_info < (3, 7):
    if not hasattr(time, 'time_ns'):
        time.time_ns = lambda: int(time.time() * 1_000_000_000)
    # 3.6 has no stdout.reconfigure()
    try:
        sys.stdout = open(sys.stdout.fileno(), 'w', buffering=1,
                          encoding='ascii' if _ASCII_OUT else 'utf-8',
                          errors='mautg' if _ASCII_OUT else 'replace', closefd=False)
    except (OSError, ValueError, AttributeError):
        pass
else:
    if _ASCII_OUT:
        sys.stdout.reconfigure(encoding='ascii', errors='mautg', line_buffering=True)
    else:
        sys.stdout.reconfigure(line_buffering=True)

# macOS does not export IP_RECVTOS in Python's socket module (value=27 on Darwin)
_IP_RECVTOS = getattr(socket, 'IP_RECVTOS', 27)

# Destination address of every datagram (to tell MC / UC / BC apart):
# Linux IP_PKTINFO (in_pktinfo: ifindex, spec_dst, dst), BSD/macOS IP_RECVDSTADDR.
if sys.platform.startswith('linux'):
    _DST_OPT = getattr(socket, 'IP_PKTINFO', 8)
elif sys.platform == 'win32':
    _DST_OPT = None
else:
    _DST_OPT = getattr(socket, 'IP_RECVDSTADDR', 7)
_DST_OFFSET = 8 if sys.platform.startswith('linux') else 0   # address inside the cmsg data
_CAST_CACHE = {}               # raw destination address -> 'MC' | 'UC' | 'BC'
# Linux: the kernel counts datagrams it had to drop because the socket queue was
# full (we were too slow) and reports the running total with every packet
_SO_RXQ_OVFL = getattr(socket, 'SO_RXQ_OVFL', 40) if sys.platform.startswith('linux') else None
PKT_LINE_LIMIT = 500           # per-packet display: at most this many lines per second



# --- Terminal colors ----------------------------------------------------------

class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    WHITE = '\033[1;97m'
    GRAY = '\033[90m'
    BOLD = '\033[1m'
    ENDC = '\033[0m'


# --- Terminal close / termination handling ----------------------------------

class _Terminate(BaseException):
    """Raised in the main thread by SIGHUP / SIGTERM (or a lost terminal) so
    that every loop unwinds, the sockets / CSV / sync threads are closed and
    the process really ends - nothing keeps running in the background."""

    def __init__(self, signame='SIGTERM'):
        super().__init__(signame)
        self.signame = signame


_terminating = False
_tty_gone = False


def _silence_output():
    """Point stdout/stderr to /dev/null (the terminal is gone) so that final
    prints cannot fail with EIO / EPIPE."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, 1)
        os.dup2(devnull, 2)
        os.close(devnull)
    except OSError:
        pass


def _on_signal(signum, _frame):
    global _terminating
    if _terminating:
        return
    _terminating = True
    name = signal.Signals(signum).name
    if name in ('SIGHUP', 'SIGBREAK') or _tty_gone:
        _silence_output()
    raise _Terminate(name)


def _terminal_lost(fd):
    """True if the controlling terminal behind fd has gone away."""
    try:
        os.tcgetpgrp(fd)
        return False
    except OSError as e:
        return e.errno in (errno.EIO, errno.ENOTTY, errno.EBADF, errno.ENXIO)


def _install_termination_handlers():
    """Stop cleanly on SIGHUP (terminal closed), SIGTERM and SIGBREAK, and
    watch the TTY for hang-ups that do not deliver a signal."""
    for name in ('SIGHUP', 'SIGTERM', 'SIGBREAK'):
        sig = getattr(signal, name, None)
        if sig is not None:
            try:
                signal.signal(sig, _on_signal)
            except (OSError, ValueError):
                pass

    fd = None
    for candidate in (0, 1):
        try:
            if os.isatty(candidate):
                fd = candidate
                break
        except OSError:
            pass
    if fd is None or not hasattr(os, 'tcgetpgrp'):
        return

    def watchdog():
        while True:
            time.sleep(1.0)
            if _terminal_lost(fd):
                global _tty_gone
                _tty_gone = True
                _silence_output()
                # SIGTERM: not blockable by an inherited signal mask like SIGHUP
                if hasattr(signal, 'SIGTERM') and sys.platform != 'win32':
                    os.kill(os.getpid(), signal.SIGTERM)
                else:
                    os._exit(1)
                return

    threading.Thread(target=watchdog, name='tty-watchdog', daemon=True).start()


# --- DSCP names ---------------------------------------------------------------

DSCP_NAMES = {
    0: "BE", 8: "CS1", 10: "AF11", 12: "AF12", 14: "AF13", 16: "CS2",
    18: "AF21", 20: "AF22", 22: "AF23", 24: "CS3", 26: "AF31", 28: "AF32",
    30: "AF33", 32: "CS4", 34: "AF41", 36: "AF42", 38: "AF43", 40: "CS5",
    44: "VA", 46: "EF", 48: "CS6", 56: "CS7",
}

# (value, name, meaning) for the DSCP pick list
DSCP_TABLE = [
    (0, 'BE', 'Best Effort (default)'), (8, 'CS1', 'Scavenger / lower than best effort'),
    (10, 'AF11', 'Assured Fwd 1, low drop'), (12, 'AF12', 'Assured Fwd 1, medium drop'),
    (14, 'AF13', 'Assured Fwd 1, high drop'), (16, 'CS2', 'OAM / network management'),
    (18, 'AF21', 'Assured Fwd 2, low drop'), (20, 'AF22', 'Assured Fwd 2, medium drop'),
    (22, 'AF23', 'Assured Fwd 2, high drop'), (24, 'CS3', 'Signaling / broadcast video'),
    (26, 'AF31', 'Assured Fwd 3, low drop'), (28, 'AF32', 'Assured Fwd 3, medium drop'),
    (30, 'AF33', 'Assured Fwd 3, high drop'), (32, 'CS4', 'Real-time interactive'),
    (34, 'AF41', 'Assured Fwd 4, low drop (video)'), (36, 'AF42', 'Assured Fwd 4, medium drop'),
    (38, 'AF43', 'Assured Fwd 4, high drop'), (40, 'CS5', 'Broadcast video / signaling'),
    (44, 'VA', 'Voice-Admit (CAC voice)'), (46, 'EF', 'Expedited Forwarding (voice)'),
    (48, 'CS6', 'Network control'), (56, 'CS7', 'Network control (reserved)'),
]


def dscp_to_name(dscp):
    return DSCP_NAMES.get(dscp, f"DSCP-{dscp}")


def format_elapsed(seconds):
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def clamp_delay_ms(delay_ms):
    """Floor a one-way delay estimate at 0 for display purposes.

    A negative reading can't be a real one-way delay - it's measurement
    noise (clock-sync jitter, or the symmetric-path assumption behind the
    4-timestamp exchange not quite holding) around a true delay close to
    zero. We floor it here so the screen doesn't show something
    physically impossible; the raw, unclamped value is still written to
    the CSV log so nothing is lost for later analysis.
    """
    if delay_ms is None:
        return None
    return delay_ms if delay_ms >= 0 else 0.0


# --- Kernel RX timestamping ----------------------------------------------------
# SO_TIMESTAMPNS gives us the packet arrival time as stamped by the kernel
# (CLOCK_REALTIME), instead of calling time.time_ns() in Python after
# recvfrom()/recvmsg() returns. That Python-level call can be delayed by
# scheduler/GIL jitter of a few hundred microseconds to low milliseconds -
# the same order of magnitude as the one-way delays we're trying to
# measure, so it's a real (and avoidable) source of noise. Linux-only;
# other platforms silently fall back to time.time_ns().

_HAS_TIMESTAMPNS = hasattr(socket, 'SO_TIMESTAMPNS')
_TIMESPEC_STRUCT = struct.Struct('ll')  # struct timespec (tv_sec, tv_nsec)


def _extract_kernel_rx_ns(ancdata):
    """Extract a kernel RX timestamp (CLOCK_REALTIME, ns) from SO_TIMESTAMPNS
    ancillary data. Returns None if absent."""
    if not ancdata:
        return None
    for level, type_, data in ancdata:
        if level == socket.SOL_SOCKET and type_ == socket.SO_TIMESTAMPNS:
            sec, nsec = _TIMESPEC_STRUCT.unpack_from(data, 0)
            return sec * 1_000_000_000 + nsec
    return None


# --- OWD sync wire protocol (binary, fixed-size) --------------------------
# Replaces the earlier JSON messages. Each message starts with a 1-byte
# type tag so a malformed/foreign UDP packet on this port is rejected on
# size+tag mismatch rather than raising a decode error somewhere downstream.
# Used by both the sync server and the sync client below - keep them in step.

_SYNC_MSG_REQ = 0x01
_SYNC_MSG_RSP = 0x02

_SYNC_REQ_STRUCT = struct.Struct('!BQ')     # type(1) + t1_ns(8)              =  9 bytes
_SYNC_RSP_STRUCT = struct.Struct('!BQQQ')   # type(1) + t1_ns/t2_ns/t3_ns(8*3) = 25 bytes
_SYNC_RECV_BUFSIZE = 64  # generous margin over the 25-byte response


# --- OWD Time Sync Server (runs in every mode) -------------------------------

OWD_SYNC_PORT = 5556


class OWDSyncServer:
    """Embedded OWD time sync server — runs as daemon thread in every mode.

    Responds to 4-timestamp timing requests from receivers.
    Uses time.time_ns() (CLOCK_REALTIME) for cross-host compatibility.
    Supports stop/restart for port changes at runtime.
    """

    def __init__(self, port=OWD_SYNC_PORT, bind_addr='0.0.0.0'):
        self.port = port
        self.bind_addr = bind_addr
        self._running = False
        self._thread = None
        self._client_count = 0
        self._lock = threading.Lock()
        self._ready = threading.Event()

    def start(self):
        """Start sync server as daemon thread. Blocks briefly until socket is bound."""
        self._ready.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=2.0)

    def restart(self, new_port):
        """Stop current server and restart on new port."""
        self.stop()
        if self._thread:
            self._thread.join(timeout=2.0)
        self.port = new_port
        self.start()

    def _run(self):
        """Main server loop."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)

        if _HAS_TIMESTAMPNS:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_TIMESTAMPNS, 1)
            except OSError:
                pass

        try:
            sock.bind((self.bind_addr, self.port))
        except OSError as e:
            print(f"{Colors.RED}✗ OWD sync server bind error on port {self.port}: {e}{Colors.ENDC}")
            self._ready.set()
            return

        self._running = True
        self._ready.set()
        print(f"{Colors.GREEN}✓ OWD sync server running on port {self.port}{Colors.ENDC}")

        while self._running:
            try:
                if _HAS_TIMESTAMPNS:
                    data, ancdata, _flags, addr = sock.recvmsg(
                        _SYNC_RECV_BUFSIZE, socket.CMSG_SPACE(_TIMESPEC_STRUCT.size)
                    )
                    t2_ns = _extract_kernel_rx_ns(ancdata) or time.time_ns()
                else:
                    data, addr = sock.recvfrom(_SYNC_RECV_BUFSIZE)
                    t2_ns = time.time_ns()
                self._handle_request(sock, data, addr, t2_ns)
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    continue
                break

        sock.close()

    def _handle_request(self, sock, data, addr, t2_ns):
        """Process a single timing request (fixed-size binary protocol)."""
        if len(data) != _SYNC_REQ_STRUCT.size:
            return
        try:
            msg_type, t1_ns = _SYNC_REQ_STRUCT.unpack(data)
        except struct.error:
            return
        if msg_type != _SYNC_MSG_REQ:
            return

        # t3 stamped as close to sendto() as possible - no encode step
        # (json.dumps) sits between the stamp and the actual send anymore
        t3_ns = time.time_ns()
        response = _SYNC_RSP_STRUCT.pack(_SYNC_MSG_RSP, t1_ns, t2_ns, t3_ns)
        sock.sendto(response, addr)

        with self._lock:
            self._client_count += 1

    def stop(self):
        self._running = False

    @property
    def active(self):
        """True while the server socket is bound and serving."""
        return self._running

    @property
    def client_count(self):
        with self._lock:
            return self._client_count


OWD_WARMUP_COUNT = 3
OWD_RESYNC_INTERVAL = 3.0   # re-measure offset every N seconds (was 30s,
                            # then 15s; shorter interval + drift tracking
                            # below keeps the offset estimate tighter
                            # between syncs, at the cost of more sync
                            # traffic - override with --resync-interval)
OWD_INITIAL_SAMPLE_COUNT = 16  # samples for the initial sync (blocking, once)
OWD_RESYNC_SAMPLE_COUNT = 8    # samples per periodic resync (background thread)
OWD_HISTORY_LEN = 8            # sliding window used for the drift-rate estimate
_MAX_DRIFT_US_PER_S = 200.0    # sanity clamp (~200ppm; real crystals drift far less;
                                # guards against a wild slope after e.g. a suspend/resume gap)


class OWDSyncClient:
    """OWD time sync client — measures clock offset to sender via 4-timestamp protocol.

    Uses time.time_ns() (CLOCK_REALTIME) on both sides, backed by kernel
    RX timestamps (SO_TIMESTAMPNS) where available.
    The sender embeds CLOCK_REALTIME timestamps (us) in data packets.
    This client measures the clock offset between sender and receiver,
    allowing accurate one-way delay calculation without a third-party time server.

    Two important limitations of this approach (inherent to any two-way
    exchange without a shared external reference, e.g. GPS/PTP):
      - It assumes the forward and return paths have equal delay. Any
        asymmetry (different queuing, routing, media) biases the offset,
        which can make small real delays appear slightly negative.
      - Between syncs the local clock can drift; we now track and
        extrapolate that drift (see _estimate_drift), but it's still an
        estimate, not a hardware-disciplined clock.
    Neither is "fixable" without an external time reference, but more
    samples, outlier rejection, kernel-level timestamps and drift
    tracking substantially reduce the noise on top of those limits.
    """

    def __init__(self, sender_ip, sync_port=OWD_SYNC_PORT,
                 resync_interval=OWD_RESYNC_INTERVAL):
        self.sender_addr = (sender_ip, sync_port)
        self.resync_interval = resync_interval

        # clock offset in microseconds: sender_time = local_time + offset_us
        self.offset_us = 0.0
        self.rtt_ms = 0.0
        self.synced = False

        # drift tracking: offset is extrapolated between resyncs as
        # offset_us + drift_us_per_s * (now - last_update)
        self._drift_us_per_s = 0.0
        self._last_update_mono = time.monotonic()
        self._history = []  # [(monotonic_time, offset_us), ...] newest last

        self._lock = threading.Lock()
        self._running = False
        self._thread = None

    def initial_sync(self) -> bool:
        """Perform initial sync with warmup. Returns True on success."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        self._enable_rx_timestamping(sock)

        try:
            # warmup: prime ARP, conntrack, buffers. If not a single
            # warmup exchange gets an answer the sync server is
            # unreachable (firewall / wrong port) - give up early instead
            # of waiting out all the measurement timeouts.
            warmup_ok = 0
            for _ in range(OWD_WARMUP_COUNT):
                if self._measure_once(sock) is not None:
                    warmup_ok += 1
                time.sleep(0.05)
            if warmup_ok == 0:
                return False

            # actual measurement: sample many, then apply the clock filter
            results = []
            for _ in range(OWD_INITIAL_SAMPLE_COUNT):
                r = self._measure_once(sock)
                if r is not None:
                    results.append(r)
                time.sleep(0.05)

            best = self._select_best(results)
            if best is None:
                return False

            self._apply_measurement(*best)
            return True

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}⊘ Sync cancelled{Colors.ENDC}")
            return False
        except Exception as e:
            print(f"{Colors.YELLOW}⚠ OWD sync error: {e}{Colors.ENDC}")
            return False
        finally:
            sock.close()

    def start_background_resync(self):
        """Start background thread for periodic offset re-measurement."""
        self._running = True
        self._thread = threading.Thread(target=self._resync_loop, daemon=True)
        self._thread.start()

    def _resync_loop(self):
        """Periodically re-measure clock offset to track drift."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        self._enable_rx_timestamping(sock)

        while self._running:
            time.sleep(self.resync_interval)
            try:
                results = []
                for _ in range(OWD_RESYNC_SAMPLE_COUNT):
                    r = self._measure_once(sock)
                    if r is not None:
                        results.append(r)
                    time.sleep(0.05)

                best = self._select_best(results)
                if best is not None:
                    self._apply_measurement(*best)
            except OSError:
                pass

        sock.close()

    @staticmethod
    def _enable_rx_timestamping(sock):
        if _HAS_TIMESTAMPNS:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_TIMESTAMPNS, 1)
            except OSError:
                pass

    @staticmethod
    def _select_best(results):
        """NTP-style clock filter over a batch of (rtt_ms, offset_us) samples.

        Rejects RTT outliers via a median/MAD filter (a scheduling hiccup
        on either host can spike a single sample's RTT), then returns the
        remaining sample with the lowest RTT - the lowest-RTT sample is
        the one least affected by queuing delay in either direction, so
        it gives the most trustworthy offset estimate.
        """
        if not results:
            return None
        if len(results) < 4:
            return min(results, key=lambda r: r[0])

        rtts = sorted(r[0] for r in results)
        n = len(rtts)
        median = rtts[n // 2] if n % 2 else (rtts[n // 2 - 1] + rtts[n // 2]) / 2.0
        deviations = sorted(abs(r - median) for r in rtts)
        mad = deviations[n // 2] if n % 2 else (deviations[n // 2 - 1] + deviations[n // 2]) / 2.0
        # at least 0.5ms slack so a near-zero MAD (very stable link) doesn't
        # reject every sample outright
        threshold = median + max(3 * mad, 0.5)

        filtered = [r for r in results if r[0] <= threshold]
        if not filtered:
            filtered = results
        return min(filtered, key=lambda r: r[0])

    def _apply_measurement(self, rtt_ms, offset_us):
        """Record a new offset measurement and update the drift estimate."""
        now = time.monotonic()
        with self._lock:
            self.rtt_ms = rtt_ms
            self.offset_us = offset_us
            self._last_update_mono = now
            self.synced = True

            self._history.append((now, offset_us))
            if len(self._history) > OWD_HISTORY_LEN:
                self._history.pop(0)

            self._drift_us_per_s = self._estimate_drift()

    def _estimate_drift(self):
        """Least-squares slope of offset-vs-time over recent history.

        Must be called with self._lock held. Returns 0.0 until there's
        enough history to fit a trend, and clamps the result to a
        physically sane range so a fluke (e.g. a resync after the process
        was suspended for a while) can't produce a wild extrapolation.
        """
        pts = self._history
        n = len(pts)
        if n < 3:
            return 0.0

        t0 = pts[0][0]
        xs = [p[0] - t0 for p in pts]
        ys = [p[1] for p in pts]
        mean_x = sum(xs) / n
        mean_y = sum(ys) / n
        denom = sum((x - mean_x) ** 2 for x in xs)
        if denom == 0:
            return 0.0
        slope = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys)) / denom
        return max(-_MAX_DRIFT_US_PER_S, min(_MAX_DRIFT_US_PER_S, slope))

    def _current_offset_us(self):
        """Must be called with self._lock held. Extrapolates the last
        measured offset forward using the tracked drift rate, instead of
        holding it flat until the next resync."""
        elapsed = time.monotonic() - self._last_update_mono
        return self.offset_us + self._drift_us_per_s * elapsed

    def _measure_once(self, sock) -> Optional[tuple]:
        """Single 4-timestamp measurement (fixed-size binary protocol).

        Returns (rtt_ms, offset_us) or None on failure.
        """
        # stamp T1 as late as possible, right before sending - no encode
        # step (json.dumps) sits between the stamp and the actual send
        t1_ns = time.time_ns()
        request = _SYNC_REQ_STRUCT.pack(_SYNC_MSG_REQ, t1_ns)

        try:
            sock.sendto(request, self.sender_addr)
            if _HAS_TIMESTAMPNS:
                data, ancdata, _flags, _addr = sock.recvmsg(
                    _SYNC_RECV_BUFSIZE, socket.CMSG_SPACE(_TIMESPEC_STRUCT.size)
                )
                t4_ns = _extract_kernel_rx_ns(ancdata) or time.time_ns()
            else:
                data, _addr = sock.recvfrom(_SYNC_RECV_BUFSIZE)
                t4_ns = time.time_ns()
        except (socket.timeout, OSError):
            return None

        if len(data) != _SYNC_RSP_STRUCT.size:
            return None
        try:
            msg_type, resp_t1_ns, t2_ns, t3_ns = _SYNC_RSP_STRUCT.unpack(data)
        except struct.error:
            return None

        if msg_type != _SYNC_MSG_RSP or resp_t1_ns != t1_ns:
            return None

        # RTT = (T4-T1) - (T3-T2)  (total round-trip minus server processing)
        rtt_ns = (t4_ns - t1_ns) - (t3_ns - t2_ns)

        # clock offset theta = ((T2-T1) + (T3-T4)) / 2
        # positive = sender clock is ahead of receiver clock
        offset_ns = ((t2_ns - t1_ns) + (t3_ns - t4_ns)) / 2.0

        rtt_ms = rtt_ns / 1_000_000.0
        offset_us = offset_ns / 1_000.0

        return (rtt_ms, offset_us)

    def get_delay_us(self, sender_timestamp_us: int,
                      local_ts_us: Optional[float] = None) -> Optional[float]:
        """Compute one-way delay in microseconds from sender timestamp.

        Returns None if not synced.

        local_ts_us lets the caller pass a kernel RX timestamp (preferred,
        lower jitter) for the local receive time; if omitted, falls back
        to time.time_ns() at call time.

        Derivation:
          offset theta = ((T2-T1)+(T3-T4))/2 where T1/T4=receiver, T2/T3=sender
          theta > 0 means sender clock is AHEAD of receiver clock
          sender_time = receiver_time + theta
          For a data packet:  receiver_now = sender_stamp - theta + delay
          Therefore:          delay = receiver_now - sender_stamp + theta
        """
        with self._lock:
            if not self.synced:
                return None
            offset = self._current_offset_us()

        if local_ts_us is None:
            local_ts_us = time.time_ns() / 1_000.0
        delay_us = local_ts_us - sender_timestamp_us + offset
        return delay_us

    def stop(self):
        self._running = False




# --- Sender lock-in / sync management (receiver side) ------------------------

SYNC_RETRY_INTERVAL = 5.0   # seconds between failed sync attempts
_LOCK_STALE_S = 10.0        # locked sender silent this long -> accept a new one


class _SyncSlot:
    """OWD sync state of ONE sender (= one stream of the receiver).

    The initial sync takes a few seconds, so it runs in a background
    thread; until it succeeds `client` stays None and delays show n/a.
    """

    def __init__(self, ip, port, resync_interval):
        self.ip = ip
        self.port = port
        self.resync_interval = resync_interval
        self.client = None
        self.failed = False
        self._gen = 0
        self._stopped = False

    @property
    def target(self):
        return f"{self.ip}:{self.port}"

    def status_text(self):
        if self.port == 0:
            return f"sender {self.ip} offers no sync server"
        if self.client:
            return f"active ({self.target})"
        if self.failed:
            return f"FAILED - {self.target} unreachable, retrying"
        return f"syncing with {self.target}..."

    def connect_blocking(self):
        """Initial sync before the receive loop starts (explicit mode)."""
        print(f"{Colors.CYAN}Synchronizing with sender {self.target} "
              f"(resync every {self.resync_interval:g}s)...{Colors.ENDC}")
        client = OWDSyncClient(self.ip, self.port, resync_interval=self.resync_interval)
        if client.initial_sync():
            self._adopt(client)
        else:
            self._warn_unreachable()
            self.start(warned=True)

    def _adopt(self, client):
        print(f"{Colors.GREEN}✓ OWD sync OK with {self.target} — "
              f"RTT: {client.rtt_ms:.2f}ms, offset: {client.offset_us:+.1f}µs{Colors.ENDC}")
        client.start_background_resync()
        self.failed = False
        self.client = client

    def _warn_unreachable(self):
        print(f"{Colors.YELLOW}⚠ OWD sync with {self.target} failed — "
              f"UDP port reachable? (firewall / NAT / --sender-sync-port). "
              f"Retrying every {SYNC_RETRY_INTERVAL:.0f}s; delay shown as n/a "
              f"until it works{Colors.ENDC}")

    def start(self, warned=False):
        """(Re)start the background sync."""
        self._gen += 1
        gen = self._gen
        old, self.client = self.client, None
        self.failed = False
        if old:
            old.stop()
        threading.Thread(target=self._connect_loop, args=(gen, warned),
                         daemon=True).start()

    def _connect_loop(self, gen, warned=False):
        while gen == self._gen and not self._stopped:
            client = OWDSyncClient(self.ip, self.port, resync_interval=self.resync_interval)
            ok = client.initial_sync()
            if gen != self._gen or self._stopped:
                return
            if ok:
                self._adopt(client)
                return
            self.failed = True
            if not warned:
                warned = True
                self._warn_unreachable()
            waited = 0.0
            while waited < SYNC_RETRY_INTERVAL and gen == self._gen and not self._stopped:
                time.sleep(0.2)
                waited += 0.2

    def stop(self):
        self._stopped = True
        self._gen += 1
        if self.client:
            self.client.stop()


class SyncController:
    """Decides which sender a stream of the receiver is synchronized with.

    mode 'explicit': sender IP given on the command line / menu; its
                     streams get delay values (a stream from another IP
                     only if no stream matched yet - NAT / multi-homed
                     sender).
    mode 'auto':     every detected stream (source IP + sync port from the
                     payload) gets its own sync slot.
    mode 'off':      no sync, no delay values.
    """

    def __init__(self, mode, sender_ip=None, sync_port=0,
                 resync_interval=OWD_RESYNC_INTERVAL):
        self.mode = mode
        self.resync_interval = resync_interval
        self.override_port = sync_port      # 0 = take it from the packets
        self.slots = {}                     # (ip, sync_port) -> _SyncSlot
        self._stopped = False
        self._explicit = None
        self._explicit_used = False
        if mode == 'explicit':
            self._explicit = _SyncSlot(sender_ip, sync_port or OWD_SYNC_PORT,
                                       resync_interval)

    # -- status (banner) --------------------------------------------------
    def status_text(self):
        if self.mode == 'off':
            return "off (no delay values)"
        if self.mode == 'explicit':
            return self._explicit.status_text()
        return "auto - one sync per detected sender"

    # -- explicit mode ----------------------------------------------------
    def connect_blocking(self):
        if self._explicit:
            self._explicit.connect_blocking()

    # -- called once per new stream --------------------------------------
    def slot_for(self, src_ip, sync_port):
        """Returns the _SyncSlot for a new stream (None = no delay values)."""
        if self.mode == 'off':
            return None
        if self.mode == 'explicit':
            if src_ip == self._explicit.ip or not self._explicit_used:
                self._explicit_used = True
                return self._explicit
            return None

        key = (src_ip, sync_port)
        if key in self.slots:
            return self.slots[key]
        port = self.override_port or sync_port
        slot = _SyncSlot(src_ip, port, self.resync_interval)
        self.slots[key] = slot
        if port:
            slot.start()
        return slot

    def reset_assignment(self):
        """After a live-view reset the explicit slot may be handed out again."""
        self._explicit_used = False

    def stop(self):
        self._stopped = True
        for slot in list(self.slots.values()) + ([self._explicit] if self._explicit else []):
            slot.stop()



# --- Packet format ------------------------------------------------------------

# Data packet layout:
#   [0:4]   sequence      uint32 BE
#   [4:12]  timestamp     uint64 BE, microseconds, CLOCK_REALTIME
#   [12:16] magic         b"MAUT"
#   [16]    format ver.   1
#   [17:19] sync port     uint16 BE, port of the sender's OWD sync server
#                         (0 = sender runs no sync server)
#   [19:-4] padding       readable preamble (if it fits) + 0x2A fill
#   [-4:]   CRC32         uint32 BE over everything before it
_HDR_STRUCT = struct.Struct('!IQ')   # seq(4) + timestamp(8) = 12 bytes
_CRC_STRUCT = struct.Struct('!I')    # crc32(4)
_PORT_STRUCT = struct.Struct('!H')   # sync port(2)
_MAGIC = b'MAUT'
_FORMAT_VERSION = 1
_MAGIC_OFFSET = _HDR_STRUCT.size                 # 12
_VERSION_OFFSET = _MAGIC_OFFSET + len(_MAGIC)    # 16
_PORT_OFFSET = _VERSION_OFFSET + 1               # 17
_PAD_OFFSET = _PORT_OFFSET + _PORT_STRUCT.size   # 19
_HEADER_SIZE = _PAD_OFFSET + _CRC_STRUCT.size    # 23 (incl. CRC)
_PREAMBLE = b'mautg_trafficgen_www.jeitler.cc:'
_FILL_BYTE = 0x2A  # decimal 42


@functools.lru_cache(maxsize=64)
def _expected_padding(n):
    """Padding bytes for a packet with n padding bytes: the readable
    preamble if it fits, then the fill byte."""
    if n >= len(_PREAMBLE):
        return _PREAMBLE + bytes([_FILL_BYTE]) * (n - len(_PREAMBLE))
    return bytes([_FILL_BYTE]) * n


def _verify_packet(packet):
    """Full check of a received packet: CRC32 and padding pattern.
    Used on sender lock-in and with --verify (a plain magic check is
    enough for the normal per-packet path)."""
    if len(packet) < _HEADER_SIZE:
        return False
    stored_crc = _CRC_STRUCT.unpack_from(packet, len(packet) - 4)[0]
    if zlib.crc32(memoryview(packet)[:-4]) & 0xFFFFFFFF != stored_crc:
        return False
    return packet[_PAD_OFFSET:-4] == _expected_padding(len(packet) - _HEADER_SIZE)

# UDP/IP header overhead: 20 bytes IP + 8 bytes UDP = 28 bytes
# User enters wire size (e.g. 1500), we subtract this for UDP payload
_UDP_IP_OVERHEAD = 28

_MIN_PACKET_SIZE = _HEADER_SIZE  # 23 bytes


class PacketInfo(NamedTuple):
    """Parsed packet data."""
    seq: int
    delay_ms: Optional[float]  # None if sync unavailable
    packet_size: int
    dscp: int
    stream: object = None   # Stream the packet belongs to
    ts_us: int = 0          # sender timestamp (µs)
    cast: str = ''          # MC / UC / BC (destination address type), '' = unknown


def _grow_rcvbuf(sock):
    """Larger receive buffer: the default (about 200 KB on Linux) holds only a
    few hundred packets, i.e. a few ms at 80k pps - a scheduling hiccup or a
    redraw of the live view would already drop packets.  The kernel caps the
    value (Linux: net.core.rmem_max, macOS: kern.ipc.maxsockbuf); a refused
    size falls back to the next smaller one.  Root on Linux can exceed the cap
    (SO_RCVBUFFORCE).  Returns the size the kernel really granted (bytes)."""
    force = getattr(socket, 'SO_RCVBUFFORCE', 33) if sys.platform.startswith('linux') else None
    for size in (8 << 20, 4 << 20, 2 << 20, 1 << 20):
        try:
            if force is not None and os.geteuid() == 0:
                sock.setsockopt(socket.SOL_SOCKET, force, size)
            else:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, size)
            break
        except OSError:
            continue
    try:
        return sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    except OSError:
        return 0


RCVBUF_GOOD = 4 << 20          # below this a hint is shown after receiver drops


def _rcvbuf_hint(size):
    """How to get a bigger receive buffer ('' if it is big enough)."""
    if size >= RCVBUF_GOOD or size <= 0:
        return ''
    kb = size // 1024
    if sys.platform.startswith('linux'):
        return (f"receive buffer is only {kb} KB (net.core.rmem_max) - raise it once with: "
                f"sudo sysctl -w net.core.rmem_max=16777216  (permanent: put "
                f"net.core.rmem_max=16777216 into /etc/sysctl.d/99-mautg.conf), then restart "
                f"the receiver; or run it as root")
    return (f"receive buffer is only {kb} KB - raise it with: "
            f"sudo sysctl -w kern.ipc.maxsockbuf=8388608")


_RX_HDR = _HDR_STRUCT.unpack_from      # per-packet parsing (receiver fast path)
_RX_PORT = _PORT_STRUCT.unpack_from


# --- Statistics ---------------------------------------------------------------

class RunningStats:
    """O(1) running statistics — no unbounded list growth."""
    __slots__ = ('count', 'total', 'min_val', 'max_val')

    def __init__(self):
        self.count = 0
        self.total = 0.0
        self.min_val = float('inf')
        self.max_val = float('-inf')

    def add(self, value):
        self.count += 1
        self.total += value
        if value < self.min_val:
            self.min_val = value
        if value > self.max_val:
            self.max_val = value

    @property
    def avg(self):
        return self.total / self.count if self.count else 0.0

    @property
    def minimum(self):
        return self.min_val if self.count else 0.0

    @property
    def maximum(self):
        return self.max_val if self.count else 0.0


class DscpStats:
    """Per-DSCP running statistics."""
    __slots__ = ('packets', 'delays', 'loss')

    def __init__(self):
        self.packets = 0
        self.delays = RunningStats()
        self.loss = 0


# --- Receiver -----------------------------------------------------------------

MAX_PORTS = 512


def parse_ports(spec):
    """'5005' / 5005 / '5005-5010' / '5005,5007,6000-6003' -> sorted list of ports.
    Raises ValueError with a readable message."""
    if isinstance(spec, int):
        spec = str(spec)
    ports = set()
    for part in str(spec).replace(' ', '').split(','):
        if not part:
            continue
        lo_s, sep, hi_s = part.partition('-')
        try:
            lo = int(lo_s)
            hi = int(hi_s) if sep else lo
        except ValueError:
            raise ValueError(f"'{part}' is not a port or port range")
        if not (1 <= lo <= 65535 and 1 <= hi <= 65535):
            raise ValueError(f"port out of range 1-65535: {part}")
        if hi < lo:
            raise ValueError(f"empty range: {part}")
        ports.update(range(lo, hi + 1))
        if len(ports) > MAX_PORTS:
            raise ValueError(f"too many ports (max {MAX_PORTS})")
    if not ports:
        raise ValueError("no port given")
    return sorted(ports)


MAX_GROUPS = 16          # stays below the Linux default of 20 memberships per socket


def _ip_to_int(text):
    try:
        return struct.unpack('!I', socket.inet_aton(text))[0] if text.count('.') == 3 else None
    except OSError:
        return None


def parse_groups(spec):
    """'239.1.1.1' / '239.1.1.1,239.1.1.10' / '239.1.1.1-239.1.1.10' /
    '239.1.1.1-10' (short: only the last octet of the end) / combinations ->
    sorted list of IPv4 strings. Raises ValueError with a readable message."""
    groups = set()
    for part in str(spec).replace(' ', '').split(','):
        if not part:
            continue
        lo_s, sep, hi_s = part.partition('-')
        lo = _ip_to_int(lo_s)
        if lo is None:
            raise ValueError(f"'{lo_s}' is not an IPv4 address")
        hi = lo
        if sep:
            if '.' in hi_s:
                hi = _ip_to_int(hi_s)
                if hi is None:
                    raise ValueError(f"'{hi_s}' is not an IPv4 address")
            elif hi_s.isdigit() and int(hi_s) <= 255:
                hi = (lo & 0xFFFFFF00) | int(hi_s)
            else:
                raise ValueError(f"'{hi_s}' is neither an address nor a last octet (0-255)")
            if hi < lo:
                raise ValueError(f"empty range: {part}")
        if hi - lo + 1 + len(groups) > MAX_GROUPS:
            raise ValueError(f"too many groups (max {MAX_GROUPS})")
        groups.update(range(lo, hi + 1))
    if not groups:
        raise ValueError("no group given")
    return [socket.inet_ntoa(struct.pack('!I', g)) for g in sorted(groups)]


def format_groups(groups):
    """['239.1.1.1', '239.1.1.2', '239.1.1.3', '239.1.1.9'] -> '239.1.1.1-3,239.1.1.9'."""
    nums = [_ip_to_int(g) for g in groups]
    out, i = [], 0
    while i < len(nums):
        j = i
        while j + 1 < len(nums) and nums[j + 1] == nums[j] + 1:
            j += 1
        if j == i:
            out.append(groups[i])
        elif nums[i] >> 8 == nums[j] >> 8:
            out.append(f"{groups[i]}-{nums[j] & 255}")
        else:
            out.append(f"{groups[i]}-{groups[j]}")
        i = j + 1
    return ','.join(out)


def format_ports(ports):
    """[5005, 5006, 5007, 6000] -> '5005-5007,6000'."""
    out, i = [], 0
    while i < len(ports):
        j = i
        while j + 1 < len(ports) and ports[j + 1] == ports[j] + 1:
            j += 1
        out.append(str(ports[i]) if j == i else f"{ports[i]}-{ports[j]}")
        i = j + 1
    return ','.join(out)


_STREAM_LABELS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'


class Stream:
    """State of ONE detected sender stream (source IP + advertised sync port).

    Every stream has its own sequence tracker, statistics and OWD sync, so
    several senders (or the same sender reaching us over two interfaces)
    never get mixed up.
    """

    # Sender restart detection: if seq drops by more than this threshold
    # relative to last_seq, treat it as a sender restart, not misorder.
    _RESTART_THRESHOLD = 10

    def __init__(self, label, ip, sync_port, sync, port=0, show_port=False):
        self.label = label
        self.ip = ip
        self.sync_port = sync_port
        self.port = port                  # local destination port
        self.show_port = show_port
        self.sync = sync                  # _SyncSlot or None
        self.first_time = time.monotonic()

        # lifetime totals
        self.total_packets = 0
        self.total_bytes = 0
        self.delay_stats = RunningStats()
        self.dscp_stats = defaultdict(DscpStats)
        self.last_dscp = 0                # DSCP of the most recent packet
        self.cast = ''                    # MC / UC / BC of the most recent packet

        # interval counters (reset after each summary)
        self.iv_packets = 0
        self.iv_bytes = 0
        self.iv_delay = RunningStats()
        self.iv_missing = 0
        self.iv_misorder = 0
        self.iv_dscp_stats = defaultdict(DscpStats)

        # sequence tracking
        self.expected_seq = None
        self.last_seq = -1
        self.total_missing = 0
        self.total_misorder = 0
        self.restart_from = None          # last_seq before the latest restart
        self.restarts = 0

        # copies of the same packets seen on another stream (two interfaces)
        self.dup_count = 0
        self.dup_of = None                # label of the stream seen first
        self.dup_delta = RunningStats()   # arrival time vs. the first copy (ms)

    @property
    def title(self):
        t = f"{self.ip} (sync port {self.sync_port})" if self.sync_port else self.ip
        return t + (f" -> port {self.port}" if self.show_port else "")

    def loss_pct(self):
        total_expected = self.total_packets + self.total_missing
        if total_expected <= 0:
            return 0.0
        return (self.total_missing / total_expected) * 100

    def check_order(self, seq):
        """Check sequence order. Returns (status, gap).

        gap = number of missing packets for LOSS status, else 0.
        Detects sender restart:
          1) seq == 0 always indicates a fresh sender start
          2) seq drops by more than _RESTART_THRESHOLD
        On RESTART `restart_from` holds the previous sequence number.
        """
        if self.expected_seq is None:
            self.expected_seq = seq

        gap = 0
        is_restart = False

        if seq == 0 and self.last_seq > 0:
            is_restart = True
        elif seq < self.last_seq and (self.last_seq - seq) > self._RESTART_THRESHOLD:
            is_restart = True

        if is_restart:
            self.restart_from = self.last_seq
            self.restarts += 1
            self.expected_seq = seq
            self.last_seq = -1
            status = 'RESTART'
        elif seq < self.last_seq:
            self.total_misorder += 1
            status = 'MISORDER'
        elif seq > self.expected_seq:
            gap = seq - self.expected_seq
            self.total_missing += gap
            status = 'LOSS'
        else:
            status = 'OK'

        if seq >= self.expected_seq:
            self.expected_seq = seq + 1
        self.last_seq = max(self.last_seq, seq)

        return status, gap


class PacketReceiver:
    MAX_STREAMS = len(_STREAM_LABELS)   # more distinct senders are counted, not tracked
    _DUP_WINDOW = 4096       # packets remembered for duplicate detection

    def __init__(self, group, port, interface=None, log_file=None,
                 summary_interval=None, sync=None, unicast_mode=False,
                 summary_compact=False, verify_all=False, show_ip=False,
                 live=None, print_limit=PKT_LINE_LIMIT):
        self.live = live          # LiveView or None
        self.show_ip = show_ip
        self.groups = parse_groups(group) if group else []
        self.group = format_groups(self.groups) if self.groups else group
        self.ports = parse_ports(port)
        self.port = self.ports[0]
        self.port_col = len(self.ports) > 1
        self.interface = interface or 'all'
        self.log_file = log_file
        self.summary_interval = summary_interval
        self.summary_last = summary_interval or 2   # restored by "d" in the live view
        self.summary_compact = summary_compact
        self.sync = sync or SyncController('off')
        self.verify_all = verify_all
        self.unicast_mode = unicast_mode

        # packets that were not ours / not evaluated
        self.foreign_packets = 0      # no mautg magic (or too short)
        self.corrupt_packets = 0      # magic ok but CRC/padding wrong
        self.other_sender_packets = 0  # valid, but beyond MAX_STREAMS
        self._warned_foreign = False
        self._warned_cap = False

        self.own_ip = self._get_own_ip() if unicast_mode else None

        # per-packet display limit (token bucket); counting is never limited
        self.print_limit = max(0, int(print_limit or 0))
        self._tok = 0.0
        self._tok_cap = max(20.0, self.print_limit / 10.0)
        self._tok_t = time.monotonic()
        self.skipped_lines = 0
        self._skip_seen = 0
        self._skip_at = 0.0
        self._warned_limit = False
        # receiver overload: kernel queue drops (Linux) / never caught up
        self.kdrops = {}              # port -> running drop counter of that socket
        self._kd_seen = 0
        self._kd_at = 0.0             # when drops were last seen
        self._kd_recent = 0           # drops since the last report
        self.kdrops_total_seen = 0
        self.last_empty = time.monotonic()   # last time the socket queue was empty
        self.rcvbuf = 0               # smallest receive buffer the kernel granted (bytes)
        self._hinted = False

        # multicast join: on which interface(s) (see resolve_mcast_interfaces)
        self.mc_ifaces = ([(None, '')] if (unicast_mode or not self.groups)
                          else resolve_mcast_interfaces(self.interface))
        self.mc_desc = describe_mcast_interfaces(self.interface, self.mc_ifaces)
        self._join_problems = set()

        # streams: (source ip, sync port) -> Stream
        self.streams = {}
        self.multi = False            # True once a 2nd stream shows up
        self._recent = OrderedDict()  # duplicate detection (multi only)

        # timing
        self.iv_start_time = time.monotonic()
        self.start_time = self.iv_start_time
        self.last_summary_time = self.start_time

        # CSV
        self.csv_file = None
        self.csv_writer = None
        if log_file:
            self.csv_file = open(log_file, 'w', newline='', buffering=8192)
            self.csv_writer = csv.writer(self.csv_file)
            self.csv_writer.writerow([
                'Timestamp', 'Seq', 'Delay_ms', 'DSCP', 'DSCP_Name', 'Status',
                'Stream', 'Source_IP', 'Sync_Port', 'Port', 'Cast'
            ])

        try:
            self._setup_sockets()
        except OSError:
            if self.csv_file:
                self.csv_file.close()
            raise
        if self.live:
            self.live.rx = self
            for sk in self.socks:
                sk.settimeout(0.2)

    @staticmethod
    def _get_own_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except OSError:
            return "127.0.0.1"

    def _setup_sockets(self):
        """One UDP socket per port; ports that cannot be opened are reported
        and skipped as long as at least one works."""
        self.socks = {}
        failed = []
        first_err = None
        for port in self.ports:
            try:
                self.socks[self._setup_socket(port)] = port
            except OSError as e:
                failed.append(port)
                first_err = first_err or e
        if not self.socks:
            raise OSError(f"cannot open port {format_ports(self.ports)}: {first_err}")
        if failed:
            self.ports = [p for p in self.ports if p not in failed]
            self.port = self.ports[0]
            self.port_col = len(self.ports) > 1
            print(f"{Colors.YELLOW}⚠ Could not open port(s) {format_ports(failed)}: "
                  f"{first_err} - continuing with {format_ports(self.ports)}{Colors.ENDC}")
        self.sock = next(iter(self.socks))   # first socket (single-port fast path)


    def _setup_socket(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # SO_REUSEPORT allows multiple processes to bind to the same port.
        # Required on macOS/BSD; on Linux it enables kernel load-balancing.
        if hasattr(socket, 'SO_REUSEPORT'):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass

        if hasattr(socket, 'IP_RECVTOS'):
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTOS, 1)
            except OSError:
                pass
        # macOS: also try the raw numeric value (27) in case not exported
        if _IP_RECVTOS != getattr(socket, 'IP_RECVTOS', None):
            try:
                sock.setsockopt(socket.IPPROTO_IP, _IP_RECVTOS, 1)
            except OSError:
                pass

        if _HAS_TIMESTAMPNS:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_TIMESTAMPNS, 1)
            except OSError:
                pass

        if _DST_OPT is not None:
            try:
                sock.setsockopt(socket.IPPROTO_IP, _DST_OPT, 1)
            except OSError:
                pass
        if _SO_RXQ_OVFL is not None:
            try:
                sock.setsockopt(socket.SOL_SOCKET, _SO_RXQ_OVFL, 1)
            except OSError:
                pass

        if self.unicast_mode:
            sock.bind((self.own_ip, port))
        else:
            sock.bind(('', port))
            self._join_multicast(sock)

        got = _grow_rcvbuf(sock)
        self.rcvbuf = min(self.rcvbuf, got) if self.rcvbuf else got
        sock.settimeout(1.0)
        return sock

    def _join_multicast(self, sock):
        """Join all groups (at most MAX_GROUPS) on every selected interface.
        With 'all', an interface that cannot join (down, no multicast, kernel
        limit of 20 memberships per socket) is skipped and reported; with a
        single chosen interface (or 'auto') any error is fatal."""
        lenient = self.interface.lower() == 'all' and len(self.mc_ifaces) > 1
        joined, last_err = 0, None
        for ip, _name in self.mc_ifaces:
            iface = socket.inet_aton(ip) if ip else None
            for g in self.groups:
                gi = _ip_to_int(g)
                if gi is None or not (0xE0000000 <= gi <= 0xEFFFFFFF):
                    joined += 1
                    continue                  # not multicast: nothing to join
                gb = socket.inet_aton(g)
                mreq = (struct.pack('4s4s', gb, iface) if iface
                        else struct.pack('4sL', gb, socket.INADDR_ANY))
                try:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                    joined += 1
                except OSError as e:
                    if e.errno == errno.EADDRINUSE:   # already a member
                        joined += 1
                    elif lenient:
                        last_err = e
                        self._join_problems.add(f"{g} on {ip}: {e.strerror or e}")
                    else:
                        raise
        if not joined and last_err is not None:
            raise last_err

    @staticmethod
    def _classify_dest(raw):
        """MC / UC / BC for a destination address (4 raw bytes), cached."""
        cast = _CAST_CACHE.get(raw)
        if cast is None:
            if 224 <= raw[0] <= 239:
                cast = 'MC'
            elif raw == b'\xff\xff\xff\xff':
                cast = 'BC'
            elif raw[3] == 255 and socket.inet_ntoa(raw) not in dict(local_ipv4_addresses()):
                cast = 'BC'              # directed broadcast (x.y.z.255)
            else:
                cast = 'UC'
            _CAST_CACHE[raw] = cast
        return cast

    def _extract_ancillary(self, ancillary):
        """Pull DSCP, the kernel RX timestamp and the destination type out of
        one recvmsg() ancillary-data list. Returns (dscp, rx_ns, cast, ovfl) -
        rx_ns is None if SO_TIMESTAMPNS isn't available/enabled, cast is ''
        if the destination address is not reported (Windows), ovfl is the
        kernel's running count of datagrams dropped on this socket (Linux)."""
        dscp = 0
        rx_ns = None
        cast = ''
        ovfl = None
        for level, type_, data in ancillary:
            if level == socket.IPPROTO_IP:
                if type_ in (socket.IP_TOS, _IP_RECVTOS):
                    tos = data[0] if isinstance(data, bytes) else data
                    dscp = (tos >> 2) & 0x3F
                elif type_ == _DST_OPT:
                    cast = self._classify_dest(bytes(data[_DST_OFFSET:_DST_OFFSET + 4]))
            elif _HAS_TIMESTAMPNS and level == socket.SOL_SOCKET and type_ == socket.SO_TIMESTAMPNS:
                sec, nsec = _TIMESPEC_STRUCT.unpack_from(data, 0)
                rx_ns = sec * 1_000_000_000 + nsec
            elif level == socket.SOL_SOCKET and type_ == _SO_RXQ_OVFL:
                ovfl = int.from_bytes(data[:4], sys.byteorder)
        return dscp, rx_ns, cast, ovfl

    # -- streams -----------------------------------------------------------
    def _stream_for(self, src_ip, sync_port, packet, port=0):
        """Stream of a packet; a new one is created after a full check
        (CRC + padding). None if the packet cannot be assigned."""
        key = (src_ip, sync_port, port)
        stream = self.streams.get(key)
        if stream is not None:
            return stream

        if not _verify_packet(packet):
            self.corrupt_packets += 1
            return None
        if len(self.streams) >= self.MAX_STREAMS:
            self.other_sender_packets += 1
            if not self._warned_cap:
                self._warned_cap = True
                print(f"{Colors.YELLOW}⚠ More than {self.MAX_STREAMS} streams — "
                      f"further senders are only counted{Colors.ENDC}")
            return None

        label = _STREAM_LABELS[len(self.streams)]
        sync_port_used = self.sync.override_port or sync_port
        slot = self.sync.slot_for(src_ip, sync_port)
        stream = Stream(label, src_ip, sync_port, slot, port, self.port_col)
        self.streams[key] = stream
        self._announce_stream(stream, sync_port_used)
        return stream

    def _announce_stream(self, stream, sync_port_used):
        c = Colors
        if len(self.streams) == 1:
            if self.sync.mode == 'auto':
                if sync_port_used:
                    print(f"{c.CYAN}✓ Sender detected: {stream.ip} "
                          f"(sync port {sync_port_used}) — synchronizing, "
                          f"delay values follow after sync...{c.ENDC}")
                else:
                    print(f"{c.YELLOW}⚠ Sender {stream.ip} runs no OWD sync server "
                          f"— delay values not available{c.ENDC}")
            return

        if not self.multi:
            self.multi = True
            first = next(iter(self.streams.values()))
            print(f"{c.CYAN}ⓘ Several streams detected — lines now carry a stream "
                  f"label. Stream {first.label} = {first.title}{c.ENDC}")
        extra = ""
        if self.sync.mode == 'auto':
            if sync_port_used:
                extra = " — synchronizing, delay values follow after sync"
            else:
                extra = " — no OWD sync server, delay not available"
        print(f"{c.CYAN}✓ New stream {stream.label} = {stream.title}{extra}{c.ENDC}")

    def _parse_packet(self, packet, src_ip, dscp=0, rx_ns=None, port=0):
        """Parse packet and compute one-way delay via OWD sync.

        Returns PacketInfo, or None if the packet is not a (valid) mautg
        packet or cannot be assigned to a stream.
        delay_ms is None if sync is unavailable.
        rx_ns, when given, is the kernel-timestamped packet arrival time
        (CLOCK_REALTIME, ns) and is used in place of a fresh
        time.time_ns() call to avoid scheduling jitter.
        """
        # cheap per-packet identity check: magic + format version
        if (len(packet) < _MIN_PACKET_SIZE
                or packet[_MAGIC_OFFSET:_VERSION_OFFSET] != _MAGIC
                or packet[_VERSION_OFFSET] != _FORMAT_VERSION):
            self.foreign_packets += 1
            if not self._warned_foreign:
                self._warned_foreign = True
                print(f"{Colors.YELLOW}⚠ Ignoring non-mautg packet(s) on this port "
                      f"(first from {src_ip}) — count shown in the final statistics"
                      f"{Colors.ENDC}")
            return None

        if self.verify_all and not _verify_packet(packet):
            self.corrupt_packets += 1
            return None

        sync_port = _PORT_STRUCT.unpack_from(packet, _PORT_OFFSET)[0]
        stream = self._stream_for(src_ip, sync_port, packet, port)
        if stream is None:
            return None

        seq, timestamp_us = _HDR_STRUCT.unpack_from(packet, 0)

        delay_ms = None
        slot = stream.sync
        client = slot.client if slot else None
        if client:
            local_ts_us = (rx_ns / 1000.0) if rx_ns is not None else None
            delay_us = client.get_delay_us(timestamp_us, local_ts_us)
            if delay_us is not None:
                delay_ms = delay_us / 1000.0

        return PacketInfo(
            seq=seq,
            delay_ms=delay_ms,
            packet_size=len(packet) + _UDP_IP_OVERHEAD,  # wire size
            dscp=dscp,
            stream=stream,
            ts_us=timestamp_us,
        )

    def _note_duplicate(self, stream, pkt, rx_ns):
        """Same packet (sync port, timestamp, seq) seen on two streams, e.g.
        a multicast stream arriving over Ethernet and WLAN."""
        now_ns = rx_ns if rx_ns is not None else time.time_ns()
        key = (stream.sync_port, stream.port, pkt.ts_us, pkt.seq)
        prev = self._recent.get(key)
        if prev is None:
            self._recent[key] = (stream, now_ns)
            if len(self._recent) > self._DUP_WINDOW:
                self._recent.popitem(last=False)
        elif prev[0] is not stream:
            stream.dup_count += 1
            stream.dup_of = prev[0].label
            stream.dup_delta.add((now_ns - prev[1]) / 1e6)
            del self._recent[key]

    # -- output ------------------------------------------------------------
    def _print_packet_line(self, pkt, status):
        s = pkt.stream
        time_str = datetime.now().strftime('%H:%M:%S')
        if status in ('OK', 'RESTART'):
            sc = Colors.GREEN
        elif status == 'LOSS':
            sc = Colors.YELLOW
        else:
            sc = Colors.RED

        if pkt.delay_ms is not None:
            disp = clamp_delay_ms(pkt.delay_ms)
            # "~" marks a reading that was actually negative (measurement
            # noise / path asymmetry) and got floored to 0 for display
            marker = "~" if pkt.delay_ms < 0 else " "
            delay_str = f"Delay:{marker}{disp:6.2f}ms"
        else:
            delay_str = "Delay:   n/a  "

        if self.live and self._live_level('pkt') == 'narrow':
            # narrow format, only used on small terminals
            who = ((f" {s.label}" if self.multi else "") + (f" {s.ip:<15s}" if self.show_ip else "")
                   + (f" {s.port:>5d}" if self.port_col else "") + f" {pkt.cast or '--':<2s}")
            dl = f"{disp:7.2f}ms" if pkt.delay_ms is not None else "    n/a  "
            mk = "~" if (pkt.delay_ms is not None and pkt.delay_ms < 0) else " "
            print(f"{time_str}{who} Seq:{pkt.seq:6d} {pkt.packet_size:5d}B "
                  f"{dscp_to_name(pkt.dscp):<6s}{mk}Dly:{dl} {sc}{status:<5s}{Colors.ENDC}"
                  f"{s.loss_pct():6.2f}%")
            return
        lab = f" | {s.label}" if self.multi else ""
        if self.show_ip:
            lab += f" | {s.ip:<15s}"
        if self.port_col:
            lab += f" | {s.port:>5d}"
        lab += f" | {pkt.cast or '--':<4s}"
        print(f"{time_str}{lab} | Seq:{pkt.seq:6d} | Size:{pkt.packet_size:5d} "
              f"| DSCP:{dscp_to_name(pkt.dscp):6s}| "
              f"{delay_str} | {sc}{status:5s}{Colors.ENDC} "
              f"| Loss:{s.loss_pct():6.2f}%")

    # -- live view: pick the widest line format that fits the terminal ---------
    def _live_level(self, kind):
        """'full' (original format), 'compact' or 'narrow' for kind 'pkt'/'sum'."""
        avail = self.live._size[0] - 1
        extra = (4 if self.multi else 0) + (18 if self.show_ip else 0) + 7   # 7: Cast column
        extra += (8 if kind == 'pkt' else 8) if self.port_col else 0
        if kind == 'pkt':
            return 'full' if 87 + extra <= avail else 'narrow'
        if not self.summary_compact and 149 + extra <= avail:
            return 'full'
        return 'compact' if 83 + extra <= avail else 'narrow'

    def log_header(self):
        """Column headline for the log region, aligned to the line format
        that is currently in use."""
        multi, ip = self.multi, self.show_ip
        if not self.summary_interval:
            who = (' | ' + 'S') if multi else ''
            who += (' | ' + f"{'Sender-IP':<15s}") if ip else ''
            who += (' | ' + f"{'Port':>5s}") if self.port_col else ''
            if self._live_level('pkt') == 'full':
                who += ' | ' + f"{'Cast':<4s}"
                return (f"{'Time':<8s}{who} | {'Sequence':<10s} | {'Size':<10s} "
                        f"| {'DSCP':<11s}| {'Delay':<15s} | {'State':<5s} | Loss")
            who = (((' ' + 'S') if multi else '') + ((' ' + f"{'Sender-IP':<15s}") if ip else '')
                   + ((' ' + f"{'Port':>5s}") if self.port_col else '') + ' Ty')
            return (f"{'Time':<8s}{who} {'Sequence':<10s} {'Size':<6s} {'DSCP':<7s}"
                    f"{'Delay':<13s} {'State':<5s}{'Loss':>7s}")
        lab = (('S | ' if multi else '') + (f"{'Sender-IP':<15s} | " if ip else '')
               + (f"{'Port':>5s} | " if self.port_col else '') + f"{'Cast':<4s} | ")
        lvl = self._live_level('sum')
        if lvl == 'full':
            return (f"{'Time':<8s} | {lab}{'Interval':>10s} | {'Throughput':>12s} "
                    f"| {'Size':>6s} | {'DSCP':<11s}| {'State':<6s} | {'Packets':<13s} "
                    f"| {'Loss / lost packets':<22s} | Delay avg/min/max (ms)")
        if lvl == 'compact':
            return (f"{lab}{'Interval':>10s} | {'Throughput':>12s} | {'DSCP':<6s}"
                    f"| {'Stat':<4s} | {'Packets':<13s} | {'Lost':<12s} | Dly")
        return (f"{lab}{'Interval':>9s} {'Mbit/s':>7s} {'DSCP':<6s} {'State':<5s} "
                f"{'Packets':>10s} {'Lost':>8s} Delay")

    def _print_summary(self):
        """Interval summary: one line per stream."""
        now = time.monotonic()
        iv_elapsed = now - self.iv_start_time
        total_elapsed = now - self.start_time

        # time range as clean integer seconds
        iv_end = round(total_elapsed)
        iv_start = round(total_elapsed - iv_elapsed)
        if iv_start < 0:
            iv_start = 0
        time_str = datetime.now().strftime('%H:%M:%S')
        # fixed-width range: "   0–2s  " or " 100–102s" — always 10 chars
        range_str = f"{iv_start}–{iv_end}s"
        range_str = f"{range_str:>10s}"

        if not self.streams:
            if self.summary_compact:
                print(f"{range_str} "
                      f"| {Colors.YELLOW}no traffic{Colors.ENDC}")
            else:
                print(f"{time_str} | {range_str} "
                      f"| {Colors.YELLOW}no traffic received{Colors.ENDC}")
        for s in self.streams.values():
            self._print_stream_summary(s, time_str, range_str, iv_elapsed)
        new, saturated = self.health(now)
        if new:
            print(f"{Colors.RED}⚠ receiver overloaded: the local kernel dropped {new} packets "
                  f"in this interval (we were too slow) - this is NOT network loss{Colors.ENDC}")
        elif saturated:
            print(f"{Colors.YELLOW}⚠ receiver at its processing limit (queue never empty) - "
                  f"loss shown may be caused by this host{Colors.ENDC}")
        self.iv_start_time = now

    def _print_stream_summary(self, s, time_str, range_str, iv_elapsed):
        lab = f"{s.label} | " if self.multi else ""
        if self.show_ip:
            lab += f"{s.ip:<15s} | "
        if self.port_col:
            lab += f"{s.port:>5d} | "
        lab += f"{s.cast or '--':<4s} | "

        if s.iv_packets == 0:
            if self.summary_compact:
                print(f"{lab}{range_str} "
                      f"| {Colors.YELLOW}no traffic{Colors.ENDC}")
            else:
                print(f"{time_str} | {lab}{range_str} "
                      f"| {Colors.YELLOW}no traffic received{Colors.ENDC}")
            return

        # throughput
        iv_throughput = (s.iv_bytes * 8) / (iv_elapsed * 1e6) if iv_elapsed > 0 else 0

        # packet size
        pkt_size = s.iv_bytes // s.iv_packets if s.iv_packets > 0 else 0

        # dominant DSCP
        if s.iv_dscp_stats:
            top_dscp = max(s.iv_dscp_stats, key=lambda d: s.iv_dscp_stats[d].packets)
        else:
            top_dscp = 0

        # delay
        if s.iv_delay.count > 0:
            delay_str = (f"Dly(ms): avg:{s.iv_delay.avg:.2f} "
                         f"min:{s.iv_delay.minimum:.2f} "
                         f"max:{s.iv_delay.maximum:.2f}")
        else:
            delay_str = "Dly(ms): n/a"

        # loss
        iv_expected = s.iv_packets + s.iv_missing
        iv_loss_pct = (s.iv_missing / iv_expected * 100) if iv_expected > 0 else 0.0

        # status
        if s.iv_missing > 0:
            status = 'LOSS'
            sc = Colors.YELLOW
        elif s.iv_misorder > 0:
            status = 'MISORD'
            sc = Colors.RED
        else:
            status = 'OK'
            sc = Colors.GREEN

        lvl = (self._live_level('sum') if self.live
               else ('compact' if self.summary_compact else 'full'))
        if lvl == 'narrow':
            dly = f"{s.iv_delay.avg:.2f}" if s.iv_delay.count > 0 else "n/a"
            print(f"{lab}{range_str[1:]} {iv_throughput:6.2f}M "
                  f"{dscp_to_name(top_dscp):<6s} {sc}{status:<5s}{Colors.ENDC} "
                  f"P:{s.iv_packets:8d} L:{s.iv_missing:6d} Dly:{dly}")
        elif lvl == 'compact':
            # compact: no timestamp, no size, short DSCP, short delay
            dly_str = f"Dly:{s.iv_delay.avg:.2f}" if s.iv_delay.count > 0 else "Dly:n/a"
            print(f"{lab}{range_str} "
                  f"| {iv_throughput:7.2f} Mbps "
                  f"| {dscp_to_name(top_dscp):6s}"
                  f"| {sc}{status:4s}{Colors.ENDC} "
                  f"| Pkt:{s.iv_packets:9d} "
                  f"| LPkt:{s.iv_missing:7d} "
                  f"| {dly_str}")
        else:
            print(f"{time_str} | {lab}{range_str} "
                  f"| {iv_throughput:7.2f} Mbps "
                  f"| {pkt_size:5d}B "
                  f"| DSCP:{dscp_to_name(top_dscp):6s}"
                  f"| {sc}{status:6s}{Colors.ENDC} "
                  f"| Pkt:{s.iv_packets:9d} "
                  f"| Loss:{iv_loss_pct:5.2f}% Pkt:{s.iv_missing:6d} "
                  f"| {delay_str}")

        # reset interval counters
        s.iv_packets = 0
        s.iv_bytes = 0
        s.iv_delay = RunningStats()
        s.iv_missing = 0
        s.iv_misorder = 0
        s.iv_dscp_stats = defaultdict(DscpStats)

    def reset_interval(self, now=None):
        """Restart the current summary interval (after changing it)."""
        now = time.monotonic() if now is None else now
        for s in self.streams.values():
            s.iv_packets = 0
            s.iv_bytes = 0
            s.iv_delay = RunningStats()
            s.iv_missing = 0
            s.iv_misorder = 0
            s.iv_dscp_stats = defaultdict(DscpStats)
        self.iv_start_time = now
        self.last_summary_time = now

    def reset(self):
        """Live-view reset: forget all streams and counters, start over.
        OWD sync slots and the CSV file stay as they are."""
        now = time.monotonic()
        self.streams.clear()
        self.multi = False
        self._recent.clear()
        self.foreign_packets = self.corrupt_packets = self.other_sender_packets = 0
        self._warned_foreign = self._warned_cap = False
        self.start_time = now
        self.iv_start_time = now
        self.last_summary_time = now
        self.sync.reset_assignment()

    def _ignored_text(self):
        parts = []
        if self.foreign_packets:
            parts.append(f"{self.foreign_packets} non-mautg")
        if self.corrupt_packets:
            parts.append(f"{self.corrupt_packets} corrupt (CRC/pattern)")
        if self.other_sender_packets:
            parts.append(f"{self.other_sender_packets} from streams beyond the "
                         f"limit of {self.MAX_STREAMS}")
        return ', '.join(parts)

    def _live_stop(self):
        if self.live:
            self.live.stop()

    def _print_final_summary(self):
        elapsed = time.monotonic() - self.start_time
        ignored = self._ignored_text()

        if not self.streams:
            print(f"{Colors.YELLOW}No packets received{Colors.ENDC}")
            if ignored:
                print(f"{Colors.YELLOW}Ignored packets: {ignored}{Colors.ENDC}")
            print()
            return

        for s in self.streams.values():
            self._print_stream_final(s, elapsed)
        self.health()
        if self.kdrops_total_seen:
            print(f"{Colors.RED}⚠ Receiver overload: the local kernel dropped "
                  f"{self.kdrops_total_seen:,} packets because this receiver was too slow "
                  f"(included in the loss above, not network loss){Colors.ENDC}")
        if self.skipped_lines:
            print(f"{Colors.YELLOW}Per-packet display skipped {self.skipped_lines:,} lines "
                  f"(limit {self.print_limit}/s) - all packets were counted{Colors.ENDC}")
        if ignored:
            print(f"{Colors.YELLOW}Ignored packets: {ignored}{Colors.ENDC}\n")

    def _print_stream_final(self, s, elapsed):
        g = Colors.GREEN
        active = time.monotonic() - s.first_time
        throughput = (s.total_bytes * 8) / (active * 1e6) if active > 0 else 0
        ds = s.delay_stats
        title = (f"Final Statistics - Stream {s.label}: {s.title}" if self.multi
                 else f"Final Statistics - port {s.port}" if self.port_col
                 else "Final Statistics")

        print(f"\n{g}╔═════════════════════════════════════════════════════{Colors.ENDC}")
        print(f"{g}║  {title}{Colors.ENDC}")
        print(f"{g}║  Time: {format_elapsed(elapsed)}{Colors.ENDC}")
        print(f"{g}║  Packets: {s.total_packets:,}{Colors.ENDC}")
        print(f"{g}║  Data: {s.total_bytes / 1e6:.1f} MB{Colors.ENDC}")
        print(f"{g}║  Throughput: {throughput:.2f} Mbit/s{Colors.ENDC}")
        if ds.count > 0:
            print(f"{g}║  Delay: {ds.avg:.2f}ms "
                  f"(min:{ds.minimum:.2f}ms max:{ds.maximum:.2f}ms){Colors.ENDC}")
        else:
            print(f"{g}║  Delay: n/a (sync unavailable){Colors.ENDC}")
        print(f"{g}║  Loss: {s.loss_pct():.2f}% "
              f"({s.total_missing} packets){Colors.ENDC}")
        print(f"{g}║  Misorder: {s.total_misorder}{Colors.ENDC}")
        if s.restarts:
            print(f"{Colors.YELLOW}║  Sender restarts: {s.restarts}{Colors.ENDC}")
        if s.dup_count:
            d = s.dup_delta
            print(f"{Colors.YELLOW}║  Copies of stream {s.dup_of}: {s.dup_count:,} "
                  f"(arrival vs. {s.dup_of}: avg {d.avg:+.2f}ms, "
                  f"min {d.minimum:+.2f}ms, max {d.maximum:+.2f}ms){Colors.ENDC}")
        print(f"{g}╚═════════════════════════════════════════════════════{Colors.ENDC}\n")

    def receive_loop(self):
        """Main receive loop."""
        if self.unicast_mode:
            mode_text = f"Unicast only (local IP: {self.own_ip})"
        elif self.group:
            mode_text = f"Multicast {self.group}, Unicast and Broadcast"
        else:
            mode_text = "Unicast + Multicast"

        sync_status = self.sync.status_text()

        if self.live:
            self.live.start()
        else:
            print(f"\n{Colors.GREEN}╔═════════════════════════════════════════════════════{Colors.ENDC}")
            print(f"{Colors.GREEN}║   Receiver active{Colors.ENDC}")
            print(f"{Colors.GREEN}║   Mode: {mode_text:<28}{Colors.ENDC}")
            if not self.unicast_mode and self.groups:
                print(f"{Colors.GREEN}║   Multicast join on: {self.mc_desc}{Colors.ENDC}")
            print(f"{Colors.GREEN}║   Receive buffer: {self.rcvbuf // 1024} KB{Colors.ENDC}")
            for problem in sorted(self._join_problems):
                print(f"{Colors.YELLOW}║   ⚠ join failed: {problem}{Colors.ENDC}")
            if self.port_col:
                print(f"{Colors.GREEN}║   Ports: {format_ports(self.ports)} ({len(self.ports)}){Colors.ENDC}")
            else:
                print(f"{Colors.GREEN}║   Port: {self.port:<33}{Colors.ENDC}")
            print(f"{Colors.GREEN}║   OWD Sync: {sync_status}{Colors.ENDC}")
            if self.verify_all:
                print(f"{Colors.GREEN}║   Verify: CRC + pattern of every packet{Colors.ENDC}")
            if self.summary_interval:
                print(f"{Colors.GREEN}║   Summary every {self.summary_interval}s{Colors.ENDC}")
            else:
                print(f"{Colors.GREEN}║   View: per-packet display{Colors.ENDC}")
            print(f"{Colors.GREEN}║   Stop: CTRL+C{Colors.ENDC}")
            print(f"{Colors.GREEN}╚═════════════════════════════════════════════════════{Colors.ENDC}\n")

        use_recvmsg = hasattr(self.sock, 'recvmsg')
        extract = self._extract_ancillary
        process = self._process
        timeout = 0.2 if self.live else 1.0
        # non-blocking sockets: a socket with a timeout makes Python call
        # poll() before *every* recv (one extra system call per packet, about
        # 30 % of the receive cost).  Waiting is done explicitly, only when
        # the queue is empty.
        for sk in self.socks:
            sk.setblocking(False)
        kdrops = self.kdrops

        try:
            if len(self.socks) == 1:
                # single port: one recvmsg per packet (fastest path)
                sock = self.sock
                recvmsg = sock.recvmsg
                recvfrom = sock.recvfrom
                port = self.port
                while True:
                    try:
                        if use_recvmsg:
                            packet, ancillary, _flags, addr = recvmsg(65535, 256)
                            dscp, rx_ns, cast, ovfl = extract(ancillary)
                            if ovfl is not None:
                                kdrops[port] = ovfl
                        else:
                            packet, addr = recvfrom(65535)
                            dscp, rx_ns, cast = 0, None, ''
                    except (BlockingIOError, socket.timeout):
                        # queue empty: wait for traffic, then tick
                        self.last_empty = time.monotonic()
                        if not select.select([sock], [], [], timeout)[0]:
                            self.last_empty = time.monotonic()   # waited: not saturated
                            self._idle()
                        continue
                    process(packet, addr[0], dscp, rx_ns, port, cast)
            else:
                # port range / list: one socket per port, multiplexed
                sel = selectors.DefaultSelector()
                for sk, prt in self.socks.items():
                    sel.register(sk, selectors.EVENT_READ, prt)
                while True:
                    events = sel.select(timeout)
                    if not events:
                        self.last_empty = time.monotonic()       # waited: not saturated
                        self._idle()
                        continue
                    for key, _mask in events:
                        sk, port = key.fileobj, key.data
                        # drain what is queued (bounded: the other ports must not starve)
                        for _ in range(32):
                            try:
                                if use_recvmsg:
                                    packet, ancillary, _flags, addr = sk.recvmsg(65535, 256)
                                    dscp, rx_ns, cast, ovfl = extract(ancillary)
                                    if ovfl is not None:
                                        kdrops[port] = ovfl
                                else:
                                    packet, addr = sk.recvfrom(65535)
                                    dscp, rx_ns, cast = 0, None, ''
                            except (BlockingIOError, socket.timeout):
                                self.last_empty = time.monotonic()
                                break
                            process(packet, addr[0], dscp, rx_ns, port, cast)

        except KeyboardInterrupt:
            self._live_stop()
            self._print_final_summary()
        except _Terminate:
            self._live_stop()
            self._print_final_summary()
            raise
        finally:
            self._live_stop()
            for sk in self.socks:
                sk.close()
            if self.csv_file:
                self.csv_file.close()
            self.sync.stop()

    def health(self, now=None):
        """Receiver overload check. Returns (drops_since_last_call, saturated):
        packets the local kernel dropped because we were too slow (Linux), and
        whether the receive queue has not been empty for over a second (any OS).
        A packet dropped here shows up as loss, but it is not network loss."""
        now = time.monotonic() if now is None else now
        total = sum(self.kdrops.values())
        new = max(0, total - self._kd_seen)
        self._kd_seen = total
        self.kdrops_total_seen = total
        if new:
            self._kd_at = now
            self._kd_recent += new
            hint = _rcvbuf_hint(self.rcvbuf)
            if hint and not self._hinted:
                self._hinted = True
                print(f"{Colors.YELLOW}⚠ {hint}{Colors.ENDC}")
        return new, (now - self.last_empty > 1.0)

    def health_text(self, now=None):
        """Short warning for the live status bar ('' = all fine)."""
        now = time.monotonic() if now is None else now
        self.health(now)
        parts = []
        if now - self._kd_at < 10.0 and self._kd_recent:
            parts.append(f"RX OVERLOAD: {self.kdrops_total_seen} DROPPED LOCALLY")
        elif now - self.last_empty > 1.0:
            parts.append("RX AT LIMIT")
        if self.skipped_lines and now - self._skip_at < 2.0:
            parts.append(f"DISPLAY LIMITED {self.print_limit}/S")
        return ('  !! ' + ' | '.join(parts)) if parts else ''

    def _idle(self):
        """No packet within the timeout: summaries / live view still tick."""
        now = time.monotonic()
        if (self.summary_interval and not (self.live and self.live.paused)
                and now - self.last_summary_time >= self.summary_interval):
            self._print_summary()
            self.last_summary_time = now
        if self.live:
            self.live.tick(now)

    def _process(self, packet, src_ip, dscp, rx_ns, port, cast=''):
        """Account, log and display one received datagram.

        Fast path (known stream, plain magic check): parsing is done inline
        without building objects - this runs for every packet.  Everything
        else (first packet of a stream, foreign packets, --verify) takes the
        full path through _parse_packet().
        """
        stream = None
        if (not self.verify_all and len(packet) >= _MIN_PACKET_SIZE
                and packet[_MAGIC_OFFSET:_VERSION_OFFSET] == _MAGIC
                and packet[_VERSION_OFFSET] == _FORMAT_VERSION):
            stream = self.streams.get((src_ip, _RX_PORT(packet, _PORT_OFFSET)[0], port))
        if stream is not None:
            seq, ts_us = _RX_HDR(packet, 0)
            delay_ms = None
            slot = stream.sync
            client = slot.client if slot else None
            if client:
                delay_us = client.get_delay_us(
                    ts_us, (rx_ns / 1000.0) if rx_ns is not None else None)
                if delay_us is not None:
                    delay_ms = delay_us / 1000.0
            size = len(packet) + _UDP_IP_OVERHEAD      # wire size
        else:
            pkt = self._parse_packet(packet, src_ip, dscp, rx_ns, port)
            if pkt is None:
                return
            stream, seq, delay_ms, size, dscp, ts_us = (
                pkt.stream, pkt.seq, pkt.delay_ms, pkt.packet_size, pkt.dscp, pkt.ts_us)

        s = stream
        if cast:
            s.cast = cast
        status, gap = s.check_order(seq)
        if status == 'RESTART':
            who = f"stream {s.label}: " if self.multi else ""
            print(f"{Colors.YELLOW}⚠ {who}Sender restart detected "
                  f"(seq {s.restart_from} → {seq}) — "
                  f"resetting sequence tracker{Colors.ENDC}")
        if self.multi:
            self._note_duplicate(s, PacketInfo(seq, delay_ms, size, dscp, s, ts_us, cast), rx_ns)

        # clamped (>=0) delay for on-screen stats/averages; the
        # raw, possibly-negative delay_ms still goes to CSV
        disp_delay = clamp_delay_ms(delay_ms)

        s.total_packets += 1
        s.total_bytes += size
        s.last_dscp = dscp
        ds = s.dscp_stats[dscp]
        ds.packets += 1

        # interval counters
        s.iv_packets += 1
        s.iv_bytes += size
        iv_ds = s.iv_dscp_stats[dscp]
        iv_ds.packets += 1
        if disp_delay is not None:
            s.delay_stats.add(disp_delay)
            ds.delays.add(disp_delay)
            s.iv_delay.add(disp_delay)
            iv_ds.delays.add(disp_delay)
        if status != 'OK':
            if status == 'LOSS':
                ds.loss += gap
                s.iv_missing += gap
                iv_ds.loss += gap
            elif status == 'MISORDER':
                s.iv_misorder += 1
                # late arrival of a previously loss-counted packet
                if s.iv_missing > 0:
                    s.iv_missing -= 1

        # CSV
        if self.csv_writer:
            self.csv_writer.writerow([
                datetime.now().isoformat(),
                seq,
                f"{delay_ms:.3f}" if delay_ms is not None else "",
                dscp,
                dscp_to_name(dscp),
                status,
                s.label,
                s.ip,
                s.sync_port,
                s.port,
                cast,
            ])

        # display
        live = self.live
        now = time.monotonic()
        paused = live is not None and live.paused
        if not self.summary_interval:
            if not paused:
                lim = self.print_limit
                if lim:
                    # token bucket: a terminal cannot draw 50k lines/s, and
                    # trying to makes the receiver itself drop packets
                    tok = min(self._tok + (now - self._tok_t) * lim, self._tok_cap)
                    self._tok_t = now
                    if tok >= 1.0:
                        self._tok = tok - 1.0
                        self._print_packet_line(
                            PacketInfo(seq, delay_ms, size, dscp, s, ts_us, cast), status)
                    else:
                        self._tok = tok
                        self.skipped_lines += 1
                        self._skip_at = now
                        if not self._warned_limit and not live:
                            self._warned_limit = True
                            print(f"{Colors.YELLOW}⚠ per-packet display limited to {lim} lines/s - "
                                  f"all packets are still counted (use -i for summaries, "
                                  f"--print-limit 0 for no limit){Colors.ENDC}")
                else:
                    self._print_packet_line(
                        PacketInfo(seq, delay_ms, size, dscp, s, ts_us, cast), status)
        elif now - self.last_summary_time >= self.summary_interval and not paused:
            self._print_summary()
            self.last_summary_time = now
        if live:
            live.tick(now)


# --- Sender -------------------------------------------------------------------


def _is_broadcast(addr):
    """Check if address is a broadcast address."""
    try:
        octets = socket.inet_aton(addr)
    except OSError:
        return False
    if octets == b'\xff\xff\xff\xff':
        return True
    if octets[-1] == 255:
        return True
    return False


def _create_send_socket(config, warn=None):
    """Create and configure UDP send socket. Non-fatal problems are printed,
    or handed to warn(text) (live view: the screen must not be written to)."""
    def note(text):
        if warn:
            warn(text)
        else:
            print(f"{Colors.YELLOW}⚠ {text}{Colors.ENDC}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Broadcast requires SO_BROADCAST — without it kernel returns EACCES
    if _is_broadcast(config['destination_address']):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    if config['source_address'] or config['source_port']:
        try:
            sock.bind((config['source_address'] or '', config['source_port'] or 0))
        except OSError:
            sock.close()
            raise
    if config['source_address']:
        # also selects the outgoing interface for multicast destinations
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                            socket.inet_aton(config['source_address']))
        except OSError as e:
            note(f"Could not select multicast interface: {e}")

    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, config['ttl'])

    if sys.platform != 'win32' and config['dscp_value']:
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS,
                            config['dscp_value'] << 2)
        except OSError as e:
            note(f"Could not set DSCP: {e}")

    if config.get('df_bit', False):
        if sys.platform == 'linux':
            try:
                # IP_MTU_DISCOVER=10, IP_PMTUDISC_DO=2
                sock.setsockopt(socket.IPPROTO_IP, 10, 2)
            except OSError as e:
                note(f"Could not set DF bit: {e}")
        else:
            note("DF bit not supported on this platform (Linux only)")

    return sock


def _open_send_socket(config, report=None):
    """Send socket, or None (after printing the reason, or handing it to
    report(text)) if it cannot be set up - e.g. a source address that does
    not exist on this host."""
    try:
        return _create_send_socket(config, warn=report)
    except (OSError, OverflowError) as e:
        src = config.get('source_address') or ''
        hint = (f" - source address {src} is not an address of this host"
                if src and getattr(e, 'errno', None) in (errno.EADDRNOTAVAIL, 10049) else '')
        if report:
            report(f"Cannot set up the send socket: {e}{hint}")
        else:
            print(f"{Colors.RED}✗ Cannot set up the send socket: {e}{hint}{Colors.ENDC}\n")
        return None


def _build_packet_buffer(wire_size, sync_port=0):
    """Pre-allocate mutable bytearray for packet construction.

    wire_size is the total IP packet size on the wire (as entered by user).
    UDP payload = wire_size - 28 (IP header 20 + UDP header 8).
    Layout: see "Data packet layout" above. Magic, format version, sync
    port and padding are constant and written once here; only sequence,
    timestamp and CRC change per packet.
    """
    udp_payload = max(wire_size - _UDP_IP_OVERHEAD, _HEADER_SIZE)
    buf = bytearray(udp_payload)
    buf[_MAGIC_OFFSET:_MAGIC_OFFSET + len(_MAGIC)] = _MAGIC
    buf[_VERSION_OFFSET] = _FORMAT_VERSION
    _PORT_STRUCT.pack_into(buf, _PORT_OFFSET, sync_port)
    pad = _expected_padding(udp_payload - _HEADER_SIZE)
    buf[_PAD_OFFSET:_PAD_OFFSET + len(pad)] = pad
    return buf


def _advertised_sync_port(sync_server):
    """Sync port written into every data packet (0 = no sync server)."""
    return sync_server.port if sync_server.active else 0


def _get_timestamp_us():
    """Current wallclock time in microseconds (CLOCK_REALTIME)."""
    return time.time_ns() // 1000


def _pack_and_send(buf, seq, timestamp_us, sock, dest_addr):
    """Pack header + CRC into pre-allocated buffer and send.

    Retries on ENOBUFS (kernel send buffer full) with brief backoff.
    """
    _HDR_STRUCT.pack_into(buf, 0, seq, timestamp_us)
    crc = zlib.crc32(memoryview(buf)[:-_CRC_STRUCT.size]) & 0xFFFFFFFF
    _CRC_STRUCT.pack_into(buf, len(buf) - _CRC_STRUCT.size, crc)
    while True:
        try:
            sock.sendto(buf, dest_addr)
            return
        except OSError as e:
            if e.errno == errno.ENOBUFS:
                time.sleep(0.001)  # 1ms backoff, then retry
                continue
            raise


def _print_banner(config, sync_server, mode_label):
    """Print startup banner."""
    print(f"\n{Colors.GREEN}╔══════════════════════════════════════════════════════{Colors.ENDC}")
    print(f"{Colors.GREEN}║   {mode_label}{Colors.ENDC}")
    print(f"{Colors.GREEN}║   Destination: "
          f"{config['destination_address']}:{config['destination_port']}{Colors.ENDC}")
    if config.get('source_address') or config.get('source_port'):
        print(f"{Colors.GREEN}║   Source: "
              f"{config.get('source_address') or 'any'}:{config.get('source_port') or 'any'}{Colors.ENDC}")
    print(f"{Colors.GREEN}║   Packet size: {config['packet_size']} bytes{Colors.ENDC}")
    if 'BURST' not in mode_label:
        print(f"{Colors.GREEN}║   Rate: "
              f"{config['packets_per_second']:.1f} pps{Colors.ENDC}")
    else:
        bw = config.get('burst_mbps', 0)
        if bw > 0:
            print(f"{Colors.GREEN}║   Bandwidth limit: {bw:.0f} Mbit/s{Colors.ENDC}")
        else:
            print(f"{Colors.GREEN}║   Bandwidth: unlimited{Colors.ENDC}")
    if sync_server.active:
        print(f"{Colors.GREEN}║   OWD Sync: port {sync_server.port} (advertised in packets){Colors.ENDC}")
    else:
        print(f"{Colors.YELLOW}║   OWD Sync: no sync server - receivers get no delay values{Colors.ENDC}")
    if config.get('df_bit', False):
        print(f"{Colors.GREEN}║   DF bit: set{Colors.ENDC}")
    print(f"{Colors.GREEN}║   CTRL+C to stop{Colors.ENDC}")
    print(f"{Colors.GREEN}╚══════════════════════════════════════════════════════{Colors.ENDC}\n")


def send_packets(config, sync_server):
    """Send packets with precise timing using perf_counter."""
    sock = _open_send_socket(config)
    if sock is None:
        return
    dest_addr = (config['destination_address'], config['destination_port'])
    buf = _build_packet_buffer(config['packet_size'], _advertised_sync_port(sync_server))

    _print_banner(config, sync_server, 'Sender active')

    pps = config['packets_per_second']
    packet_interval = 1.0 / pps
    use_sleep = pps <= 1000
    seq = 0
    next_send_time = time.perf_counter()

    try:
        while True:
            now = time.perf_counter()
            if now < next_send_time:
                remaining = next_send_time - now
                if use_sleep and remaining > 0.001:
                    time.sleep(remaining - 0.0005)
                continue

            _pack_and_send(buf, seq, _get_timestamp_us(), sock, dest_addr)
            seq += 1
            next_send_time += packet_interval

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⊘ Sender stopped after {seq:,} packets{Colors.ENDC}\n")
    except _Terminate:
        print(f"\n{Colors.YELLOW}⊘ Sender stopped after {seq:,} packets{Colors.ENDC}\n")
        raise
    except OSError as e:
        print(f"{Colors.RED}✗ Send error: {e}{Colors.ENDC}\n")
    finally:
        sock.close()


def send_packets_burst(config, sync_server, duration_seconds=60):
    """Send packets in burst mode with optional bandwidth limit.

    If burst_mbps > 0, packets are paced to match the target bandwidth.
    Uses perf_counter spin-wait for accurate pacing at high rates.
    If burst_mbps == 0, packets are sent as fast as possible (no pacing).
    """
    sock = _open_send_socket(config)
    if sock is None:
        return
    dest_addr = (config['destination_address'], config['destination_port'])
    pkt_size = config['packet_size']
    buf = _build_packet_buffer(pkt_size, _advertised_sync_port(sync_server))
    burst_mbps = config.get('burst_mbps', 0)

    if burst_mbps > 0:
        _print_banner(config, sync_server, f'BURST-MODE: {burst_mbps:.0f} Mbit/s')
    else:
        _print_banner(config, sync_server, 'BURST-MODE: Max Speed! 🚀')

    seq = 0
    start = time.perf_counter()
    last_report = start
    report_interval = 5.0

    # Rate limiting via pacing
    # target_pps = bits_per_second / bits_per_packet
    if burst_mbps > 0:
        bits_per_packet = pkt_size * 8
        target_pps = (burst_mbps * 1_000_000) / bits_per_packet
        packet_interval = 1.0 / target_pps
        use_sleep = target_pps <= 50000
        next_send_time = start
        pacing = True
    else:
        pacing = False

    try:
        while True:
            if pacing:
                now = time.perf_counter()
                if now < next_send_time:
                    remaining = next_send_time - now
                    if use_sleep and remaining > 0.0005:
                        time.sleep(remaining - 0.0003)
                    continue

            _pack_and_send(buf, seq, _get_timestamp_us(), sock, dest_addr)
            seq += 1

            if pacing:
                next_send_time += packet_interval

            # periodic status report
            check_interval = 0xFFF if not pacing else 0x3FF
            if seq & check_interval == 0:
                now = time.perf_counter()
                if now - last_report >= report_interval:
                    elapsed = now - start
                    actual_pps = seq / elapsed
                    actual_mbps = (seq * pkt_size * 8) / (elapsed * 1e6)
                    if pacing:
                        print(f"{Colors.CYAN}[{elapsed:6.1f}s] "
                              f"Pkts:{seq:10d} | {actual_pps:10.0f} pps | "
                              f"{actual_mbps:6.1f}/{burst_mbps:.0f} Mbit/s{Colors.ENDC}")
                    else:
                        print(f"{Colors.CYAN}[{elapsed:6.1f}s] "
                              f"Pkts:{seq:10d} | {actual_pps:10.0f} pps | "
                              f"{actual_mbps:6.1f} Mbit/s{Colors.ENDC}")
                    last_report = now

                if duration_seconds > 0 and (now - start) >= duration_seconds:
                    break

    except KeyboardInterrupt:
        pass
    except OSError as e:
        print(f"{Colors.RED}✗ Send error: {e}{Colors.ENDC}")
    finally:
        sock.close()

    # final stats
    elapsed = time.perf_counter() - start
    if elapsed > 0 and seq > 0:
        actual_pps = seq / elapsed
        actual_mbps = (seq * pkt_size * 8) / (elapsed * 1e6)
        data_mb = seq * pkt_size / 1e6

        print(f"\n{Colors.GREEN}╔══════════════════════════════════════════════════════{Colors.ENDC}")
        print(f"{Colors.GREEN}║   BURST Statistics{Colors.ENDC}")
        print(f"{Colors.GREEN}║   Time: {elapsed:.1f}s{Colors.ENDC}")
        print(f"{Colors.GREEN}║   Packets: {seq:,}{Colors.ENDC}")
        print(f"{Colors.GREEN}║   Rate: {actual_pps:,.0f} pps{Colors.ENDC}")
        print(f"{Colors.GREEN}║   Throughput: {actual_mbps:.1f} Mbit/s{Colors.ENDC}")
        if burst_mbps > 0:
            print(f"{Colors.GREEN}║   Target: {burst_mbps:.0f} Mbit/s{Colors.ENDC}")
        print(f"{Colors.GREEN}║   Data: {data_mb:.1f} MB{Colors.ENDC}")
        print(f"{Colors.GREEN}╚══════════════════════════════════════════════════════{Colors.ENDC}\n")



# --- Multi-stream sender --------------------------------------------------------

SEND_MAX_STREAMS = 32      # streams in the sender (raise here if more are needed)

_STREAM_KEYS = ('destination_address', 'destination_port', 'packet_size',
                'packets_per_second', 'source_address', 'source_port',
                'dscp_value', 'ttl', 'burst_mbps', 'df_bit', 'burst_mode')


def _stream_params(d=None):
    """Complete parameter dict of one stream (defaults filled in, only the
    known keys kept)."""
    base = {k: v for k, v in _default_config()['send'].items() if k in _STREAM_KEYS}
    if d:
        base.update({k: d[k] for k in _STREAM_KEYS if k in d})
    return base


def _si(n):
    """Counter for narrow columns: 1234567 -> '1.23M'."""
    n = int(n)
    if n < 10_000_000:
        return str(n)
    for unit, div in (('G', 1e9), ('M', 1e6)):
        if n >= div:
            return f"{n / div:.2f}{unit}"
    return str(n)


def _short(n, w):
    """Counter that fits w characters: 12345 -> '12.3k' / '12k'."""
    n = int(n)
    if len(str(n)) <= w:
        return str(n)
    for unit, div in (('G', 1e9), ('M', 1e6), ('k', 1e3)):
        if n >= div:
            for dec in (1, 0):
                t = f"{n / div:.{dec}f}{unit}"
                if len(t) <= w:
                    return t
    return str(n)[:w]


def _tbl_total(groups):
    """Width of a table line: 1 leading blank, cells of a group separated by a
    blank, groups by ' | '."""
    return 1 + sum(sum(c[2] for c in g) + len(g) - 1 for g in groups) + 3 * (len(groups) - 1)


def _tbl_pick(cands, width):
    """First column layout that fits the width (the last one otherwise)."""
    for c in cands:
        if _tbl_total(c) <= width:
            return c
    return cands[-1]


def _tbl_row(groups, vals=None, colors=None):
    """One table line; vals=None gives the headline. Cells are
    (key, title, width, align)."""
    out = []
    for g in groups:
        cells = []
        for key, title, w, al in g:
            txt = f"{title if vals is None else vals[key]!s:{al}{w}}"[:w]
            col = (colors or {}).get(key, '')
            cells.append(col + txt + Colors.ENDC if col else txt)
        out.append(' '.join(cells))
    return ' ' + ' | '.join(out)


class SendStream:
    """One send stream: its own socket and thread, own sequence numbers.

    The parameters can be changed while the stream is running (apply()); the
    worker then rebuilds socket and packet buffer and carries on with the same
    sequence numbers, so the receiver sees no gap. Stop/start resumes the
    sequence as well. All streams share the one OWD sync server of the process.
    """

    def __init__(self, params, sync_server):
        self.p = _stream_params(params)
        self.sync_server = sync_server
        self.state = 'stopped'            # stopped | running | error
        self.error = ''
        self.error_at = 0.0
        self.errors = 0
        self.notes = []
        self.seq = 0
        self.sent = 0
        self.bytes = 0
        self.rate_pps = 0.0
        self.rate_mbps = 0.0
        self._samp = (0, 0, time.monotonic())
        self._lock = threading.Lock()
        self._gen = 0
        self._halt = False
        self._thread = None

    # -- control -------------------------------------------------------------
    def params(self):
        with self._lock:
            return dict(self.p)

    def apply(self, params):
        """New parameters, effective immediately (also while running)."""
        with self._lock:
            self.p = _stream_params(params)
            self._gen += 1
        if self.state == 'error':
            self.start()

    def start(self):
        if self._thread is not None and self._thread.is_alive() and not self._halt:
            return
        if self._thread is not None:
            self._thread.join(2.0)
        self._halt = False
        self.error = ''
        self.notes = []
        self.state = 'running'
        self._samp = (self.sent, self.bytes, time.monotonic())
        self._thread = threading.Thread(target=self._run, daemon=True, name='send-stream')
        self._thread.start()

    def stop(self, wait=True):
        self._halt = True
        t = self._thread
        if t is not None and wait:
            t.join(2.0)
        self.state = 'stopped'
        self.rate_pps = self.rate_mbps = 0.0

    @property
    def running(self):
        return self.state == 'running'

    def state_text(self):
        if self.state == 'running' and time.monotonic() - self.error_at < 3.0:
            return 'ERROR'
        return {'running': 'running', 'stopped': 'stopped', 'error': 'ERROR'}[self.state]

    def mode_text(self):
        p = self.params()
        if p['burst_mode']:
            return f"burst {p['burst_mbps']:g}M" if p['burst_mbps'] > 0 else 'burst max'
        return f"{p['packets_per_second']:g} pps"

    def rate_text(self):
        """Short rate for the table (8 characters at most)."""
        p = self.params()
        if p['burst_mode']:
            return f"{p['burst_mbps']:g} Mb/s" if p['burst_mbps'] > 0 else 'max rate'
        pps = p['packets_per_second']
        return f"{pps / 1000:g}k pps" if pps >= 10000 else f"{pps:g} pps"

    def sample(self, now):
        """Measured rate since the last sample (called by the view)."""
        sent0, bytes0, t0 = self._samp
        dt = now - t0
        if dt < 0.5:
            return
        if self.state == 'running':
            self.rate_pps = (self.sent - sent0) / dt
            self.rate_mbps = (self.bytes - bytes0) * 8 / (dt * 1e6)
        else:
            self.rate_pps = self.rate_mbps = 0.0
        self._samp = (self.sent, self.bytes, now)

    # -- worker --------------------------------------------------------------
    def _note(self, text):
        self.notes.append(text)

    def _fail(self, e):
        self.errors += 1
        self.error = str(e)
        self.error_at = time.monotonic()

    _active = 0                   # stream threads running (class-wide)
    _active_lock = threading.Lock()

    def _run(self):
        with SendStream._active_lock:
            SendStream._active += 1
        try:
            self._run_streams()
        finally:
            with SendStream._active_lock:
                SendStream._active -= 1

    def _run_streams(self):
        try:
            while not self._halt:
                gen = self._gen
                p = self.params()
                try:
                    dest = (socket.gethostbyname(p['destination_address'].strip()),
                            p['destination_port'])
                except (OSError, UnicodeError) as e:
                    self._fail(f"destination {p['destination_address']}: {e}")
                    self.state = 'error'
                    return
                self.notes = []
                sock = _open_send_socket(p, report=self._note)
                if sock is None:
                    self._fail(self.notes[-1] if self.notes else 'cannot open the send socket')
                    self.state = 'error'
                    return
                try:
                    buf = _build_packet_buffer(p['packet_size'],
                                               _advertised_sync_port(self.sync_server))
                    self._send_loop(p, gen, sock, dest, buf)
                finally:
                    sock.close()
        except Exception as e:      # a stream must never take the program down
            self._fail(f"{type(e).__name__}: {e}")
            self.state = 'error'

    def _send_loop(self, p, gen, sock, dest, buf):
        """Hot loop of one stream.  Everything used per packet is bound to a
        local name (attribute and global lookups cost more than the send
        itself at 100k+ pps).  Packets that are due are sent as a batch
        (catching up after a late wake-up, at most 64 per round) and the
        thread sleeps until the next one is due; below 0.2 ms it spins with
        sleep(0) instead, which keeps the pacing exact at low rates."""
        wire = len(buf) + _UDP_IP_OVERHEAD
        if p['burst_mode']:
            pacing = p['burst_mbps'] > 0
            interval = (wire * 8) / (p['burst_mbps'] * 1e6) if pacing else 0.0
        else:
            pacing = True
            interval = 1.0 / max(p['packets_per_second'], 0.01)
        # A lone stream sleeps until shortly before the next packet is due and
        # then waits actively (exact spacing, every packet on its own).  With
        # several streams running, spinning threads would fight for the GIL,
        # so fast ones (< 1 ms apart) sleep until the packet is due and send
        # what has become due as a small batch.
        sleep_exact = 0.0005
        sleep_shared = 0.0002 if interval < 0.001 else 0.001
        cls = SendStream
        crc_len = len(buf) - _CRC_STRUCT.size
        crc_off = crc_len
        pack_hdr = _HDR_STRUCT.pack_into
        pack_crc = _CRC_STRUCT.pack_into
        crc32 = zlib.crc32
        body = memoryview(buf)[:crc_len]
        sendto = sock.sendto
        time_ns = time.time_ns
        perf = time.perf_counter
        sleep = time.sleep
        ENOBUFS = errno.ENOBUFS
        batch_max = 64
        seq = self.seq
        next_t = perf()
        try:
            while not self._halt and self._gen == gen:
                count = 1
                if pacing:
                    now = perf()
                    if now < next_t:
                        rem = next_t - now
                        sleep_min = sleep_exact if cls._active == 1 else sleep_shared
                        if rem > sleep_min:
                            sleep(min(rem - sleep_min * 0.5, 0.05))
                        else:
                            sleep(0)        # yield the GIL to the other streams
                        continue
                    if now - next_t > 1.0:  # far behind (suspend, overload): no catch-up burst
                        next_t = now
                    count = min(batch_max, int((now - next_t) / interval) + 1)
                else:
                    count = batch_max
                sent_now = 0
                try:
                    for _ in range(count):
                        pack_hdr(buf, 0, seq, time_ns() // 1000)
                        pack_crc(buf, crc_off, crc32(body))
                        while True:
                            try:
                                sendto(buf, dest)
                                break
                            except OSError as e:
                                if e.errno != ENOBUFS:
                                    raise
                                sleep(0.001)    # send buffer full: back off, retry
                        seq = (seq + 1) & 0xFFFFFFFF
                        sent_now += 1
                except OSError as e:
                    self._fail(e)
                    sleep(0.2)
                    next_t = perf()
                finally:
                    self.seq = seq
                    self.sent += sent_now
                    self.bytes += sent_now * wire
                if pacing:
                    next_t += interval * sent_now
                else:
                    sleep(0)
        finally:
            body.release()


def parse_stream_spec(spec, defaults):
    """'dest:port[,pps=N][,size=N][,dscp=N|NAME][,ttl=N][,burst[=Mbit/s]]
    [,src=IP][,sport=N][,df]' -> parameter dict (missing values from defaults)."""
    parts = [x.strip() for x in spec.split(',') if x.strip()]
    if not parts:
        raise ValueError('empty stream specification')
    p = _stream_params(defaults)
    head = parts[0]
    if ':' in head:
        host, _, port = head.rpartition(':')
        if not port.isdigit():
            raise ValueError(f"bad port in '{head}'")
        p['destination_address'], p['destination_port'] = host, int(port)
    elif head.isdigit():
        p['destination_port'] = int(head)
    else:
        p['destination_address'] = head
    names = {v.lower(): k for k, v in DSCP_NAMES.items()}
    for item in parts[1:]:
        key, eq, val = item.partition('=')
        key = key.strip().lower()
        val = val.strip()
        try:
            if key == 'pps':
                p['packets_per_second'], p['burst_mode'] = float(val), False
            elif key == 'size':
                p['packet_size'] = int(val)
            elif key == 'dscp':
                p['dscp_value'] = names[val.lower()] if val.lower() in names else int(val)
            elif key == 'ttl':
                p['ttl'] = int(val)
            elif key == 'burst':
                p['burst_mode'], p['burst_mbps'] = True, (float(val) if val else 0.0)
            elif key in ('src', 'source'):
                p['source_address'] = val
            elif key in ('sport', 'source-port'):
                p['source_port'] = int(val)
            elif key == 'df':
                p['df_bit'] = (val.lower() not in ('0', 'off', 'no', 'false')) if eq else True
            else:
                raise ValueError(f"unknown option '{key}'")
        except KeyError:
            raise ValueError(f"unknown DSCP name '{val}'")
        except ValueError as e:
            if 'unknown option' in str(e):
                raise
            raise ValueError(f"bad value in '{item}'")
    problem = check_stream_params(p)
    if problem:
        raise ValueError(f"{spec}: {problem}")
    return p


def check_stream_params(p):
    """'' if the stream parameters are usable, otherwise the problem."""
    if not str(p['destination_address']).strip():
        return 'destination required'
    if not 1 <= p['destination_port'] <= 65535:
        return 'destination port must be 1-65535'
    if not _MIN_PACKET_SIZE + _UDP_IP_OVERHEAD <= p['packet_size'] <= 65507:
        return f"size must be {_MIN_PACKET_SIZE + _UDP_IP_OVERHEAD}-65507"
    if not p['burst_mode'] and not 0.01 <= p['packets_per_second'] <= 10_000_000:
        return 'pps must be 0.01-10000000'
    if not 0 <= p['dscp_value'] <= 63:
        return 'DSCP must be 0-63'
    if not 1 <= p['ttl'] <= 255:
        return 'TTL must be 1-255'
    if not 0 <= p['source_port'] <= 65535:
        return 'source port must be 0-65535'
    if p['source_address'] and not _ip_usable(p['source_address']):
        return f"source address {p['source_address']} is not an address of this host"
    return ''


def streams_from_config(cfg):
    """Stream parameters from the config: the form values (stream 1) plus
    the saved additional streams."""
    sc = cfg['send']
    plist = [_stream_params(sc)]
    for extra in (sc.get('extra_streams') or [])[:SEND_MAX_STREAMS - 1]:
        if isinstance(extra, dict):
            plist.append(_stream_params(extra))
    return plist


def store_streams(cfg, plist):
    """Stream 1 becomes the form values, the rest the additional streams."""
    if not plist:
        cfg['send']['extra_streams'] = []
        return
    cfg['send'].update(plist[0])
    cfg['send']['extra_streams'] = [dict(x) for x in plist[1:]]


def _print_stream_totals(streams, elapsed):
    print(f"{Colors.GREEN}Sender stopped after {format_elapsed(elapsed)}:{Colors.ENDC}")
    for i, st in enumerate(streams, 1):
        p = st.params()
        print(f"  {i}  {p['destination_address']}:{p['destination_port']:<5d} "
              f"{st.sent:>12,d} packets  {st.bytes / 1e6:>10.1f} MB"
              + (f"  ({st.errors} send errors)" if st.errors else ''))
    print()


def run_senders_plain(plist, sync_server):
    """Several streams without a live view (no terminal): banner per stream,
    a status line every 5 s, Ctrl+C stops."""
    streams = [SendStream(p, sync_server) for p in plist[:SEND_MAX_STREAMS]]
    for i, st in enumerate(streams, 1):
        p = st.params()
        print(f"{Colors.GREEN}Stream {i}: {p['destination_address']}:{p['destination_port']}  "
              f"{p['packet_size']} B  {st.mode_text()}  DSCP {p['dscp_value']} "
              f"({dscp_to_name(p['dscp_value'])})  TTL {p['ttl']}{Colors.ENDC}")
    sync = (f"port {sync_server.port}" if sync_server.active
            else "none - receivers get no delay values")
    print(f"{Colors.GREEN}OWD sync: {sync}.  CTRL+C to stop{Colors.ENDC}\n")
    start = time.monotonic()
    try:
        for st in streams:
            st.start()
        last = start
        while True:
            time.sleep(0.2)
            now = time.monotonic()
            if now - last >= 5.0:
                last = now
                for i, st in enumerate(streams, 1):
                    print(f"[{format_elapsed(now - start)}] stream {i}: {st.state_text():<8s} "
                          f"{st.sent:>12,d} packets" + (f"  {st.error}" if st.error else ''))
    except KeyboardInterrupt:
        pass
    finally:
        for st in streams:
            st.stop(wait=False)
        for st in streams:
            st.stop()
    _print_stream_totals(streams, time.monotonic() - start)


# --- Config (~/.mau/config.json) ----------------------------------------------

CONFIG_DIR = Path.home() / '.mau'


def _default_config():
    return {
        'sync_port': OWD_SYNC_PORT,          # local OWD sync server (all modes)
        'send': {
            'destination_address': '239.1.1.1',
            'destination_port': 5001,
            'packet_size': 256,
            'packets_per_second': 10,
            'source_address': '',
            'source_port': 0,
            'dscp_value': 0,
            'ttl': 32,
            'burst_mbps': 0,                 # 0 = unlimited
            'df_bit': False,
            'burst_mode': False,             # form menu: Normal / Burst
            'extra_streams': [],             # streams 2..N (sender live view), same keys as above
        },
        'recv': {
            'sender_ip': '',                 # '' = auto-detect, 'none' = no OWD sync
            'sender_sync_port': 0,           # 0 = taken from the packets
            'live': True,                    # form menu: full-screen live view
            'show_ip': False,                # show the sender IP in every line
            'verify': False,                 # CRC + pattern check of every packet
            'unicast': False,
            'group': '239.1.1.1',
            'interface': 'all',              # multicast join: all | auto | IP | interface name
            'print_limit': PKT_LINE_LIMIT,   # per-packet display: max lines/s (0 = unlimited)
            'port': '5001-5008',             # port, range or list
            'summary': 2,                    # seconds, 0 = per-packet display
            'compact': False,
            'resync_interval': OWD_RESYNC_INTERVAL,
            'log': '',                       # '' = no log, 'auto' = timestamp name, else file name (current dir)
        },
    }


def load_config():
    """Load ~/.mau/config.json over the defaults."""
    cfg = _default_config()
    config_file = CONFIG_DIR / 'config.json'
    try:
        if config_file.exists():
            with open(config_file, 'r') as f:
                stored = json.load(f)
            for key, val in stored.items():
                if isinstance(val, dict) and isinstance(cfg.get(key), dict):
                    cfg[key].update(val)
                elif key in cfg:
                    cfg[key] = val
    except (json.JSONDecodeError, OSError) as e:
        print(f"{Colors.YELLOW}⚠ Config load error: {e}{Colors.ENDC}")
    return cfg


def save_config(cfg):
    """Persist config to disk."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        clean = {k: ({kk: vv for kk, vv in v.items() if not kk.startswith('_')}
                     if isinstance(v, dict) else v) for k, v in cfg.items()}
        with open(CONFIG_DIR / 'config.json', 'w') as f:
            json.dump(clean, f, indent=2)
    except OSError as e:
        print(f"{Colors.RED}✗ Config save error: {e}{Colors.ENDC}")


# --- Menus --------------------------------------------------------------------

def _menu_header(title):
    print(f"\n{Colors.WHITE}"
          f"╔══════════════════════════════════════════════════════{Colors.ENDC}")
    print(f"{Colors.WHITE}║  mautg v{VERSION} - {title}   {CREDIT}{Colors.ENDC}")
    print(f"{Colors.WHITE}"
          f"╚══════════════════════════════════════════════════════{Colors.ENDC}\n")


def _ask(prompt):
    """input() that turns Ctrl+C / Ctrl+D into None."""
    try:
        return input(prompt).strip()
    except (KeyboardInterrupt, EOFError):
        print(f"\n{Colors.YELLOW}⊘ Cancelled{Colors.ENDC}\n")
        return None


def _change_sync_port(cfg, sync_server):
    raw = input("Local OWD Sync Server Port: ").strip()
    new_port = int(raw)
    if new_port != cfg['sync_port']:
        cfg['sync_port'] = new_port
        print(f"{Colors.CYAN}Restarting OWD sync server...{Colors.ENDC}")
        sync_server.restart(new_port)


def main_menu(cfg, sync_server):
    """Top-level menu. Loops until the user exits."""
    while True:
        _menu_header("by Ewald Jeitler")
        print(f"  {Colors.GREEN}1. Sender{Colors.ENDC}")
        print(f"  {Colors.GREEN}2. Receiver{Colors.ENDC}")
        print(f"  {Colors.RED}e. Exit{Colors.ENDC}\n")
        choice = _ask(f"{Colors.CYAN}Choose option [1/2/e]: {Colors.ENDC}")
        if choice is None or choice.lower() == 'e':
            return
        if choice == '1':
            sender_menu_loop(cfg, sync_server)
        elif choice == '2':
            receiver_menu_loop(cfg, sync_server)
        else:
            print(f"{Colors.RED}✗ Unknown option{Colors.ENDC}")


def sender_menu(cfg, sync_server):
    """Sender configuration menu. Returns ('normal'|'burst') or None (= back)."""
    config = cfg['send']
    _menu_header("Sender")

    fields = {
        '1': ('destination_address', 'Destination Address', str),
        '2': ('destination_port', 'Destination Port', int),
        '3': ('packet_size', 'Packet Size (bytes)', int),
        '4': ('packets_per_second', 'Rate (pps)', float),
        '5': ('dscp_value', 'DSCP Value (0-63)', int),
        '7': ('ttl', 'TTL (1-255)', int),
        '8': ('burst_mbps', 'Burst Bandwidth Limit (Mbit/s, 0=unlimited)', float),
    }

    while True:
        burst_label = (f"{config['burst_mbps']:.0f} Mbit/s"
                       if config['burst_mbps'] > 0 else "unlimited")

        print(f"{Colors.CYAN}Current Settings:{Colors.ENDC}")
        print(f"  1. Destination Address:    {config['destination_address']}")
        print(f"  2. Destination Port:       {config['destination_port']}")
        print(f"  3. Packet Size:            {config['packet_size']} bytes")
        print(f"  4. Rate (pps):             {config['packets_per_second']:.1f}")
        print(f"  5. DSCP Value:             {config['dscp_value']}")
        print(f"  6. OWD Sync Server Port:   {cfg['sync_port']}")
        print(f"  7. TTL:                    {config['ttl']}")
        print(f"  8. Burst Bandwidth Limit:  {burst_label}")
        df_label = "on" if config.get('df_bit', False) else "off"
        print(f"  9. Don't Fragment (DF):    {df_label}")
        print(f"\n  {Colors.GREEN}0. START (Normal Mode){Colors.ENDC}")
        print(f"  {Colors.GREEN}b. BURST-MODE{Colors.ENDC}")
        print(f"  {Colors.YELLOW}s. Save Config{Colors.ENDC}")
        print(f"  {Colors.RED}e. Back{Colors.ENDC}\n")

        choice = _ask(f"{Colors.CYAN}Choose option [0-9/b/s/e]: {Colors.ENDC}")
        if choice is None:
            return None
        choice = choice.lower()

        try:
            if choice == 'e':
                return None
            elif choice == 's':
                save_config(cfg)
                print(f"{Colors.GREEN}✓ Config saved{Colors.ENDC}\n")
            elif choice == '0':
                return 'normal'
            elif choice == 'b':
                return 'burst'
            elif choice == '6':
                _change_sync_port(cfg, sync_server)
            elif choice == '9':
                config['df_bit'] = not config.get('df_bit', False)
            elif choice in fields:
                key, label, cast = fields[choice]
                config[key] = cast(input(f"{label}: ").strip())
            else:
                print(f"{Colors.RED}✗ Unknown option{Colors.ENDC}")
        except ValueError:
            print(f"{Colors.RED}✗ Invalid input{Colors.ENDC}")
        except (KeyboardInterrupt, EOFError):
            print(f"\n{Colors.YELLOW}⊘ Cancelled{Colors.ENDC}")
        print()


def sender_menu_loop(cfg, sync_server):
    """Sender menu; after Ctrl+C stops sending, return to this menu."""
    while True:
        mode = sender_menu(cfg, sync_server)
        if mode is None:
            return
        if mode == 'burst':
            send_packets_burst(cfg['send'], sync_server, duration_seconds=0)
        else:
            send_packets(cfg['send'], sync_server)
        print(f"{Colors.CYAN}Returning to menu...{Colors.ENDC}\n")


def receiver_menu(cfg, sync_server):
    """Receiver configuration menu. Returns 'start' or None (= back)."""
    rc = cfg['recv']
    _menu_header("Receiver")

    while True:
        if not rc['sender_ip']:
            sender = "auto (detected from first packet)"
        elif rc['sender_ip'] == 'none':
            sender = "off (no delay values)"
        else:
            sender = rc['sender_ip']
        mode = "Unicast (own IP)" if rc['unicast'] else "Multicast"
        summary = f"{rc['summary']} s" if rc['summary'] else "per packet"
        print(f"{Colors.CYAN}Current Settings:{Colors.ENDC}")
        print(f"  1. Sender IP (OWD sync):   {sender}")
        print(f"  2. Receive Mode:           {mode}")
        print(f"  3. Multicast Group:        {rc['group']}")
        print(f"  4. Data Port(s):           {rc['port']}   (e.g. 5005 | 5005-5010 | 5005,6000)")
        print(f"  5. Summary Interval:       {summary}")
        print(f"  6. Compact Summary:        {'on' if rc['compact'] else 'off'}")
        print(f"  7. Sender Sync Port:       {rc['sender_sync_port'] or 'from packet'}")
        print(f"  8. Resync Interval:        {rc['resync_interval']:g} s")
        if rc['log'] == 'auto' and not rc.get('_log_name'):
            rc['_log_name'] = default_log_name()
        log_label = (rc['_log_name'] if rc['log'] == 'auto' else rc['log'] or 'none')
        print(f"  9. CSV Log File:           {log_label}   (in current directory)")
        print(f"  a. Local OWD Sync Server:  port {cfg['sync_port']}")
        print(f"  v. Verify every packet:    {'on' if rc['verify'] else 'off'}")
        print(f"  i. Show sender IP:         {'on' if rc.get('show_ip') else 'off'}")
        print(f"  m. Multicast interface:    {rc.get('interface') or 'all'}   (all | auto | IP | name)")
        print(f"\n  {Colors.GREEN}0. START Receiver{Colors.ENDC}")
        print(f"  {Colors.YELLOW}s. Save Config{Colors.ENDC}")
        print(f"  {Colors.RED}e. Back{Colors.ENDC}\n")

        choice = _ask(f"{Colors.CYAN}Choose option [0-9/a/v/i/m/s/e]: {Colors.ENDC}")
        if choice is None:
            return None
        choice = choice.lower()

        try:
            if choice == 'e':
                return None
            elif choice == 's':
                save_config(cfg)
                print(f"{Colors.GREEN}✓ Config saved{Colors.ENDC}\n")
            elif choice == '0':
                return 'start'
            elif choice == '1':
                val = input("Sender IP (Enter = auto, '-' = off): ").strip()
                rc['sender_ip'] = 'none' if val == '-' else val
            elif choice == '2':
                rc['unicast'] = not rc['unicast']
            elif choice == '3':
                rc['group'] = input("Multicast Group: ").strip()
            elif choice == '4':
                spec = input("Data Port(s) (e.g. 5005, 5005-5010, 5005,6000-6003): ").strip()
                parse_ports(spec)
                rc['port'] = int(spec) if spec.isdigit() else spec
            elif choice == '5':
                rc['summary'] = max(0, int(input("Summary Interval (s, 0 = per packet): ").strip()))
            elif choice == '6':
                rc['compact'] = not rc['compact']
                if rc['compact'] and not rc['summary']:
                    print(f"{Colors.YELLOW}⚠ Compact needs a summary interval (item 5){Colors.ENDC}")
            elif choice == '7':
                rc['sender_sync_port'] = int(input("Sender Sync Port (0 = from packet): ").strip())
            elif choice == '8':
                rc['resync_interval'] = float(input("Resync Interval (s): ").strip())
            elif choice == '9':
                val = input("CSV Log File name (Enter = auto timestamp name, '-' = none): ").strip()
                rc['log'] = ('' if val == '-' else (val or 'auto'))
                rc.pop('_log_name', None)
            elif choice == 'a':
                _change_sync_port(cfg, sync_server)
            elif choice == 'v':
                rc['verify'] = not rc['verify']
            elif choice == 'i':
                rc['show_ip'] = not rc.get('show_ip')
            elif choice == 'm':
                for ip, name in local_ipv4_addresses():
                    if not ip.startswith('127.'):
                        print(f"    {ip:<15s} {name}")
                val = input("Multicast interface (all | auto | IP | interface name): ").strip() or 'all'
                resolve_mcast_interfaces(val)
                rc['interface'] = val
            else:
                print(f"{Colors.RED}✗ Unknown option{Colors.ENDC}")
        except ValueError:
            print(f"{Colors.RED}✗ Invalid input{Colors.ENDC}")
        except (KeyboardInterrupt, EOFError):
            print(f"\n{Colors.YELLOW}⊘ Cancelled{Colors.ENDC}")
        print()


def receiver_menu_loop(cfg, sync_server):
    """Receiver menu; after Ctrl+C stops receiving, return to this menu."""
    while True:
        if receiver_menu(cfg, sync_server) is None:
            return
        run_receiver(cfg['recv'])
        print(f"{Colors.CYAN}Returning to menu...{Colors.ENDC}\n")


# --- Receiver runner ----------------------------------------------------------

def default_log_name():
    """mautg-log_2026-10-07_14:02:04.csv (Windows: ':' -> '-' in the time)."""
    fmt = '%Y-%m-%d_%H-%M-%S' if sys.platform == 'win32' else '%Y-%m-%d_%H:%M:%S'
    return datetime.now().strftime(f'mautg-log_{fmt}.csv')


def run_receiver(rc, live=False):
    """Set up OWD sync + PacketReceiver from a recv settings dict and run
    until Ctrl+C. Returns afterwards (the caller decides what's next)."""
    try:
        parse_ports(rc['port'])
    except ValueError as e:
        print(f"{Colors.RED}✗ Invalid port specification: {e}{Colors.ENDC}\n")
        return
    if not rc['unicast']:
        try:
            parse_groups(rc['group'])
        except ValueError as e:
            print(f"{Colors.RED}✗ Invalid multicast group specification: {e}{Colors.ENDC}\n")
            return
        try:
            resolve_mcast_interfaces(rc.get('interface'))
        except ValueError as e:
            print(f"{Colors.RED}✗ Multicast interface: {e}{Colors.ENDC}\n")
            return
    ip = rc['sender_ip']
    if ip == 'none':
        sync = SyncController('off')
        print(f"{Colors.YELLOW}⚠ OWD sync switched off — delay values disabled{Colors.ENDC}")
    elif ip:
        sync = SyncController('explicit', ip, rc['sender_sync_port'], rc['resync_interval'])
        sync.connect_blocking()
    else:
        sync = SyncController('auto', None, rc['sender_sync_port'], rc['resync_interval'])

    log_file = None
    if rc['log']:
        if rc['log'] == 'auto':
            log_name = rc.pop('_log_name', None) or default_log_name()
            if (Path.cwd() / log_name).exists():   # e.g. second run within the same second
                log_name = default_log_name()
        else:
            log_name = rc['log']
        log_file = Path.cwd() / log_name   # absolute names stay as given
        print(f"{Colors.CYAN}CSV log: {log_file}{Colors.ENDC}")

    view = None
    if live:
        cols, rows = shutil.get_terminal_size((80, 24))
        ok, _why = tui_available()
        if ok and cols >= 80 and rows >= 16:
            view = LiveView()
        elif ok or sys.stdout.isatty():
            print(f"{Colors.YELLOW}⚠ Live view needs a terminal of at least 80x16 - "
                  f"using the plain output{Colors.ENDC}")

    try:
        receiver = _make_receiver(rc, log_file, sync, view)
    except OSError as e:
        print(f"{Colors.RED}✗ Receiver cannot start: {e}{Colors.ENDC}\n")
        sync.stop()
        return
    receiver.receive_loop()


def _make_receiver(rc, log_file, sync, view):
    return PacketReceiver(
        None if rc['unicast'] else rc['group'],
        rc['port'],
        interface=rc.get('interface') or 'all',
        log_file=log_file,
        summary_interval=rc['summary'] or None,
        summary_compact=bool(rc['compact'] and rc['summary']),
        sync=sync,
        verify_all=bool(rc.get('verify')),
        show_ip=bool(rc.get('show_ip')),
        unicast_mode=rc['unicast'],
        live=view,
        print_limit=rc.get('print_limit', PKT_LINE_LIMIT),
    )


# --- Local addresses ------------------------------------------------------------

def _ip_usable(ip):
    """True if ip is an IPv4 address that this host can bind to."""
    parts = ip.split('.')
    if len(parts) != 4 or not all(x.isdigit() and 0 <= int(x) <= 255 for x in parts):
        return False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sk:
            sk.bind((ip, 0))
        return True
    except OSError:
        return False


def local_ipv4_addresses():
    """[(ip, interface name)] of this host, loopback last. Standard library
    only: parses `ip` / `ifconfig` / `ipconfig`, falls back to the resolver."""
    import re
    import subprocess
    found = {}

    def add(ip, name=''):
        if _ip_usable(ip):
            found.setdefault(ip, name)

    def run(cmd):
        try:
            return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  universal_newlines=True, timeout=3,
                                  errors='replace').stdout
        except (OSError, subprocess.SubprocessError):
            return ''

    if sys.platform == 'win32':
        name = ''
        for line in run(['ipconfig']).splitlines():
            if line and not line[0].isspace() and line.rstrip().endswith(':'):
                name = line.rstrip(' :')
            elif 'IPv4' in line:
                m = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if m:
                    add(m.group(1), name)
    else:
        for line in run(['ip', '-o', '-4', 'addr', 'show']).splitlines():
            m = re.match(r'\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)', line)
            if m:
                add(m.group(2), m.group(1))
        if not found:
            name = ''
            for line in run(['ifconfig', '-a']).splitlines():
                m = re.match(r'(\S+?):?\s', line)
                if m and not line[0].isspace():
                    name = m.group(1)
                m = re.search(r'\binet\s+(?:addr:)?(\d+\.\d+\.\d+\.\d+)', line)
                if m:
                    add(m.group(1), name)
    if not found:
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                add(info[4][0])
        except OSError:
            pass
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sk:
                sk.connect(("192.0.2.1", 9))
                add(sk.getsockname()[0])
        except OSError:
            pass
    add('127.0.0.1', 'loopback')
    items = sorted(found.items(), key=lambda kv: (kv[0].startswith('127.'), kv[0]))
    return items


def resolve_mcast_interfaces(spec):
    """Multicast receive interface setting -> [(ip, name)] to join on.
    'all' = every IPv4 address of this host except loopback, 'auto' = [(None, '')]
    (the kernel picks the interface from its routing table), otherwise an
    address of this host or an interface name.  ValueError if unusable."""
    spec = (spec or 'all').strip()
    if spec.lower() == 'auto':
        return [(None, '')]
    addrs = local_ipv4_addresses()
    if spec.lower() == 'all':
        return [(ip, n) for ip, n in addrs if not ip.startswith('127.')] or [(None, '')]
    if _ip_usable(spec):
        return [(spec, dict(addrs).get(spec, ''))]
    named = [(ip, n) for ip, n in addrs if n == spec]
    if named:
        return named
    raise ValueError(f"'{spec}' is not 'all', 'auto', an address of this host or an interface name")


def describe_mcast_interfaces(spec, ifaces):
    """Short text for the banner / the form."""
    spec = (spec or 'all').strip()
    if spec.lower() == 'auto' or ifaces == [(None, '')]:
        return 'auto (kernel picks it from the routing table)'
    names = ', '.join(f"{n} {ip}".strip() for ip, n in ifaces)
    return f"all ({names})" if spec.lower() == 'all' else names


# --- Terminal UI (form menu + live receiver view) ------------------------------
#
# Only plain ANSI / VT100 sequences are used (cursor addressing, erase line,
# reverse video, scroll region, save/restore cursor) and the standard library,
# so it works on a VT100 as well as in modern terminals. No curses (not
# available on Windows). Colors are decoration only: nothing depends on them.

_ESC = '\x1b'
_RESET = _ESC + '[0m'
_REV = _ESC + '[7m'


def _w(text):
    sys.stdout.write(text)
    sys.stdout.flush()


def _enable_vt_windows():
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        handle = k32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if k32.GetConsoleMode(handle, ctypes.byref(mode)):
            k32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def _utf8_terminal():
    return (not _ASCII_OUT) and _locale_utf8()


def tui_available():
    """(ok, reason). The full-screen UI needs a real terminal of at least
    60x16; otherwise the simple line menus are used."""
    if os.environ.get('MAUTG_NO_TUI'):
        return False, ''
    try:
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            return False, ''
    except (OSError, ValueError):
        return False, ''
    if sys.platform != 'win32' and os.environ.get('TERM', 'dumb').lower() in ('dumb', ''):
        return False, ''
    cols, rows = shutil.get_terminal_size((80, 24))
    if cols < 60 or rows < 16:
        return False, (f"Terminal too small for the full-screen UI "
                       f"({cols}x{rows}, need 60x16) - using the simple menu")
    return True, ''


class _Keys:
    """Key reader on the raw tty / Windows console. Returns 'up', 'down',
    'left', 'right', 'home', 'end', 'delete', 'enter', 'esc', 'tab', 'btab',
    'backspace', 'ctrl-x', or the typed character; None on timeout."""

    def __init__(self):
        self._win = sys.platform == 'win32'
        self._fd = None if self._win else sys.stdin.fileno()
        self._old = None

    def start(self):
        if self._win:
            _enable_vt_windows()
            return
        import termios
        import tty
        self._old = termios.tcgetattr(self._fd)
        tty.setcbreak(self._fd)       # keeps Ctrl+C (ISIG) and output processing

    def stop(self):
        if self._old is not None:
            import termios
            try:
                termios.tcsetattr(self._fd, termios.TCSADRAIN, self._old)
            except (OSError, termios.error):
                pass
            self._old = None

    def read(self, timeout=None):
        return self._read_win(timeout) if self._win else self._read_posix(timeout)

    # -- POSIX -------------------------------------------------------------
    def _read_posix(self, timeout):
        import select
        if not select.select([self._fd], [], [], timeout)[0]:
            return None
        data = os.read(self._fd, 1)
        if not data:
            raise EOFError
        c = data[0]
        if c == 0x1b:
            return self._escape()
        if c in (13, 10):
            return 'enter'
        if c in (127, 8):
            return 'backspace'
        if c == 9:
            return 'tab'
        if c < 32:
            return 'ctrl-' + chr(c + 96)
        if c >= 0xc0:
            extra = 1 if c < 0xe0 else 2 if c < 0xf0 else 3
            try:
                return (bytes([c]) + os.read(self._fd, extra)).decode('utf-8')
            except UnicodeDecodeError:
                return None
        return chr(c)

    def _escape(self):
        import select
        fd = self._fd
        if not select.select([fd], [], [], 0.05)[0]:
            return 'esc'
        lead = os.read(fd, 1)
        if lead not in (b'[', b'O'):
            return None
        seq = b''
        while select.select([fd], [], [], 0.05)[0]:
            ch = os.read(fd, 1)
            seq += ch
            if ch.isalpha() or ch == b'~':
                break
        letters = {b'A': 'up', b'B': 'down', b'C': 'right', b'D': 'left',
                   b'H': 'home', b'F': 'end', b'Z': 'btab'}
        tildes = {b'1~': 'home', b'7~': 'home', b'4~': 'end', b'8~': 'end',
                  b'3~': 'delete', b'5~': 'pgup', b'6~': 'pgdn'}
        if seq[-1:] in letters:
            return letters[seq[-1:]]
        return tildes.get(seq)

    # -- Windows -----------------------------------------------------------
    def _read_win(self, timeout):
        import msvcrt
        end = None if timeout is None else time.monotonic() + timeout
        while True:
            if msvcrt.kbhit():
                ch = msvcrt.getwch()
                if ch in ('\x00', '\xe0'):
                    code = msvcrt.getwch()
                    return {'H': 'up', 'P': 'down', 'K': 'left', 'M': 'right',
                            'G': 'home', 'O': 'end', 'S': 'delete', 'I': 'pgup', 'Q': 'pgdn',
                            '\x0f': 'btab'}.get(code)
                if ch == '\x03':
                    raise KeyboardInterrupt
                if ch == '\r':
                    return 'enter'
                if ch == '\x08':
                    return 'backspace'
                if ch == '\t':
                    return 'tab'
                if ch == '\x1b':
                    return 'esc'
                if ch < ' ':
                    return 'ctrl-' + chr(ord(ch) + 96)
                return ch
            if end is not None and time.monotonic() >= end:
                return None
            time.sleep(0.02)


_STYLES = {
    #          with colors                 without colors
    'bar':    (_ESC + '[1;97m',            _REV),    # bold white (like eping)
    'help':   (_ESC + '[90m',              _REV),    # grey key hints
    'hint':   (_ESC + '[37m',              ''),      # key bar: =ACTION (light grey, like eping)
    'hkey':   (_ESC + '[1;97m',            _ESC + '[1m'),  # key bar: [KEY] (bold white)
    'sel':    (_ESC + '[7m',               _REV),    # reverse video
    'title':  (_ESC + '[1;97m',            ''),
    'frame':  (_ESC + '[97m',              ''),
    'val':    (_ESC + '[96m',              ''),
    'choice': (_ESC + '[96m',              ''),
    'on':     (_ESC + '[92m',              ''),
    'off':    (_ESC + '[90m',              ''),
    'btn':    (_ESC + '[1;92m',            ''),
}


def _sty(name):
    """Escape sequence of a UI element: colored if colors are on, otherwise a
    monochrome (reverse video / plain) fallback that works on a VT100."""
    return _STYLES[name][0 if Colors.ENDC else 1]


def _keybar(pairs, width):
    """Bottom key bar in eping style: [KEY]=ACTION, everything upper case
    (the keys are not case sensitive).  Keys are highlighted, the rest is
    light grey (the style of eping); the line is cut to `width` visible characters and padded."""
    hk, ht = _sty('hkey'), _sty('hint')
    out = [ht + ' ']
    used = 1
    for key, act in pairs:
        key, act = key.upper(), act.upper()
        n = len(key) + len(act) + 4 + (2 if used > 1 else 0)
        if used + n > width:
            break
        if used > 1:
            out.append('  ')
            used += 2
        out.append(f"{hk}[{key}]{_RESET}{ht}={act}")
        used += len(key) + len(act) + 3
    out.append(_RESET + ' ' * max(0, width - used))
    return ''.join(out)


def color_ok():
    """Colors only where the terminal can show them (not on vt100 / dumb)."""
    if os.environ.get('NO_COLOR'):
        return False
    if sys.platform == 'win32':
        return True
    term = os.environ.get('TERM', '').lower()
    return bool(term) and term not in ('dumb', 'unknown') and not term.startswith('vt')


def disable_colors():
    """--no-color / NO_COLOR: no color escape codes at all."""
    for name in ('CYAN', 'GREEN', 'YELLOW', 'RED', 'BLUE', 'WHITE', 'GRAY', 'BOLD', 'ENDC'):
        setattr(Colors, name, '')


# --- Live receiver view -----------------------------------------------------

class LiveView:
    """Full-screen receiver: status bar, stream table, scrolling log region
    (VT100 scroll region) and a key help line. Fed by PacketReceiver."""

    INTERVALS = (1, 2, 3, 5, 10, 20, 30, 60)
    HELP = (('q', 'Stop'), ('p', 'Pause'), ('r', 'Reset'), ('i', 'IP'),
            ('d', 'Packets/Summary'), ('+/-', 'Interval'))

    def __init__(self):
        self.rx = None
        self.keys = _Keys()
        self.paused = False
        self.active = False
        self.last_poll = 0.0
        self.last_draw = 0.0
        self._size = (80, 24)
        self._prev = {}

    # -- lifecycle -----------------------------------------------------------
    def start(self):
        self.keys.start()
        self.active = True
        self._layout()

    def stop(self):
        if not self.active:
            return
        self.active = False
        try:
            _w(_ESC + '[?7h' + _ESC + '[r' + _ESC + f'[{self._size[1]};1H' + _RESET
               + _ESC + '[K\n')
        except (OSError, ValueError):
            pass
        self.keys.stop()

    def _layout(self):
        cols, rows = shutil.get_terminal_size((80, 24))
        self._size = (cols, rows)
        self.n_alloc = 2 if rows < 20 else 4 if rows < 30 else 8
        self.log_top = self.n_alloc + 8
        self.log_bottom = rows - 1
        _w(_ESC + '[?7l' + _ESC + '[2J' + _ESC + f'[{self.log_top};{self.log_bottom}r'
           + _ESC + f'[{self.log_bottom};1H')
        self.draw()

    # -- drawing -----------------------------------------------------------
    @staticmethod
    def _fmt_dly(stats, which):
        if stats.count == 0:
            return 'n/a'
        v = {'avg': stats.avg, 'min': stats.minimum, 'max': stats.maximum}[which]
        return f"{v:.2f}"

    def _sync_text(self, s):
        if self.rx.sync.mode == 'off':
            return 'off'
        slot = s.sync
        if slot is None or slot.port == 0:
            return 'none'
        if slot.client:
            return 'ok'
        return 'FAIL' if slot.failed else 'wait'

    def _columns(self, width, pc):
        """Column layout of the stream table for this width (widest that fits)."""
        def build(extra, mn, sep_sync, ordc, sepall=False, missc=True):
            g1 = [('st', 'St', 2, '<'), ('src', 'Source', 15, '<')]
            if pc:
                g1.append(('port', 'Port', 5, '>'))
            g1.append(('cast', 'Cast', 4, '<') if mn else ('cast', 'Ty', 2, '<'))
            g2 = [('pk', 'Packets', 8, '>'), ('loss', 'Loss%', 6, '>')]
            if missc:
                g2.append(('miss', 'Miss', 5, '>'))
            if ordc:
                g2.append(('ord', 'Ord', 3, '>'))
            g3 = [('avg', 'Avg', 6, '>')] + ([('min', 'Min', 6, '>')] if mn else []) \
                + [('max', 'Max', 6, '>')]
            mb, sy = ('mbit', 'Mbit/s', 7, '>'), ('sync', 'Sync', 4, '<')
            groups = [g1, g2, g3] + ([[mb], [sy]] if sep_sync else [[mb, sy]])
            if extra:
                groups.append([('sport', 'SPort', 5, '>'), ('dscp', 'DSCP', 6, '>'),
                               ('size', 'Size', 6, '>')])
            if sepall:      # every column on its own, separated by ' | '
                groups = [[c] for g in groups for c in g]
            return groups
        return _tbl_pick([build(True, True, True, True, True), build(False, True, True, True, True),
                          build(False, False, True, True, True), build(False, False, True, False, True),
                          build(True, True, True, True), build(False, True, True, True),
                          build(False, False, True, True), build(False, False, False, True),
                          build(False, False, False, False),
                          build(False, False, False, False, False, False)], width)

    def draw(self):
        rx = self.rx
        cols, rows = self._size
        width = cols            # autowrap is off in this view
        now = time.monotonic()
        dt = now - self.last_draw if self.last_draw else 0.0
        self.last_draw = now

        streams = list(rx.streams.values())
        if rx.unicast_mode:
            where = f"unicast {format_ports(rx.ports)}"
        else:
            where = f"{rx.group or 'any'}:{format_ports(rx.ports)}"
        flags = ""
        if self.paused:
            flags += "  [PAUSED]"
        if rx.summary_interval:
            flags += f"  summary {rx.summary_interval}s"
        status = (f" mautg v{VERSION}  {where}  sync {rx.sync.mode}  "
                  f"streams {len(streams)}  {format_elapsed(now - rx.start_time)}{flags}")
        warn = rx.health_text(now)

        pc = rx.port_col
        groups = self._columns(width, pc)
        head = _tbl_row(groups)
        rule = '-' * width
        bar = _sty('bar')
        fr = _sty('frame')
        rs = _RESET if fr else ''
        n = self.n_alloc
        out = [_ESC + '7',
               _ESC + '[1;1H' + bar + status[:width]
               + ((_RESET + _ESC + '[1m' + Colors.RED + warn[:max(0, width - len(status))]
                   + _RESET + bar) if warn and Colors.RED else warn[:max(0, width - len(status))])
               + _pad_credit(width - len(status) - len(warn)) + _RESET + _ESC + '[K',
               _ESC + '[2;1H' + fr + rule + rs + _ESC + '[K',
               _ESC + '[3;1H' + _ESC + '[1m' + head[:width] + _RESET + _ESC + '[K',
               _ESC + '[4;1H' + fr + rule + rs + _ESC + '[K']
        for i in range(n):
            line = ''
            if i < len(streams):
                if i == n - 1 and len(streams) > n:
                    line = f" ... +{len(streams) - n + 1} more streams"
                else:
                    s = streams[i]
                    prev = self._prev.get(s.label)
                    mbps = prev[2] if prev else 0.0
                    if prev is None or dt >= 0.4:
                        if prev and dt > 0:
                            mbps = (s.total_bytes - prev[0]) * 8 / (dt * 1e6)
                        self._prev[s.label] = (s.total_bytes, now, mbps)
                    sync = self._sync_text(s)
                    dname = dscp_to_name(s.last_dscp) + ('*' if len(s.dscp_stats) > 1 else '')
                    size = s.total_bytes // s.total_packets if s.total_packets else 0
                    loss = s.loss_pct()
                    vals = {
                        'st': s.label, 'src': s.ip, 'port': s.port, 'cast': s.cast or '--',
                        'pk': _short(s.total_packets, 8),
                        'loss': f"{loss:.2f}" if loss < 100 else "100",
                        'miss': _short(s.total_missing, 5), 'ord': _short(s.total_misorder, 3),
                        'avg': self._fmt_dly(s.delay_stats, 'avg'),
                        'min': self._fmt_dly(s.delay_stats, 'min'),
                        'max': self._fmt_dly(s.delay_stats, 'max'),
                        'mbit': f"{mbps:.2f}", 'sync': sync,
                        'sport': s.sync_port, 'dscp': dname, 'size': f"{size}B"}
                    colors = {
                        'loss': Colors.YELLOW if s.total_missing else Colors.GREEN,
                        'sync': {'ok': Colors.GREEN, 'FAIL': Colors.RED,
                                 'wait': Colors.YELLOW, 'off': Colors.GRAY}.get(sync, '')}

                    line = _tbl_row(groups, vals, colors)
            elif i == 0 and not streams:
                line = Colors.GRAY + " waiting for traffic ..." + Colors.ENDC
            out.append(_ESC + f'[{5 + i};1H' + line + _ESC + '[K')
        out.append(_ESC + f'[{5 + n};1H' + fr + rule + rs + _ESC + '[K')
        out.append(_ESC + f'[{6 + n};1H' + _ESC + '[1m' + rx.log_header()[:width] + _RESET + _ESC + '[K')
        out.append(_ESC + f'[{7 + n};1H' + fr + rule + rs + _ESC + '[K')
        out.append(_ESC + f'[{rows};1H' + _keybar(self.HELP, width) + _ESC + '[K')
        out.append(_ESC + '8')
        _w(''.join(out))

    # -- keys / periodic work ------------------------------------------------
    def tick(self, now):
        """Called from the receive loop; raises KeyboardInterrupt on 'q'."""
        if now - self.last_poll >= 0.1:
            self.last_poll = now
            while True:
                k = self.keys.read(0)
                if k is None:
                    break
                if self._handle(k, now):
                    raise KeyboardInterrupt
            if shutil.get_terminal_size((80, 24)) != self._size:
                self._layout()
        if now - self.last_draw >= 0.5:
            self.draw()

    def _handle(self, key, now):
        rx = self.rx
        k = key.lower() if len(key) == 1 else key
        if k == 'q':
            return True
        if k == 'p':
            self.paused = not self.paused
        elif k == 'i':
            rx.show_ip = not rx.show_ip
        elif k == 'd':
            if rx.summary_interval:
                rx.summary_last = rx.summary_interval
                rx.summary_interval = None
            else:
                rx.summary_interval = rx.summary_last
            rx.reset_interval(now)
        elif k in ('+', '=', '-', '_'):
            steps = self.INTERVALS
            cur = rx.summary_interval
            if not cur:
                new = rx.summary_last
            elif k in ('+', '='):
                new = next((v for v in steps if v > cur), steps[-1])
            else:
                new = next((v for v in reversed(steps) if v < cur), steps[0])
            rx.summary_interval = rx.summary_last = new
            rx.reset_interval(now)
        elif k == 'r':
            rx.reset()
            self._prev.clear()
            self._layout()
            return False
        elif k == 'ctrl-l':
            self._layout()
        self.draw()
        return False


# --- Form menu ----------------------------------------------------------------

class _Field:
    def __init__(self, label, kind, get=None, set=None, choices=(), lo=None,
                 hi=None, enabled=None, show=None, action=None, check=None,
                 on_change=None, items=None, cast=None, title=''):
        self.label = label
        self.kind = kind          # text int float bool choice button sep
        self.get = get
        self.set = set
        self.choices = list(choices)
        self.lo = lo
        self.hi = hi
        self.enabled = enabled
        self.show = show
        self.action = action
        self.check = check
        self.on_change = on_change
        self.items = items        # pick: callable -> [(label, value)]
        self.cast = cast          # pick: manual text -> value
        self.title = title

    def is_enabled(self):
        return self.enabled is None or self.enabled()

    @property
    def selectable(self):
        return self.kind != 'sep' and self.is_enabled()


def _dict_field(label, kind, d, key, **kw):
    return _Field(label, kind, lambda: d.get(key), lambda v: d.__setitem__(key, v), **kw)


class _StreamProxy:
    """dict-like view of the stream currently shown in the sender form."""

    def __init__(self, tui):
        self._t = tui

    def get(self, key, default=None):
        return self._t.cur_stream().get(key, default)

    def __getitem__(self, key):
        return self._t.cur_stream()[key]

    def __setitem__(self, key, value):
        self._t.cur_stream()[key] = value


class TUI:
    LABEL_W = 22
    tab_names = ('Sender', 'Receiver')
    multi_form = True         # sender tab: Left/Right switch between streams
    send_idx = 0

    def __init__(self, cfg, sync_server, tab=0):
        self.cfg = cfg
        self.sync_server = sync_server
        self.keys = _Keys()
        self.tab = tab
        self.edit = None          # {'buf': [chars], 'pos': int}
        self.dialog = None        # index of the highlighted option
        self.popup = None         # pick list: {'field','items','idx','off'}
        self.msg = ''
        self.err = False
        self.dirty = True
        self.full = True
        self._size = None
        self.utf = _utf8_terminal()
        self._init_virtual()
        self.send_idx = 0
        self.pages = [self._sender_page(), self._receiver_page()]
        self.sel = [self._first(p) for p in self.pages]
        self.off = [0, 0]
        self.base = self._snapshot()

    # -- streams of the sender form ---------------------------------------------
    def _extras(self):
        return self.cfg['send'].setdefault('extra_streams', [])

    def n_streams(self):
        return 1 + len(self._extras())

    def cur_stream(self):
        """Settings dict of the stream shown in the sender form (stream 1 =
        the send settings themselves, the others the saved extra streams)."""
        if self.send_idx <= 0 or self.send_idx > len(self._extras()):
            self.send_idx = 0
            return self.cfg['send']
        return self._extras()[self.send_idx - 1]

    def _all_streams(self):
        return [_stream_params(self.cfg['send'])] + [_stream_params(x) for x in self._extras()]

    def _switch_stream(self, step):
        n = self.n_streams()
        if n > 1:
            self.send_idx = (self.send_idx + step) % n
            self._say(f"Stream {self.send_idx + 1} of {n}")

    def _new_stream(self):
        n = self.n_streams()
        if n >= SEND_MAX_STREAMS:
            self._say(f"Maximum of {SEND_MAX_STREAMS} streams", True)
            return
        new = _stream_params(self.cur_stream())
        used = {q['destination_port'] for q in self._all_streams()}
        port = new['destination_port']
        while port in used and port < 65535:
            port += 1
        new['destination_port'] = port
        self._extras().append(new)
        self.send_idx = n
        self._select('Destination')
        self._say(f"Stream {n + 1} created (copy of the previous one)")

    def _delete_stream(self):
        if self.n_streams() <= 1:
            self._say('The only stream cannot be deleted', True)
            return
        i = self.send_idx
        if i == 0:
            first = self._extras().pop(0)
            self.cfg['send'].update(_stream_params(first))
        else:
            self._extras().pop(i - 1)
        self.send_idx = max(0, i - 1)
        self._say(f"Stream {i + 1} deleted")

    def _tab_names(self):
        names = list(self.tab_names)
        if len(names) == 2 and self.n_streams() > 1:
            names[0] = f"Sender {self.send_idx + 1}/{self.n_streams()}"
        return names

    # -- config <-> virtual fields --------------------------------------------
    def _init_virtual(self):
        rc = self.cfg['recv']
        ip = rc.get('sender_ip', '')
        rc['_sync_mode'] = 'auto' if not ip else ('off' if ip == 'none' else 'sender IP')
        rc['_ip'] = '' if ip in ('', 'none') else ip
        lg = rc.get('log', '')
        rc['_log_mode'] = 'off' if not lg else ('auto' if lg == 'auto' else 'file')
        rc['_log_file'] = '' if lg in ('', 'auto') else lg

    def _apply_virtual(self):
        rc = self.cfg['recv']
        mode = rc['_sync_mode']
        rc['sender_ip'] = '' if mode == 'auto' else ('none' if mode == 'off' else rc['_ip'].strip())
        lm = rc['_log_mode']
        rc['log'] = '' if lm == 'off' else ('auto' if lm == 'auto' else rc['_log_file'].strip())

    def _snapshot(self):
        self._apply_virtual()
        clean = {k: ({kk: vv for kk, vv in v.items() if not kk.startswith('_')}
                     if isinstance(v, dict) else v) for k, v in self.cfg.items()}
        return json.dumps(clean, sort_keys=True, default=str)

    @property
    def modified(self):
        return self._snapshot() != self.base

    # -- pages ----------------------------------------------------------------
    def _set_sync_port(self, v):
        if v == self.cfg['sync_port']:
            return
        self.cfg['sync_port'] = v
        try:
            self.sync_server.restart(v)
        except OSError as e:
            self._say(f"OWD sync server: {e}", True)

    _MANUAL = object()

    @staticmethod
    def _dscp_items():
        items = [(f"{v:>2}  {n:<5s} {d}", v) for v, n, d in DSCP_TABLE]
        items.append(("    Custom value (0-63)...", TUI._MANUAL))
        return items

    @staticmethod
    def _source_items():
        items = [("any            let the OS choose", "")]
        for ip, name in local_ipv4_addresses():
            items.append((f"{ip:<15s} {name}", ip))
        items.append(("Other address...", TUI._MANUAL))
        return items

    def _sender_page(self):
        sc = _StreamProxy(self)
        burst = lambda: bool(sc.get('burst_mode'))
        return [
            _Field('Stream', 'text', lambda: self.send_idx,
                   lambda v: None, enabled=lambda: False,
                   show=lambda v: (f"{v + 1} of {self.n_streams()} - Left/Right: switch"
                                   if self.n_streams() > 1
                                   else "1 of 1 - New stream adds more")),
            _dict_field('Destination', 'text', sc, 'destination_address',
                        check=lambda t: '' if t.strip() else 'Destination required'),
            _dict_field('Destination port', 'int', sc, 'destination_port', lo=1, hi=65535),
            _dict_field('Packet size (bytes)', 'int', sc, 'packet_size',
                        lo=_MIN_PACKET_SIZE + _UDP_IP_OVERHEAD, hi=65507),
            _Field('Mode', 'choice', lambda: 'Burst' if burst() else 'Normal',
                   lambda v: sc.__setitem__('burst_mode', v == 'Burst'),
                   choices=['Normal', 'Burst']),
            _dict_field('Rate (pps)', 'float', sc, 'packets_per_second', lo=0.01, hi=10_000_000,
                        enabled=lambda: not burst()),
            _dict_field('Burst limit (Mbit/s)', 'float', sc, 'burst_mbps', lo=0, hi=1_000_000,
                        enabled=burst,
                        show=lambda v: 'unlimited' if not v else f"{v:g}"),
            _dict_field('DSCP', 'pick', sc, 'dscp_value', lo=0, hi=63, cast=int,
                        items=self._dscp_items, title='DSCP value',
                        show=lambda v: f"{v} ({dscp_to_name(v)})"),
            _dict_field('TTL', 'int', sc, 'ttl', lo=1, hi=255),
            _dict_field("Don't fragment (DF)", 'bool', sc, 'df_bit'),
            _dict_field('Source address', 'pick', sc, 'source_address',
                        items=self._source_items, title='Source address (this host)',
                        check=lambda t: '' if (not t or _ip_usable(t))
                        else f"{t} is not an address of this host",
                        show=lambda v: v or 'any'),
            _dict_field('Source port', 'int', sc, 'source_port', lo=0, hi=65535,
                        show=lambda v: 'any' if not v else str(v)),
            _Field('Local OWD sync port', 'int', lambda: self.cfg['sync_port'],
                   self._set_sync_port, lo=1, hi=65535),
            _Field('', 'sep'),
            _Field('[ Start sender ]', 'button', action='start'),
            _Field('[ New stream ]', 'button', action='newstream'),
            _Field('[ Delete this stream ]', 'button', action='delstream'),
            _Field('[ Save settings ]', 'button', action='save'),
        ]

    @staticmethod
    def _iface_items():
        items = [("all            every interface (default)", "all"),
                 ("auto           the kernel picks it from the routing table", "auto")]
        for ip, name in local_ipv4_addresses():
            if not ip.startswith('127.'):
                items.append((f"{ip:<15s} {name}", ip))
        items.append(("Other address / interface name...", TUI._MANUAL))
        return items

    @staticmethod
    def _check_iface(text):
        try:
            resolve_mcast_interfaces(text)
            return ''
        except ValueError as e:
            return str(e)

    @staticmethod
    def _iface_show(v):
        v = v or 'all'
        if v in ('all', 'auto'):
            return v
        name = dict(local_ipv4_addresses()).get(v, '')
        return f"{v} {name}".strip()

    @staticmethod
    def _check_groups(text):
        try:
            parse_groups(text)
            return ''
        except ValueError as e:
            return str(e)

    @staticmethod
    def _check_ports(text):
        try:
            parse_ports(text)
            return ''
        except ValueError as e:
            return str(e)

    def _receiver_page(self):
        rc = self.cfg['recv']
        mode = lambda: rc['_sync_mode']

        def log_show(_v):
            if rc['_log_mode'] == 'auto':
                if not rc.get('_log_name'):
                    rc['_log_name'] = default_log_name()
                return rc['_log_name']
            return rc['_log_file'] or ('-' if rc['_log_mode'] == 'off' else '')

        return [
            _Field('Receive mode', 'choice',
                   lambda: 'Unicast' if rc['unicast'] else 'Multicast',
                   lambda v: rc.__setitem__('unicast', v == 'Unicast'),
                   choices=['Multicast', 'Unicast']),
            _dict_field('Multicast group(s)', 'text', rc, 'group',
                        enabled=lambda: not rc['unicast'],
                        check=self._check_groups),
            _dict_field('Multicast interface', 'pick', rc, 'interface',
                        enabled=lambda: not rc['unicast'],
                        items=self._iface_items, title='Multicast join on',
                        check=self._check_iface, show=self._iface_show),
            _Field('Data port(s)', 'text', lambda: str(rc['port']),
                   lambda v: rc.__setitem__('port', int(v) if v.isdigit() else v.replace(' ', '')),
                   check=self._check_ports),
            _dict_field('OWD sync', 'choice', rc, '_sync_mode',
                        choices=['auto', 'sender IP', 'off']),
            _dict_field('Sender IP', 'text', rc, '_ip',
                        enabled=lambda: mode() == 'sender IP'),
            _dict_field('Sender sync port', 'int', rc, 'sender_sync_port', lo=0, hi=65535,
                        enabled=lambda: mode() != 'off',
                        show=lambda v: 'from packet' if not v else str(v)),
            _dict_field('Resync interval (s)', 'float', rc, 'resync_interval', lo=0.5, hi=3600,
                        enabled=lambda: mode() != 'off'),
            _dict_field('Summary (s)', 'int', rc, 'summary', lo=0, hi=3600,
                        show=lambda v: 'per packet' if not v else f"every {v} s"),
            _dict_field('Compact summary', 'bool', rc, 'compact',
                        enabled=lambda: rc['summary'] > 0),
            _dict_field('Show sender IP', 'bool', rc, 'show_ip'),
            _dict_field('Verify every packet', 'bool', rc, 'verify'),
            _dict_field('CSV log', 'choice', rc, '_log_mode', choices=['off', 'auto', 'file']),
            _dict_field('Log file name', 'text', rc, '_log_file',
                        enabled=lambda: rc['_log_mode'] == 'file', show=log_show),
            _dict_field('Live view', 'bool', rc, 'live'),
            _Field('Local OWD sync port', 'int', lambda: self.cfg['sync_port'],
                   self._set_sync_port, lo=1, hi=65535),
            _Field('', 'sep'),
            _Field('[ Start receiver ]', 'button', action='start'),
            _Field('[ Save settings ]', 'button', action='save'),
        ]

    @staticmethod
    def _first(page):
        for i, f in enumerate(page):
            if f.selectable:
                return i
        return 0

    # -- helpers --------------------------------------------------------------
    def _select(self, label):
        for i, f in enumerate(self.pages[self.tab]):
            if f.label == label:
                self.sel[self.tab] = i

    def _say(self, text, err=False):
        self.msg, self.err, self.dirty = text, err, True

    def _value_text(self, f):
        v = f.get() if f.get else None
        if f.show:
            return f.show(v)
        if f.kind == 'bool':
            return '[x]' if v else '[ ]'
        if f.kind == 'choice':
            return f"< {v} >"
        if f.kind == 'float':
            return f"{v:g}"
        return '' if v is None else str(v)

    def _move(self, delta):
        page, i = self.pages[self.tab], self.sel[self.tab]
        n = len(page)
        for _ in range(n):
            i = (i + delta) % n
            if page[i].selectable:
                self.sel[self.tab] = i
                return

    # -- drawing --------------------------------------------------------------
    def _chars(self):
        if self.utf:
            return '┌', '┐', '└', '┘', '─', '│'
        return '+', '+', '+', '+', '-', '|'

    def _row(self, f, selected, inner):
        tl, tr, bl, br, h, v = self._chars()
        fr = _sty('frame')
        v = fr + v + _RESET if fr else v
        if f.kind == 'sep':
            return v + ' ' * inner + v
        left = f" {f.label:<{self.LABEL_W}} " if f.kind != 'button' else f"  {f.label}"
        editing = self.edit is not None and selected
        if editing:
            buf, pos = self.edit['buf'], self.edit['pos']
            room = max(1, inner - len(left) - 1)
            start = max(0, pos - room + 1)
            shown = buf[start:start + room]
            p = pos - start
            before = ''.join(shown[:p])
            cur = shown[p] if p < len(shown) else ' '
            after = ''.join(shown[p + 1:])
            pad = inner - len(left) - len(before) - 1 - len(after)
            vc = _sty('val')
            return (v + left + vc + before + _RESET + _REV + cur + _RESET + vc + after
                    + _RESET + ' ' * max(0, pad) + v)
        enabled = f.is_enabled()
        val = '' if f.kind == 'button' else self._value_text(f)
        if f.kind != 'button' and not enabled:
            val = f"({val})"
        room = max(0, inner - len(left))
        val = val[:room]
        pad = ' ' * max(0, inner - len(left) - len(val))
        if selected:
            return v + _sty('sel') + (left + val + pad)[:inner] + _RESET + v
        if f.kind == 'button':
            return v + _sty('btn') + (left + pad)[:inner] + _RESET + v
        if not enabled:
            return v + _sty('off') + (left + val + pad)[:inner] + _RESET + v
        raw = f.get() if f.get else None
        if f.kind == 'choice':
            vc = _sty('choice')
        elif f.kind == 'bool':
            vc = _sty('on') if raw else _sty('off')
        else:
            vc = _sty('val')
        return v + left[:inner] + vc + val + _RESET + pad + v

    def _help_pairs(self):
        if self.popup is not None:
            return (('Up/Down', 'Select'), ('Enter', 'Choose'), ('Esc', 'Cancel'))
        if self.dialog is not None:
            return (('Left/Right', 'Choose'), ('Enter', 'Confirm'), ('Esc', 'Quit'))
        if self.edit is not None:
            return (('Enter', 'Accept'), ('Esc', 'Cancel'), ('Ctrl-U', 'Clear'),
                    ('Left/Right', 'Move'))
        f = self.pages[self.tab][self.sel[self.tab]]
        sender = self.multi_form and self.tab == 0
        what = {'bool': ('Space', 'Toggle'),
                'choice': ('Space', 'Change') if sender else ('Left/Right', 'Change'),
                'button': ('Enter', 'Run'),
                'pick': ('Enter', 'Choose from list')}.get(f.kind, ('Enter', 'Edit'))
        if sender and self.n_streams() > 1:
            return (('Up/Down', 'Select'), what, ('Left/Right', 'Stream'),
                    ('s/r', 'Tab'), ('Esc/q', 'Quit'))
        return (('Up/Down', 'Select'), what, ('s/r', 'Sender/Receiver'),
                ('Esc/q', 'Quit'))

    def draw(self):
        cols, rows = shutil.get_terminal_size((80, 24))
        size = (cols, rows)
        out = []
        if self.full or size != self._size:
            out.append(_ESC + '[2J')
            self.full = False
        self._size = size
        W = max(40, min(cols - 1, 80))
        inner = W - 2
        tl, tr, bl, br, h, v = self._chars()
        fr = _sty('frame')
        rs = _RESET if fr else ''

        # top border with tabs
        title = f" mautg v{VERSION}{'*' if self.modified else ''} "
        names = self._tab_names()
        used = 1 + 1 + len(title) + 2 + sum(len(n) + 2 + 1 for n in names) + 1
        top = fr + tl + h + rs + _sty('title') + title + _RESET + fr + h + h + rs
        for i, n in enumerate(names):
            if i == self.tab:
                top += _sty('sel') + f" {n} " + _RESET
            else:
                top += f" {n} "
            top += fr + h + rs
        top += fr + h * max(0, W - used) + tr + rs

        body_h = rows - 4
        page = self.pages[self.tab]
        sel = self.sel[self.tab]
        off = self.off[self.tab]
        if sel < off:
            off = sel
        if sel >= off + body_h:
            off = sel - body_h + 1
        self.off[self.tab] = off

        lines = [top]
        vv = fr + v + rs
        for i in range(body_h):
            idx = off + i
            lines.append(self._row(page[idx], idx == sel, inner) if idx < len(page)
                         else vv + ' ' * inner + vv)
        cr = _credit(inner - 6)
        if cr:
            lines.append(fr + bl + h * (inner - len(cr) - 5) + rs + ' ' + cr + ' '
                         + fr + h * 3 + br + rs)
        else:
            lines.append(fr + bl + h * inner + br + rs)

        if self.dialog is not None:
            opts = ['Save & quit', 'Quit without saving', 'Cancel']
            msg = ' Unsaved changes:  ' + '  '.join(
                (_sty('sel') + f" {o} " + _RESET) if i == self.dialog else f" {o} "
                for i, o in enumerate(opts))
            lines.append(msg)
        else:
            colr = (Colors.RED if self.err else Colors.GREEN) if self.msg else ''
            lines.append(colr + (' ' + self.msg)[:W] + (Colors.ENDC if colr else ''))
        lines.append(_keybar(self._help_pairs(), W))

        for i, ln in enumerate(lines):
            out.append(_ESC + f'[{i + 1};1H' + ln + _ESC + '[K')
        if self.popup is not None:
            for r, c, t in self._popup_lines(cols, rows):
                out.append(_ESC + f'[{r};{c}H' + t)
        out.append(_ESC + '[?25l')
        _w(''.join(out))
        self.dirty = False

    # -- input ----------------------------------------------------------------
    def _open_popup(self, f):
        items = f.items()
        cur = f.get()
        idx = next((i for i, (_l, v) in enumerate(items) if v == cur and v is not self._MANUAL), 0)
        self.popup = {'field': f, 'items': items, 'idx': idx, 'off': 0}
        self.dirty = True

    def _popup_key(self, k):
        pp = self.popup
        n = len(pp['items'])
        step = {'up': -1, 'down': 1, 'pgup': -8, 'pgdn': 8}.get(k)
        if step:
            pp['idx'] = max(0, min(n - 1, pp['idx'] + step))
        elif k == 'home':
            pp['idx'] = 0
        elif k == 'end':
            pp['idx'] = n - 1
        elif k == 'esc':
            self.popup = None
        elif k in ('enter', ' '):
            f = pp['field']
            label, value = pp['items'][pp['idx']]
            self.popup = None
            if value is self._MANUAL:
                self._begin_edit(f)
            else:
                f.set(value)
                self._say('')
        self.dirty = True

    def _popup_lines(self, cols, rows):
        """(row, col, text) lines of the pick list drawn over the form."""
        pp = self.popup
        items = pp['items']
        W = max(30, min(cols - 1, 64))
        inner = W - 2
        h = max(3, min(len(items), rows - 6))
        if pp['idx'] < pp['off']:
            pp['off'] = pp['idx']
        if pp['idx'] >= pp['off'] + h:
            pp['off'] = pp['idx'] - h + 1
        tl, tr, bl, br, hz, vt = self._chars()
        fr, rs = _sty('frame'), _RESET
        top = max(2, (rows - (h + 2)) // 2 + 1)
        left = max(1, (cols - W) // 2 + 1)
        title = f" {pp['field'].title or pp['field'].label} "
        out = [(top, left, fr + tl + hz + rs + _sty('title') + title[:inner - 2] + rs + fr
                + hz * max(0, inner - 1 - len(title[:inner - 2])) + tr + rs)]
        for i in range(h):
            idx = pp['off'] + i
            label = items[idx][0] if idx < len(items) else ''
            text = (' ' + label)[:inner].ljust(inner)
            if idx == pp['idx']:
                text = _sty('sel') + text + rs
            out.append((top + 1 + i, left, fr + vt + rs + text + fr + vt + rs))
        more = ('' if len(items) <= h else f" {pp['idx'] + 1}/{len(items)} ")
        out.append((top + h + 1, left, fr + bl + hz * (inner - len(more)) + more + br + rs))
        return out

    def _begin_edit(self, f):
        v = f.get()
        text = f"{v:g}" if f.kind == 'float' else ('' if v is None else str(v))
        self.edit = {'buf': list(text), 'pos': len(text)}
        self.dirty = True

    def _commit_edit(self, f):
        text = ''.join(self.edit['buf']).strip()
        try:
            if f.kind == 'int' or (f.kind == 'pick' and f.cast):
                val = int(text)
            elif f.kind == 'float':
                val = float(text)
            else:
                val = text
                if f.check:
                    problem = f.check(text)
                    if problem:
                        self._say(problem, True)
                        return
        except ValueError:
            self._say('Not a valid number', True)
            return
        if f.kind in ('int', 'float', 'pick') and f.lo is not None and (
                (f.lo is not None and val < f.lo) or (f.hi is not None and val > f.hi)):
            self._say(f"Value must be between {f.lo:g} and {f.hi:g}", True)
            return
        f.set(val)
        self.edit = None
        self._say('')

    def _edit_key(self, k, f):
        e = self.edit
        buf, pos = e['buf'], e['pos']
        if k == 'enter':
            self._commit_edit(f)
        elif k == 'esc':
            self.edit = None
            self._say('')
        elif k == 'left':
            e['pos'] = max(0, pos - 1)
        elif k == 'right':
            e['pos'] = min(len(buf), pos + 1)
        elif k == 'home':
            e['pos'] = 0
        elif k == 'end':
            e['pos'] = len(buf)
        elif k == 'backspace':
            if pos > 0:
                del buf[pos - 1]
                e['pos'] = pos - 1
        elif k == 'delete':
            if pos < len(buf):
                del buf[pos]
        elif k == 'ctrl-u':
            buf.clear()
            e['pos'] = 0
        elif len(k) == 1 and k >= ' ':
            buf.insert(pos, k)
            e['pos'] = pos + 1
        self.dirty = True

    def _dialog_key(self, k):
        if k == 'left':
            self.dialog = (self.dialog - 1) % 3
        elif k in ('right', 'tab'):
            self.dialog = (self.dialog + 1) % 3
        elif k == 'esc':
            self.dialog = None
            return 'quit'
        elif k == 'enter':
            choice, self.dialog = self.dialog, None
            if choice == 0:
                self._save()
                return 'quit'
            if choice == 1:
                return 'quit'
        self.dirty = True
        return None

    def _save(self):
        self._apply_virtual()
        save_config(self.cfg)
        self.base = self._snapshot()
        self._say(f"Saved to {CONFIG_DIR / 'config.json'}")

    def _validate_start(self):
        rc = self.cfg['recv']
        if self.tab == 1 and rc['_sync_mode'] == 'sender IP' and not rc['_ip'].strip():
            self._select('Sender IP')
            return 'Sender IP required (or set OWD sync to auto / off)'
        if self.tab == 1 and rc['_log_mode'] == 'file' and not rc['_log_file'].strip():
            self._select('Log file name')
            return 'Log file name required'
        if self.tab == 0:
            seen = {}
            for i, q in enumerate(self._all_streams()):
                problem = check_stream_params(q)
                key = (q['source_address'], q['destination_port'])
                if not problem and key in seen:
                    problem = (f"same destination port as stream {seen[key] + 1} - "
                               f"a receiver would merge them")
                seen.setdefault(key, i)
                if problem:
                    self.send_idx = i
                    self._select('Destination')
                    return f"Stream {i + 1}: {problem}"
        return ''

    def _start(self, autostart=True):
        problem = self._validate_start()
        if problem:
            self._say(problem, True)
            return
        self._apply_virtual()
        self.keys.stop()
        _w(_RESET + _ESC + '[?25h' + _ESC + '[2J' + _ESC + '[H')
        try:
            if self.tab == 0:
                run_sender(self.cfg, self.sync_server, streams_from_config(self.cfg),
                           autostart=autostart)
            else:
                rc = self.cfg['recv']
                run_receiver(rc, live=bool(rc.get('live')))
        except KeyboardInterrupt:
            pass
        print(f"{Colors.CYAN}Press any key to return to the menu...{Colors.ENDC}")
        self.keys.start()
        try:
            self.keys.read(None)
        except KeyboardInterrupt:
            pass
        self.full = True
        self.dirty = True
        self._say('')

    def _on_key(self, k):
        if self.dialog is not None:
            return self._dialog_key(k)
        if self.popup is not None:
            self._popup_key(k)
            return None
        page = self.pages[self.tab]
        f = page[self.sel[self.tab]]
        if self.edit is not None:
            self._edit_key(k, f)
            return None
        self.dirty = True
        if k == 'up':
            self._move(-1)
        elif k == 'down':
            self._move(1)
        elif k == 'home':
            self.sel[self.tab] = self._first(page)
        elif k == 'end':
            self.sel[self.tab] = len(page) - 1
        elif self.multi_form and k in ('s', 'S', 'r', 'R'):
            self.tab = 0 if k in ('s', 'S') else 1
            self._say('')
        elif k in ('tab', 'btab'):
            self.tab = (self.tab + (1 if k == 'tab' else -1)) % 2
            self._say('')
        elif k in ('esc', 'q'):
            if self.modified:
                self.dialog = 0
            else:
                return 'quit'
        elif self.multi_form and self.tab == 0 and k in ('left', 'right'):
            self._switch_stream(1 if k == 'right' else -1)
        elif f.kind == 'bool' and k in (' ', 'enter', 'left', 'right'):
            f.set(not f.get())
            self._say('')
        elif f.kind == 'choice' and k in (' ', 'enter', 'left', 'right'):
            i = f.choices.index(f.get()) if f.get() in f.choices else 0
            i = (i - 1 if k == 'left' else i + 1) % len(f.choices)
            f.set(f.choices[i])
            if f.label == 'CSV log' and f.choices[i] == 'auto':
                self.cfg['recv'].pop('_log_name', None)
            self._say('')
        elif f.kind in ('text', 'int', 'float') and k == 'enter':
            self._begin_edit(f)
        elif f.kind == 'pick' and k in ('enter', ' '):
            self._open_popup(f)
        elif f.kind == 'button' and k in ('enter', ' '):
            if f.action == 'save':
                self._save()
            elif f.action == 'newstream':
                self._new_stream()
            elif f.action == 'delstream':
                self._delete_stream()
            else:
                self._start()
        return None

    # -- main loop --------------------------------------------------------------
    def run(self):
        self.keys.start()
        try:
            while True:
                if self.dirty or shutil.get_terminal_size((80, 24)) != self._size:
                    self.draw()
                try:
                    k = self.keys.read(0.5)
                except KeyboardInterrupt:
                    break
                if k is None:
                    continue
                if self._on_key(k) == 'quit':
                    break
        except EOFError:
            pass
        finally:
            self.keys.stop()
            try:
                _w(_RESET + _ESC + '[?25h' + _ESC + '[2J' + _ESC + '[H')
            except (OSError, ValueError):
                pass


# --- Stream editor (one stream, as a popup form) -------------------------------

class StreamEditor(TUI):
    """The sender form for ONE stream, opened from the sender live view. Uses
    the key reader of the view; returns True on Apply, False on Cancel."""

    multi_form = False

    def __init__(self, keys, params, title, apply_label, validate, nav=False,
                 index=0, total=1, sync_port=0):
        self.nav = nav
        self.send_idx = index
        self._total = total
        self.cfg = {'send': params, 'sync_port': sync_port, 'recv': {}}
        self.sync_server = None
        self.keys = keys
        self.tab = 0
        self.tab_names = (title,)
        self.validate = validate
        self.edit = None
        self.dialog = None
        self.popup = None
        self.msg = ''
        self.err = False
        self.dirty = True
        self.full = True
        self._size = None
        self.utf = _utf8_terminal()
        drop = ('[ Start sender ]', '[ Save settings ]', '[ New stream ]',
                '[ Delete this stream ]', '')
        page = [f for f in self._sender_page() if f.label not in drop]
        for f in page:
            if f.label == 'Local OWD sync port':
                f.enabled = lambda: False          # information only here
            elif f.label == 'Stream':
                f.show = lambda v: (f"{v + 1} of {self._total} - Left/Right: switch"
                                    if self.nav else f"{v + 1} of {self._total}")
        page += [_Field('', 'sep'),
                 _Field(f'[ {apply_label} ]', 'button', action='apply'),
                 _Field('[ Cancel ]', 'button', action='cancel')]
        self.pages = [page]
        self.sel = [self._first(page)]
        self.off = [0]

    @property
    def modified(self):
        return False

    def n_streams(self):
        return self._total

    def _help_pairs(self):
        base = super()._help_pairs()
        if self.dialog is not None or self.popup is not None or self.edit is not None:
            return base
        f = self.pages[0][self.sel[0]]
        what = {'bool': ('Space', 'Toggle'), 'choice': ('Space', 'Change'),
                'button': ('Enter', 'Run'),
                'pick': ('Enter', 'Choose from list')}.get(f.kind, ('Enter', 'Edit'))
        if self.nav:
            return (('Up/Down', 'Select'), what, ('Left/Right', 'Stream'),
                    ('Esc/q', 'Cancel'))
        return (('Up/Down', 'Select'), what, ('Esc/q', 'Cancel'))

    def _on_key(self, k):
        if self.dialog is not None or self.popup is not None or self.edit is not None:
            return super()._on_key(k)
        f = self.pages[0][self.sel[0]]
        if k in ('esc', 'q'):
            return 'cancel'
        step = {'tab': 'next', 'pgdn': 'next', 'btab': 'prev', 'pgup': 'prev'}.get(k)
        if step is None and self.nav:
            step = {'right': 'next', 'left': 'prev'}.get(k)
        if step:
            if not self.nav:
                return None
            problem = self.validate(self.cfg['send'])
            if problem:
                self._say(problem, True)
                return None
            return step
        if f.kind == 'button' and k in ('enter', ' '):
            if f.action == 'cancel':
                return 'cancel'
            problem = self.validate(self.cfg['send'])
            if problem:
                self._say(problem, True)
                return None
            return 'apply'
        return super()._on_key(k)

    def run_embedded(self):
        while True:
            if self.dirty or shutil.get_terminal_size((80, 24)) != self._size:
                self.draw()
            try:
                k = self.keys.read(0.2)
            except EOFError:
                return False
            if k is None:
                continue
            r = self._on_key(k)
            if r in ('apply', 'cancel', 'next', 'prev'):
                return r


# --- Sender live view ----------------------------------------------------------

class SenderView:
    """Full-screen sender: table of the streams (up to SEND_MAX_STREAMS), start
    / stop / edit / add / delete while they are running."""

    HELP = (('q', 'Quit'), ('Space', 'Toggle'), ('e', 'Edit'), ('n', 'New'),
            ('d', 'Del'), ('s/x', 'All'), ('w', 'Save'))

    def __init__(self, streams, sync_server, on_save=None):
        self.streams = streams
        self.sync_server = sync_server
        self.on_save = on_save
        self.keys = _Keys()
        self.sel = 0
        self.off = 0
        self.msg = ''
        self.msg_err = False
        self.msg_at = 0.0
        self.confirm = None
        self.start_time = time.monotonic()
        self.last_draw = 0.0
        self._size = (80, 24)
        self.dirty = True

    # -- messages ------------------------------------------------------------
    def say(self, text, err=False):
        self.msg, self.msg_err, self.msg_at, self.dirty = text, err, time.monotonic(), True

    # -- main loop -------------------------------------------------------------
    def run(self, autostart=True):
        self.keys.start()
        try:
            if autostart:
                for st in self.streams:
                    st.start()
            self._layout()
            while True:
                try:
                    k = self.keys.read(0.1)
                except EOFError:
                    break
                if k is not None and self._handle(k):
                    break
                now = time.monotonic()
                if shutil.get_terminal_size((80, 24)) != self._size:
                    self._layout()
                elif self.dirty or now - self.last_draw >= 0.25:
                    self.draw()
        except KeyboardInterrupt:
            pass
        finally:
            for st in self.streams:
                st.stop(wait=False)
            for st in self.streams:
                st.stop()
            try:
                _w(_RESET + _ESC + '[?25h' + _ESC + '[?7h' + _ESC + f'[{self._size[1]};1H'
                   + _ESC + '[K\n')
            except (OSError, ValueError):
                pass
            self.keys.stop()

    def _layout(self):
        self._size = shutil.get_terminal_size((80, 24))
        _w(_ESC + '[?7l' + _ESC + '[2J')
        self.draw()

    # -- drawing -----------------------------------------------------------------
    def _visible(self):
        return max(1, self._size[1] - 9)

    @staticmethod
    def _columns(width):
        def build(ttl, merge, compact, sepn=False):
            size, sent = (4, 5) if compact else (5, 7)
            groups = ([[('n', '#', 2, '>')], [('state', 'State', 7, '<')]] if sepn else
                      [[('n', '#', 2, '>'), ('state', 'State', 7, '<')]]) + [
                      [('dest', 'Destination', 15, '<')], [('port', 'Port', 5, '>')],
                      [('size', 'Size', size, '>')], [('rate', 'Rate', 8, '<')],
                      [('dscp', 'DSCP', 7, '<')]]
            if ttl:
                groups.append([('ttl', 'TTL', 3, '>')])
            sm, mb = ('sent', 'Sent', sent, '>'), ('mbit', 'Mbit/s', 6, '>')
            groups += [[sm, mb]] if merge else [[sm], [mb]]
            return groups
        return _tbl_pick([build(True, False, False, True), build(False, False, False, True),
                          build(True, False, False), build(False, False, False),
                          build(False, True, False), build(False, True, True)], width)

    def draw(self):
        cols, rows = self._size
        width = cols - 1
        now = time.monotonic()
        self.last_draw = now
        self.dirty = False
        for st in self.streams:
            st.sample(now)
        n = len(self.streams)
        if self.msg and now - self.msg_at > 6.0:
            self.msg = ''
        self.sel = max(0, min(self.sel, n - 1)) if n else 0
        vis = self._visible()
        if self.sel < self.off:
            self.off = self.sel
        if self.sel >= self.off + vis:
            self.off = self.sel - vis + 1
        self.off = max(0, min(self.off, max(0, n - vis)))

        sync = (f"sync port {self.sync_server.port}" if self.sync_server.active
                else "sync off")
        running = sum(1 for st in self.streams if st.running)
        status = (f" mautg v{VERSION}  send  {sync}  streams {n}/{SEND_MAX_STREAMS}"
                  f" ({running} running)  {format_elapsed(now - self.start_time)}")
        width = cols            # autowrap is off in this view
        groups = self._columns(width)
        head = _tbl_row(groups)
        sent_w = next(c[2] for g in groups for c in g if c[0] == 'sent')
        rule = '-' * width
        bar = _sty('bar')
        fr = _sty('frame')
        rs = _RESET if fr else ''
        R = lambda row: _ESC + f'[{row};1H'
        out = [_ESC + '[?25l',
               R(1) + bar + (status[:width] + _pad_credit(width - len(status)))[:width] + _RESET + _ESC + '[K',
               R(2) + fr + rule + rs + _ESC + '[K',
               R(3) + _ESC + '[1m' + head[:width] + _RESET + _ESC + '[K',
               R(4) + fr + rule + rs + _ESC + '[K']
        for i in range(vis):
            idx = self.off + i
            line = ''
            if idx < n:
                st = self.streams[idx]
                p = st.params()
                state = st.state_text()
                vals = {'n': idx + 1, 'state': state, 'dest': p['destination_address'],
                        'port': p['destination_port'], 'size': p['packet_size'],
                        'rate': st.rate_text(),
                        'dscp': f"{p['dscp_value']} {dscp_to_name(p['dscp_value'])}",
                        'ttl': p['ttl'], 'sent': _short(st.sent, sent_w),
                        'mbit': f"{st.rate_mbps:.2f}"}
                if idx == self.sel:
                    line = (_sty('sel') + _tbl_row(groups, vals)[:width].ljust(width) + _RESET)
                else:
                    stc = {'running': Colors.GREEN, 'stopped': Colors.GRAY,
                           'ERROR': Colors.RED}.get(state, '')

                    line = _tbl_row(groups, vals, {'state': stc} if stc else None)
            elif idx == 0 and n == 0:
                line = Colors.GRAY + " no streams - press n to create one" + Colors.ENDC
            out.append(R(5 + i) + line + _ESC + '[K')

        # detail block of the selected stream
        d1 = d2 = ''
        if n:
            st = self.streams[self.sel]
            p = st.params()
            d1 = (f" Stream {self.sel + 1}:  source {p['source_address'] or 'any'}:"
                  f"{p['source_port'] or 'any'}   TTL {p['ttl']}   "
                  f"DF {'on' if p['df_bit'] else 'off'}   seq {st.seq}   "
                  f"{st.rate_pps:,.1f} pps now")
            d2 = f" {st.errors} send errors" if st.errors else ''
            if st.error:
                d2 += f"   last error: {st.error}"
            elif st.notes:
                d2 += f" {st.notes[-1]}"
        c2 = Colors.RED if (n and self.streams[self.sel].error) else ''
        out.append(R(5 + vis) + fr + rule + rs + _ESC + '[K')
        out.append(R(6 + vis) + d1[:width] + _ESC + '[K')
        out.append(R(7 + vis) + c2 + d2[:width] + (Colors.ENDC if c2 else '') + _ESC + '[K')
        if self.confirm is not None:
            m = f" Delete stream {self.confirm + 1}?  y = yes, any other key = no"
            out.append(R(rows - 1) + Colors.YELLOW + m[:width] + Colors.ENDC + _ESC + '[K')
        else:
            col = Colors.RED if self.msg_err else Colors.GREEN
            out.append(R(rows - 1) + (col + (' ' + self.msg)[:width] + Colors.ENDC
                                      if self.msg else '') + _ESC + '[K')
        out.append(R(rows) + _keybar(self.HELP, width) + _ESC + '[K')
        _w(''.join(out))

    # -- actions -------------------------------------------------------------------
    def _validate(self, params, ignore=None):
        problem = check_stream_params(params)
        if problem:
            return problem
        for i, st in enumerate(self.streams):
            if i == ignore:
                continue
            q = st.params()
            if (q['destination_port'] == params['destination_port']
                    and q['source_address'] == params['source_address']):
                return (f"Port {params['destination_port']} is already used by stream "
                        f"{i + 1} - a receiver would merge the two")
        return ''

    def _new_params(self):
        if self.streams:
            base = self.streams[self.sel].params()
        else:
            base = _stream_params()
        used = {st.params()['destination_port'] for st in self.streams}
        port = base['destination_port']
        while port in used and port < 65535:
            port += 1
        base['destination_port'] = port
        return base

    def _edit(self, idx):
        if idx is None:
            params = self._new_params()
            n = len(self.streams)
            ed = StreamEditor(self.keys, params, f"Sender {n + 1}/{n + 1} (new)",
                              'Add and start', lambda p: self._validate(p, ignore=None),
                              index=n, total=n + 1, sync_port=self.sync_server.port)
            r = ed.run_embedded()
            self._layout()
            if r == 'apply':
                st = SendStream(params, self.sync_server)
                self.streams.append(st)
                self.sel = len(self.streams) - 1
                st.start()
                self.say(f"Stream {self.sel + 1} added and started")
            return
        while True:
            n = len(self.streams)
            st = self.streams[idx]
            params = st.params()
            ed = StreamEditor(self.keys, params, f"Sender {idx + 1}/{n}", 'Apply',
                              lambda p, i=idx: self._validate(p, ignore=i), nav=n > 1,
                              index=idx, total=n, sync_port=self.sync_server.port)
            r = ed.run_embedded()
            if r == 'cancel':
                break
            st.apply(params)
            self.sel = idx
            self.say(f"Stream {idx + 1} updated" + ("" if st.running
                                                      else " (stopped - Space starts it)"))
            if r == 'apply':
                break
            idx = (idx + (1 if r == 'next' else -1)) % n
        self._layout()

    def _handle(self, k):
        if self.confirm is not None:
            idx, self.confirm = self.confirm, None
            if k in ('y', 'Y') and idx < len(self.streams):
                self.streams[idx].stop()
                del self.streams[idx]
                self.say(f"Stream {idx + 1} deleted")
            self.dirty = True
            return False
        n = len(self.streams)
        cur = self.streams[self.sel] if n else None
        self.dirty = True
        if k == 'q':
            return True
        if k == 'up':
            self.sel = max(0, self.sel - 1)
        elif k == 'down':
            self.sel = min(max(0, n - 1), self.sel + 1)
        elif k == 'home':
            self.sel = 0
        elif k == 'end':
            self.sel = max(0, n - 1)
        elif k == ' ' and cur:
            if not cur.running:
                cur.start()
                self.say(f"Stream {self.sel + 1} started")
            else:
                cur.stop()
                self.say(f"Stream {self.sel + 1} stopped")
        elif k in ('s', 'S'):
            for st in self.streams:
                st.start()
            self.say('All streams started')
        elif k in ('x', 'X'):
            for st in self.streams:
                st.stop()
            self.say('All streams stopped')
        elif k in ('e', 'enter') and cur:
            self._edit(self.sel)
        elif k == 'n':
            if n >= SEND_MAX_STREAMS:
                self.say(f"Maximum of {SEND_MAX_STREAMS} streams", True)
            else:
                self._edit(None)
        elif k in ('d', 'delete') and cur:
            self.confirm = self.sel
        elif k == 'w':
            if self.on_save:
                self.say(self.on_save([st.params() for st in self.streams]))
        elif k == 'ctrl-l':
            self._layout()
        return False


def run_sender(cfg, sync_server, plist, live=True, autostart=True):
    """Run the stream list until the user quits / Ctrl+C. Live view on a
    suitable terminal, otherwise plain output. Returns afterwards; the
    (possibly edited) streams are stored back into cfg."""
    plist = [_stream_params(x) for x in plist][:SEND_MAX_STREAMS]
    ok, _why = tui_available()
    cols, rows = shutil.get_terminal_size((80, 24))
    if live and ok and cols >= 80 and rows >= 16:
        def on_save(pl):
            store_streams(cfg, pl)
            save_config(cfg)
            return f"Saved to {CONFIG_DIR / 'config.json'}"
        streams = [SendStream(x, sync_server) for x in plist]
        view = SenderView(streams, sync_server, on_save=on_save)
        started = time.monotonic()
        try:
            view.run(autostart)
        finally:
            store_streams(cfg, [st.params() for st in streams])
        _print_stream_totals(streams, time.monotonic() - started)
        return
    if live and (ok or sys.stdout.isatty()):
        print(f"{Colors.YELLOW}⚠ Sender view needs a terminal of at least 80x16 - "
              f"using the plain output{Colors.ENDC}")
    if len(plist) == 1:
        sc = dict(cfg['send'])
        sc.update(plist[0])
        if plist[0]['burst_mode']:
            send_packets_burst(sc, sync_server, duration_seconds=0)
        else:
            send_packets(sc, sync_server)
    else:
        run_senders_plain(plist, sync_server)


# --- Main ---------------------------------------------------------------------

def _ui_flags(p):
    p.add_argument('--no-color', action='store_true', default=argparse.SUPPRESS,
                   help='No color codes (also: NO_COLOR environment variable)')
    p.add_argument('--color', action='store_true', default=argparse.SUPPRESS,
                   help='Force colors even if the terminal type does not advertise them')
    p.add_argument('--ascii', action='store_true', default=argparse.SUPPRESS,
                   help='ASCII-only output (automatic when the locale is not UTF-8; also: MAUTG_ASCII=1)')
    p.add_argument('--no-tui', action='store_true', default=argparse.SUPPRESS,
                   help='Use the simple line menus instead of the full-screen UI')


def build_parser():
    parser = argparse.ArgumentParser(
        prog='mautg',
        description=f'mautg v{VERSION} - Multicast/Unicast Traffic Generator & Analyzer',
        epilog=f'Without a sub-command the interactive main menu is shown.  {AUTHOR}, {URL}')
    parser.add_argument('--version', action='store_true', help='Show version')
    _ui_flags(parser)
    sub = parser.add_subparsers(dest='cmd', metavar='{send,recv}')

    s = sub.add_parser('send', help='Traffic generator (also runs the OWD sync server)')
    s.add_argument('-d', '--destination', help='Destination address')
    s.add_argument('-p', '--port', type=int, help='Destination port')
    s.add_argument('-s', '--size', type=int, help='Packet size in bytes (wire size)')
    s.add_argument('--pps', type=float, help='Packets per second')
    s.add_argument('--dscp', type=int, help='DSCP value (0-63)')
    s.add_argument('--ttl', type=int, help='TTL (1-255)')
    s.add_argument('--burst', action='store_true', help='Burst mode')
    s.add_argument('--burst-mbps', type=float,
                   help='Burst bandwidth limit in Mbit/s (0=unlimited)')
    s.add_argument('--df', action='store_true', default=None,
                   help="Set Don't Fragment (DF) bit on all packets (Linux)")
    s.add_argument('--source', metavar='IP',
                   help='Source IP of this host (also selects the multicast interface)')
    s.add_argument('--source-port', type=int, help='Source port')
    s.add_argument('--sync-port', type=int, help='Local OWD sync server port')
    s.add_argument('--no-sync-server', action='store_true',
                   help='Do not start the OWD sync server')
    s.add_argument('--stream', action='append', default=[], metavar='SPEC',
                   help="Add a stream (repeatable, up to %d): "
                        "DEST:PORT[,pps=N][,size=N][,dscp=N|NAME][,ttl=N][,burst[=MBIT]]"
                        "[,src=IP][,sport=N][,df]; unset values come from the other "
                        "send options / the saved settings" % SEND_MAX_STREAMS)
    s.add_argument('--no-live', action='store_true',
                   help='Plain output instead of the full-screen sender view')
    s.add_argument('-m', '--menu', action='store_true', help='Interactive sender menu')
    _ui_flags(s)

    r = sub.add_parser('recv', help='Traffic receiver / analyzer')
    r.add_argument('--print-limit', type=int, default=PKT_LINE_LIMIT, metavar='N',
                   help="Per-packet display: at most N lines per second, 0 = no limit "
                        "(default: %d). All packets are counted regardless." % PKT_LINE_LIMIT)
    r.add_argument('-I', '--interface', default='all', metavar='IF',
                   help="Interface(s) for the multicast join: all (default) | auto "
                        "(kernel decides) | IP address | interface name, e.g. eth0")
    r.add_argument('-g', '--group', default='239.1.1.1',
                   metavar='GROUPS',
                   help='Multicast group(s): 239.1.1.1 | 239.1.1.1,239.1.1.10 | '
                        '239.1.1.1-239.1.1.10 | 239.1.1.1-10 (default: 239.1.1.1)')
    r.add_argument('-p', '--port', default='5001-5008', metavar='PORTS',
                   help='Data port, range or list, e.g. 5005 | 5005-5010 | 5005,5007,6000-6003 '
                        '(default: 5001-5008)')
    r.add_argument('-u', '--unicast', action='store_true',
                   help='Unicast mode (listen on own IP)')
    r.add_argument('-i', '--interval', type=int,
                   help='Summary interval in seconds (default: 2, 0 = per-packet display)')
    r.add_argument('-c', '--compact', type=int,
                   help='Compact summary interval in seconds (overrides -i)')
    r.add_argument('-l', '--log', nargs='?', const='auto', default=None, metavar='NAME',
                   help='CSV log in the current directory; without NAME: '
                        'mautg-log_<date>_<time>.csv')
    r.add_argument('--sender', default=None, metavar='IP',
                   help="Sender IP for OWD sync (default: auto-detect from the first "
                        "valid packet; 'none' = no sync, no delay values)")
    r.add_argument('--sender-sync-port', type=int, default=None,
                   help='OWD sync port on the sender (default: taken from the packets; '
                        f'{OWD_SYNC_PORT} with an explicit --sender)')
    r.add_argument('--show-ip', action='store_true',
                   help='Show the sender IP in every line, after the stream label')
    r.add_argument('--verify', action='store_true',
                   help='Check CRC + padding pattern of every packet (default: '
                        'magic check only; full check on sender lock-in)')
    r.add_argument('--resync-interval', type=float, default=OWD_RESYNC_INTERVAL,
                   help=f'OWD resync interval in seconds (default: {OWD_RESYNC_INTERVAL:g})')
    r.add_argument('--sync-port', type=int, help='Local OWD sync server port')
    r.add_argument('--no-sync-server', action='store_true',
                   help='Do not start the OWD sync server')
    r.add_argument('-m', '--menu', action='store_true', help='Interactive receiver menu')
    r.add_argument('--no-live', action='store_true',
                   help='Plain scrolling output instead of the full-screen live view '
                        '(default view; keys q/p/i/d)')
    _ui_flags(r)
    return parser


def _goodbye():
    try:
        print(f"\nTHX for using mautg.py v{VERSION} - {URL.split('://')[-1]}")
    except (OSError, ValueError):
        pass


def main():
    args = build_parser().parse_args()

    if args.version:
        print(f"mautg v{VERSION} {CREDIT}\n")
        return

    _install_termination_handlers()
    if getattr(args, 'no_color', False) or os.environ.get('NO_COLOR'):
        disable_colors()
    elif not getattr(args, 'color', False) and sys.stdout.isatty() and not color_ok():
        disable_colors()          # e.g. TERM=vt100: no color codes
    use_tui = False
    if not getattr(args, 'no_tui', False):
        use_tui, why = tui_available()
        if why:
            print(f"{Colors.YELLOW}{why}{Colors.ENDC}")

    cfg = load_config()
    no_server = getattr(args, 'no_sync_server', False)
    if getattr(args, 'sync_port', None) is not None:
        cfg['sync_port'] = args.sync_port

    sync_server = OWDSyncServer(port=cfg['sync_port'])
    if not no_server:
        sync_server.start()

    try:
        if args.cmd == 'send':
            sc = cfg['send']
            for arg_name, key in (('destination', 'destination_address'),
                                  ('port', 'destination_port'),
                                  ('size', 'packet_size'),
                                  ('pps', 'packets_per_second'),
                                  ('dscp', 'dscp_value'),
                                  ('ttl', 'ttl'),
                                  ('burst_mbps', 'burst_mbps')):
                val = getattr(args, arg_name)
                if val is not None:
                    sc[key] = val
            if args.source is not None:
                sc['source_address'] = args.source
            if args.source_port is not None:
                sc['source_port'] = args.source_port
            if args.df:
                sc['df_bit'] = True

            print(f"\n{Colors.WHITE}mautg v{VERSION} - send   {CREDIT}{Colors.ENDC}\n")
            if args.menu or (not args.destination and not args.burst and not args.stream):
                if use_tui:
                    TUI(cfg, sync_server, tab=0).run()
                else:
                    sender_menu_loop(cfg, sync_server)
            else:
                # a command line is deterministic: only the streams given on it
                # (the saved additional streams are not added)
                if args.burst:
                    sc['burst_mode'] = True
                if len(args.stream) > SEND_MAX_STREAMS:
                    print(f"{Colors.RED}✗ At most {SEND_MAX_STREAMS} streams{Colors.ENDC}")
                    sys.exit(2)
                try:
                    if args.stream:
                        plist = [parse_stream_spec(x, sc) for x in args.stream]
                        seen = {}
                        for i, q in enumerate(plist, 1):
                            key = (q['source_address'], q['destination_port'])
                            if key in seen:
                                raise ValueError(
                                    f"streams {seen[key]} and {i} use destination port "
                                    f"{q['destination_port']} - a receiver would merge them")
                            seen[key] = i
                    else:
                        problem = check_stream_params(_stream_params(sc))
                        if problem:
                            raise ValueError(problem)
                        plist = [_stream_params(sc)]
                except ValueError as e:
                    print(f"{Colors.RED}✗ {e}{Colors.ENDC}")
                    sys.exit(2)
                run_sender(cfg, sync_server, plist, live=not args.no_live)

        elif args.cmd == 'recv':
            # CLI receive runs on defaults + flags (not on the saved menu
            # config), so a command line behaves the same every time.
            rc = cfg['recv']
            rc.update({
                'sender_ip': args.sender or '',
                'sender_sync_port': args.sender_sync_port or 0,
                'verify': args.verify,
                'show_ip': args.show_ip,
                'unicast': args.unicast,
                'group': args.group,
                'interface': args.interface,
                'print_limit': args.print_limit,
                'port': args.port,
                'summary': args.compact or (2 if args.interval is None else max(0, args.interval)),
                'compact': bool(args.compact),
                'resync_interval': args.resync_interval,
                'log': args.log or '',
            })
            print(f"\n{Colors.WHITE}mautg v{VERSION} - recv   {CREDIT}{Colors.ENDC}\n")
            if args.menu:
                if use_tui:
                    TUI(cfg, sync_server, tab=1).run()
                else:
                    receiver_menu_loop(cfg, sync_server)
            else:
                run_receiver(rc, live=not args.no_live)

        else:
            if use_tui:
                TUI(cfg, sync_server, tab=0).run()
            else:
                main_menu(cfg, sync_server)
    except _Terminate as t:
        # terminal closed / SIGTERM: everything has been unwound; end for real
        code = 128 + getattr(signal, t.signame, signal.SIGTERM)
        sync_server.stop()
        sys.exit(int(code))
    else:
        _goodbye()
    finally:
        sync_server.stop()


if __name__ == '__main__':
    main()
