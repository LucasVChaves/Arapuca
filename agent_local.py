#!/usr/bin/env python3
import argparse
import ctypes
import ctypes.util
import logging
import math
import os
import select
import signal
import struct
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock

import psutil

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("/tmp/hips_agent.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("hips-agent")

HONEYPOT_PREFIX = ".hp_"          # prefix of bait files
ENTROPY_THRESHOLD = 7.5           # bits/byte (max = 8.0)
RATE_WINDOW_SECONDS = 5           # sliding window for operation threshold
RATE_THRESHOLD_OPS = 10           # ops on same PID -> suspicious
SCORE_THRESHOLD_KILL = 80         # score >= this -> kill + block PID
EVENT_BUF_SIZE = 4096 * 8

FAN_ACCESS = 0x00000001
FAN_MODIFY = 0x00000002
FAN_CLOSE_WRITE = 0x00000008
FAN_CLOSE_NOWRITE = 0x00000010
FAN_OPEN = 0x00000020
FAN_Q_OVERFLOW = 0x00004000
FAN_OPEN_PERM = 0x00010000
FAN_ACCESS_PERM = 0x00020000
FAN_ONDIR = 0x40000000
FAN_EVENT_ON_CHILD = 0x08000000

FAN_CLOEXEC = 0x00000001
FAN_NONBLOCK = 0x00000002
FAN_CLASS_NOTIF = 0x00000000
FAN_CLASS_CONTENT = 0x00000004
FAN_UNLIMITED_QUEUE = 0x00000010
FAN_UNLIMITED_MARKS = 0x00000020

FAN_MARK_ADD = 0x00000001
FAN_MARK_REMOVE = 0x00000002
FAN_MARK_MOUNT = 0x00000010
FAN_MARK_FILESYSTEM = 0x00000100

FAN_ALLOW = 0x01
FAN_DENY = 0x02

AT_FDCWD = -100

# struct fanotify_event_metadata (24 bytes on x86_64, naturally aligned)
_EVENT_META_FMT = "=IBBHQiI"   # event_len, vers, reserved, metadata_len, mask, fd, pid
_EVENT_META_LEN = struct.calcsize(_EVENT_META_FMT)  # == 24
assert _EVENT_META_LEN == 24, f"unexpected metadata size {_EVENT_META_LEN}"

# struct fanotify_response
_RESPONSE_FMT = "=iI"  # fd, response
_RESPONSE_LEN = struct.calcsize(_RESPONSE_FMT)


class FanotifyLL:

    def __init__(self):
        libc_name = ctypes.util.find_library("c") or "libc.so.6"
        self.libc = ctypes.CDLL(libc_name, use_errno=True)
        self.libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
        self.libc.fanotify_init.restype = ctypes.c_int
        self.libc.fanotify_mark.argtypes = [
            ctypes.c_int, ctypes.c_uint, ctypes.c_uint64,
            ctypes.c_int, ctypes.c_char_p,
        ]
        self.libc.fanotify_mark.restype = ctypes.c_int

    def init(self, flags: int, event_f_flags: int) -> int:
        fd = self.libc.fanotify_init(flags, event_f_flags)
        if fd < 0:
            errno = ctypes.get_errno()
            raise OSError(errno, os.strerror(errno), "fanotify_init")
        return fd

    def mark(self, fan_fd: int, flags: int, mask: int, path: str, dirfd: int = AT_FDCWD):
        rc = self.libc.fanotify_mark(fan_fd, flags, mask, dirfd, path.encode())
        if rc < 0:
            errno = ctypes.get_errno()
            raise OSError(errno, os.strerror(errno), f"fanotify_mark({path})")


class HoneypotManager:
    def __init__(self, watch_dirs: list[str], count_per_dir: int = 10):
        self.watch_dirs = watch_dirs
        self.count_per_dir = count_per_dir
        self.honeypot_paths: set[str] = set()

    def deploy(self):
        sample_content = (
            b"Confidential Document - Financial Report Q3\n"
            b"This file is a bait for HIPS detection.\n" * 20
        )
        for d in self.watch_dirs:
            Path(d).mkdir(parents=True, exist_ok=True)
            for i in range(self.count_per_dir):
                name = f"{HONEYPOT_PREFIX}{i:03d}_Financial_Report.docx"
                p = Path(d) / name
                p.write_bytes(sample_content)
                self.honeypot_paths.add(str(p.resolve()))
        log.info("Honeypots implanted: %d files in %d directories",
                  len(self.honeypot_paths), len(self.watch_dirs))

    def is_honeypot(self, path: str) -> bool:
        return path in self.honeypot_paths


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = defaultdict(int)
    for byte in data:
        freq[byte] += 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def file_entropy(path: str, max_bytes: int = 65536) -> float | None:
    try:
        with open(path, "rb") as f:
            chunk = f.read(max_bytes)
        return shannon_entropy(chunk)
    except (FileNotFoundError, PermissionError, IsADirectoryError, OSError):
        return None


class RateTracker:
    def __init__(self, window_seconds: int = RATE_WINDOW_SECONDS):
        self.window = window_seconds
        self._events: dict[int, deque] = defaultdict(deque)
        self._lock = Lock()

    def record(self, pid: int) -> int:
        now = time.time()
        with self._lock:
            dq = self._events[pid]
            dq.append(now)
            while dq and now - dq[0] > self.window:
                dq.popleft()
            return len(dq)


@dataclass
class RiskState:
    score: int = 0
    reasons: list[str] = field(default_factory=list)


class RiskCorrelator:
    def __init__(self):
        self._pid_scores: dict[int, RiskState] = defaultdict(RiskState)
        self._lock = Lock()

    def add(self, pid: int, points: int, reason: str) -> RiskState:
        with self._lock:
            state = self._pid_scores[pid]
            state.score = min(100, state.score + points)
            state.reasons.append(reason)
            return state

    def get(self, pid: int) -> RiskState:
        with self._lock:
            return self._pid_scores[pid]


class ResponseEngine:
    def __init__(self, quarantine_dir: str = "/tmp/hips_quarantine"):
        self.quarantine_dir = quarantine_dir
        Path(quarantine_dir).mkdir(parents=True, exist_ok=True)

    def contain(self, pid: int, reason: str):
        log.warning("LEVEL 1 CONTAINMENT ACTIVATED PID=%s reason=%s", pid, reason)
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            children = proc.children(recursive=True)
            for child in children:
                try:
                    child.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            proc.kill()
            log.warning("Process %s (PID %s) and %d child(ren) killed.",
                        proc_name, pid, len(children))
        except psutil.NoSuchProcess:
            log.info("PID %s already ended", pid)
        except psutil.AccessDenied:
            log.error("Without permission to kill PID %s. Run agent as root.", pid)

        self.alert_central_console(pid, reason)

    def alert_central_console(self, pid: int, reason: str):
        log.info("[ALERT -> CENTRAL CONSOLE] pid=%s reason=%s host=%s",
                  pid, reason, os.uname().nodename)


class FanotifyGuard:
    def __init__(self, watch_dirs: list[str], honeypots: HoneypotManager):
        self.watch_dirs = [str(Path(d).resolve()) for d in watch_dirs]
        self.honeypots = honeypots
        self.rate_tracker = RateTracker()
        self.correlator = RiskCorrelator()
        self.responder = ResponseEngine()

        self.blocked_pids: set[int] = set()
        self._blocked_lock = Lock()

        self._ll = FanotifyLL()
        self._stop = threading.Event()
        self.fan_fd = self._ll.init(
            FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS,
            os.O_RDONLY | getattr(os, "O_LARGEFILE", 0),
        )

    def add_marks(self):
        mask = FAN_OPEN_PERM | FAN_CLOSE_WRITE
        marked_fs = set()
        for d in self.watch_dirs:
            dev = os.stat(d).st_dev
            if dev in marked_fs:
                continue
            try:
                self._ll.mark(self.fan_fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, mask, d)
                marked_fs.add(dev)
                log.info("fanotify: marked filesystem containing %s", d)
            except OSError as e:
                log.warning(
                    "FAN_MARK_FILESYSTEM failed for %s (%s); falling back to "
                    "FAN_MARK_MOUNT (older kernel?)", d, e,
                )
                self._ll.mark(self.fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, mask, d)
                marked_fs.add(dev)

    def _in_watch_dirs(self, path: str) -> bool:
        return any(path.startswith(d) for d in self.watch_dirs)

    def _is_blocked(self, pid: int) -> bool:
        with self._blocked_lock:
            return pid in self.blocked_pids

    def _block(self, pid: int):
        with self._blocked_lock:
            self.blocked_pids.add(pid)

    def run(self):
        log.info("fanotify guard active. fan_fd=%d", self.fan_fd)
        while not self._stop.is_set():
            ready, _, _ = select.select([self.fan_fd], [], [], 1.0)
            if not ready:
                continue
            try:
                buf = os.read(self.fan_fd, EVENT_BUF_SIZE)
            except OSError as e:
                log.error("fanotify read error: %s", e)
                continue
            offset = 0
            while offset + _EVENT_META_LEN <= len(buf):
                event_len, vers, _reserved, metadata_len, mask, ev_fd, pid = \
                    struct.unpack_from(_EVENT_META_FMT, buf, offset)
                self._handle_event(mask, ev_fd, pid)
                offset += event_len

    def stop(self):
        self._stop.set()

    def _respond(self, ev_fd: int, decision: int):
        os.write(self.fan_fd, struct.pack(_RESPONSE_FMT, ev_fd, decision))

    def _handle_event(self, mask: int, ev_fd: int, pid: int):
        is_perm = bool(mask & (FAN_OPEN_PERM | FAN_ACCESS_PERM))

        if mask & FAN_Q_OVERFLOW:
            log.warning("fanotify event queue OVERFLOW - some events were dropped")
            return

        if ev_fd < 0:
            return

        try:
            path = os.path.realpath(f"/proc/self/fd/{ev_fd}")
        finally:
            os.close(ev_fd)

        if is_perm and self._is_blocked(pid):
            self._respond(ev_fd, FAN_DENY)
            log.warning("BLOCKED open by contained PID %s -> %s", pid, path)
            return

        if is_perm:
            self._respond(ev_fd, FAN_ALLOW)

        if not self._in_watch_dirs(path):
            return

        if self.honeypots.is_honeypot(path):
            state = self.correlator.add(pid, 100, f"honeypot touched: {path}")
            log.warning("HONEYPOT TOUCHED by PID %s in %s", pid, path)
            self._maybe_respond(pid, state)
            return

        if mask & FAN_CLOSE_WRITE:
            ent = file_entropy(path)
            if ent is not None and ent >= ENTROPY_THRESHOLD:
                state = self.correlator.add(
                    pid, 40, f"high entropy ({ent:.2f} bits/byte) in {path}"
                )
                log.info("High entropy detected: %.2f in %s (PID %s)", ent, path, pid)
                self._maybe_respond(pid, state)

        ops_in_window = self.rate_tracker.record(pid)
        if ops_in_window >= RATE_THRESHOLD_OPS:
            state = self.correlator.add(
                pid, 50, f"{ops_in_window} file operations in {RATE_WINDOW_SECONDS}s"
            )
            log.info("Suspicious rate: PID %s touched %d files in %ds",
                      pid, ops_in_window, RATE_WINDOW_SECONDS)
            self._maybe_respond(pid, state)

    def _maybe_respond(self, pid: int, state: RiskState):
        log.debug("Score PID %s: %d (%s)", pid, state.score, state.reasons)
        if state.score >= SCORE_THRESHOLD_KILL and not self._is_blocked(pid):
            self._block(pid)
            self.responder.contain(pid, "; ".join(state.reasons))


def main():
    parser = argparse.ArgumentParser(description="HIPS Agent - Level 2 (fanotify)")
    parser.add_argument("--watch", action="append", required=True,
                         help="Directory to monitor (repeat for multiple)")
    parser.add_argument("--honeypot-count", type=int, default=10,
                         help="Amount of honeypots per directory")
    args = parser.parse_args()

    if os.geteuid() != 0:
        log.error("fanotify permission events require CAP_SYS_ADMIN. Run as root.")
        sys.exit(1)

    watch_dirs = [str(Path(d).resolve()) for d in args.watch]

    honeypots = HoneypotManager(watch_dirs, args.honeypot_count)
    honeypots.deploy()

    guard = FanotifyGuard(watch_dirs, honeypots)
    guard.add_marks()

    log.info("HIPS Agent (Level 2 / fanotify) running. Monitoring: %s", watch_dirs)
    log.info("Agent PID: %s | Log: /tmp/hips_agent.log", os.getpid())

    def shutdown(signum, frame):
        log.info("Stopping agent...")
        guard.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    guard.run()


if __name__ == "__main__":
    main()
