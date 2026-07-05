#!/usr/bin/env python3
import argparse
import logging
import math
import os
import signal
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock

import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# Config
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("/tmp/hips_agent.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("hips-agent")

HONEYPOT_PREFIX = ".hp_"          # prefix of bait-files
ENTROPY_THRESHOLD = 7.5           # bits/byte (max = 8.0)
RATE_WINDOW_SECONDS = 5           # sliding window for operation treshold
RATE_THRESHOLD_OPS = 10           # operation on the same process -> suspicious
SCORE_THRESHOLD_KILL = 80         # score >= ops_tresh -> kill process

class HoneypotManager:
    def __init__(self, watch_dirs: list[str], count_per_dir: int = 10):
        self.watch_dirs = watch_dirs
        self.count_per_dir = count_per_dir
        self.honeypot_paths: set[str] = set()

    def deploy(self):
        sample_content = (
            b"Confidential Document - Finantial Report Q3\n"
            b"This file is a bait for HIPS detection.\n" * 20
        )
        for d in self.watch_dirs:
            Path(d).mkdir(parents=True, exist_ok=True)
            for i in range(self.count_per_dir):
                name = f"{HONEYPOT_PREFIX}{i:03d}_Finantial_Report.docx"
                p = Path(d) / name
                p.write_bytes(sample_content)
                self.honeypot_paths.add(str(p.resolve()))
        log.info("Honeypots implanted: %d files in %d directorys",
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
    except (FileNotFoundError, PermissionError, IsADirectoryError):
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


# PID atribution via /proc/*/fd
def guess_pid_for_path(target_dir: str) -> int | None:
    target_dir = os.path.realpath(target_dir)
    best_pid = None
    best_mtime = -1.0
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            for f in proc.open_files():
                if os.path.realpath(f.path).startswith(target_dir):
                    #prioriza o de fd mais recente
                    try:
                        mtime = os.stat(f"/proc/{proc.pid}").st_mtime
                    except OSError:
                        mtime = 0
                    if mtime > best_mtime:
                        best_mtime = mtime
                        best_pid = proc.pid
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return best_pid

@dataclass
class RiskState:
    score: int = 0
    reasons: list[str] = field(default_factory=list)


class RiskCorrelator:
    def __init__(self):
        self._pid_scores: dict[int, RiskState] = defaultdict(RiskState)

    def add(self, pid: int, points: int, reason: str) -> RiskState:
        state = self._pid_scores[pid]
        state.score = min(100, state.score + points)
        state.reasons.append(reason)
        return state

    def get(self, pid: int) -> RiskState:
        return self._pid_scores[pid]

class ResponseEngine:
    def __init__(self, quarantine_dir: str = "/tmp/hips_quarantine"):
        self.quarantine_dir = quarantine_dir
        Path(quarantine_dir).mkdir(parents=True, exist_ok=True)

    def contain(self, pid: int, reason: str, affected_path: str | None = None):
        log.warning("LEVEL 1 CONAINMENT ACTIVATED PID=%s reason=%s", pid, reason)
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            proc.kill()
            log.warning("Process %s (PID %s) killed.", proc_name, pid)
        except psutil.NoSuchProcess:
            log.info("PID %s already ended", pid)
        except psutil.AccessDenied:
            log.error("Without permission to kill PID %s. Run agent as root.", pid)

        self.alert_central_console(pid, reason)
        # Ponto de extensao: aqui entraria a logica de "Nivel 2"

    def alert_central_console(self, pid: int, reason: str):
        # Placeholder: usar aqui pra comunicar com o console central
        log.info("[ALERT -> CENTRAL CONSOL] pid=%s reason=%s host=%s",
                  pid, reason, os.uname().nodename)


#Event Handler
class RansomwareDetectionHandler(FileSystemEventHandler):
    def __init__(self, honeypots: HoneypotManager, watch_dirs: list[str]):
        self.honeypots = honeypots
        self.watch_dirs = watch_dirs
        self.rate_tracker = RateTracker()
        self.correlator = RiskCorrelator()
        self.responder = ResponseEngine()
        self._contained_pids: set[int] = set()

    def on_modified(self, event):
        self._handle(event)

    def on_created(self, event):
        self._handle(event)

    def on_moved(self, event):
        self._handle(event, path_override=event.dest_path)

    def _handle(self, event, path_override: str | None = None):
        if event.is_directory:
            return
        path = path_override or event.src_path

        # descobre em qual watch_dir esse path esta, p/ atribuicao de PID
        parent_dir = next((d for d in self.watch_dirs if path.startswith(d)), None)
        if parent_dir is None:
            return

        pid = guess_pid_for_path(parent_dir)
        if pid is None:
            log.debug("Could not set PID for event in %s", path)
            return

        if pid in self._contained_pids:
            return

        # Sig 1: Honeypot
        if self.honeypots.is_honeypot(str(Path(path).resolve())):
            state = self.correlator.add(pid, 100, f"honeypot touched: {path}")
            log.warning("HONEYPOT ADDED by PID %s in %s", pid, path)
            self._maybe_respond(pid, state)
            return

        # Sig 2: Entropy
        ent = file_entropy(path)
        if ent is not None and ent >= ENTROPY_THRESHOLD:
            state = self.correlator.add(
                pid, 40, f"high entropy ({ent:.2f} bits/byte) in {path}"
            )
            log.info("High entrpy detected: %.2f in %s (PID %s)", ent, path, pid)
            self._maybe_respond(pid, state)

        # Sig 3: Op rate
        ops_in_window = self.rate_tracker.record(pid)
        if ops_in_window >= RATE_THRESHOLD_OPS:
            state = self.correlator.add(
                pid, 50,
                f"{ops_in_window} file operations in {RATE_WINDOW_SECONDS}s"
            )
            log.info("Suspicious rate: PID %s modified %d files in %ds",
                      pid, ops_in_window, RATE_WINDOW_SECONDS)
            self._maybe_respond(pid, state)

    def _maybe_respond(self, pid: int, state: RiskState):
        log.debug("Score PID %s: %d (%s)", pid, state.score, state.reasons)
        if state.score >= SCORE_THRESHOLD_KILL:
            self._contained_pids.add(pid)
            self.responder.contain(pid, "; ".join(state.reasons))

def main():
    parser = argparse.ArgumentParser(description="HIPS Agent - Level 1")
    parser.add_argument("--watch", action="append", required=True,
                         help="Directory monitores (repeat for multiple)")
    parser.add_argument("--honeypot-count", type=int, default=10,
                         help="Amount of honeypots per directory")
    args = parser.parse_args()

    watch_dirs = [str(Path(d).resolve()) for d in args.watch]

    honeypots = HoneypotManager(watch_dirs, args.honeypot_count)
    honeypots.deploy()

    handler = RansomwareDetectionHandler(honeypots, watch_dirs)
    observer = Observer()
    for d in watch_dirs:
        observer.schedule(handler, d, recursive=True)

    observer.start()
    log.info("HIPS Agent (Level 1) running. Monitoring: %s", watch_dirs)
    log.info("Agent PID: %s | Log: /tmp/hips_agent.log", os.getpid())

    def shutdown(signum, frame):
        log.info("Stopping agent...")
        observer.stop()
        observer.join()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
