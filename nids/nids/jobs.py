"""Background jobs the dashboard starts: the demo feed, watch mode, training, evaluation.

Each job is a `python -m nids ...` subprocess in its own session, with its pid and output
under data/jobs/, so it survives dashboard reruns and can be stopped from any session.
Only argument lists built here are run (no shell); the dashboard offers fixed commands.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from nids.pipeline import ROOT

JOBS_DIR = ROOT / "data" / "jobs"


def _meta(name: str, jobs_dir: Path) -> Path:
    return jobs_dir / f"{name}.json"


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    try:  # a finished child stays a zombie until reaped; reap it so it reads as stopped
        done, _ = os.waitpid(pid, os.WNOHANG)
        return done == 0
    except ChildProcessError:  # not our child: existence is all we can know
        return True


def start(name: str, args: list[str], jobs_dir: Path = JOBS_DIR, env: dict | None = None) -> dict:
    """Start `python -m nids ARGS` as job NAME; refuses if it is already running."""
    cur = status(name, jobs_dir)
    if cur["running"]:
        return cur
    jobs_dir.mkdir(parents=True, exist_ok=True)
    out = jobs_dir / f"{name}.log"
    with out.open("w", encoding="utf-8") as fh:
        proc = subprocess.Popen([sys.executable, "-u", "-m", "nids", *args], cwd=ROOT, stdout=fh,
                                stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True,
                                env={**os.environ, **(env or {})})
    meta = {"name": name, "pid": proc.pid, "args": args, "started_at": time.time()}
    _meta(name, jobs_dir).write_text(json.dumps(meta))
    return status(name, jobs_dir)


def status(name: str, jobs_dir: Path = JOBS_DIR) -> dict:
    p = _meta(name, jobs_dir)
    if not p.exists():
        return {"name": name, "running": False, "pid": None, "args": [], "started_at": None}
    meta = json.loads(p.read_text())
    return {**meta, "running": _alive(meta["pid"])}


def stop(name: str, jobs_dir: Path = JOBS_DIR, timeout: float = 5.0) -> bool:
    st = status(name, jobs_dir)
    if not st["running"]:
        return False
    try:
        os.killpg(st["pid"], signal.SIGTERM)
    except ProcessLookupError:
        return False
    deadline = time.time() + timeout
    while time.time() < deadline and _alive(st["pid"]):
        time.sleep(0.1)
    if _alive(st["pid"]):
        os.killpg(st["pid"], signal.SIGKILL)
    return True


def output(name: str, jobs_dir: Path = JOBS_DIR, lines: int = 200) -> str:
    p = jobs_dir / f"{name}.log"
    if not p.exists():
        return ""
    return "\n".join(p.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:])
