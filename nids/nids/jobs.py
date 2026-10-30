"""Background jobs the dashboard starts: the demo feed, watch mode, training, evaluation.

Each job is a `python -m nids ...` subprocess in its own session or process group, with its pid and output
under data/jobs/, so it survives dashboard reruns and can be stopped from any session.
Only argument lists built here are run (no shell); the dashboard offers fixed commands.
"""
from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import psutil

from nids.pipeline import ROOT

JOBS_DIR = ROOT / "data" / "jobs"


def _meta(name: str, jobs_dir: Path) -> Path:
    return jobs_dir / f"{name}.json"


def _alive(pid: int) -> bool:
    """psutil, not os.kill(pid, 0): on Windows any os.kill signal other than Ctrl-C terminates the process."""
    try:
        p = psutil.Process(pid)
        return p.is_running() and p.status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False


def start(name: str, args: list[str], jobs_dir: Path = JOBS_DIR, env: dict | None = None) -> dict:
    """Start `python -m nids ARGS` as job NAME; refuses if it is already running."""
    cur = status(name, jobs_dir)
    if cur["running"]:
        return cur
    jobs_dir.mkdir(parents=True, exist_ok=True)
    out = jobs_dir / f"{name}.log"
    with out.open("w", encoding="utf-8") as fh:
        proc = subprocess.Popen([sys.executable, "-u", "-m", "nids", *args], cwd=ROOT, stdout=fh,
                                stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, **_detach(),
                                env={**os.environ, "PYTHONUTF8": "1", **(env or {})})
    meta = {"name": name, "pid": proc.pid, "args": args, "started_at": time.time()}
    _meta(name, jobs_dir).write_text(json.dumps(meta), encoding="utf-8")
    return status(name, jobs_dir)


def status(name: str, jobs_dir: Path = JOBS_DIR) -> dict:
    p = _meta(name, jobs_dir)
    if not p.exists():
        return {"name": name, "running": False, "pid": None, "args": [], "started_at": None}
    meta = json.loads(p.read_text(encoding="utf-8"))
    return {**meta, "running": _alive(meta["pid"])}


def _detach() -> dict:
    """Own session (POSIX) or process group (Windows), so the job outlives a dashboard rerun and can be stopped as a tree."""
    if os.name == "nt":
        return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "CREATE_NO_WINDOW", 0)}
    return {"start_new_session": True}


def _tree(pid: int) -> list[psutil.Process]:
    try:
        root = psutil.Process(pid)
        return [*root.children(recursive=True), root]
    except psutil.NoSuchProcess:
        return []


def stop(name: str, jobs_dir: Path = JOBS_DIR, timeout: float = 5.0) -> bool:
    st = status(name, jobs_dir)
    if not st["running"]:
        return False
    procs = _tree(st["pid"])
    for p in procs:
        with contextlib.suppress(psutil.NoSuchProcess):
            p.terminate()
    _, alive = psutil.wait_procs(procs, timeout=timeout)
    for p in alive:
        with contextlib.suppress(psutil.NoSuchProcess):
            p.kill()
    return True


def output(name: str, jobs_dir: Path = JOBS_DIR, lines: int = 200) -> str:
    p = jobs_dir / f"{name}.log"
    if not p.exists():
        return ""
    return "\n".join(p.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:])
