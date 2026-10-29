"""Live demo feed: stream a recorded Zeek log directory into another one in real time.

    python -m nids replay data/lab/demo --out data/live --speed 10
    python -m nids watch data/live --interval 5      # in another terminal (or the dashboard)

Records from every log are merged by timestamp and appended to OUT/<log>.log as JSON
lines at SPEED times the original pace, exactly as a running Zeek would append them, so
`nids watch` sees a live sensor. Timestamps are shifted by whole days to the latest date that is not in the future: the
time of day is kept, because the anomaly calibration and the profile are per hour.
`--align now` shifts to the wall clock instead (hours then differ from training).
"""
from __future__ import annotations

import heapq
import math
import json
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TextIO

from nids.sensing.zeek import LineParser

LOGS = ("conn", "dns", "http", "ssl", "notice", "weird", "capture_loss", "stats")
DAY = 86_400.0


def _stream(path: Path, name: str) -> Iterator[tuple[float, str, dict]]:
    parser = LineParser()
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            rec = parser.parse(line)
            if rec is not None and "ts" in rec:
                ts = float(rec["ts"])
                yield ts, name, rec


def merged(logdir: Path) -> Iterator[tuple[float, str, dict]]:
    """(ts, log, record) across all logs in time order; each log is already in order."""
    streams = [_stream(logdir / f"{name}.log", name) for name in LOGS if (logdir / f"{name}.log").exists()]
    return heapq.merge(*streams, key=lambda x: x[0])


def span(logdir: Path) -> tuple[float, float]:
    first = last = None
    for ts, _, _ in merged(logdir):
        first = ts if first is None else first
        last = ts
    if first is None:
        raise SystemExit(f"no Zeek logs with timestamps in {logdir}")
    return first, last


def shift_for(first: float, align: str, now: float) -> float:
    if align == "now":
        return now - first
    if align == "day":
        return math.floor((now - first) / DAY) * DAY  # never into the future
    if align == "none":
        return 0.0
    raise ValueError(f"unknown --align {align!r}")


def replay(logdir: Path, out: Path, speed: float = 10.0, align: str = "day", tick: float = 0.5,
           clock: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep,
           log: Callable[[str], None] = print) -> int:
    first, last = span(logdir)
    shift = shift_for(first, align, clock())
    out.mkdir(parents=True, exist_ok=True)
    for name in LOGS:  # a fresh sensor: watch mode sees new inodes and starts from zero
        try:
            (out / f"{name}.log").unlink(missing_ok=True)
        except PermissionError:  # Windows: a watcher from an earlier demo still holds it open
            raise SystemExit(f"cannot reset {out / (name + '.log')}: stop the watch job that is reading it first")
    handles: dict[str, TextIO] = {}
    wall0 = clock()
    log(f"replaying {logdir} ({last - first:.0f}s of traffic) into {out} at {speed:g}x "
        f"(~{(last - first) / speed:.0f}s), timestamps shifted {shift:+.0f}s")
    n = 0
    records = merged(logdir)
    nxt = next(records, None)
    try:
        while nxt is not None:
            horizon = first + (clock() - wall0) * speed
            while nxt is not None and nxt[0] <= horizon:
                ts, name, rec = nxt
                if name not in handles:
                    handles[name] = (out / f"{name}.log").open("a", encoding="utf-8", newline="\n")
                handles[name].write(json.dumps(dict(rec, ts=ts + shift)) + "\n")
                n += 1
                nxt = next(records, None)
            for fh in handles.values():
                fh.flush()
            if nxt is not None:
                sleep(tick)
    finally:
        for fh in handles.values():
            fh.close()
    log(f"replay finished: {n} records")
    return n
