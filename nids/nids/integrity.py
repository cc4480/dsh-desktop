"""Integrity of model files.

Models are scikit-learn pickles, and loading a pickle runs code. A model file is therefore
only loaded if it matches the digest written next to it when it was trained
(`model.joblib.sig`). If NIDS_MODEL_KEY is set the digest is an HMAC-SHA256 under that key,
so someone who can write to the models directory but does not hold the key cannot forge
a matching file; without a key it is a plain SHA-256, which catches corruption and
accidental swaps but not a deliberate attacker with write access.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path


def _digest(path: Path) -> str:
    key = os.environ.get("NIDS_MODEL_KEY", "").encode()
    h = hmac.new(key, digestmod=hashlib.sha256) if key else hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return ("hmac-sha256:" if key else "sha256:") + h.hexdigest()


def sig_path(path: Path) -> Path:
    return path.with_name(path.name + ".sig")


def sign(path: str | Path) -> None:
    path = Path(path)
    sig_path(path).write_text(_digest(path) + "\n", encoding="utf-8")


def verify(path: str | Path) -> None:
    path = Path(path)
    sig = sig_path(path)
    if not sig.exists():
        raise ValueError(f"{path.name} has no {sig.name}: refusing to load an unsigned model (retrain it)")
    if not hmac.compare_digest(sig.read_text(encoding="utf-8").strip(), _digest(path)):
        raise ValueError(f"{path.name} does not match its {sig.name}: the file changed after training "
                         "(or NIDS_MODEL_KEY differs from the one used to train)")
