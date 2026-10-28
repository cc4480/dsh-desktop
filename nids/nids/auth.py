"""Dashboard accounts: per-user logins with roles, PBKDF2-hashed, in config/users.yaml.

Roles
  analyst   triage: read incidents, view commands, acknowledge / close, take the study
  approver  everything an analyst can, plus approve or reject a rendered command

This is the minimum that gives per-person accountability in the audit log. Production
still wants SSO + RBAC in front of the dashboard (see README).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
USERS_PATH = ROOT / "config" / "users.yaml"
ROLES = {"analyst": 1, "approver": 2}
ITERATIONS = 310_000  # OWASP 2023 guidance for PBKDF2-HMAC-SHA256
_NAME = re.compile(r"^[A-Za-z0-9_.\-]{1,40}$")


def hash_password(password: str, salt: bytes | None = None, iterations: int = ITERATIONS) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def check_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt, digest = stored.split("$")
    except ValueError:
        return False
    if algo != "pbkdf2_sha256":
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt), int(iters))
    return hmac.compare_digest(base64.b64encode(dk).decode(), digest)


def load_users(path: Path = USERS_PATH) -> dict[str, dict]:
    if not path.exists():
        return {}
    return (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("users", {})


def add_user(path: Path, name: str, password: str, role: str) -> None:
    if not _NAME.match(name):
        raise ValueError("user names are 1-40 of A-Z a-z 0-9 _ . -")
    if role not in ROLES:
        raise ValueError(f"role must be one of {sorted(ROLES)}")
    if len(password) < 10:
        raise ValueError("use at least 10 characters")
    users = load_users(path)
    users[name] = {"role": role, "password": hash_password(password)}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump({"users": users}, sort_keys=True), encoding="utf-8")
    os.chmod(path, 0o600)


def authenticate(name: str, password: str, path: Path = USERS_PATH) -> str | None:
    """Returns the user's role, or None. Spends the same time on unknown users."""
    user = load_users(path).get(name)
    stored = user["password"] if user else hash_password("x" * 16, b"\0" * 16)
    ok = check_password(password, stored)
    return user["role"] if user and ok else None


def can(role: str | None, action: str) -> bool:
    need = {"approve": "approver"}.get(action, "analyst")
    return role is not None and ROLES.get(role, 0) >= ROLES[need]
