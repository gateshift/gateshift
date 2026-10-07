# Copyright (c) 2026 Timo Duttine - SPDX-License-Identifier: BUSL-1.1
"""Login for the UI (docs/ACCESS_DESIGN.md): one local account, a signed
session cookie, a growing delay after failed attempts.

Standard library only: scrypt for the password hash, HMAC-SHA256 over the
session, the signing key derived (HKDF) from GATESHIFT_SECRET_KEY - the
same secret that protects credentials at rest, so no new value in .env.
Without that key sessions are signed with a per-process random key and
end with the next restart.
"""
import base64
import hashlib
import hmac
import os
import secrets
import threading
import time
from functools import lru_cache

SESSION_COOKIE = "gs_session"
SESSION_TTL = 12 * 3600          # seconds; renewed on use once half is gone
MIN_PASSWORD_LEN = 10

_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2 ** 15, 8, 1
_SCRYPT_MAXMEM = 64 * 1024 * 1024  # n * r * 128 = 32 MiB for these parameters


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ── passwords ───────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    """scrypt$n$r$p$salt$hash - the prefix names the algorithm so a later
    change is a new prefix, old rows keep verifying."""
    salt = os.urandom(32)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R,
                        p=_SCRYPT_P, dklen=32, maxmem=_SCRYPT_MAXMEM)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${_b64(salt)}${_b64(dk)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, dk = (stored or "").split("$")
        if algo != "scrypt":
            return False
        want = _unb64(dk)
        got = hashlib.scrypt(password.encode(), salt=_unb64(salt), n=int(n), r=int(r),
                             p=int(p), dklen=len(want), maxmem=_SCRYPT_MAXMEM)
        return hmac.compare_digest(got, want)
    except Exception:
        return False


# ── sessions ────────────────────────────────────────────────────────────
@lru_cache(maxsize=1)
def _session_key() -> bytes:
    raw = (os.environ.get("GATESHIFT_SECRET_KEY") or "").strip().encode()
    if not raw:
        raw = secrets.token_bytes(32)
    # HKDF-SHA256 (RFC 5869) by hand - extract, then one expand block
    prk = hmac.new(b"gateshift-session-salt", raw, hashlib.sha256).digest()
    return hmac.new(prk, b"gateshift-session" + b"\x01", hashlib.sha256).digest()


def make_session(user_id: int, ttl: int = SESSION_TTL) -> str:
    exp = int(time.time()) + int(ttl)
    msg = f"{int(user_id)}.{exp}".encode()
    sig = hmac.new(_session_key(), msg, hashlib.sha256).digest()
    return f"{int(user_id)}.{exp}.{_b64(sig)}"


def read_session(token: str | None) -> tuple[int, int] | None:
    """(user_id, expires_at) for a valid, unexpired token, else None."""
    if not token:
        return None
    try:
        uid, exp, sig = token.split(".")
        msg = f"{int(uid)}.{int(exp)}".encode()
        want = hmac.new(_session_key(), msg, hashlib.sha256).digest()
        if not hmac.compare_digest(_unb64(sig), want):
            return None
        if int(exp) <= time.time():
            return None
        return int(uid), int(exp)
    except Exception:
        return None


# ── login throttle (per client address, in memory) ─────────────────────
_FAILS: dict[str, tuple[int, float]] = {}   # address -> (count, not_before)
_FAILS_LOCK = threading.Lock()
_FREE_ATTEMPTS = 4   # the fifth failure starts the delay: 1, 2, 4 ... 30 s


def login_wait(address: str) -> float:
    """Seconds the client still has to wait before the next attempt (0 = go)."""
    with _FAILS_LOCK:
        count, not_before = _FAILS.get(address, (0, 0.0))
    return max(0.0, not_before - time.time())


def login_failed(address: str) -> None:
    with _FAILS_LOCK:
        count, _ = _FAILS.get(address, (0, 0.0))
        count += 1
        delay = min(30.0, float(2 ** (count - _FREE_ATTEMPTS - 1))) if count > _FREE_ATTEMPTS else 0.0
        _FAILS[address] = (count, time.time() + delay)
        if len(_FAILS) > 10000:      # bounded memory on a hostile network
            _FAILS.clear()


def login_ok(address: str) -> None:
    with _FAILS_LOCK:
        _FAILS.pop(address, None)
