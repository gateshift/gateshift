# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""Encrypted-at-rest secret storage for operator-supplied VPN PSKs.

The Fernet key comes from the GATESHIFT_SECRET_KEY environment variable - NEVER
the database - so a DB leak alone can't decrypt stored secrets. If the key is
unset (or invalid), secret storage is *disabled*: set/read fail gracefully and
the VPN push falls back to the placeholder PSK exactly as before. Plaintext
secrets live only transiently in memory at push-time; they are never logged,
never returned by any GET, and never baked into the generated/previewed config.
"""
from __future__ import annotations

import os
import re
from functools import lru_cache

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, NoEncryption, Encoding, PrivateFormat)
from cryptography.x509 import load_pem_x509_certificate

_ENV_KEY = "GATESHIFT_SECRET_KEY"


@lru_cache(maxsize=1)
def _fernet() -> Fernet | None:
    raw = (os.environ.get(_ENV_KEY) or "").strip()
    if not raw:
        return None
    try:
        return Fernet(raw.encode())
    except Exception:
        return None


def is_configured() -> bool:
    """True iff a valid GATESHIFT_SECRET_KEY is set - secret storage usable."""
    return _fernet() is not None


def encrypt(plaintext: str) -> str:
    """Encrypt a plaintext secret → storable token. Raises if unconfigured."""
    f = _fernet()
    if f is None:
        raise RuntimeError(
            "secret storage not configured (set GATESHIFT_SECRET_KEY)")
    return f.encrypt(plaintext.encode()).decode()


def decrypt(token: str) -> str | None:
    """Decrypt a stored blob → plaintext, or None if storage is unconfigured
    or the blob can't be decrypted (wrong/rotated key). Callers fall back to
    the placeholder rather than crashing the push."""
    f = _fernet()
    if f is None:
        return None
    try:
        return f.decrypt((token or "").encode()).decode()
    except Exception:
        return None


# ── Device credentials (api_key, gaia_password) ──────────────────────────
#
# Unlike PSKs, these are needed on *every* import and push, and older
# installations already hold them in clear text. So storage is tagged rather
# than swapped: a protected value carries the prefix below, anything without
# it is legacy plaintext and is passed through untouched. That keeps the
# migration lazy (a row upgrades the next time it is written) and keeps the
# tool usable with GATESHIFT_SECRET_KEY unset, which is the documented
# degraded mode everywhere else too.
_CRED_PREFIX = "enc:v1:"


def is_protected(stored: str | None) -> bool:
    """True iff the stored value is one of our encrypted credentials."""
    return bool(stored) and str(stored).startswith(_CRED_PREFIX)


def protect(plaintext: str | None) -> str | None:
    """Encrypt a device credential for storage.

    Returns the value unchanged when there is nothing to protect, when the
    secret store is unconfigured (degraded mode: stored as before), or when
    it is already protected - so it is safe to wrap any write site.
    """
    if not plaintext or is_protected(plaintext) or not is_configured():
        return plaintext
    return _CRED_PREFIX + encrypt(str(plaintext))


def reveal(stored: str | None) -> str | None:
    """Plaintext of a stored device credential.

    Legacy clear-text values pass through unchanged. A protected value that
    cannot be decrypted - key unset, rotated or wrong - yields None rather
    than the ciphertext: callers must not send an encrypted blob to a vendor
    API, where it would surface as a confusing authentication failure.
    """
    if not stored:
        return stored
    s = str(stored)
    if not s.startswith(_CRED_PREFIX):
        return s
    return decrypt(s[len(_CRED_PREFIX):])


def _safe_cert_name(s: str) -> str:
    """Vendor-safe cert reference name: alphanumerics, dash, underscore, dot;
    collapse the rest; cap at 63 (the store column + a sane vendor limit)."""
    s = re.sub(r"[^A-Za-z0-9_.-]+", "-", (s or "").strip()).strip("-")
    return (s or "gateshift-vpn-cert")[:63]


def validate_cert_key(cert_pem: str, key_pem: str,
                      passphrase: str | None = None) -> tuple[str, str]:
    """Validate an identity cert + its private key (VPN cert upload). Confirms
    both parse and that the key matches the cert's public key, then returns
    ``(normalized_cert_pem, unprotected_key_pem)`` - the key re-serialized
    WITHOUT a passphrase so the push can import it directly (it is Fernet-
    encrypted before storage by the caller). Raises ValueError with a
    user-facing message on any problem (never leaks key bytes)."""
    cert_pem = (cert_pem or "").strip()
    key_pem = (key_pem or "").strip()
    if not cert_pem or not key_pem:
        raise ValueError("both a certificate and a private key (PEM) are required")
    try:
        cert = load_pem_x509_certificate(cert_pem.encode())
    except Exception:
        raise ValueError("certificate is not valid PEM")
    pw = passphrase.encode() if passphrase else None
    try:
        key = load_pem_private_key(key_pem.encode(), password=pw)
    except TypeError:
        raise ValueError("private key is passphrase-protected - supply the passphrase")
    except ValueError:
        raise ValueError("private key is not valid PEM, or the passphrase is wrong")
    except Exception:
        raise ValueError("private key could not be loaded")
    # Key must belong to the cert.
    cert_pub = cert.public_key().public_bytes(
        Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    key_pub = key.public_key().public_bytes(
        Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if cert_pub != key_pub:
        raise ValueError("the private key does not match the certificate")
    norm_cert = cert.public_bytes(Encoding.PEM).decode()
    norm_key = key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    return norm_cert, norm_key


def default_cert_name(cert_pem: str, fallback: str) -> str:
    """Derive a reference name from the cert's CN (else the fallback)."""
    try:
        from cryptography.x509.oid import NameOID
        cert = load_pem_x509_certificate((cert_pem or "").encode())
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn:
            return _safe_cert_name(cn[0].value)
    except Exception:
        pass
    return _safe_cert_name(fallback)
