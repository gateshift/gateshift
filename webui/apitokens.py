# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
"""API tokens: a token is created by a
signed-in user, shown once, stored as its SHA-256 and sent by a program as
`Authorization: Bearer <token>`. The plain token is 32 random bytes, url-safe,
prefixed `gs_`; the table keeps the hash, the name, when it was made, last
used and revoked. A session never authenticates an API call and a token never
opens a page.

A token carries a scope (D24): `read` for the reads, `project` for the writes of
a project (curation, build, the review stamp), `full` also for the push, publish
and discard (operator 2026-11-23), the Device and project life cycle, keys and
tenants. It may expire (`expires_at`) and may be bound to one tenant
(`tenant_id`), which is then the only tenant it sees.

The audit: every write
through the API that succeeded lands as one row of fw_api_audit with the
token's name and id, the call, what it touched and the caller's reason. The
override rows the write made stay `manual`, the audit says whose hand it was."""
from __future__ import annotations

import hashlib
import hmac
import secrets

PREFIX = "gs_"
TOKEN_BYTES = 32

SCOPES = ("read", "project", "full")
_RANK = {"read": 0, "project": 1, "full": 2}


def scope_allows(have: str | None, need: str) -> bool:
    """Whether a token of scope `have` may call a route that needs `need`."""
    return _RANK.get(have or "", -1) >= _RANK.get(need, 99)


def new_token() -> str:
    """A fresh plain token: the prefix and 32 random bytes, url-safe."""
    return PREFIX + secrets.token_urlsafe(TOKEN_BYTES)


def token_hash(token: str) -> str:
    """The stored form of a token: its SHA-256, hex."""
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def looks_like_token(value: str | None) -> bool:
    """The shape a bearer value must have before the database is asked."""
    v = (value or "").strip()
    return v.startswith(PREFIX) and 30 <= len(v) <= 80 and all(
        c.isalnum() or c in "-_" for c in v[len(PREFIX):])


def hashes_match(stored: str | None, token: str) -> bool:
    """Constant-time comparison of the stored hash with the hash of a token."""
    return bool(stored) and hmac.compare_digest(str(stored), token_hash(token))


def _text(sql: str):
    # the database driver is imported at call time: the token functions above
    # run in the host's unit tests, where SQLAlchemy is not installed
    from sqlalchemy import text
    return text(sql)


def ensure_table(conn) -> None:
    """The token table (lifespan DDL, one statement per call)."""
    conn.execute(_text("""
        CREATE TABLE IF NOT EXISTS fw_api_tokens (
            id           INT AUTO_INCREMENT PRIMARY KEY,
            name         VARCHAR(64)  NOT NULL,
            token_hash   CHAR(64)     NOT NULL UNIQUE,
            scope        ENUM('read','project','full') NOT NULL DEFAULT 'full',
            expires_at   DATETIME     NULL,
            tenant_id    INT          NULL,
            created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_used_at DATETIME     NULL,
            revoked_at   DATETIME     NULL
        )
    """))


# The columns of D24 and D26 on tables that exist already: one statement each,
# the lifespan runs every one in its own transaction.
TOKEN_COLUMN_DDL = (
    "ALTER TABLE fw_api_tokens ADD COLUMN IF NOT EXISTS scope ENUM('read','project','full') NOT NULL DEFAULT 'full'",
    "ALTER TABLE fw_api_tokens ADD COLUMN IF NOT EXISTS expires_at DATETIME NULL",
    "ALTER TABLE fw_api_tokens ADD COLUMN IF NOT EXISTS tenant_id INT NULL",
)
AUDIT_COLUMN_DDL = (
    "ALTER TABLE fw_api_audit ADD COLUMN IF NOT EXISTS token_id INT NULL",
    "ALTER TABLE fw_api_audit ADD COLUMN IF NOT EXISTS reason VARCHAR(200) NULL",
    "ALTER TABLE fw_api_audit MODIFY detail TEXT NULL",
)


def create(conn, name: str, scope: str = "full", expires_at=None, tenant_id: int | None = None) -> tuple[int, str]:
    """Store a new token under `name` with its scope, expiry and tenant, return
    (id, plain token). The plain token is shown once and never stored. A live
    token's name is taken once: ValueError with the sentence."""
    name = (name or "").strip()[:64] or "token"
    if scope not in SCOPES:
        raise ValueError("the scope must be read, project or full")
    if conn.execute(_text("SELECT 1 FROM fw_api_tokens WHERE name = :n AND revoked_at IS NULL"),
                    {"n": name}).fetchone():
        raise ValueError(f"a live token named {name} exists, revoke it first or pick another name")
    plain = new_token()
    res = conn.execute(_text(
        "INSERT INTO fw_api_tokens (name, token_hash, scope, expires_at, tenant_id) "
        "VALUES (:n, :h, :s, :e, :t)"),
        {"n": name, "h": token_hash(plain), "s": scope, "e": expires_at,
         "t": int(tenant_id) if tenant_id else None})
    return int(res.lastrowid), plain


def revoke(conn, token_id: int) -> bool:
    """Mark a token revoked; a revoked token never authenticates again."""
    res = conn.execute(_text(
        "UPDATE fw_api_tokens SET revoked_at = NOW() WHERE id = :i AND revoked_at IS NULL"),
        {"i": int(token_id)})
    return bool(res.rowcount)


def list_tokens(conn) -> list[dict]:
    """Every token with its name, scope, expiry, tenant and dates, the hash
    never leaves the table."""
    rows = conn.execute(_text(
        "SELECT t.id, t.name, t.scope, t.expires_at, t.tenant_id, tn.name AS tenant_name, "
        "t.created_at, t.last_used_at, t.revoked_at, "
        "(t.expires_at IS NOT NULL AND t.expires_at <= NOW()) AS expired "
        "FROM fw_api_tokens t LEFT JOIN fw_tenants tn ON tn.id = t.tenant_id "
        "ORDER BY t.revoked_at IS NOT NULL, t.created_at DESC")).mappings().all()
    return [dict(r, expired=bool(r["expired"])) for r in rows]


def lookup(conn, token: str) -> dict | None:
    """The live token row of a plain token, or None (unknown, revoked, expired,
    or not shaped like a token). The hash is compared in constant time."""
    if not looks_like_token(token):
        return None
    row = conn.execute(_text(
        "SELECT id, name, token_hash, scope, tenant_id, expires_at FROM fw_api_tokens "
        "WHERE token_hash = :h AND revoked_at IS NULL "
        "AND (expires_at IS NULL OR expires_at > NOW())"),
        {"h": token_hash(token.strip())}).mappings().fetchone()
    if not row or not hashes_match(row["token_hash"], token.strip()):
        return None
    return {"id": int(row["id"]), "name": row["name"], "scope": row["scope"] or "full",
            "tenant_id": (int(row["tenant_id"]) if row["tenant_id"] else None),
            "expires_at": (str(row["expires_at"])[:19] if row["expires_at"] else None)}


def touch(conn, token_id: int) -> None:
    conn.execute(_text("UPDATE fw_api_tokens SET last_used_at = NOW() WHERE id = :i"),
                 {"i": int(token_id)})


# ── the audit of the API's writes (D8) ────────────────────────────────

def ensure_audit_table(conn) -> None:
    """The audit table (lifespan DDL, one statement per call)."""
    conn.execute(_text("""
        CREATE TABLE IF NOT EXISTS fw_api_audit (
            id         INT AUTO_INCREMENT PRIMARY KEY,
            token_name VARCHAR(64)  NOT NULL,
            method     VARCHAR(8)   NOT NULL,
            path       VARCHAR(255) NOT NULL,
            project_id INT          NULL,
            device_id  INT          NULL,
            detail     VARCHAR(512) NULL,
            created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
            KEY ix_fw_api_audit_project (project_id, id),
            KEY ix_fw_api_audit_device (device_id, id)
        )
    """))


def audit(conn, token_name: str, method: str, path: str, detail: str | None = None,
          project_id: int | None = None, device_id: int | None = None,
          token_id: int | None = None, reason: str | None = None) -> None:
    """One row per API write that succeeded: the token's name and id, the
    call, what it touched (detail, as long as it needs to name the items) and
    the caller's reason (D25)."""
    conn.execute(_text(
        "INSERT INTO fw_api_audit (token_name, token_id, method, path, project_id, device_id, detail, reason) "
        "VALUES (:n, :tid, :m, :p, :pid, :did, :d, :r)"),
        {"n": (token_name or "?")[:64], "tid": token_id, "m": (method or "")[:8].upper(),
         "p": (path or "")[:255], "pid": project_id, "did": device_id,
         "d": (detail or None) and str(detail)[:20000],
         "r": (reason or None) and str(reason).strip()[:200]})


def list_audit(conn, project_id: int | None = None, device_id: int | None = None,
               limit: int = 50, offset: int = 0, tenant_id: int | None = None) -> tuple[list[dict], int]:
    """The audit rows, newest first, and their total; by project or Device
    when asked, and only the rows of one tenant's projects and Devices for a
    tenant-bound token."""
    where, params = [], {}
    if project_id:
        where.append("project_id = :pid")
        params["pid"] = int(project_id)
    if device_id:
        where.append("device_id = :did")
        params["did"] = int(device_id)
    if tenant_id:
        where.append("(project_id IN (SELECT id FROM fw_projects WHERE tenant_id = :tn) "
                     "OR device_id IN (SELECT id FROM fw_devices WHERE tenant_id = :tn))")
        params["tn"] = int(tenant_id)
    cond = (" WHERE " + " AND ".join(where)) if where else ""
    total = int(conn.execute(_text(f"SELECT COUNT(*) FROM fw_api_audit{cond}"), params).scalar() or 0)
    rows = conn.execute(_text(
        f"SELECT id, token_name, token_id, method, path, project_id, device_id, detail, reason, created_at "
        f"FROM fw_api_audit{cond} ORDER BY id DESC LIMIT :lim OFFSET :off"),
        {**params, "lim": int(limit), "off": int(offset)}).mappings().all()
    return [dict(r) for r in rows], total
