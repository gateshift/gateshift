# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
"""The client of Gateshift's automation API.

One token from the environment, TLS verified against the system store or the
PEM file the operator names (there is no switch that turns verification off),
the API's error envelope handed on as the sentence it is, one 401 and the
client refuses every further call locally (a retrying model would otherwise
lock the operator's address out at the API), and every string that comes back
scrubbed of token, header and key patterns before a model sees it (D5)."""
from __future__ import annotations

import os
import re
from typing import Any, Callable

from . import SERVER_VERSION

DEAD_SENTENCE = "the token is unknown, revoked or expired"
PROBE_PATH = "/audit"

_SECRET_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"gs_[A-Za-z0-9_-]{20,}"), "gs_[redacted]"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"), "Bearer [redacted]"),
    (re.compile(r"(?i)\b(x-pan-key|x-chkp-sid|x-api-key|authorization|api[_-]?key|access[_-]?token|"
                r"password|passwd|secret|pre-shared key|psk)(\s*[=:]\s*)(?!\[redacted\])(?!bearer\b)[^\s,;&\"']+"),
     r"\1\2[redacted]"),
]


class ApiError(Exception):
    """What the API refused: its status and its sentence (`error`, `hint`,
    and the correlation id `ref` of a 500)."""

    def __init__(self, status: int, error: str, hint: str | None = None, ref: str | None = None,
                 data: dict | None = None):
        super().__init__(error)
        self.status = int(status)
        self.error = str(error)
        self.hint = hint
        self.ref = ref
        self.data = data or {}     # the envelope's other fields (a 409's `confirmable`, for one)

    def sentence(self) -> str:
        s = self.error
        if self.hint:
            s += f" ({self.hint})"
        if self.ref:
            s += f" [ref {self.ref}]"
        return scrub(s)


class ConfigError(Exception):
    """The environment does not name what the server needs."""


def scrub(text: Any) -> Any:
    """A string without token, header and key values; other values unchanged."""
    if not isinstance(text, str):
        return text
    out = text
    for pat, rep in _SECRET_PATTERNS:
        out = pat.sub(rep, out)
    return out


def scrub_deep(value: Any) -> Any:
    """`scrub` over every string inside dicts and lists."""
    if isinstance(value, str):
        return scrub(value)
    if isinstance(value, list):
        return [scrub_deep(v) for v in value]
    if isinstance(value, dict):
        return {k: scrub_deep(v) for k, v in value.items()}
    return value


class Api:
    """The calls to /api/v1. `send` may be injected (tests): a callable
    (method, url, params, json_body, timeout) -> (status, body), where body
    is the decoded JSON or the raw text."""

    def __init__(self, base_url: str, token: str, ca: str | None = None, timeout: float = 60.0,
                 send: Callable | None = None, verify: Any = None):
        self.base = base_url.rstrip("/")
        if not self.base.endswith("/api/v1"):
            self.base += "/api/v1"
        self._token = token.strip()
        self._ca = ca or None
        self._verify = verify          # an ssl.SSLContext (the loopback pin of D15) wins over `ca`
        self.timeout = float(timeout)
        self._send = send or self._httpx_send
        self._client = None
        self.dead: str | None = None
        self.token_name: str | None = None      # GATESHIFT_MCP_TOKEN_NAME, narrows the tally to this token's writes
        self.probed = False
        self.notice: str | None = None
        self.api_version: str | None = None

    # ── transport ─────────────────────────────────────────────────────
    def _httpx_send(self, method: str, url: str, params: dict | None, json_body: Any, timeout: float):
        try:
            import httpx2 as httpx   # the SDK 2.x ships httpx2, the same client under its new name
        except ImportError:          # an older SDK: the httpx it brought
            import httpx
        if self._client is None:
            verify = self._verify if self._verify is not None else (self._ca if self._ca else True)
            self._client = httpx.Client(verify=verify, timeout=timeout,
                                        headers={"Authorization": f"Bearer {self._token}",
                                                 "User-Agent": f"gateshift-mcp/{SERVER_VERSION}"})
        try:
            r = self._client.request(method, url, params=params or None, json=json_body, timeout=timeout)
        except httpx.RemoteProtocolError:
            # a pooled connection the server closed between two calls: the
            # request never reached a handler, one more try on a fresh connection
            r = self._client.request(method, url, params=params or None, json=json_body, timeout=timeout)
        try:
            body = r.json()
        except ValueError:
            body = r.text
        return r.status_code, body

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    # ── calls ─────────────────────────────────────────────────────────
    def call(self, method: str, path: str, params: dict | None = None, body: Any = None,
             timeout: float | None = None) -> Any:
        if self.dead:
            raise ApiError(401, self.dead)
        url = self.base + (path if path.startswith("/") else "/" + path)
        try:
            status, data = self._send(method.upper(), url, params, body, timeout or self.timeout)
        except ApiError:
            raise
        except Exception as exc:    # the transport: no answer, a refused certificate, a timeout
            raise ApiError(0, f"Gateshift did not answer at {self.base}: {type(exc).__name__}: {scrub(str(exc))[:200]}")
        if status == 401:
            self.dead = DEAD_SENTENCE
            raise ApiError(401, DEAD_SENTENCE)
        if status >= 400:
            if isinstance(data, dict):
                raise ApiError(status, str(data.get("error") or f"HTTP {status}"), data.get("hint"), data.get("ref"),
                               data=data)
            raise ApiError(status, f"HTTP {status}: {scrub(str(data))[:200]}")
        return data

    def get(self, path: str, params: dict | None = None, timeout: float | None = None) -> Any:
        return self.call("GET", path, params=params, timeout=timeout)

    def post(self, path: str, body: Any = None, params: dict | None = None) -> Any:
        return self.call("POST", path, params=params, body=body)

    def patch(self, path: str, body: Any = None) -> Any:
        return self.call("PATCH", path, body=body)

    def put(self, path: str, body: Any = None) -> Any:
        return self.call("PUT", path, body=body)

    def delete(self, path: str, params: dict | None = None) -> Any:
        return self.call("DELETE", path, params=params)

    # ── the first-call probe (D10) ────────────────────────────────────
    def probe(self) -> str | None:
        """Once, on the first tool call: one cheap authenticated read proves
        the token (a 401 ends in the local refusal), then the API's version is
        compared with this server's. Returns the notice for the first answer,
        None when the versions agree."""
        if self.probed:
            return None
        self.probed = True
        self.get(PROBE_PATH, params={"limit": 1}, timeout=3.0)
        try:
            doc = self.get("/openapi.json", timeout=3.0)
            self.api_version = str(((doc or {}).get("info") or {}).get("version") or "")
        except ApiError:
            self.api_version = None
        if self.api_version and self.api_version != SERVER_VERSION:
            self.notice = (f"this server was shipped with Gateshift {SERVER_VERSION}, the installation runs "
                           f"{self.api_version}: a tool may not match the API")
        return self.notice


def from_env(environ: dict | None = None) -> Api:
    """The client from the environment (D10): GATESHIFT_URL and
    GATESHIFT_MCP_TOKEN required, GATESHIFT_CA optional."""
    env = environ if environ is not None else os.environ
    url = (env.get("GATESHIFT_URL") or "").strip()
    token = (env.get("GATESHIFT_MCP_TOKEN") or "").strip()
    ca = (env.get("GATESHIFT_CA") or "").strip() or None
    if not url.startswith(("https://", "http://")):
        raise ConfigError("GATESHIFT_URL must name the installation, for example https://gateshift.example.net")
    if not token.startswith("gs_"):
        raise ConfigError("GATESHIFT_MCP_TOKEN must hold a token from the Automation page (scope project)")
    if ca and not os.path.isfile(ca):
        raise ConfigError(f"GATESHIFT_CA names no file: {ca}")
    api = Api(url, token, ca=ca)
    api.token_name = (env.get("GATESHIFT_MCP_TOKEN_NAME") or "").strip() or None
    return api


LOOPBACK_BASE = "https://127.0.0.1:8443"
LOOPBACK_CA = "/certs/gateshift.crt"


def loopback_context(ca_path: str | None):
    """The SSL context of the loopback (D15): the installation's own certificate
    file as the trust anchor, certificate required, no hostname check (the
    file is the peer, its names are the operator's, not 127.0.0.1). Without
    the file, the system store."""
    import ssl
    if ca_path and os.path.isfile(ca_path):
        ctx = ssl.create_default_context(cafile=ca_path)
    else:
        ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


_LOOPBACK_CTX = None


def loopback_api(token: str, environ: dict | None = None) -> Api:
    """The client a connection's token gets inside the stack (D13, D15): the
    container's own listener over the pinned loopback, GATESHIFT_MCP_API_BASE
    and GATESHIFT_MCP_API_CA for another layout."""
    global _LOOPBACK_CTX
    env = environ if environ is not None else os.environ
    base = (env.get("GATESHIFT_MCP_API_BASE") or LOOPBACK_BASE).strip()
    if _LOOPBACK_CTX is None or environ is not None:
        _LOOPBACK_CTX = loopback_context((env.get("GATESHIFT_MCP_API_CA") or LOOPBACK_CA).strip())
    return Api(base, token, verify=_LOOPBACK_CTX)
