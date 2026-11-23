# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
"""The MCP endpoint in the stack: the
server built once, its Streamable HTTP app with stateful sessions bound to
the token the web application's gate validated, the ASGI endpoint the
application routes `/mcp` to, and the session manager's lifespan. The SDK is
imported behind a guard: the host test suite imports the application without
it, the image has it; without the SDK the route answers 503 with a sentence."""
from __future__ import annotations

import contextlib
import json
import logging
import os
import threading

log = logging.getLogger("gateshift.mcp")

AVAILABLE = False
REASON = ""
try:
    from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
    from mcp.server.auth.provider import AccessToken
    from mcp.server.mcpserver.exceptions import ToolError
    from mcp.server.streamable_http_manager import StreamableHTTPASGIApp
    from mcp.server.transport_security import TransportSecuritySettings
    AVAILABLE = True
except Exception as exc:    # pragma: no cover - the host without the SDK
    REASON = f"the MCP SDK is not installed: {type(exc).__name__}"

SESSION_IDLE_SECONDS = 1800.0
MAX_SESSIONS = 1000
NO_TOKEN_SENTENCE = "no token on this connection: the endpoint needs Authorization: Bearer <token>"

_lock = threading.Lock()
_srv = None
_asgi = None
_cache = None


def _build():
    """The server, its app and the per-token cache, once per process."""
    global _srv, _asgi, _cache
    with _lock:
        if _srv is not None:
            return
        from .api import loopback_api
        from .server import build
        from .state import StateCache
        cache = StateCache(loopback_api)

        def resolve(ctx):
            headers = getattr(ctx, "headers", None) or {}
            auth_h = headers.get("authorization") or ""
            if not auth_h.lower().startswith("bearer "):
                raise ToolError(NO_TOKEN_SENTENCE)
            return cache.get(auth_h[7:].strip())

        srv = build(resolve, cache=cache)
        srv.streamable_http_app(
            streamable_http_path="/mcp", stateless_http=False,
            session_idle_timeout=SESSION_IDLE_SECONDS, max_sessions=MAX_SESSIONS,
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False))
        _cache = cache
        _asgi = StreamableHTTPASGIApp(srv.session_manager)
        _srv = srv


class Endpoint:
    """The ASGI endpoint of `/mcp` (a class instance, so Starlette routes the
    raw ASGI call to it instead of wrapping it as a request handler)."""

    async def __call__(self, scope, receive, send) -> None:
        if not AVAILABLE or _asgi is None:
            body = json.dumps({"error": REASON or "the MCP endpoint is not running"}).encode()
            await send({"type": "http.response.start", "status": 503,
                        "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
            await send({"type": "http.response.body", "body": body})
            return
        await _asgi(scope, receive, send)


def authenticated_user(token_row: dict):
    """The SDK's user for the request scope (D14): the session manager binds
    a session to it and refuses another token's requests on that session.
    Keyed on the token id, never the token's text."""
    if not AVAILABLE:
        return None
    tid = str(token_row.get("id"))
    return AuthenticatedUser(AccessToken(token=f"gs-token-{tid}", client_id=tid,
                                         scopes=[str(token_row.get("scope") or "full")]))


@contextlib.asynccontextmanager
async def lifespan():
    """Runs the session manager for the application's lifetime (D15): enter it
    around the application lifespan's yield, once per process."""
    if not AVAILABLE:
        log.warning("MCP endpoint off: %s", REASON)
        yield
        return
    _build()
    async with _srv.session_manager.run():
        yield


def read_only() -> bool:
    from .server import env_read_only
    return env_read_only()
