# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
"""Record the API conversation with a Device.

``GATESHIFT_RECORD_DIR=<dir>`` makes the app wrap ``requests.Session.request``
at start: every call that leaves the app through ``requests`` (the readers,
the drivers, the catalogue fetches) is appended as one JSON line to
``<dir>/<host>.jsonl``, with the request's method, path, query and body and
the response's status, content type and body. Secrets are dropped before
the line is written: the PAN-OS ``key`` parameter, the Check Point login
body, the OPNsense authorization header and every session header. The file
is what the live demo's replay serves (tools/demo-host/mock/replay.py) and
what a support case can read as the exact conversation of an import.

Off by default. The wrapper adds nothing to the call when the directory is
unset, and a line that cannot be written never fails the call.
"""
from __future__ import annotations

import base64
import json
import os
import threading
import urllib.parse

ENV_DIR = "GATESHIFT_RECORD_DIR"

# query parameters and body keys that carry a credential or a session, never
# recorded and never part of a replay signature
VOLATILE_QUERY = frozenset({"key", "password", "secret", "token", "_"})
VOLATILE_BODY = frozenset({"api-key", "password", "user", "username", "secret",
                           "session-id", "sid", "csrf"})
# the Check Point login's body is the credential itself
VOLATILE_PATH_BODIES = ("/web_api/login", "/web_api/v1/login", "/gaia_api/login")
_lock = threading.Lock()


def _split_url(url: str) -> tuple[str, str, dict]:
    u = urllib.parse.urlsplit(url)
    host = u.hostname or "unknown"
    if u.port and u.port not in (80, 443):
        host = f"{host}_{u.port}"
    query = {k: v for k, v in urllib.parse.parse_qsl(u.query, keep_blank_values=True)
             if k not in VOLATILE_QUERY}
    return host, u.path or "/", query


def _merge_query(query: dict, params) -> dict:
    """``requests`` takes ``params=`` beside the URL's own query."""
    out = dict(query)
    if params:
        items = params.items() if isinstance(params, dict) else params
        for k, v in items:
            if k in VOLATILE_QUERY:
                continue
            out[str(k)] = v if isinstance(v, str) else json.dumps(v, sort_keys=True)
    return out


def _body_of(kwargs: dict, path: str) -> object:
    """The request body as the recording keeps it: a JSON object with the
    volatile keys dropped, a form as a dict, text as text, else base64."""
    if any(path.endswith(p) for p in VOLATILE_PATH_BODIES):
        return {"_login": True}
    body = kwargs.get("json")
    if body is None:
        data = kwargs.get("data")
        if data is None:
            return None
        if isinstance(data, dict):
            body = dict(data)
        elif isinstance(data, (bytes, bytearray)):
            try:
                body = data.decode("utf-8")
            except UnicodeDecodeError:
                return {"_b64": base64.b64encode(bytes(data)).decode()}
        else:
            body = str(data)
    if isinstance(body, dict):
        return {k: v for k, v in body.items() if k not in VOLATILE_BODY}
    if isinstance(body, str):
        try:
            parsed = json.loads(body)
        except ValueError:
            # a form body as text: drop the volatile fields the same way
            if "=" in body and "\n" not in body:
                pairs = urllib.parse.parse_qsl(body, keep_blank_values=True)
                return {k: v for k, v in pairs if k not in VOLATILE_QUERY | VOLATILE_BODY}
            return body
        if isinstance(parsed, dict):
            return {k: v for k, v in parsed.items() if k not in VOLATILE_BODY}
        return parsed
    return body


def signature(method: str, path: str, query: dict, body: object) -> str:
    """The key a replay matches on: method, path, sorted query, canonical body."""
    return json.dumps([method.upper(), path, sorted(query.items()),
                       body], sort_keys=True, separators=(",", ":"))


def _response_body(resp) -> dict:
    ctype = (resp.headers.get("Content-Type") or "").split(";")[0].strip()
    raw = resp.content or b""
    try:
        return {"content_type": ctype, "text": raw.decode("utf-8")}
    except UnicodeDecodeError:
        return {"content_type": ctype, "b64": base64.b64encode(raw).decode()}


def record_line(directory: str, method: str, url: str, kwargs: dict, resp) -> None:
    host, path, query = _split_url(url)
    query = _merge_query(query, kwargs.get("params"))
    body = _body_of(kwargs, path)
    line = {"method": method.upper(), "path": path, "query": query, "body": body,
            "signature": signature(method, path, query, body),
            "status": int(resp.status_code), **_response_body(resp)}
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in host)
    with _lock:
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, f"{safe}.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(line, sort_keys=True) + "\n")


def records(url: str, kwargs: dict) -> bool:
    """Only a Device's call is recorded: a streamed response cannot be read for
    the file without emptying it for the caller (the ruleset pipeline starts
    its exec through the Docker SDK, which rides on requests with stream=True
    and lost its socket to the recorder, 2026-11-17), and the Docker daemon's
    URLs (http+docker, http+unix) are no Device."""
    if kwargs.get("stream"):
        return False
    scheme = (url or "").split("://", 1)[0].lower() if "://" in (url or "") else ""
    return scheme in ("http", "https")


def install(directory: str | None = None) -> bool:
    """Wrap ``requests.Session.request`` when the directory is set. Returns
    True when recording is on."""
    directory = (directory if directory is not None else os.environ.get(ENV_DIR) or "").strip()
    if not directory:
        return False
    import requests
    if getattr(requests.Session.request, "_gs_recording", False):
        return True
    original = requests.Session.request

    def recording_request(self, method, url, **kwargs):
        resp = original(self, method, url, **kwargs)
        try:
            if records(url, kwargs):
                record_line(directory, method, url, kwargs, resp)
        except Exception:  # noqa: BLE001 - a recording failure never fails the call
            pass
        return resp

    recording_request._gs_recording = True   # type: ignore[attr-defined]
    requests.Session.request = recording_request  # type: ignore[assignment]
    return True
