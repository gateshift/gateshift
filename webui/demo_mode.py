# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
"""Live-demo mode.

Set ``GATESHIFT_DEMO=1`` and the app runs as one seat of the public demo:
the login wall is gone (the middleware issues a session for the first
enabled operator), every page carries the demo banner, and the actions that
would reach a firewall or register a new one are refused with one sentence.
Everything else is the shipped product. The flag is read once at start,
like the other environment settings.

Nothing in here touches the database or the app's request objects, so the
rules are testable on their own and the wiring in main.py stays a few lines.
The one hook is on the HTTP client: a replayed Device's gap becomes one
sentence (``install_gap_hook``).
"""
from __future__ import annotations

import os

ENV_FLAG = "GATESHIFT_DEMO"
ENV_MINUTES = "GATESHIFT_DEMO_MINUTES"
DEFAULT_MINUTES = 45

# every sentence of the demo ends with the same call (user's wording, 2026-11-17)
INSTALL = "Install Gateshift and connect real firewalls for full functionality."
REFUSAL = "Not every function is available in the live demo, this one is off. " + INSTALL
# a Device read the demo's recordings lack: the
# replay marks its answer with this header and the app shows one sentence
# instead of the transport error
GAP_HEADER = "X-Gateshift-Replay"
GAP_VALUE = "gap"
GAP = "The live demo's Devices are recordings and this read is not in them. " + INSTALL


class ReplayGap(RuntimeError):
    """A Device read the replay has no recording for."""


def is_gap(exc: BaseException | None) -> bool:
    """True for the replay's gap, also when a driver wrapped it in an error of its own."""
    return isinstance(exc, ReplayGap) or GAP in str(exc or "")


def install_gap_hook() -> None:
    """Wrap ``requests.Session.request`` so a replay answer carrying the gap
    header raises ReplayGap before any driver reads it. Demo seats only."""
    import requests
    original = requests.Session.request
    if getattr(original, "_gs_demo_gap", False):
        return

    def gap_request(self, method, url, *args, **kwargs):
        resp = original(self, method, url, *args, **kwargs)
        try:
            marked = resp.headers.get(GAP_HEADER) == GAP_VALUE
        except Exception:
            marked = False
        if marked:
            raise ReplayGap(GAP)
        return resp

    gap_request._gs_demo_gap = True  # type: ignore[attr-defined]
    requests.Session.request = gap_request  # type: ignore[assignment]

# POST paths the demo refuses: everything that registers a Device (the add
# dialog and its platform-specific steps, the uploads included: visitors
# should not feed a public box with their own configurations), everything
# that writes a Device (push, publish, discard, the Check Point pin check),
# and the log pipeline (its runs and the sender scan exec into the python
# container through the Docker socket, which a seat does not have). The reads
# of a Device (import, collect, the fetches, hit counts) stay open: a seat's
# firewalls are replayed recordings, only a cloud
# account's import is refused in the handler, it has no replay. Builds,
# reviews, edits and the whole project view stay open.
_BLOCKED_PREFIXES = (
    "/api-tokens", "/api/v1/",   # the automation API and its tokens: no writes from a seat
    "/devices/add",
    "/devices/logs/upload",
    "/devices/senders/scan",
    "/deploy/push/",
    "/deploy/publish/",
    "/deploy/discard/",
    "/deploy/cp-pin/",
    # the ruleset pipeline (/run/*) runs in a seat since the demo design D8:
    # a stand-in answers the webapp's Docker SDK and runs the stages in the seat's
    # own pipeline container
)
_BLOCKED_DEVICE_SUFFIXES: tuple[str, ...] = ()


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


def enabled(environ=None) -> bool:
    env = os.environ if environ is None else environ
    return _truthy(env.get(ENV_FLAG))


def minutes(environ=None) -> int:
    """The seat length the banner names. The broker on the demo host owns the
    real timer, this is the sentence's number."""
    env = os.environ if environ is None else environ
    raw = (env.get(ENV_MINUTES) or "").strip()
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_MINUTES
    return value if value > 0 else DEFAULT_MINUTES


def blocked(method: str, path: str) -> bool:
    """True for a request the demo refuses. Reads (GET) are never refused:
    the dialogs may open, their submit is what comes back with the sentence."""
    meth = (method or "").upper()
    if meth != "POST" and not (meth in ("PATCH", "PUT", "DELETE") and path.startswith("/api/v1/")):
        return False       # the pages write with POST; the API also with PATCH, PUT and DELETE
    if path.startswith(_BLOCKED_PREFIXES):
        return True
    if path.startswith("/devices/"):
        rest = path[len("/devices/"):]
        # "/devices/<id>/import" and "/devices/<id>/collect" (the id is the
        # first segment, anything after the suffix is not a match)
        head, sep, tail = rest.partition("/")
        return bool(sep) and head.isdigit() and ("/" + tail) in _BLOCKED_DEVICE_SUFFIXES
    return False


def banner_sentence(seat_minutes: int) -> str:
    return (f"Live demo. This seat resets {seat_minutes} minutes after its start, "
            f"and nothing you do here reaches a firewall.")
