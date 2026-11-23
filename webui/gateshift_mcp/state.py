# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
"""One connection, one token, one state: the
client of the API bound to the token, the rate limiter of D9, the token's
identity from GET /whoami and a cap on the calls in flight. A bounded cache
keeps the states by token, guarded by a lock (the SDK runs tool calls
concurrently) and emptied of idle entries."""
from __future__ import annotations

import hashlib
import threading
import time
from typing import Callable

from .api import Api, ApiError
from .tools import RateLimiter

MAX_ENTRIES = 64
IDLE_SECONDS = 3600.0
CALLS_IN_FLIGHT = 4
BUSY_SENTENCE = f"{CALLS_IN_FLIGHT} calls of this token are in flight, wait for one to finish"


class TokenState:
    def __init__(self, api: Api, key: str, clock: Callable[[], float] = time.monotonic):
        self.api = api
        self.key = key
        self.limiter = RateLimiter()
        self.token_id: int | None = None
        self.token_name: str | None = None
        self.scope: str | None = None
        self.tenant_id: int | None = None
        self.slots = threading.BoundedSemaphore(CALLS_IN_FLIGHT)
        self.clock = clock
        self.last_used = clock()

    def identify(self) -> None:
        """One read of GET /whoami: the token's id, name, scope and tenant. A
        refused token raises the API's 401 sentence."""
        me = self.api.get("/whoami", timeout=5.0) or {}
        self.token_id = int(me["token_id"]) if me.get("token_id") is not None else None
        self.token_name = me.get("name") or None
        self.scope = me.get("scope") or None
        self.tenant_id = int(me["tenant_id"]) if me.get("tenant_id") else None
        self.api.token_name = self.token_name
        self.api.probed = True        # the identity read is the probe

    def touch(self) -> None:
        self.last_used = self.clock()


def token_key(token: str) -> str:
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()[:32]


class StateCache:
    """The states by token (D13): `factory(token)` builds the API client for a
    token, the cache identifies it once and keeps it until it idles out or
    the cache is full (the oldest goes). A 401 drops the entry (`forget`)."""

    def __init__(self, factory: Callable[[str], Api], max_entries: int = MAX_ENTRIES,
                 idle_seconds: float = IDLE_SECONDS, clock: Callable[[], float] = time.monotonic):
        self.factory = factory
        self.max_entries = int(max_entries)
        self.idle_seconds = float(idle_seconds)
        self.clock = clock
        self._lock = threading.Lock()
        self._states: dict[str, TokenState] = {}

    def _evict(self) -> None:
        now = self.clock()
        for k in [k for k, s in self._states.items() if now - s.last_used > self.idle_seconds]:
            self._states.pop(k).api.close()
        while len(self._states) >= self.max_entries:
            k = min(self._states, key=lambda k: self._states[k].last_used)
            self._states.pop(k).api.close()

    def get(self, token: str) -> TokenState:
        key = token_key(token)
        with self._lock:
            st = self._states.get(key)
            if st is not None:
                st.touch()
                return st
            self._evict()
            st = TokenState(self.factory(token), key, clock=self.clock)
            self._states[key] = st
        try:
            st.identify()
        except ApiError:
            self.forget(key)
            raise
        return st

    def forget(self, key: str) -> None:
        with self._lock:
            st = self._states.pop(key, None)
        if st is not None:
            st.api.close()

    def __len__(self) -> int:
        with self._lock:
            return len(self._states)
