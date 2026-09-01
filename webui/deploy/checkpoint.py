# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""
Check Point (R8x) deploy driver.

Renders Check Point Management API commands and pushes them via the
SmartCenter Web API. Does NOT auto-publish - the user must run `publish`
on the management server.

Sections produced by generate() are JSON-encoded lists of
``{"command": <api-command>, "payload": <dict>}`` items. push() iterates
and POSTs each one. This keeps the renderer testable in isolation
(produces plain data) and the push step a thin loop.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
import time
from typing import Any, Iterator

import requests

from . import integrity as _integ
from .base import (
    DeployDriver,
    DroppedField,
    StepResult,
    expand_multiproto_services,
    register_driver,
)

# Pass-through V1 schema fields the checkpoint driver does not yet render.
# Each non-empty occurrence is reported via dropped_fields[] so the UI can
# surface what's lost before push.
# Rule fields the CP renderer does not translate at all. `application` is NOT
# here: it IS rendered (valid CP App-Sites are mixed into the service list;
# foreign app-ids are dropped with a precise per-name dropped_field), so a
# blanket "not yet rendered" note for it was just noise.
_UNSUPPORTED_RULE_FIELDS = (
    "url_category",
)

log = logging.getLogger(__name__)

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


# Cap the TCP-connect phase separately from the read phase. On a reachable
# box the handshake is near-instant; an unreachable/blackholed endpoint would
# otherwise eat the full read-timeout (60-120s) per attempt just to fail the
# connect - multiplied across retries that froze the whole discover.
_CONNECT_TIMEOUT = 5


def _post_with_retry(
    url: str, *, payload: dict, headers: dict | None = None,
    timeout: int = 120, retries: int = 2,
) -> requests.Response:
    """POST with retry on transport-level drops. CP Mgmt-API and Gaia REST
    both occasionally drop the TCP connection mid-request (observed as
    RemoteDisconnected after the TLS handshake but before the response).
    One flaky call shouldn't kill a whole discover/push, so we retry on
    ``ConnectionError``/``ChunkedEncodingError`` with linear backoff. The
    connect phase is capped at ``_CONNECT_TIMEOUT`` so an unreachable host
    fails fast instead of blocking ``timeout`` seconds per attempt."""
    connect_timeout = min(_CONNECT_TIMEOUT, timeout)
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            return requests.post(
                url, json=payload, headers=headers or {},
                verify=False, timeout=(connect_timeout, timeout),
            )
        except (requests.exceptions.ConnectionError,
                requests.exceptions.ChunkedEncodingError) as exc:
            last_exc = exc
            if attempt == retries:
                raise RuntimeError(
                    f"POST {url} → connection error after "
                    f"{retries + 1} attempts: {exc}"
                ) from exc
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"POST {url} → unreachable: {last_exc}")


# ── CP Management API helpers ────────────────────────────────────

def _get_mgmt_endpoint(device: dict) -> tuple[str, int]:
    """Resolve the Mgmt-Server (ip, port) for Mgmt-API calls.

    Per the gateway-as-device model, ``device.mgmt_ip`` holds the Gateway-IP
    (Gaia). The Mgmt-Server lives at ``config.cp.mgmt.ip`` and must be set
    explicitly - silently falling back to ``mgmt_ip`` would dispatch every
    Mgmt-API call at the Gateway and surface as opaque JSONDecodeErrors when
    Gaia returns its HTML login page.
    """
    cfg_raw = device.get("config")
    cfg = {}
    if cfg_raw:
        try:
            cfg = json.loads(cfg_raw) if isinstance(cfg_raw, str) else cfg_raw
        except (ValueError, TypeError):
            cfg = {}
    mgmt = ((cfg.get("cp") or {}).get("mgmt") or {}) if isinstance(cfg, dict) else {}
    ip = mgmt.get("ip")
    if not ip:
        raise RuntimeError(
            "CP device has no Mgmt-Server configured (config.cp.mgmt.ip). "
            "Re-add via the CP wizard or populate config.cp.mgmt manually."
        )
    return ip, int(mgmt.get("port") or 443)


def _gaia_comment(it: dict) -> str | None:
    """Gaia stores interface comments brace-wrapped ("{text}") - strip them."""
    raw = (it.get("comments") or it.get("comment") or "").strip()
    if raw.startswith("{") and raw.endswith("}"):
        raw = raw[1:-1].strip()
    return raw or None


def _api_url(device: dict) -> str:
    ip, port = _get_mgmt_endpoint(device)
    return f"https://{ip}:{port}/web_api"


def _cp_cluster_members(gw: dict) -> list[dict]:
    """Extract ClusterXL members from a ``show-simple-cluster`` object →
    ``[{name, gaia_ip, interfaces}]``.

    ``gaia_ip`` is the member's OWN management IP (the ``ip-address`` field;
    cpgw1=.111 / cpgw2=.112), which is the per-member Gaia endpoint - the cluster
    VIP is NOT a Gaia endpoint, so a cluster network push must target each member
    here (see project_cp_cluster_plan F4). ``interfaces`` is the member's iface
    list (dicts shaped like a simple-gateway's, so the import parse loop reuses
    them). Returns ``[]`` for a non-cluster gateway (no ``cluster-members``).
    Shared by the import collect (CP-1) and the per-member network push (CP-2)."""
    out: list[dict] = []
    for m in gw.get("cluster-members") or []:
        ip = m.get("ip-address") or m.get("ipv4-address")
        if not ip:
            continue
        out.append({
            "name":       m.get("name") or "",
            "gaia_ip":    ip,
            "interfaces": m.get("interfaces") or [],
        })
    return out


# Module-level SID cache: key = (base_url, api_key) → (sid, expires_epoch).
# CP rate-limits ~3 logins in <30s, but the Discover UI fires four kinds
# back-to-back. Caching the SID lets all four share one login. The cache
# TTL stays well under CP's session timeout (default ~10 min for read).
_SID_CACHE: dict[tuple[str, str], tuple[str, float]] = {}
_SID_TTL = 240.0  # seconds


def _login(device: dict, *, fresh: bool = False) -> tuple[str, str]:
    """Login to CP Management API via API-key. Returns (sid, base_url).

    Reuses a cached SID for (base_url, api_key) when fresh. `fresh=True` forces a
    DEDICATED session that is never read from nor written to the shared cache - for
    callers that stage changes and then publish/discard that exact session, so they
    never touch a sibling operation's pending changes. On failure,
    surfaces CP's response body - `requests.raise_for_status()` alone gives
    only "400 Bad Request" which hides whether the cause is a wrong api-key
    (`err_login_failed`), rate-limit (`err_too_many_requests`), or other.

    Rate-limit retry: CP returns 403 ``err_too_many_requests`` after ~3 logins
    in close succession. We retry up to three times with linear backoff
    (5s, 10s, 15s) before surfacing the error.
    """
    base_url = _api_url(device)
    api_key = device.get("api_key") or ""
    if not api_key:
        raise RuntimeError("No API key configured")
    # Multi-Domain (MDS): config.cp.domain scopes the whole session to that domain -
    # every show-/set-/add- call then operates inside it. No domain = MDS level (or a
    # plain SmartCenter). Sessions are PER-DOMAIN, so the domain is part of the cache key.
    try:
        _cfg = device.get("config") or {}
        if isinstance(_cfg, str):
            _cfg = json.loads(_cfg or "{}")
        domain = ((_cfg.get("cp") or {}).get("domain")) or None
    except Exception:
        domain = None
    cache_key = (base_url, api_key, domain)
    if not fresh:
        cached = _SID_CACHE.get(cache_key)
        if cached and cached[1] > time.time():
            return cached[0], base_url
    login_payload = {"api-key": api_key}
    if domain:
        login_payload["domain"] = domain
    last_msg = ""
    for attempt in range(4):
        resp = _post_with_retry(
            f"{base_url}/login",
            payload=login_payload,
            timeout=60,
        )
        if resp.status_code < 400:
            try:
                data = resp.json()
            except ValueError:
                snippet = (resp.text or "").strip()[:120]
                raise RuntimeError(
                    f"login HTTP {resp.status_code}: response was not JSON - "
                    f"{base_url} likely points at the Gateway/Gaia, not the "
                    f"Mgmt-API. Set config.cp.mgmt.ip to the Mgmt-Server. "
                    f"Body: {snippet!r}"
                )
            sid = data.get("sid")
            if not sid:
                raise RuntimeError(f"login failed: {data}")
            if not fresh:
                _SID_CACHE[cache_key] = (sid, time.time() + _SID_TTL)
            return sid, base_url
        try:
            body = resp.json()
        except Exception:
            body = {"_raw": resp.text}
        msg = body.get("message") or str(body)
        code = body.get("code")
        prefix = f"{code}: " if code else ""
        last_msg = f"login HTTP {resp.status_code}: {prefix}{msg}"
        if code == "err_too_many_requests" and attempt < 3:
            time.sleep(5 * (attempt + 1))
            continue
        raise RuntimeError(last_msg)
    raise RuntimeError(last_msg or "login failed")


def _logout(base_url: str, sid: str) -> None:
    """Best-effort logout. With SID caching, callers of `_login()` don't
    actually want to invalidate a still-cached session - so only POST
    /logout when this SID is no longer the cached one (i.e. the cache has
    expired or rotated). Otherwise let the TTL handle release."""
    for key, (cached_sid, _exp) in list(_SID_CACHE.items()):
        if cached_sid == sid and key[0] == base_url:
            return  # still cached - keep alive for sibling calls
    try:
        requests.post(
            f"{base_url}/logout",
            json={},
            headers={"X-chkp-sid": sid},
            verify=False,
            timeout=30,
        )
    except Exception:
        pass


def _discard_orphan_sessions(base_url: str, sid: str) -> tuple[int, str | None]:
    """Discard every other open session belonging to the same user as ours.

    A prior push that crashed (SSE disconnect, exception, container restart)
    leaves its Mgmt-API session open with locks on every staged object until
    the ~10 min idle timeout. Subsequent pushes from a fresh session then
    fail the wipe phase with HTTP 409 ``locked: [General lock by <user>]``.

    Assumption: Gateshift runs under its own dedicated CP API user per device, so
    discarding *all* other sessions of that user is safe - no human admin
    is co-editing under that identity. Returns ``(discarded, error)``.
    """
    try:
        me = _call(base_url, sid, "show-session", {})
    except Exception as e:
        return 0, f"show-session failed: {e}"
    my_uid = me.get("uid")
    my_user = (me.get("user-name") or me.get("user") or "").strip()
    if not my_user:
        return 0, "could not resolve current user-name"

    sessions: list[dict] = []
    offset = 0
    while True:
        try:
            page = _call(base_url, sid, "show-sessions", {
                "limit": 50, "offset": offset, "details-level": "full",
            })
        except Exception as e:
            return 0, f"show-sessions failed: {e}"
        chunk = page.get("objects") or []
        sessions.extend(chunk)
        total = page.get("total") or 0
        offset += len(chunk)
        if not chunk or offset >= total:
            break

    discarded = 0
    last_err: str | None = None
    for s in sessions:
        uid = s.get("uid")
        if not uid or uid == my_uid:
            continue
        if (s.get("user-name") or s.get("user") or "").strip() != my_user:
            continue
        # CP Mgmt-API has no "force-logout" verb. The reliable lock-release
        # path: take-over-session pulls the orphan's locks into our current
        # session, then discard drops them as part of our own pending
        # changes. Order matters - take-over first, then discard our session
        # (no uid). discard {uid} alone leaves locks pinned to the orphan.
        try:
            _call(base_url, sid, "take-over-session",
                  {"uid": uid, "disconnect-active-session": True})
            discarded += 1
        except Exception as e:
            last_err = f"take-over-session {uid}: {e}"
    if discarded:
        try:
            _call(base_url, sid, "discard", {})
        except Exception as e:
            last_err = f"discard own session: {e}"
    return discarded, last_err


def _call(base_url: str, sid: str, command: str, payload: dict) -> dict:
    """POST a CP API command. Returns parsed JSON. Raises on non-2xx.

    On failure the raised RuntimeError carries the top-level message AND
    any nested ``errors``/``blocking-errors`` detail. CP's top-level message
    is usually generic ("Validation failed with 1 error") - the actual cause
    (e.g. "Object with name 'X' already exists") lives in those arrays.
    """
    resp = _post_with_retry(
        f"{base_url}/{command}",
        payload=payload,
        headers={"X-chkp-sid": sid, "Content-Type": "application/json"},
        timeout=120,
    )
    if resp.status_code >= 400:
        try:
            body = resp.json()
        except Exception:
            body = {"_raw": resp.text}
        msg = body.get("message") or str(body)
        details: list[str] = []
        for key in ("blocking-errors", "errors"):
            for entry in body.get(key) or ():
                if isinstance(entry, dict) and entry.get("message"):
                    details.append(entry["message"])
        if details:
            msg = f"{msg} [{'; '.join(details)}]"
        raise RuntimeError(f"{command} → HTTP {resp.status_code}: {msg}")
    try:
        return resp.json()
    except ValueError:
        snippet = (resp.text or "").strip()[:120]
        raise RuntimeError(
            f"{command} → HTTP {resp.status_code}: response was not JSON. "
            f"Body: {snippet!r}"
        )


# ── Gaia REST API helpers ────────────────────────────────────────
#
# The Gaia API lives at https://<gw>/gaia_api and authenticates with
# user+password (NOT the Mgmt-API key). It returns a `sid` that subsequent
# calls send as `X-chkp-sid`. Idle timeout is 10 min on Gateways; we don't
# cache sids across calls - each list_target_* method does its own
# login/logout cycle in a try/finally.

def _gaia_url(device: dict) -> str:
    ip = device.get("mgmt_ip") or "127.0.0.1"
    port = device.get("mgmt_port") or 443
    return f"https://{ip}:{port}/gaia_api"


def _gaia_login(device: dict, *, retries: int = 2) -> tuple[str, str]:
    """Login to Gaia REST API via user+password. Returns (sid, base_url).

    Raises NotImplementedError when no Gaia credentials are configured -
    main.py converts that into a 400 + ``supported: false`` so the UI tab
    stays quietly empty (same path as ``list_target_zones`` for CP).

    Best-effort callers (the optional bond/interface enrichment fetchers)
    pass ``retries=0`` so an unreachable Gaia gateway fails after one fast
    connect-timeout instead of three.
    """
    base_url = _gaia_url(device)
    user = device.get("gaia_user") or ""
    password = device.get("gaia_password") or ""
    if not user or not password:
        raise NotImplementedError(
            f"CheckpointDriver: Gaia credentials missing on device "
            f"{device.get('host_name')!r} - set gaia_user and gaia_password "
            "to enable Gateway-side discover (interfaces, routes)"
        )
    resp = _post_with_retry(
        f"{base_url}/login",
        payload={"user": user, "password": password},
        timeout=60, retries=retries,
    )
    resp.raise_for_status()
    try:
        data = resp.json()
    except ValueError:
        snippet = (resp.text or "").strip()[:120]
        raise RuntimeError(
            f"gaia login HTTP {resp.status_code}: response was not JSON - "
            f"{base_url} likely does not expose Gaia REST. Body: {snippet!r}"
        )
    sid = data.get("sid")
    if not sid:
        raise RuntimeError(f"gaia login failed: {data}")
    return sid, base_url


def _gaia_logout(base_url: str, sid: str) -> None:
    try:
        requests.post(
            f"{base_url}/logout",
            json={},
            headers={"X-chkp-sid": sid},
            verify=False,
            timeout=30,
        )
    except Exception:
        pass


def _gaia_call(base_url: str, sid: str, command: str, payload: dict,
               timeout: int = 120) -> dict:
    """POST a Gaia API command. Returns parsed JSON. Raises on non-2xx.

    Mirrors ``_call``'s error aggregation - Gaia surfaces detailed problems
    in nested ``errors`` / ``warnings`` arrays just like the Mgmt-API.

    ``timeout`` is overridable for the mgmt-iface force-set, where we EXPECT
    the call to hang+drop (the IP change cuts our session) and don't want to
    block the push on the full 120s read timeout.
    """
    resp = _post_with_retry(
        f"{base_url}/{command}",
        payload=payload,
        headers={"X-chkp-sid": sid, "Content-Type": "application/json"},
        timeout=timeout,
    )
    if resp.status_code >= 400:
        try:
            body = resp.json()
        except Exception:
            body = {"_raw": resp.text}
        msg = body.get("message") or str(body)
        details: list[str] = []
        for key in ("blocking-errors", "errors", "warnings"):
            for entry in body.get(key) or ():
                if isinstance(entry, dict) and entry.get("message"):
                    details.append(entry["message"])
        if details:
            msg = f"{msg} [{'; '.join(details)}]"
        else:
            # Gaia sometimes returns a top-level "Validation Error" with no
            # nested details - surface the offending payload + a body excerpt
            # so the next debug iteration has something to chew on.
            try:
                body_dump = json.dumps(body)[:300]
            except Exception:
                body_dump = repr(body)[:300]
            try:
                payload_dump = json.dumps(payload)[:200]
            except Exception:
                payload_dump = repr(payload)[:200]
            msg = (f"{msg} [body={body_dump}] "
                   f"[payload={payload_dump}]")
        raise RuntimeError(f"{command} → HTTP {resp.status_code}: {msg}")
    try:
        return resp.json()
    except ValueError:
        snippet = (resp.text or "").strip()[:120]
        raise RuntimeError(
            f"{command} → HTTP {resp.status_code}: response was not JSON. "
            f"Body: {snippet!r}"
        )


def _extract_static_next_hop(rt: dict) -> str | None:
    """Pull the first usable gateway IP out of a Gaia static-route entry.

    Gaia returns ``next-hop`` as a list of ``{gateway, priority, ...}`` dicts
    in the modern shape, but older versions / single-NH entries collapse it
    to a flat ``{gateway: ...}``  or even just a top-level ``gateway`` field.
    We accept all three. ECMP (multiple gateways) is V2 - V1 picks the first.
    """
    nh = rt.get("next-hop")
    if isinstance(nh, list):
        for entry in nh:
            if isinstance(entry, dict):
                gw = (entry.get("gateway") or entry.get("address")
                      or "").strip()
                if gw and gw.lower() != "blackhole":
                    return gw
        return None
    if isinstance(nh, dict):
        gw = (nh.get("gateway") or nh.get("address") or "").strip()
        return gw or None
    if isinstance(nh, str):
        return nh.strip() or None
    gw = (rt.get("gateway") or "").strip()
    return gw or None


def _gaia_bond_members(item: dict) -> list[str]:
    """Extract physical-IF members from a Gaia show-bonding-interfaces item.

    Gaia's response shape varies by build: members may sit on the bond entry
    as ``members``, ``slaves`` or ``ports``, each either as ``["eth1","eth2"]``
    or ``[{"name": "eth1"}, ...]``. We tolerate both, normalize to a sorted
    list of member names.
    """
    raw = (item.get("members") or item.get("slaves")
           or item.get("ports") or item.get("interfaces") or [])
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for m in raw:
        if isinstance(m, dict):
            n = (m.get("name") or m.get("interface")
                 or m.get("interface-name") or "").strip()
        elif isinstance(m, str):
            n = m.strip()
        else:
            n = ""
        if n:
            out.append(n)
    out.sort()
    return out


def _fetch_bond_membership_optional(device: dict) -> dict[str, list[str]]:
    """Best-effort Gaia lookup of bond → members mapping.

    Used by the Mgmt-API interface-discovery path to fill in the membership
    that show-simple-gateway doesn't expose. Returns ``{}`` silently when
    Gaia creds are missing or the call fails - the caller treats absence as
    "members unknown" rather than as an error, since the Mgmt-API still
    delivered the interface list itself.
    """
    bonds = _fetch_bonds_optional(device)
    return {name: members for name, (_ips, members) in bonds.items()}


def _fetch_bond_ips_optional(device: dict) -> dict[str, list[str]]:
    """Same source as bond membership; returns {bond_name: [ip/prefix, ...]}.

    Used to fill the IP list for bonds that don't appear in
    show-simple-gateway (parent IF carries no layer3, only the VLAN sub-IFs
    do). Cheap second view of the same Gaia call - the caller usually pairs
    it with _fetch_bond_membership_optional.
    """
    bonds = _fetch_bonds_optional(device)
    return {name: ips for name, (ips, _members) in bonds.items()}


def _fetch_all_gaia_interfaces_optional(device: dict) -> list[dict]:
    """Best-effort full interface list from Gaia ``show-interfaces``.

    Used as a side-channel when the Mgmt-API path (show-simple-gateway) only
    returns the topology-bound IFs and we need to know about the rest
    (loopbacks, bond VLAN sub-IFs without zone binding, etc.). Returns
    ``[{name, type, ips, description}]``. Empty when Gaia creds are missing
    or the call fails - the caller treats absence as "no extras", not error.
    """
    if not (device.get("gaia_user") and device.get("gaia_password")):
        return []
    try:
        sid, base_url = _gaia_login(device, retries=0)
    except Exception:
        return []
    try:
        resp = _gaia_call_optional(base_url, sid, "show-interfaces", {})
        if not resp:
            return []
        items = (resp.get("objects") or resp.get("interfaces") or [])
        if not isinstance(items, list):
            return []
        out: list[dict] = []
        for it in items:
            name = (it.get("name") or "").strip()
            if not name:
                continue
            # Skip the Gaia system loopback (lo = 127.0.0.1/8) - present on
            # every box, localhost, no migration value + no cross-vendor
            # equivalent. Real user loopbacks (loopXX / loop00, routable IPs)
            # are NOT named 'lo' and are kept.
            if name.lower() == "lo":
                continue
            out.append({
                "name": name,
                "type": (it.get("type") or "").strip().lower() or None,
                "ips": _gaia_iface_ips(it),
                "description": _gaia_comment(it),
                "enabled": bool(it.get("enabled", True)),
            })
        return out
    except Exception:
        return []
    finally:
        try:
            _gaia_logout(base_url, sid)
        except Exception:
            pass


def _fetch_bonds_optional(device: dict) -> dict[str, tuple[list[str], list[str]]]:
    """Single Gaia call → {bond_name: (ips, members)}.

    Returns ``{}`` silently when Gaia creds are missing or the call fails
    (Mgmt-API still delivered the topology, so bonds simply remain
    unannotated rather than aborting the whole discover).
    """
    if not (device.get("gaia_user") and device.get("gaia_password")):
        return {}
    try:
        sid, base_url = _gaia_login(device, retries=0)
    except Exception:
        return {}
    try:
        # Endpoint name varies between Gaia builds:
        # - "show-bond-interfaces"   (current)   → list with full details inc. members
        # - "show-bonding-interfaces" (older)    → same shape on builds where it
        #   exists; on newer builds returns null. We try the new name first.
        resp = _gaia_call_optional(base_url, sid, "show-bond-interfaces", {})
        if not resp:
            resp = _gaia_call_optional(
                base_url, sid, "show-bonding-interfaces", {}
            )
        if not resp:
            return {}
        items = (resp.get("objects") or resp.get("bond-interfaces")
                 or resp.get("bonding-interfaces") or resp.get("interfaces")
                 or [])
        if not isinstance(items, list):
            return {}
        out: dict[str, tuple[list[str], list[str]]] = {}
        for it in items:
            name = (it.get("name") or "").strip()
            if not name:
                continue
            out[name] = (_gaia_iface_ips(it), _gaia_bond_members(it))
        return out
    except Exception:
        return {}
    finally:
        try:
            _gaia_logout(base_url, sid)
        except Exception:
            pass


def _gaia_iface_ips(item: dict) -> list[str]:
    """Extract `ip/prefix` strings from a Gaia show-*-interface item.

    Gaia returns address + mask-length as separate keys. Sentinel string
    ``"Not-Configured"`` (Gaia's marker for "no IP set") is filtered out.
    Both v4 and v6 are emitted when present.
    """
    out: list[str] = []
    for fam, addr_key, mask_key in (
        ("v4", "ipv4-address", "ipv4-mask-length"),
        ("v6", "ipv6-address", "ipv6-mask-length"),
    ):
        addr = item.get(addr_key) or ""
        mask = item.get(mask_key)
        if (not addr or addr == "Not-Configured"
                or mask in (None, "", "Not-Configured")):
            continue
        try:
            prefix = int(mask)
        except (TypeError, ValueError):
            continue
        out.append(f"{addr}/{prefix}")
    return out


# Gaia bulk show-* commands sometimes return "command not found" on older
# versions or on Gaia Embedded. We swallow only that specific class of error
# so a single missing endpoint doesn't break the whole interface listing.
def _gaia_call_optional(base_url: str, sid: str, command: str,
                        payload: dict) -> dict | None:
    """Same as _gaia_call but returns None when the command is unsupported
    rather than raising. Auth/network failures still propagate."""
    try:
        return _gaia_call(base_url, sid, command, payload)
    except RuntimeError as e:
        msg = str(e).lower()
        if ("command not found" in msg or "unknown command" in msg
                or "http 404" in msg):
            return None
        raise


# ── Gaia write helpers (CP-Network-Push V1) ──────────────────────
#
# Gaia has NO session-staging - every write is immediate. `save-config`
# persists the running config across reboots. There is no rollback;
# forward-fix only. Each helper wraps a single Gaia command with the
# minimal payload our generate() needs.
#
# Convention: ipv4="" + mask_len=None means "no IP" (Gaia accepts the
# absence of address fields as 'leave unconfigured'). When set, both
# fields are required together.


def _gaia_iface_payload(name: str, ipv4: str, mask_len: int | None,
                        comment: str | None,
                        enabled: bool | None = None) -> dict:
    """Common shape for add-/set-{physical,loopback,vlan}-interface."""
    p: dict = {"name": name}
    if ipv4 and mask_len is not None:
        p["ipv4-address"] = ipv4
        p["ipv4-mask-length"] = int(mask_len)
    if comment:
        p["comments"] = comment
    # Gaia accepts `enabled: true|false` on every iface-type. Default is up;
    # only emit the field when the renderer explicitly wants down - that way
    # an unchanged iface keeps its prior state on partial pushes.
    if enabled is False:
        p["enabled"] = False
    elif enabled is True:
        p["enabled"] = True
    return p


def _gaia_set_physical(base_url: str, sid: str, *, name: str,
                       ipv4: str = "", mask_len: int | None = None,
                       comment: str | None = None,
                       enabled: bool | None = None,
                       timeout: int = 120) -> dict:
    """Configure an existing physical IF. Cannot create - HW-bound.

    Gaia refuses ``ipv4-address`` while the DHCP client is enabled
    ("Dhcp client is enabled for this interface, IP address can't be
    configured"). Detect that error, disable DHCP in a separate call,
    then retry. The two-step is needed even when our payload doesn't
    mention DHCP - Gaia treats DHCP as iface state, not a co-set field.
    """
    payload = _gaia_iface_payload(name, ipv4, mask_len, comment, enabled)
    try:
        return _gaia_call(base_url, sid, "set-physical-interface", payload,
                          timeout=timeout)
    except RuntimeError as e:
        msg = str(e).lower()
        if "dhcp client is enabled" not in msg:
            raise
        _gaia_call(base_url, sid, "set-physical-interface",
                   {"name": name, "dhcp": {"enabled": False}})
        return _gaia_call(base_url, sid, "set-physical-interface", payload)


def _gaia_set_physical_dhcp(base_url: str, sid: str, *, name: str,
                            comment: str | None = None,
                            enabled: bool | None = None) -> dict:
    """Enable the DHCP client on a physical IF - converse of the static
    set-physical-interface call. Gaia accepts the address and DHCP fields
    in the same payload here (going DHCP-on is allowed at any time;
    DHCP-off requires the two-step in _gaia_set_physical)."""
    payload: dict = {"name": name, "dhcp": {"enabled": True}}
    if comment:
        payload["comments"] = comment
    if enabled is False:
        payload["enabled"] = False
    elif enabled is True:
        payload["enabled"] = True
    return _gaia_call(base_url, sid, "set-physical-interface", payload)


# bond-mode is a vendor-specific knob Gateshift doesn't yet model. Lab uses LACP
# (8023AD); production rollouts can extend fw_interfaces with a bond_mode
# JSON sidecar later. Hardcoded default keeps V1 round-trippable on lab.
_CP_BOND_MODE_DEFAULT = "8023AD"


def _bond_id_from_name(name: str) -> int:
    """``bond5`` → 5. Gaia's add-bond-interface wants the numeric id."""
    base = name.lower()
    if base.startswith("bond") and base[4:].isdigit():
        return int(base[4:])
    raise ValueError(f"cannot derive bond id from name {name!r}")


def _gaia_clear_physical_ip(base_url: str, sid: str, *, name: str) -> None:
    """Strip ipv4-address + mask off a physical iface. Gaia refuses
    add-bond-interface ("Fail to update: Interface X has IPv4 addresses
    configured.") when a candidate member still carries an IP from a
    previous config - clear it here before the bond claims the slave.

    Gaia's REST clears the address when ``ipv4-address`` is an empty
    string *and* the call omits ``ipv4-mask-length`` (which has a
    mandatory 1..32 range; sending 0 fails validation). Lab-verified
    against R8x: this single call drops ipv4 + mask to Not-Configured.
    Errors propagate so the bond push surfaces the real cause if the
    clear didn't take.
    """
    _gaia_call(base_url, sid, "set-physical-interface",
               {"name": name, "ipv4-address": ""})


def _gaia_add_bond(base_url: str, sid: str, *, name: str,
                   members: list[str],
                   ipv4: str = "", mask_len: int | None = None,
                   comment: str | None = None,
                   mode: str = _CP_BOND_MODE_DEFAULT,
                   enabled: bool | None = None) -> dict:
    """Create a bond IF with members + mode. Falls back to set on 'already exists'.

    Gaia's API splits create vs configure: ``add-bond-interface`` takes a
    numeric ``id`` (not a name), ``members`` and optional ipv4 fields, but
    refuses ``bond-mode`` / ``mode``. Mode + IP must be applied via a follow-up
    ``set-bond-interface`` call keyed on the resulting ``bondN`` name.
    Members are detached from any prior physical config when they join - but
    Gaia rejects the join outright if a member still carries an IP from a
    previous configuration. Clear member IPs first, then issue add-bond.
    """
    for m in members or ():
        _gaia_clear_physical_ip(base_url, sid, name=m)
    add_payload: dict = {"id": _bond_id_from_name(name)}
    if members:
        add_payload["members"] = list(members)
    try:
        _gaia_call(base_url, sid, "add-bond-interface", add_payload)
    except RuntimeError as e:
        if "already exists" not in str(e).lower():
            raise
    set_payload = _gaia_iface_payload(name, ipv4, mask_len, comment, enabled)
    if mode:
        set_payload["mode"] = mode
    if members:
        set_payload["members"] = list(members)
    return _gaia_call(base_url, sid, "set-bond-interface", set_payload)


def _gaia_set_bond(base_url: str, sid: str, *, name: str,
                   members: list[str] | None = None,
                   ipv4: str = "", mask_len: int | None = None,
                   comment: str | None = None,
                   mode: str | None = None) -> dict:
    payload = _gaia_iface_payload(name, ipv4, mask_len, comment)
    if mode:
        payload["mode"] = mode
    if members is not None:
        payload["members"] = list(members)
    return _gaia_call(base_url, sid, "set-bond-interface", payload)


def _gaia_delete_bond(base_url: str, sid: str, *, name: str) -> dict:
    return _gaia_call(base_url, sid, "delete-bond-interface", {"name": name})


def _gaia_add_loopback(base_url: str, sid: str, *, name: str = "",
                       ipv4: str = "", mask_len: int | None = None,
                       comment: str | None = None,
                       enabled: bool | None = None) -> dict:
    """Create a loopback IF. Gaia's add-loopback-interface takes **no name/id** -
    it AUTO-ALLOCATES the name (loopXX) from the supplied IP+mask. A source name
    like 'loopback.1' is meaningless here and is rejected ('name is not a json
    parameter'), so we never send one (the `name` arg is for the caller's
    bookkeeping only). On a duplicate IP Gaia says 'already exists' → find that
    loopback by IP and set it under its Gaia-assigned name."""
    payload = _gaia_iface_payload("", ipv4, mask_len, comment, enabled)
    payload.pop("name", None)            # auto-allocated by Gaia, not user-set
    try:
        return _gaia_call(base_url, sid, "add-loopback-interface", payload)
    except RuntimeError as e:
        if "already exists" not in str(e).lower():
            raise
        existing = _gaia_call(base_url, sid, "show-loopback-interfaces", {}) or {}
        items = (existing.get("objects") or existing.get("loopback-interfaces")
                 or existing.get("interfaces") or [])
        for it in items:
            if isinstance(it, dict) and it.get("ipv4-address") == ipv4:
                sp = _gaia_iface_payload(it.get("name") or "", ipv4, mask_len,
                                         comment, enabled)
                return _gaia_call(base_url, sid, "set-loopback-interface", sp)
        raise


def _gaia_set_loopback(base_url: str, sid: str, *, name: str,
                       ipv4: str = "", mask_len: int | None = None,
                       comment: str | None = None) -> dict:
    return _gaia_call(base_url, sid, "set-loopback-interface",
                      _gaia_iface_payload(name, ipv4, mask_len, comment))


def _gaia_delete_loopback(base_url: str, sid: str, *, name: str) -> dict:
    return _gaia_call(base_url, sid, "delete-loopback-interface",
                      {"name": name})


def _gaia_add_vlan(base_url: str, sid: str, *, parent: str, vlan_id: int,
                   ipv4: str = "", mask_len: int | None = None,
                   comment: str | None = None,
                   enabled: bool | None = None) -> dict:
    """Create a VLAN sub-IF. Gaia constructs the name as 'parent.vlan_id'
    automatically; we don't pass a name field for add. Falls back to set
    via the constructed name on 'already exists'.

    The vlan-id field shifted across Gaia builds: newer R8x require ``id``
    (matching add-bond-interface), older builds expect ``vlan-id``. Both
    sides reject the other key as unknown - try ``id`` first (current),
    fall back to ``vlan-id`` on validation error.
    """
    vid = int(vlan_id)
    base_payload: dict = {"parent": parent}
    if ipv4 and mask_len is not None:
        base_payload["ipv4-address"] = ipv4
        base_payload["ipv4-mask-length"] = int(mask_len)
    if comment:
        base_payload["comments"] = comment
    if enabled is False:
        base_payload["enabled"] = False
    elif enabled is True:
        base_payload["enabled"] = True

    def _attempt(id_key: str) -> dict:
        return _gaia_call(base_url, sid, "add-vlan-interface",
                          {**base_payload, id_key: vid})

    try:
        return _attempt("id")
    except RuntimeError as e:
        msg = str(e).lower()
        if "already exists" in msg:
            return _gaia_set_vlan(base_url, sid, name=f"{parent}.{vid}",
                                  ipv4=ipv4, mask_len=mask_len, comment=comment,
                                  enabled=enabled)
        if "id is not a json parameter" in msg:
            try:
                return _attempt("vlan-id")
            except RuntimeError as e2:
                if "already exists" in str(e2).lower():
                    return _gaia_set_vlan(base_url, sid,
                                          name=f"{parent}.{vid}",
                                          ipv4=ipv4, mask_len=mask_len,
                                          comment=comment,
                                          enabled=enabled)
                raise
        raise


def _gaia_set_vlan(base_url: str, sid: str, *, name: str,
                   ipv4: str = "", mask_len: int | None = None,
                   comment: str | None = None,
                   enabled: bool | None = None) -> dict:
    return _gaia_call(base_url, sid, "set-vlan-interface",
                      _gaia_iface_payload(name, ipv4, mask_len, comment, enabled))


def _gaia_delete_vlan(base_url: str, sid: str, *, name: str) -> dict:
    return _gaia_call(base_url, sid, "delete-vlan-interface",
                      {"name": name})


def _gaia_add_static_route(base_url: str, sid: str, *, prefix: str,
                           next_hop: str,
                           blackhole: bool = False) -> dict:
    """Add (or modify) a static route. ``prefix`` is CIDR; we split into
    address + mask-length. ``next_hop`` is the gateway IP (ignored when
    blackhole=True).

    Gaia REST mirrors clish: ``set-static-route`` creates the route if
    absent and updates it if present - there is no separate
    ``add-static-route`` in current Gaia versions (some older docs list
    it; on R80+ it 404s as Command Not Found). ECMP/reject still out of
    scope for V1; blackhole is supported via type=`blackhole`.

    Gaia's next-hop ``priority`` is a gateway-SELECTION rank (a STRING in
    1..8), NOT an admin-distance/metric - and it's optional. We omit it so
    Gaia uses 'default' for the single gateway; the source metric can't map
    here and is dropped with a warn in _render_static_routes. (Sending the
    metric as priority is what produced the -3 "priority must be within
    [1 to 8], priority value must be a string".)
    """
    addr, _, mask = prefix.partition("/")
    payload: dict = {
        "address": addr,
        "mask-length": int(mask),
    }
    if blackhole:
        payload["type"] = "blackhole"
    else:
        payload["type"] = "gateway"
        payload["next-hop"] = [{"gateway": next_hop}]
    # Gaia's set-static-route rejects a `comments` field ("not a json
    # parameter") - static routes carry no description on Gaia, so we don't
    # send one (a source comment is simply not migrated for CP routes).
    return _gaia_call(base_url, sid, "set-static-route", payload)


def _gaia_delete_static_route(base_url: str, sid: str, *,
                              prefix: str) -> dict:
    addr, _, mask = prefix.partition("/")
    return _gaia_call(base_url, sid, "delete-static-route",
                      {"address": addr, "mask-length": int(mask)})


def _gaia_save_config(base_url: str, sid: str) -> dict | None:
    """Persist Gaia running-config to disk so it survives reboot.

    Different Gaia builds expose persistence under different REST names.
    Try the documented endpoints in order, then fall back to running the
    clish ``save config`` command via ``run-clish-command`` (the generic
    runner supported on most R8x builds). Returns None when none of the
    paths exist - caller treats that as 'auto-persisted'.
    """
    # Native REST endpoints (newer builds).
    for cmd in ("save-config", "save-running-config"):
        resp = _gaia_call_optional(base_url, sid, cmd, {})
        if resp is not None:
            return resp
    # Fall back to the clish runner - in our testing this behaves
    # equivalently to 'save-config' on builds that lack the endpoint.
    for runner in ("run-clish-command", "run-script"):
        for key in ("commands", "script"):
            try:
                payload = ({"commands": ["save config"]} if key == "commands"
                           else {"script": "save config"})
                resp = _gaia_call_optional(base_url, sid, runner, payload)
                if resp is not None:
                    return resp
            except RuntimeError:
                continue
    return None


# Commands where add-X must fall back to set-X on a name conflict. CP rejects
# `set-if-exists` on groups and security-zones, so re-pushes that don't first
# wipe the object DB would otherwise fail. The same payload shape works for
# both add-X and set-X (name + members/comments + ignore-warnings).
_SET_FALLBACK_COMMANDS = {
    "add-group": "set-group",
    "add-service-group": "set-service-group",
    "add-security-zone": "set-security-zone",
    # Pre-rule object types now pushed via _PUSH_ORDER. Payloads may carry
    # set-if-exists: True; this dict is the belt-and-suspenders fallback for
    # CP versions where set-if-exists isn't honored or for renderers that
    # forget to set it.
    "add-time":              "set-time",
    "add-time-group":        "set-time-group",
    "add-tag":               "set-tag",
    "add-application-site":  "set-application-site",
    # IPSec VPN (CP-VPN plan CP-2b) - re-push updates the existing object.
    "add-interoperable-device":  "set-interoperable-device",
    "add-vpn-community-meshed":  "set-vpn-community-meshed",
    "add-vpn-community-star":    "set-vpn-community-star",
}


def _call_idempotent(base_url: str, sid: str, command: str,
                     payload: dict) -> dict:
    """Like _call, but for commands in _SET_FALLBACK_COMMANDS retries with
    the set-X variant when the add fails because the object already exists.
    """
    try:
        return _call(base_url, sid, command, payload)
    except RuntimeError as e:
        fallback = _SET_FALLBACK_COMMANDS.get(command)
        if not fallback:
            raise
        msg = str(e).lower()
        if "already exists" not in msg and "more than one" not in msg:
            raise
        try:
            return _call(base_url, sid, fallback, payload)
        except RuntimeError as e2:
            # The set-fallback 404s when the colliding object is of ANOTHER
            # type (CP ambiguity, e.g. 'MMS') - that 404 hides the real cause,
            # and callers key their recovery on the original message. Re-raise
            # the ORIGINAL error in that case (QA finding).
            if "not found" in str(e2).lower():
                raise e
            raise


# ── Name sanitization ────────────────────────────────────────────

# CP allows letters, digits, dot, underscore, hyphen, colon (and space, but
# spaces in names complicate downstream tooling - we strip them too). Any
# other char becomes underscore. CP enforces global uniqueness, so name
# clashes with builtins surface as push errors rather than being masked.
# CP additionally requires names to start with a letter - names like '22-tcp'
# (auto-generated from port/proto) get an 's_' prefix so they validate.
_NAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._\-:]")
_NAME_MAX_LEN = 100  # conservative - CP allows more, but vendor docs vary by version

def _safe_name(name: str) -> str:
    s = _NAME_SAFE_RE.sub("_", name or "")
    if s and not s[0].isalpha():
        s = f"s_{s}"
    return s[:_NAME_MAX_LEN] if len(s) > _NAME_MAX_LEN else s


# ── Address-object rendering ─────────────────────────────────────

def _split_cidr(cidr: str) -> tuple[str, int] | None:
    """'10.0.0.0/24' → ('10.0.0.0', 24). None if invalid or non-IPv4."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None
    if not isinstance(net, ipaddress.IPv4Network):
        return None
    return str(net.network_address), net.prefixlen


def _split_range(rng: str) -> tuple[str, str] | None:
    """'10.0.0.1-10.0.0.10' → ('10.0.0.1', '10.0.0.10'). None if invalid."""
    if "-" not in rng:
        return None
    first, _, last = rng.partition("-")
    first, last = first.strip(), last.strip()
    try:
        ipaddress.IPv4Address(first)
        ipaddress.IPv4Address(last)
    except ValueError:
        return None
    return first, last


def _is_any_address(otype: str, v: str) -> bool:
    """True for an all-addresses 'any' object - 0.0.0.0/0, or the full
    0.0.0.0-255.255.255.255 range. CP has no /0 network object (rejects
    mask-length 0) and reserves the name 'all'; such objects must resolve to
    the builtin 'Any' instead of being pushed as a concrete object (BUG-020)."""
    otype = (otype or "").lower()
    if otype == "ip-netmask":
        p = _split_cidr(v or "")
        return bool(p) and p[1] == 0
    if otype == "ip-range":
        r = _split_range(v or "")
        return bool(r) and r[0] == "0.0.0.0" and r[1] == "255.255.255.255"
    return False


def _cp_norm_port(port: str) -> str | None:
    """Normalize a tcp/udp port spec to something CP accepts, or None when it
    can't be represented.

    CP rejects port 0 ("'Port' value is not 'any' or a valid port number").
    Two shapes reach us with a 0 (QA finding, FortiOS source): the RANGE
    '0-65535' - which means "any port" and is clamped to '1-65535' - and the
    bare sentinel '0' (FortiOS ships the factory service NONE as tcp/0),
    which carries no migratable intent → None (caller drop-warns).
    """
    p = (port or "").strip()
    if not p:
        return None
    if p[0] in "<>":
        rest = p[1:].strip()
        return p if rest.isdigit() and 1 <= int(rest) <= 65535 else None
    parts = p.split("-", 1)
    try:
        nums = [int(x) for x in parts]
    except ValueError:
        return None
    if len(nums) == 2:
        lo, hi = nums
        lo = max(lo, 1)
        if hi < lo or hi > 65535:
            return None
        return f"{lo}-{hi}"
    return p if 1 <= nums[0] <= 65535 else None


def _is_any_service(val: dict) -> bool:
    """True for an all-traffic service object - Forti builtin 'ALL'
    (protocol 'ip' / ip_protocol 0). CP has no such object; it must resolve to
    the builtin 'Any' instead of being pushed (else add-access-rule 404s on
    the missing object). Service analog of _is_any_address."""
    val = val or {}
    proto = (val.get("protocol") or "").lower().strip()
    if proto not in ("ip", "ip6", ""):
        return False
    ipp = val.get("ip_protocol")
    return ipp in (0, "0", None, "")


# ── Reserved-name collision handling (BUG-023) ───────────────────
# CP ships ~300 predefined services (+ a few predefined addresses) in the
# "Check Point Data" domain. A custom object whose name collides - including
# CP's case/separator-insensitive match (POP3 ≈ pop-3) - can't be created
# ("More than one object named X exists"). At push time we rename such customs
# to FF_<name> and rewrite every reference (rules, groups, NAT, TP). Detection
# is best-effort against CP's fuzzy matcher; a miss just fails that one object.
_CP_RESERVED_SHOW = (
    "show-services-tcp", "show-services-udp", "show-services-icmp",
    "show-services-icmp6", "show-services-other", "show-service-groups",
    "show-hosts", "show-networks", "show-address-ranges", "show-groups",
)

# Sections whose create-commands carry an object name that may collide.
_CP_OBJECT_SECTIONS = (
    "Hosts", "Networks", "Address Ranges", "Address Groups",
    "Services-TCP", "Services-UDP", "Services-ICMP", "Services-ICMP6",
    "Services-Other", "Service Groups",
)


def _cp_norm_name(name: str) -> str:
    """Collision-normalize a name: lowercase + drop all non-alphanumerics, to
    mirror CP's case/separator-insensitive matching (POP3 → pop3 ← pop-3)."""
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


# CP GLOBAL sentinel objects that no show-* listing returns but that every
# add-* collides with ("More than one object named 'none' exists" - CP ships
# several, across types). Other vendors ship real objects under these names
# (FortiGate's factory 'all'/'none' addresses, 'ALL'/'NONE' services), so a
# cross-vendor push hits them. Always reserved → renamed to FF_<name>.
# Live-found in QA (Forti→CP leg, FortiOS 7.6.7 factory 'none').
_CP_ALWAYS_RESERVED = {"none", "any", "all", "original", "internet"}


def _fetch_cp_reserved_names(base_url: str, sid: str) -> set[str]:
    """Normalized names of CP PREDEFINED objects (domain-type 'data domain' or
    read-only) - the names a custom add-* can't take. Custom objects aren't
    included (the push deletes ours first; set-if-exists updates same-name)."""
    reserved: set[str] = {_cp_norm_name(n) for n in _CP_ALWAYS_RESERVED}
    for cmd in _CP_RESERVED_SHOW:
        offset = 0
        for _ in range(60):
            try:
                resp = _call(base_url, sid, cmd,
                             {"limit": 500, "offset": offset, "details-level": "full"})
            except Exception:
                break  # unsupported show-* or transient - skip this kind
            objs = resp.get("objects") or []
            for o in objs:
                dom = (o.get("domain") or {}).get("domain-type")
                if dom == "data domain" or o.get("read-only"):
                    nm = o.get("name")
                    if nm:
                        reserved.add(_cp_norm_name(nm))
            offset += len(objs)
            if not objs or offset >= (resp.get("total") or 0):
                break
    return reserved


def _fetch_cp_access_roles(base_url: str, sid: str) -> set[str]:
    """Names of Access-Roles that EXIST at the target (Phase 2.5).

    Identity refs on rules are pushed by reference only - the role's
    definition is not migrated, so the role must already exist at the
    target or add-access-rule 404s. We fetch the live set here and gate
    the refs in push(). Returns the exact (case-preserved) role names.
    `show-access-roles` verified live: plural, hyphen, returns 0 cleanly
    when none exist. Pagination mirrors _fetch_cp_reserved_names."""
    roles: set[str] = set()
    offset = 0
    for _ in range(60):
        try:
            resp = _call(base_url, sid, "show-access-roles",
                         {"limit": 500, "offset": offset, "details-level": "standard"})
        except Exception:
            break  # unsupported / transient - fail open (no gating)
        objs = resp.get("objects") or []
        for o in objs:
            nm = o.get("name")
            if nm:
                roles.add(nm)
        offset += len(objs)
        if not objs or offset >= (resp.get("total") or 0):
            break
    return roles


def _remap_reserved_collisions(config: dict, base_url: str, sid: str) -> tuple[int, list[str]]:
    """Rename pushed objects whose name collides with a CP predefined name to
    FF_<name>, and rewrite every reference. Mutates `config` in place. Returns
    (n_renamed, up-to-5 sample original names)."""
    reserved = _fetch_cp_reserved_names(base_url, sid)
    if not reserved:
        return 0, []
    # A predefined name reached via a GROUP MEMBER / rule reference must be
    # renamed too - the object itself may not be in this push (it was already
    # renamed, or lives only as a reference). The reference rewrite below is
    # keyed on `rename`, so seed it from every section's payload names.

    rename: dict[str, str] = {}
    parsed: dict[str, list] = {}
    for sec in _CP_OBJECT_SECTIONS:
        raw = config.get(sec)
        if not raw:
            continue
        cmds = json.loads(raw)
        parsed[sec] = cmds
        for cmd in cmds:
            nm = (cmd.get("payload") or {}).get("name")
            if nm and nm not in rename and _cp_norm_name(nm) in reserved:
                rename[nm] = _safe_name(f"FF_{nm}")
    if not rename:
        return 0, []

    def _rl(v):
        return [rename.get(x, x) for x in v] if isinstance(v, list) else v

    def _ro(v):
        return rename.get(v, v) if isinstance(v, str) else v

    # 1. Object create-commands: own name + (group) member lists.
    for sec, cmds in parsed.items():
        for cmd in cmds:
            p = cmd.get("payload") or {}
            if p.get("name") in rename:
                p["name"] = rename[p["name"]]
            if isinstance(p.get("members"), list):
                p["members"] = _rl(p["members"])
        config[sec] = json.dumps(cmds)

    # 2. Access rules ({command,payload}): source / destination / service.
    if config.get("Access Rules"):
        ar = json.loads(config["Access Rules"])
        for c in ar:
            p = c.get("payload") or {}
            for f in ("source", "destination", "service"):
                if f in p:
                    p[f] = _rl(p[f])
        config["Access Rules"] = json.dumps(ar)

    # 3. NAT rules ({command,payload}): single-valued ref fields.
    if config.get("NAT Rules"):
        nr = json.loads(config["NAT Rules"])
        for c in nr:
            p = c.get("payload") or {}
            for f in ("original-source", "original-destination", "original-service",
                      "translated-source", "translated-destination", "translated-service"):
                if f in p:
                    p[f] = _ro(p[f])
        config["NAT Rules"] = json.dumps(nr)

    # 4. TP rules - shape is [{layer_name, ..., rules: [rule, ...]}] (the
    #    old flat-dict walk silently no-opped on the layer entries).
    if config.get("TP Rules"):
        tp = json.loads(config["TP Rules"])
        for entry in tp:
            for r in (entry.get("rules") or []):
                for f in ("source", "destination", "service", "protected-scope"):
                    if f in r:
                        r[f] = _rl(r[f])
        config["TP Rules"] = json.dumps(tp)

    return len(rename), sorted(rename)[:5]


def _prune_tp_dangling_refs(config: dict) -> tuple[int, int, list[str]]:
    """Prune TP-rule refs to objects the push never materializes.

    The policy render legitimately DROPS some source objects (e.g. FQDNs -
    CP has no single-host FQDN object), and the access rules get pruned by
    the integrity layer. The TP generator built its protected-scope from
    the SOURCE destination sets, so a dropped object 404s add-threat-rule
    mid-push. Prune those refs here against the roster of object names the
    push actually creates; a rule whose scope empties is skipped entirely.
    Returns (refs_pruned, rules_dropped, sample_names)."""
    if not config.get("TP Rules"):
        return 0, 0, []
    roster = {"Any"}
    for sec in ("Hosts", "Networks", "Address Ranges", "Address Groups",
                "Services-TCP", "Services-UDP", "Service Groups"):
        try:
            for cmd in json.loads(config.get(sec) or "[]"):
                nm = (cmd.get("payload") or {}).get("name") or cmd.get("name")
                if nm:
                    roster.add(nm)
        except Exception:
            pass
    # Shape: [{layer_name, strategy, params, rules: [rule, ...]}, ...]
    entries = json.loads(config["TP Rules"])
    pruned = dropped_n = 0
    gone: list[str] = []
    for entry in entries:
        kept: list[dict] = []
        for r in (entry.get("rules") or []):
            ok_rule = True
            for f in ("source", "destination", "protected-scope"):
                vals = r.get(f)
                if not isinstance(vals, list):
                    continue
                keep = [v for v in vals if v in roster]
                missing = [v for v in vals if v not in roster]
                if missing:
                    pruned += len(missing)
                    gone.extend(missing)
                    if keep:
                        r[f] = keep
                    else:
                        ok_rule = False   # scope emptied - skip the rule
            if ok_rule:
                kept.append(r)
        dropped_n += len(entry.get("rules") or []) - len(kept)
        entry["rules"] = kept
    config["TP Rules"] = json.dumps(entries)
    return pruned, dropped_n, sorted(set(gone))[:5]


def _render_address_objects(
    objects: list[dict],
    dropped: list[DroppedField],
) -> tuple[list[dict], list[dict], list[dict]]:
    """Convert agnostic address objects → CP add-host / add-network /
    add-address-range command batches.

    Returns (hosts, networks, ranges) - each a list of
    ``{"command": ..., "payload": ...}`` dicts ready for the API.

    fqdn objects are dropped (CP has no single-host FQDN object - its
    dns-domain objects are suffix-matchers with different semantics).
    """
    hosts: list[dict] = []
    networks: list[dict] = []
    ranges: list[dict] = []

    for obj in objects:
        raw_name = obj.get("name") or ""
        name = _safe_name(raw_name)
        if not name:
            continue
        val = obj.get("value") or {}
        otype = (val.get("type") or "").lower()
        v = val.get("value") or ""
        comments = val.get("description") or ""

        # An all-addresses object maps to the builtin 'Any' (see
        # _build_addr_lookup) - don't emit it as a concrete object (BUG-020).
        if _is_any_address(otype, v):
            dropped.append(DroppedField(
                rule_id=raw_name, field="value",
                reason="0.0.0.0/0 'any' object - mapped to builtin Any, not pushed",
            ))
            continue

        if otype == "ip-netmask":
            parsed = _split_cidr(v)
            if not parsed:
                # An FQDN value that reached the ip-netmask path (e.g.
                # 'gmail.com/32', '*.google.com/32') is not a malformed CIDR -
                # CP has no single-host FQDN object. Give the accurate reason
                # instead of the misleading "unparseable CIDR" (F15).
                _host = v.rsplit("/", 1)[0]
                if re.search(r"[A-Za-z]", _host) and ":" not in _host:
                    dropped.append(DroppedField(
                        rule_id=raw_name, field="fqdn",
                        reason="Check Point has no single-host FQDN object "
                               "(dns-domain objects are suffix-matchers, "
                               f"different semantics) - {_host!r} not migrated",
                    ))
                else:
                    dropped.append(DroppedField(
                        rule_id=raw_name, field="value",
                        reason=f"unparseable CIDR {v!r}",
                    ))
                continue
            ip, prefix = parsed
            payload: dict[str, Any] = {
                "name": name, "ignore-warnings": True, "set-if-exists": True,
            }
            if comments:
                payload["comments"] = comments
            if prefix == 32:
                payload["ip-address"] = ip
                hosts.append({"command": "add-host", "payload": payload})
            else:
                payload["subnet4"] = ip
                payload["mask-length4"] = prefix
                networks.append({"command": "add-network", "payload": payload})

        elif otype == "ip-range":
            parsed = _split_range(v)
            if not parsed:
                dropped.append(DroppedField(
                    rule_id=raw_name, field="value",
                    reason=f"unparseable IP range {v!r}",
                ))
                continue
            first, last = parsed
            payload = {
                "name": name,
                "ipv4-address-first": first,
                "ipv4-address-last": last,
                "ignore-warnings": True, "set-if-exists": True,
            }
            if comments:
                payload["comments"] = comments
            ranges.append({"command": "add-address-range", "payload": payload})

        elif otype == "fqdn":
            dropped.append(DroppedField(
                rule_id=raw_name, field="fqdn",
                reason="Check Point has no single-host FQDN object "
                       "(dns-domain objects are suffix-matchers, different semantics)",
            ))

        else:
            dropped.append(DroppedField(
                rule_id=raw_name, field="type",
                reason=f"unknown address-object type {otype!r}",
            ))

    return hosts, networks, ranges


# ── Service-object rendering ─────────────────────────────────────

# Protocol alias map → CP API command. Anything not here that's a numeric
# IP-protocol number gets routed through add-service-other.
_PROTO_TO_CMD = {
    "tcp": "add-service-tcp",
    "udp": "add-service-udp",
    "icmp": "add-service-icmp",
    "icmpv6": "add-service-icmp6",
    "icmp6": "add-service-icmp6",
}


# Well-known IP-protocol names → numbers (for add-service-other). Covers the
# L3 protos ASA/Forti configs commonly reference by name.
_IP_PROTO_NAMES = {
    "icmp6": 58, "igmp": 2, "ipip": 4, "gre": 47, "esp": 50, "ah": 51,
    "ospf": 89, "pim": 103, "vrrp": 112, "sctp": 132,
}


def _render_service_objects(
    objects: list[dict],
    dropped: list[DroppedField],
) -> dict[str, list[dict]]:
    """Convert agnostic service objects → CP add-service-* commands.

    Returns a dict keyed by section label ('Services-TCP', 'Services-UDP',
    'Services-ICMP', 'Services-Other'). Empty lists are pruned by caller.

    Agnostic shape: ``{"name": ..., "value": {"protocol": "tcp", "port": "443"}}``.
    Port may be a single port ('443') or a hyphen range ('1024-65535');
    both are forwarded to CP as-is.

    For raw IP-protocol numbers (e.g. '47' for GRE) we emit add-service-other.
    ICMP without an icmp-type is dropped - CP requires the type number.
    """
    out: dict[str, list[dict]] = {
        "Services-TCP": [], "Services-UDP": [],
        "Services-ICMP": [], "Services-ICMP6": [],
        "Services-Other": [],
    }

    for obj in objects:
        raw_name = obj.get("name") or ""
        name = _safe_name(raw_name)
        if not name:
            continue
        val = obj.get("value") or {}
        # All-traffic service (Forti 'ALL') → builtin 'Any', not a pushable
        # object (mirrors the _is_any_address skip). Rule refs resolve to 'Any'.
        if _is_any_service(val):
            dropped.append(DroppedField(
                rule_id=raw_name, field="protocol",
                reason="all-protocols service - mapped to builtin Any, not pushed",
            ))
            continue
        proto = (val.get("protocol") or "").lower().strip()
        port = str(val.get("port") or "").strip()
        comments = val.get("description") or ""

        cmd = _PROTO_TO_CMD.get(proto)
        base: dict[str, Any] = {
            "name": name, "ignore-warnings": True, "set-if-exists": True,
        }
        if comments:
            base["comments"] = comments

        if cmd in ("add-service-tcp", "add-service-udp"):
            # CP requires a concrete port spec for tcp/udp - bare "any" /
            # "*" / empty all yield "Cannot set 'Any' port without selecting
            # a protocol" (since CP reads "Any" as protocol-less). ASA's
            # agnostic-schema "any" → full port-range covers the same intent.
            if port.lower() in ("any", "*", ""):
                port = "1-65535"
            # ASA 'neq N' arrives as '!N': CP knows no negation and no
            # multi-range in a single service - render two range members
            # plus a service-group under the REFERENCED name so rule refs
            # resolve (QA finding, ASA-CP facet of the lt/gt/neq blocker).
            if port.startswith("!") and port[1:].strip().isdigit():
                n = int(port[1:].strip())
                section = ("Services-TCP" if cmd == "add-service-tcp"
                           else "Services-UDP")
                members = []
                for suffix, lo, hi in (("-lo", 1, n - 1), ("-hi", n + 1, 65535)):
                    if lo > hi:
                        continue
                    mname = _safe_name(f"{raw_name}{suffix}")
                    out[section].append({"command": cmd, "payload": {
                        **base, "name": mname,
                        "port": str(lo) if lo == hi else f"{lo}-{hi}"}})
                    members.append(mname)
                out.setdefault("Service Groups", []).append({
                    "command": "add-service-group",
                    "payload": {"name": name, "members": members,
                                "ignore-warnings": True}})
                continue
            # Port 0 is not a valid CP port ("'Port' value is not 'any' or a
            # valid port number"). It shows up as a SENTINEL, not real config:
            # FortiOS ships the factory service 'NONE' as tcp/0 (QA finding). Drop
            # it with a warn instead of failing the whole section.
            norm = _cp_norm_port(port)
            if norm is None:
                dropped.append(DroppedField(
                    rule_id=raw_name, field="port",
                    reason=f"port {port!r} is not a valid Check Point port "
                           "(sentinel/placeholder service) - not pushed",
                ))
                continue
            payload = {**base, "port": norm}
            section = "Services-TCP" if cmd == "add-service-tcp" else "Services-UDP"
            out[section].append({"command": cmd, "payload": payload})

        elif cmd in ("add-service-icmp", "add-service-icmp6"):
            # Agnostic schema doesn't formally carry icmp-type yet; some
            # collectors stuff it into 'port'. Default missing type to 99
            # (CP "Any ICMP type") so the service still imports and rules can
            # reference it; user can refine via Enrichment if needed.
            icmp_type = val.get("icmp_type")
            # Normalize blank/empty (Forti ALL_ICMP arrives as icmp_type="")
            # to None so the default below applies instead of int("") crashing.
            if isinstance(icmp_type, str) and not icmp_type.strip():
                icmp_type = None
            if icmp_type is None and port.isdigit():
                icmp_type = int(port)
            if icmp_type is None:
                icmp_type = 99  # CP "Any ICMP type" wildcard
                dropped.append(DroppedField(
                    rule_id=raw_name, field="icmp_type",
                    reason="icmp service without icmp-type - defaulted to 99 (Any)",
                ))
            payload = {**base, "icmp-type": int(icmp_type)}
            icmp_code = val.get("icmp_code")
            if isinstance(icmp_code, str) and not icmp_code.strip():
                icmp_code = None
            if icmp_code is not None:
                payload["icmp-code"] = int(icmp_code)
            section = "Services-ICMP" if cmd == "add-service-icmp" else "Services-ICMP6"
            out[section].append({"command": cmd, "payload": payload})

        elif proto.isdigit() or proto in _IP_PROTO_NAMES:
            # raw IP-protocol number OR well-known name (esp/ah/gre/...) →
            # service-other. Named L3 protos previously fell through the
            # converter entirely, so rules referencing them 404'd at push
            # (QA finding, ASA→CP - _inline_S_esp_any).
            num = int(proto) if proto.isdigit() else _IP_PROTO_NAMES[proto]
            payload = {**base, "ip-protocol": num}
            out["Services-Other"].append(
                {"command": "add-service-other", "payload": payload}
            )

        else:
            dropped.append(DroppedField(
                rule_id=raw_name, field="protocol",
                reason=f"unsupported protocol {proto!r}",
            ))

    return out


def _render_service_groups(
    groups: list[dict],
    dropped: list[DroppedField],
    emitted: set[str] | None = None,
) -> list[dict]:
    """Convert agnostic service groups → CP add-service-group commands.

    CP service-groups can mix tcp/udp/icmp members freely, just like the
    agnostic schema, so this is a straight pass-through.

    Members whose name still looks like the raw-UID fallback (see
    shared integrity check) point at service types we don't currently fetch
    (dce-rpc, rpc, sctp, gtp) - they were never pushed, so referencing
    them would 404 the whole group. We drop those members; if a group
    ends up empty afterwards we skip the group entirely.

    ``emitted``: when given, the set of valid member names (services actually
    rendered + all service-group names). A member not in it points at a
    dropped/unrenderable object → pruned to avoid a dangling reference
    (BUG-024). Mirrors PA's _drop_l3_service_objects integrity pass.
    """
    out: list[dict] = []
    for grp in groups:
        raw_name = grp.get("name") or ""
        name = _safe_name(raw_name)
        if not name:
            continue
        val = grp.get("value") or {}
        comments = val.get("description") or ""
        members: list[str] = []
        for m in val.get("members") or []:
            if not m:
                continue
            sm = _safe_name(m)
            if _integ.looks_like_uid(sm):
                dropped.append(DroppedField(
                    rule_id=raw_name, field="member",
                    reason=f"unresolved member UID {m!r} "
                           "(likely dce-rpc/rpc/sctp/gtp - not migrated)",
                ))
                continue
            if emitted is not None and sm not in emitted:
                dropped.append(DroppedField(
                    rule_id=raw_name, field="member",
                    reason=f"member {m!r} not among pushed objects - "
                           "pruned (would dangle)",
                ))
                continue
            members.append(sm)
        if not members:
            dropped.append(DroppedField(
                rule_id=raw_name, field="members",
                reason="all members unresolved - group skipped",
            ))
            continue
        payload: dict[str, Any] = {
            "name": name,
            "members": members,
            "ignore-warnings": True,
        }
        if comments:
            payload["comments"] = comments
        out.append({"command": "add-service-group", "payload": payload})
    # Nested service-groups need member-first order too (same 404 as the
    # address-group case - _toposort_cp_groups keys on payload name/members).
    return _toposort_cp_groups(out)


# ── Lookups (literal → object-name) ──────────────────────────────

def _build_addr_lookup(
    address_objects: list[dict], address_groups: list[dict]
) -> dict[str, str]:
    """Map a rule's literal source/destination string to its CP object name.

    Mirrors panw's lookup: rule lists carry raw IPs / CIDR / names, but a
    rendered rule must reference object names. Single-IP hosts are stored
    as ``X/32`` in the schema but rules may carry the bare ``X`` form, so
    we register both keys.
    """
    lookup: dict[str, str] = {}
    for obj in address_objects:
        raw_name = obj.get("name")
        if not raw_name:
            continue
        cp_name = _safe_name(raw_name)
        # raw_name → cp_name so rules referencing the agnostic name
        # (e.g. ASA `_inline_N_*`) land on the safe-named CP object.
        # Without this, _resolve_addr falls through to raw_name and the
        # access-rule push 404s ("object not found").
        lookup.setdefault(raw_name, cp_name)
        lookup.setdefault(cp_name, cp_name)
        val = obj.get("value") or {}
        v = val.get("value")
        # All-addresses objects resolve to the builtin 'Any' everywhere they're
        # referenced (rules via _resolve_addr, groups via _rewrite_members_cp).
        # Override the self-maps set above (BUG-020).
        if _is_any_address(val.get("type"), v or ""):
            lookup[raw_name] = "Any"
            lookup[cp_name] = "Any"
            if v:
                lookup[v] = "Any"
            continue
        if not v:
            continue
        lookup[v] = cp_name
        if val.get("type") == "ip-netmask" and v.endswith("/32"):
            lookup[v[:-3]] = cp_name
    for grp in address_groups:
        raw_name = grp.get("name")
        if raw_name:
            cp_name = _safe_name(raw_name)
            lookup.setdefault(raw_name, cp_name)
            lookup.setdefault(cp_name, cp_name)
    return lookup


def _build_svc_lookup(
    service_objects: list[dict], service_groups: list[dict]
) -> dict[tuple[str, str], str]:
    """Map (proto, port_str) → CP service-object name."""
    lookup: dict[tuple[str, str], str] = {}
    for obj in service_objects:
        raw_name = obj.get("name")
        if not raw_name:
            continue
        cp_name = _safe_name(raw_name)
        val = obj.get("value") or {}
        proto = (val.get("protocol") or "").lower()
        port = str(val.get("port") or "")
        if proto and port:
            lookup[(proto, port)] = cp_name
    return lookup


def _prune_unpushable(names: list[str], pushable: set[str] | None,
                      rule_id: str, field: str,
                      dropped: list[DroppedField]) -> list[str]:
    """Rule address-refs, filtered to what this push creates (invariant I1).

    Thin CP-side wrapper around the shared implementation: it adds the
    DroppedField reporting, which the shared layer deliberately leaves to
    the caller (each driver has its own drop vocabulary)."""
    kept, lost = _integ.prune_refs(names, pushable, keep=("any", "Any"))
    if lost:
        dropped.append(DroppedField(
            rule_id=rule_id, field=field,
            reason=f"reference(s) {lost} point at object(s) this push does not "
                   "create (IPv6 / unsupported type) - pruned",
            fallback=("side became empty → matches Any" if not kept
                      else "remaining refs kept"),
        ))
    return kept


def _resolve_addr(literal: str, lookup: dict[str, str]) -> str:
    """Resolve a rule literal to an object name. 'any' always becomes CP's
    builtin 'Any'. Defensive: _safe_name the lookup miss, since CP objects
    are pushed under their safe-named form and an un-sanitized rule
    reference would 404 (mirrors _rewrite_members_cp's pattern for groups).
    """
    if not literal:
        return "Any"
    if literal.lower() == "any":
        return "Any"
    hit = lookup.get(literal)
    if hit is not None:
        return hit
    return _safe_name(literal)


def _ensure_service(
    proto: str,
    port: str,
    svc_lookup: dict[tuple[str, str], str],
    section_lists: dict[str, list[dict]],
) -> str | None:
    """Return CP service-object name for (proto, port). Creates a new
    add-service-tcp/udp command on the fly when the lookup misses; the new
    entry is appended into ``section_lists`` (Services-TCP / Services-UDP)
    and registered in ``svc_lookup`` so subsequent calls reuse it. Returns
    None for protocols other than tcp/udp.
    """
    proto = (proto or "").lower()
    port = str(port or "").strip()
    if proto not in ("tcp", "udp") or not port:
        return None
    # Same CP port constraint as the object renderer - a rule-derived
    # 'tcp/0-65535' must be clamped to 1-65535, a bare 0 has no CP form.
    port = _cp_norm_port(port) or ""
    if not port:
        return None
    existing = svc_lookup.get((proto, port))
    if existing:
        return existing
    name = _safe_name(f"{proto}_{port}")
    cmd = "add-service-tcp" if proto == "tcp" else "add-service-udp"
    section = "Services-TCP" if proto == "tcp" else "Services-UDP"
    section_lists.setdefault(section, []).append({
        "command": cmd,
        "payload": {
            "name": name, "port": port,
            "ignore-warnings": True, "set-if-exists": True,
        },
    })
    svc_lookup[(proto, port)] = name
    return name


def _ensure_host(
    ip: str,
    addr_lookup: dict[str, str],
    section_lists: dict[str, list[dict]],
) -> str | None:
    """Return CP host-object name for an IPv4 literal. Creates a new
    add-host command on the fly when the lookup misses; the new entry
    lands in ``section_lists['Hosts']`` and addr_lookup is mutated so
    the literal-IP → name mapping is reused.

    Used by NAT rendering to materialize interface-address NAT (CP has
    no native "translate to interface IP" - we capture the IP and emit
    a host object). Returns None for empty/invalid IP.
    """
    ip = (ip or "").strip()
    if not ip:
        return None
    existing = addr_lookup.get(ip)
    if existing:
        return existing
    name = _safe_name(f"if_addr_{ip}")
    section_lists.setdefault("Hosts", []).append({
        "command": "add-host",
        "payload": {
            "name": name, "ipv4-address": ip,
            "ignore-warnings": True, "set-if-exists": True,
        },
    })
    addr_lookup[ip] = name
    return name


# ── Security-rule rendering ──────────────────────────────────────

# Action mapping: agnostic action verb → CP rulebase-action name.
_ACTION_MAP = {
    "allow": "Accept", "pass": "Accept", "accept": "Accept",
    "deny": "Drop", "drop": "Drop", "block": "Drop",
    "reject": "Reject",
}

# CP comment limit (100 chars per docs; varies slightly by version).
_CP_COMMENT_MAX = 100

# Placeholder value set on rule payloads at generate-time. push() resolves
# the actual layer from the chosen policy_package and rewrites every
# occurrence before sending to the device.
_LAYER_SENTINEL = "__resolved_at_push__"


# Preferred landing category for custom URL objects; push() falls back to
# whatever the target reports (see _resolve_url_category).
_CP_CUSTOM_URL_CATEGORY = "Custom_Application_Site"


def _resolve_url_category(base_url: str, sid: str) -> str | None:
    """A custom-URL category that EXISTS on this management server.

    Prefers the configured default, then any category whose name marks it as
    the custom bucket, else None (caller leaves the payload untouched and
    lets the API error speak)."""
    try:
        resp = _call(base_url, sid, "show-application-site-categories",
                     {"limit": 500})
    except Exception:
        return None
    names = [str(o.get("name") or "") for o in (resp.get("objects") or [])]
    if _CP_CUSTOM_URL_CATEGORY in names:
        return _CP_CUSTOM_URL_CATEGORY
    for n in names:
        if "custom" in n.lower():
            return n
    return None


def _render_tags(tags: list[dict],
                  dropped: list[DroppedField]) -> list[dict]:
    """Build add-tag commands for CP tag-objects (mirror _render_zones).

    tags: list of {"name": ..., "properties": {cp_color, cp_icon, cp_comments}}.
    CP Mgmt-API rejects unknown color values; renderer falls back to
    vendor-default (`tag_color_default("checkpoint")` → "blue") + warn.
    push() will use add-tag with `ignore-warnings` so name-collision
    against existing target tags doesn't hard-fail (CP returns
    "name is already exists" but the push-loop handles it).
    """
    from tag_schemas import tag_color_valid, tag_color_default
    out: list[dict] = []
    dflt = tag_color_default("checkpoint") or "blue"
    for t in tags:
        name = (t.get("name") or "").strip()
        if not name:
            continue
        props = t.get("properties") or {}
        color = (props.get("cp_color") or "").strip()
        if color and not tag_color_valid("checkpoint", color):
            dropped.append(DroppedField(
                rule_id=name, field="cp_color",
                reason=f"unknown CP color {color!r} - falling back to {dflt}",
                fallback=dflt,
            ))
            color = dflt
        elif not color:
            color = dflt
        payload: dict = {
            "name":   name,
            "color":  color,
            "ignore-warnings": True,
        }
        # NOTE: add-tag has NO `icon` parameter - the Mgmt-API answers
        # "Unrecognized parameter [icon]" and the whole Tags section fails
        # (live-verified R81.x, QA finding). The icon a tag shows in
        # SmartConsole is derived, not settable here, so the collected
        # cp_icon slot stays source-only (it survives a same-vendor
        # round-trip through fw_imported_objects, just not through add-tag).
        icon = (props.get("cp_icon") or "").strip()
        if icon:
            dropped.append(DroppedField(
                rule_id=name, field="cp_icon",
                reason="Check Point's add-tag API has no 'icon' parameter",
                fallback="tag created without icon"))
        comments = (props.get("cp_comments") or "").strip()
        if comments:
            payload["comments"] = comments
        out.append({"command": "add-tag", "payload": payload})
    return out


def _cp_iso_dt_split(iso: str) -> tuple[str, str]:
    """ISO 'YYYY-MM-DD HH:MM' → ('YYYY-MM-DD', 'HH:MM'). Tolerates either
    half being missing."""
    if not isinstance(iso, str) or not iso:
        return ("", "")
    s = iso.strip()
    if " " in s:
        d, t = s.split(" ", 1)
        return (d.strip(), t.strip())
    # Heuristic: contains ':' → time-only; else assume date-only.
    return ("", s) if ":" in s else (s, "")


_CP_WEEKDAYS = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}


def _cp_lcd_interval_to_payload(interval: dict) -> tuple[dict | None, str]:
    """Convert one universal `intervals` entry → CP add-time payload-parts.
    Returns ({start?, end?, recurrence?, hours-ranges?}, error_reason). On
    `kind=group` the caller dispatches to add-time-group, so we return
    (None, 'group').

    CP-API schema split (verified live 2026-06-04 against R8x):
      - `start` / `end` carry an ABSOLUTE date+time boundary (`{date, time}`).
        Both fields required when used; CP rejects with "date format" if
        date is the empty string.
      - Time-of-day for a recurring schedule lives in `hours-ranges`
        (`[{from, to, enabled, index}]`), NOT in `start.time` / `end.time`.
      - `recurrence` carries the repetition pattern only.
    """
    kind = (interval.get("kind") or "").lower()
    if kind == "group":
        return (None, "group")
    parts: dict = {}
    st = (interval.get("start_time") or "").strip()
    et = (interval.get("end_time") or "").strip()

    def _hours_range():
        if not (st and et):
            return None
        return [{"from": st, "to": et, "enabled": True, "index": 0}]

    if kind == "weekly":
        # CP accepts only Sun..Sat. Foreign tokens reach us from factory
        # sentinels (FortiOS ships schedule 'none' with day-list ['none'],
        # QA finding) - filtering them empties the list, which means "no weekday
        # this rule could ever match" → the caller drop-warns the object
        # instead of CP rejecting the whole section.
        _wd = [d for d in (interval.get("weekdays") or [])
               if str(d).strip().capitalize()[:3] in _CP_WEEKDAYS]
        if not _wd:
            return (None, "no valid weekday (sentinel/placeholder schedule)")
        parts["recurrence"] = {
            "pattern":  "Weekly",
            "weekdays": [str(d).strip().capitalize()[:3] for d in _wd],
        }
        hr = _hours_range()
        if hr:
            parts["hours-ranges"] = hr
    elif kind == "daily":
        parts["recurrence"] = {"pattern": "Daily"}
        hr = _hours_range()
        if hr:
            parts["hours-ranges"] = hr
    elif kind == "monthly":
        parts["recurrence"] = {
            "pattern": "Monthly",
            "month":   interval.get("month") or "",
            "days":    list(interval.get("days") or []),
        }
        hr = _hours_range()
        if hr:
            parts["hours-ranges"] = hr
    elif kind == "onetime":
        sd_d, sd_t = _cp_iso_dt_split(interval.get("start_datetime") or "")
        ed_d, ed_t = _cp_iso_dt_split(interval.get("end_datetime") or "")
        # CP requires a real date when start/end are present. Drop the
        # block entirely if we only have a time (rare cross-vendor edge).
        # CP add-time start/end want {iso-8601: 'YYYY-MM-DDTHH:MM'} (live-verified
        # on R8x gw1 2026-06-09; the old {date,time} shape is rejected "value is
        # not valid"). F12.
        if sd_d:
            parts["start"] = {"iso-8601": f"{sd_d}T{sd_t or '00:00'}"}
        if ed_d:
            parts["end"]   = {"iso-8601": f"{ed_d}T{ed_t or '23:59'}"}
        return (parts, "")
    else:
        return (None, f"unknown kind '{kind}'")
    return (parts, "")


def _cp_time_name_map(schedules: list[dict]) -> dict[str, str]:
    """Map each source schedule name → a CP-safe time-object name (CP rejects
    time-object names >11 chars). Truncate to 11 + dedup. Used by the schedule
    render AND the rule time-ref so both sides agree (F12)."""
    seen: set[str] = set()
    out: dict[str, str] = {}
    for s in schedules:
        name = (s.get("name") or "").strip()
        if not name or name in out:
            continue
        cp = name[:11]
        if cp in seen:
            base = cp[:9]
            i = 1
            while f"{base}{i}"[:11] in seen and i < 100:
                i += 1
            cp = f"{base}{i}"[:11]
        seen.add(cp)
        out[name] = cp
    return out


def _render_schedules(schedules: list[dict],
                       dropped: list[DroppedField]) -> tuple[list[dict], dict[str, str]]:
    """Build add-time / add-time-group commands for CP time-objects. Returns
    (commands, name_map) where name_map = source→CP-safe time name (F12).

    Schedule cross-vendor V1: prefers value.intervals (universal LCD).
    Falls back to value.cp_intervals (legacy CP-native) for objects that
    haven't been re-imported since the migrator ran. Objects with neither
    get a DroppedField warn + skip per [[feedback_user_owns_migration_decisions]].

    Multi-Interval Quirk (CP only supports ONE start/end/recurrence per
    time-object): picks the first universal interval and warns about the
    rest. TimeGroup expansion is V2.

    `kind=group` dispatches to add-time-group (separate endpoint, member
    list payload).

    Idempotency for re-pushes comes from _SET_FALLBACK_COMMANDS
    (add-time → set-time / add-time-group → set-time-group via
    _call_idempotent). R8x rejects `set-if-exists` on these endpoints
    just like it does on add-group / add-security-zone (Unrecognized
    parameter [set-if-exists]), so we DO NOT inline that flag here.
    """
    out: list[dict] = []
    name_map = _cp_time_name_map(schedules)
    for s in schedules:
        name = (s.get("name") or "").strip()
        if not name:
            continue
        cp_name = name_map.get(name, name[:11])
        val = s.get("value") or {}
        desc = (val.get("description") or val.get("cp_description") or "").strip()
        intervals = val.get("intervals") or []
        legacy_cp = val.get("cp_intervals") or []

        if intervals:
            # Multi-interval warn: V1 picks first, drops rest with reason.
            if len(intervals) > 1:
                dropped.append(DroppedField(
                    rule_id=name, field="schedule",
                    reason=(f"{len(intervals)} intervals in source - CP "
                            "time-object only carries one"),
                    fallback="first interval pushed, rest skipped",
                ))
            first = intervals[0]
            kind = (first.get("kind") or "").lower()
            if kind == "group":
                members = [m for m in (first.get("members") or [])
                           if isinstance(m, str) and m]
                if not members:
                    dropped.append(DroppedField(
                        rule_id=name, field="schedule",
                        reason="group-kind interval with no members",
                        fallback="object skipped at push",
                    ))
                    continue
                payload: dict = {
                    "name":            cp_name,
                    "members":         [name_map.get(m, m[:11]) for m in members],
                    "ignore-warnings": True,
                }
                if desc:
                    payload["comments"] = desc[:_CP_COMMENT_MAX]
                out.append({"command": "add-time-group", "payload": payload})
                continue

            parts, err = _cp_lcd_interval_to_payload(first)
            if err:
                dropped.append(DroppedField(
                    rule_id=name, field="schedule",
                    reason=f"cannot render interval to CP payload: {err}",
                    fallback="object skipped at push",
                ))
                continue
            payload = {
                "name":            cp_name,
                "ignore-warnings": True,
            }
            payload.update(parts or {})
            if desc:
                payload["comments"] = desc[:_CP_COMMENT_MAX]
            out.append({"command": "add-time", "payload": payload})
            continue

        # Legacy fallback - pre-Phase 1 cp_intervals shape (raw CP form).
        if not legacy_cp:
            dropped.append(DroppedField(
                rule_id=name, field="schedule",
                reason="no intervals slot - cross-vendor import without "
                       "any schedule mapping",
                fallback="object skipped at push",
            ))
            continue
        interval = legacy_cp[0]
        payload = {
            "name":            cp_name,
            "ignore-warnings": True,
        }
        # CP rejects start/end with empty date; only include the block
        # when a real date is present. Time-of-day for recurring lives in
        # hours-ranges (see _cp_lcd_interval_to_payload docstring).
        start = interval.get("start") or {}
        if start.get("date"):
            payload["start"] = {
                "iso-8601": f"{start.get('date', '')}T{start.get('time', '') or '00:00'}",
            }
        end = interval.get("end") or {}
        if end.get("date"):
            payload["end"] = {
                "iso-8601": f"{end.get('date', '')}T{end.get('time', '') or '23:59'}",
            }
        rec = interval.get("recurrence") or {}
        if rec:
            payload["recurrence"] = {
                "pattern":  rec.get("pattern", ""),
                "weekdays": rec.get("weekdays", []),
                "month":    rec.get("month", ""),
                "days":     rec.get("days", []),
            }
        if desc:
            payload["comments"] = desc[:_CP_COMMENT_MAX]
        out.append({"command": "add-time", "payload": payload})
    # add-time-group must follow its member time-objects - CP 404s on a
    # forward reference exactly like it does for address/service groups
    # (QA finding: 'gfgt-sched-' before 'gfgt-work').
    return _toposort_cp_groups(out), name_map


def _cp_url_list(c: dict) -> list[str]:
    """The usable CP url-list of a custom URL-category object, or []. A custom
    category is CREATABLE on CP (as an application-site) only if it carries
    one; cross-vendor imports (PA/Forti) without a `cp_list` slot are dropped
    by `_render_url_categories`. Single source of the creatability test - also
    used to decide whether a decryption rule may reference the category as a
    site-category (else add-https-rule 404s on a non-existent site)."""
    val = (c or {}).get("value") or {}
    return [u for u in (val.get("cp_list") or [])
            if isinstance(u, str) and u.strip()]


def _render_url_categories(url_categories: list[dict],
                             dropped: list[DroppedField]) -> list[dict]:
    """Build add-application-site commands for Custom URL Categories.

    CP unifies Apps + URLs in the application-site entity. Per
    url_category object we emit one add-application-site with a
    url-list body. The driver reads its own cp_ slot
    (cp_list, cp_url_defined_as_regex?, cp_description?). Objects
    without cp_list (cross-vendor import from PA/Forti) → DroppedField
    warn + skip; the user decides the manual mapping on the target per
    feedback_user_owns_migration_decisions.

    application-sites require a `primary-category`. We set
    "Custom_URL_Categories" as a generic bucket - the user can
    re-categorize on the target if needed.
    """
    out: list[dict] = []
    for c in url_categories:
        name = (c.get("name") or "").strip()
        if not name:
            continue
        val = c.get("value") or {}
        urls = _cp_url_list(c)
        if not urls:
            dropped.append(DroppedField(
                rule_id=name, field="url_category",
                reason="no cp_list slot - cross-vendor import without "
                       "CP mapping",
                fallback="object skipped at push",
            ))
            continue
        payload: dict = {
            "name":              name,
            # The category a custom URL object lands in is NAMED differently
            # across Mgmt-API versions ('Custom_URL_Categories' does not exist
            # on R81.x - add-application-site then 404s on the category, not on
            # the object). push() rewrites this to a category the target
            # actually has; the constant is only the preferred default.
            "primary-category":  _CP_CUSTOM_URL_CATEGORY,
            "url-list":          urls,
            "ignore-warnings":   True,
        }
        # The regex flag exists on some Mgmt-API versions and not on others
        # ("Unrecognized parameter [url-defined-as-regular-expression]",
        # live-verified R81.x - QA finding). Send it ONLY when the source
        # actually set it, so a plain URL list never trips the version
        # difference; if it is set and the target rejects it, that is a
        # visible failure rather than a silently wrong match mode.
        if val.get("cp_url_defined_as_regex"):
            payload["url-defined-as-regular-expression"] = True
        desc = (val.get("cp_description") or "").strip()
        if desc:
            payload["comments"] = desc[:_CP_COMMENT_MAX]
        out.append({"command": "add-application-site", "payload": payload})
    return out


def _render_security_rules(
    rules: list[dict],
    settings: dict[str, str],
    addr_lookup: dict[str, str],
    svc_lookup: dict[tuple[str, str], str],
    dropped: list[DroppedField],
    pushable_schedules: set[str] | None = None,
    schedule_name_map: dict | None = None,
    any_svc_names: set[str] | None = None,
    pushable_addrs: set[str] | None = None,
) -> list[dict]:
    """Convert agnostic rules → CP add-access-rule commands.

    Zones are not mapped - CP source/destination lists OR-match their
    members, so mixing zone objects with address objects in one list
    changes the semantics from PA's AND. We render the address criterion
    only and report the dropped zones; the user can refine in SmartConsole.

    Order is preserved by chaining ``position: {"below": <prev>}``. The
    first rule uses ``position: "top"``, so existing default (e.g.
    Cleanup) rules stay below.
    """
    # Layer is resolved at push-time from the chosen policy_package
    # (each package owns exactly one access-control layer in our scope).
    # We emit a sentinel here that push() rewrites before sending.
    layer = _LAYER_SENTINEL
    package = settings.get("policy_package") or "Standard"
    prefix = settings.get("rule_prefix") or "Gateshift-"

    out: list[dict] = []
    seen_names: dict[str, int] = {}
    prev_name: str | None = None

    for i, rule in enumerate(rules):
        rule_id = str(rule.get("rule_name") or rule.get("id") or f"#{i+1}")

        for fld in _UNSUPPORTED_RULE_FIELDS:
            if rule.get(fld):
                dropped.append(DroppedField(
                    rule_id=rule_id, field=fld,
                    reason="not yet rendered by checkpoint driver",
                ))

        # Zones get dropped (semantic mismatch with CP source/destination OR-match).
        # MITIGATION: restore the interface scoping via the gateway's Anti-Spoofing
        # topology - with each network assigned to its interface, a rule whose source
        # addresses sit behind that interface is enforced exactly as before (the packet
        # is dropped pre-rulebase when it arrives on any other interface). Only
        # source=any rules stay genuinely wider and need a manual review.
        for zfld in ("src_zones", "dst_zones"):
            zv = rule.get(zfld)
            if zv and zv != ["any"]:
                _src_any = not rule.get("sources") or rule.get("sources") == ["any"]
                dropped.append(DroppedField(
                    rule_id=rule_id, field=zfld,
                    reason="CP rule source/destination OR-match members; mixing "
                           "zones with addresses widens the rule. Zones dropped. "
                           "Mitigate on the gateway: configure Anti-Spoofing topology "
                           "(assign each network to its interface) - rules with "
                           "specific sources are then enforced as before"
                           + ("; THIS rule has source=any and stays genuinely wider "
                              "- review manually" if (zfld == "src_zones" and _src_any)
                              else ""),
                    fallback=f"{zfld}={zv}",
                ))

        # Rule name (de-dup, sanitize, truncate)
        rule_name = _safe_name(rule.get("rule_name") or f"{prefix}{i+1:03d}")
        if rule_name in seen_names:
            seen_names[rule_name] += 1
            rule_name = _safe_name(f"{rule_name}-{seen_names[rule_name]}")
        else:
            seen_names[rule_name] = 0

        sources = _prune_unpushable(
            [_resolve_addr(s, addr_lookup) for s in (rule.get("sources") or [])],
            pushable_addrs, rule_name, "source", dropped)
        # Source-User identity refs (Phase 2 User/Groups, Option C). CP
        # carries Access-Role identity constraints as source-members
        # alongside networks. We re-add the role names by reference - the
        # role's composite definition (users AND machines AND networks) is
        # NOT migrated (ref-only). The role MUST already exist at the
        # target; if not, add-access-rule 404s (DroppedField warn surfaces
        # the requirement, consistent with "identity backend is the user's
        # responsibility"). kind=keyword is a PA sentinel with no CP equiv
        # → dropped.
        identity_names: list[str] = []
        for idn in (rule.get("source_identities") or []):
            nm = (idn.get("name") or "").strip()
            kind = (idn.get("kind") or "unknown").lower()
            if not nm:
                continue
            if kind == "keyword":
                dropped.append(DroppedField(
                    rule_id=rule_name, field="source_identity",
                    reason=f"PA keyword '{nm}' has no CP Access-Role equivalent",
                    fallback="identity ref dropped",
                ))
                continue
            identity_names.append(nm)
        if identity_names:
            # 'Any' network + a role is redundant; drop the bare Any so the
            # role constrains the source. Otherwise append to the networks.
            base = [s for s in sources if s != "Any"]
            sources = base + identity_names
        if not sources:
            sources = ["Any"]
        destinations = _prune_unpushable(
            [_resolve_addr(d, addr_lookup) for d in (rule.get("destinations") or [])],
            pushable_addrs, rule_name, "destination", dropped)
        if not destinations:
            destinations = ["Any"]

        # Service resolution. Config-migrated rules carry the source's named
        # service objects/groups in `services` - reference them verbatim
        # (via the same _safe_name the object/group sections emit) so service
        # GROUPS and multi-service rules survive. The scalar (proto,port)
        # reverse-lookup below is the syslog fallback. (QA finding.)
        named_svcs = rule.get("services") or []
        proto = (rule.get("proto") or "").lower()
        port_from = rule.get("port_from")
        port_to = rule.get("port_to")
        _any_svc = any_svc_names or set()
        if named_svcs:
            # An all-traffic service (Forti 'ALL') → CP builtin 'Any'; it
            # subsumes any concrete members and isn't a pushable object, so the
            # whole rule's service becomes 'Any' (else add-access-rule 404s on
            # the missing 'ALL' object).
            if any((s or "").strip().lower() in _any_svc for s in named_svcs):
                services = ["Any"]
            else:
                services = [_safe_name(s) for s in named_svcs]
        elif proto and port_from is not None:
            port_str = (f"{port_from}-{port_to}"
                        if port_to and port_to != port_from else str(port_from))
            svc_name = svc_lookup.get((proto, port_str))
            if svc_name:
                services = [svc_name]
            else:
                services = ["Any"]
                dropped.append(DroppedField(
                    rule_id=rule_id, field="service",
                    reason=f"no service object for {proto}/{port_str}",
                    fallback="using builtin Any",
                ))
        else:
            services = ["Any"]

        # application-default App-IDs the resolver couldn't map to ports
        # (icmp-only / unmapped) - surfaced so the Any fallback is visible.
        unresolved_app = rule.get("_appdef_unresolved")
        if unresolved_app:
            dropped.append(DroppedField(
                rule_id=rule_id, field="service",
                reason="application-default not resolvable for: "
                       + ", ".join(unresolved_app),
                fallback="service left as Any - set manually",
            ))

        # ── L7 Applications (App-Sites) ─────────────────────────
        # CP's `service` field accepts a mixed list of Service-Objects AND
        # Application-Sites. The auto-binder (Slice 2) writes app overrides
        # keyed on content_hash; the SQL pipeline merges them into rule
        # `application` as CSV. We mix them into `service` here so a single
        # CP API call covers both. Track the app subset in `__applications__`
        # so push() can strip them when the access-layer has no
        # `applications-and-url-filtering` blade (rule would fail validation).
        # Only consume `application` when it came from an override - source's
        # vendor-specific app names (e.g. PA "ssl,web-browsing") don't match
        # CP's App-Site catalog and would fail validation at push.
        app_csv = (rule.get("application") or "").strip()
        if not rule.get("app_override_source"):
            app_csv = ""
        app_names: list[str] = []
        if app_csv:
            for nm in app_csv.split(","):
                nm = nm.strip()
                if not nm or nm.lower() == "any":
                    continue
                # Only real CP App-Sites may enter the service list. Foreign
                # app names (PAN-OS App-IDs, classical protocols CP models as
                # services) would 404 at add-access-rule - drop them; the
                # rule's service object already covers the port.
                if nm.lower() not in _CP_APP_SITE_NAMES:
                    dropped.append(DroppedField(
                        rule_id=rule_id, field="application",
                        reason="not a Check Point App-Site - dropped (port stays "
                               "covered by the service object)",
                        fallback=nm,
                    ))
                    continue
                if nm not in app_names:
                    app_names.append(nm)
        if app_names:
            # Drop the implicit "Any" placeholder once real entries arrive -
            # CP rejects rules whose service list mixes Any with concrete items.
            if services == ["Any"]:
                services = list(app_names)
            else:
                for nm in app_names:
                    if nm not in services:
                        services.append(nm)

        action_raw = (rule.get("action") or "allow").lower()
        action = _ACTION_MAP.get(action_raw, "Drop")

        # CP track field: per-rule override wins over device default ("Log").
        # Renderer accepts the override only when track_type is set; the
        # accounting / per-session / per-connection booleans only apply
        # when CP supports them on the chosen type (Log + accounting), so
        # we pass them through and let CP reject impossible combinations.
        track_type = (rule.get("track_type") or "Log").strip() or "Log"
        # CP refuses "Detailed Log" / "Extended Log" on Layers that have only
        # the Firewall Blade enabled (the Gateshift default - we don't push App
        # Control / URL Filtering / Content Awareness state). Downgrade to
        # plain "Log" so the rule pushes; the downgrade is recorded so the
        # operator can re-enable detailed logging manually if they later add
        # the required blades to the layer.
        if track_type in ("Detailed Log", "Extended Log"):
            dropped.append(DroppedField(
                rule_id=rule_id, field="track_type",
                reason=f"{track_type!r} requires extra blades on the Layer",
                fallback="downgraded to 'Log'",
            ))
            track_type = "Log"
        if (rule.get("accounting") or rule.get("per_session")
                or rule.get("per_connection")):
            track_payload: Any = {
                "type": track_type,
                "accounting": bool(rule.get("accounting")),
                "per-session": bool(rule.get("per_session")),
                "per-connection": bool(rule.get("per_connection")),
            }
        else:
            track_payload = track_type

        payload: dict[str, Any] = {
            "layer": layer,
            "name": rule_name,
            "source": sources,
            "destination": destinations,
            "service": services,
            "action": action,
            "track": track_payload,
            "vpn": "Any",
            "ignore-warnings": True,
            # Carries package-name through to push() for layer resolution;
            # stripped before send. Underscored to avoid colliding with any
            # real CP API field.
            "__package__": package,
            # App-Site subset of `service` - push() strips these from the
            # service list when the resolved layer has no apps-blade enabled.
            "__applications__": list(app_names),
            # Identity (Access-Role) source-refs subset (Phase 2.5). push()
            # fetches the target's existing Access-Roles live and removes
            # any ref that doesn't exist there (else add-access-rule 404s),
            # then strips this marker. Empty when the rule has no identities.
            "__identity_refs__": list(identity_names),
        }
        payload["position"] = "top" if i == 0 else {"below": prev_name}

        if rule.get("disabled"):
            payload["enabled"] = False

        # Schedule-Reference (Phase 1b). rule.schedule kommt aus rules_query
        # COALESCE(schovr.schedule_name, r.schedule). NULL = 'Any' (CP
        # default = always active). The CP API wants 'time' as a list of
        # name refs; V1 sets a single entry. The schedule must exist as a
        # time object on the target (pre-rules Schedules section).
        #
        # Cross-vendor quirk: PA/Forti schedules without cp_intervals are
        # skipped with DroppedField in _render_schedules - if we emit the
        # ref here anyway, add-access-rule blows up with HTTP 404.
        # pushable_schedules carries the names of the successfully
        # rendered time objects; everything else goes out with a drop warn.
        schedule_ref = (rule.get("schedule") or "").strip()
        if schedule_ref:
            # Translate to the CP-safe time-object name (<=11 chars) so the rule
            # ref matches the rendered add-time name (F12).
            cp_sched = (schedule_name_map or {}).get(schedule_ref, schedule_ref[:11])
            if pushable_schedules is not None and cp_sched not in pushable_schedules:
                dropped.append(DroppedField(
                    rule_id=(rule.get("rule_name") or rule.get("rhash") or "?"),
                    field="schedule",
                    reason=(f"schedule '{schedule_ref}' has no CP time-object "
                            "at the target (no cp_intervals mapping in source)"),
                    fallback="rule pushed without schedule (always-active)",
                ))
            else:
                payload["time"] = [cp_sched]

        # Per-rule negate flags (rule.negate_{source,destination,service})
        # come from rules_query COALESCE(novr.*, r.*). CP Mgmt-API only
        # accepts hyphen-form on POST per V0 lab-probe - emitting
        # negate-source/etc. → HTTP 400 "Unrecognized parameter".
        if rule.get("negate_source"):
            payload["source-negate"] = True
        if rule.get("negate_destination"):
            payload["destination-negate"] = True
        if rule.get("negate_service"):
            payload["service-negate"] = True

        # Tags - override wins over source-import (rule.cp_tags vs
        # rule.import_tags). Tag-names must already exist as tag-objects
        # at the target (pushed pre-rules by _render_tags).
        effective_tags: list[str] = []
        ovr_tags = rule.get("cp_tags")
        if isinstance(ovr_tags, str):
            try:
                import json as _json
                ovr_tags = _json.loads(ovr_tags)
            except Exception:
                ovr_tags = None
        if isinstance(ovr_tags, list):
            effective_tags = [t for t in ovr_tags if isinstance(t, str) and t.strip()]
        else:
            src_tags = rule.get("import_tags") or rule.get("tags") or []
            if isinstance(src_tags, str):
                try:
                    import json as _json
                    src_tags = _json.loads(src_tags)
                except Exception:
                    src_tags = []
            if isinstance(src_tags, list):
                effective_tags = [t for t in src_tags if isinstance(t, str) and t.strip()]

        desc = rule.get("description") or ""
        if desc:
            if len(desc) > _CP_COMMENT_MAX:
                dropped.append(DroppedField(
                    rule_id=rule_id, field="description",
                    reason=f"comment exceeds {_CP_COMMENT_MAX} chars ({len(desc)})",
                    fallback=f"truncated to {_CP_COMMENT_MAX}",
                ))
                desc = desc[:_CP_COMMENT_MAX]
            payload["comments"] = desc

        out.append({"command": "add-access-rule", "payload": payload})
        # Time-Object post-step: add-access-rule's `time` parameter is
        # documented as accepted but the staged rule shows up with no
        # schedule attached on R8x (verified live 2026-06-04 - time-object
        # `jona` lands via add-time, push succeeds, rules carry no time).
        # set-access-rule with `time` applies it reliably (same pattern as
        # the tags-fix attempt in commit 9502d3d; tags failed, time works).
        if schedule_ref and (pushable_schedules is None
                              or schedule_ref in pushable_schedules):
            out.append({
                "command": "set-access-rule",
                "payload": {
                    "name":            rule_name,
                    "layer":           layer,
                    "time":            [schedule_ref],
                    "ignore-warnings": True,
                },
            })
        # Tags - the CP Mgmt API on this lab version accepts `tags`
        # neither on add-access-rule nor on set-access-rule (HTTP 400
        # "Unrecognized parameter [tags]", verified live 2026-06-03).
        # Until the correct API form is known (possibly tags.add /
        # UID refs / version-specific from R81.10): do not push, surface
        # as DroppedField. SmartConsole can tag afterwards.
        if effective_tags:
            dropped.append(DroppedField(
                rule_id=rule_id, field="tags",
                reason="CP Mgmt-API rejects 'tags' on add-/set-access-rule "
                       "on this version",
                fallback=f"would attach {effective_tags!r}",
            ))
        prev_name = rule_name

    return out


# ── HTTPS-Inspection (SSL decryption) rule rendering ─────────────

def _canon_category(s: str | None) -> str:
    """Canonical key for cross-vendor URL-category name-matching: lowercase,
    drop the noise word 'and' (CP uses '&'), strip all non-alphanumerics. So
    PA 'alcohol-and-tobacco' and CP 'Alcohol & Tobacco' collapse to the same
    key, and 'financial-services' ↔ 'Financial Services'."""
    s = re.sub(r"[^a-z0-9 ]", " ", (s or "").lower())
    s = re.sub(r"\b(and|the)\b", " ", s)
    return re.sub(r"[^a-z0-9]", "", s)


def _render_https_rules(
    ssl_rules: list[dict],
    addr_lookup: dict[str, str],
    dropped: list[DroppedField],
    resolve_category=None,
    any_svc_names: set[str] | None = None,
    pushable_svcs: set[str] | None = None,
) -> list[dict]:
    """Agnostic ssl_rules → CP add-https-rule commands (Phase 5). HTTPS
    Inspection is CP's TLS-decryption rulebase: action decrypt|no-decrypt →
    Inspect|Bypass. source/destination resolve via addr_lookup; service goes by
    name (ref-only). URL categories → site-category via ``resolve_category(src,
    rule_id)`` (cross-vendor mapping, project_cp_url_category_map_plan): custom →
    itself, else operator-map > live name-match vs the target catalog. A category
    that can't resolve drops the WHOLE rule (its category set is its match scope
    - never push an altered/partial match). Order preserved by position
    top→below chaining. The CA is blade-level (operator-provisioned, ref-only),
    not a per-rule field, so there is no per-rule cert gate. Layer = "Default
    Layer"."""
    out: list[dict] = []
    seen: dict[str, int] = {}
    prev: str | None = None
    for i, s in enumerate(ssl_rules):
        if s.get("deleted"):
            continue
        name = _safe_name(s.get("name") or f"https-{i+1:03d}")
        if name in seen:
            seen[name] += 1
            name = _safe_name(f"{name}-{seen[name]}")
        else:
            seen[name] = 0
        sources = [_resolve_addr(x, addr_lookup) for x in (s.get("sources") or [])] or ["Any"]
        dests   = [_resolve_addr(x, addr_lookup) for x in (s.get("destinations") or [])] or ["Any"]
        action = "Bypass" if (s.get("action") == "no-decrypt") else "Inspect"
        payload: dict = {
            "layer":       "Default Layer",
            "name":        name,
            "position":    ("top" if prev is None else {"below": prev}),
            "source":      sources,
            "destination": dests,
            "action":      action,
            # Ownership marker - the re-push wipe (_wipe_https_layer) only
            # deletes rules carrying it. The Default Layer is CP's shipped
            # layer (predefined rule + possible user rules live there), so
            # a scope-based wipe like TP's is off the table.
            "comments":    _HTTPS_MARKER,
            "enabled":     not bool(s.get("disabled")),
        }
        # Reference services by the SAME _safe_name the object/group sections
        # emit (e.g. port-derived '22-tcp' is created as 's_22-tcp' because CP
        # names must start with a letter) - exactly as _render_access_rules
        # does. Without this the rule references the raw name → add-https-rule
        # 404s on a non-existent object.
        _raw_svcs = [x for x in (s.get("services") or []) if x]
        if any((x or "").strip().lower() in (any_svc_names or set()) for x in _raw_svcs):
            svcs = ["Any"]
        else:
            svcs = [_safe_name(x) for x in _raw_svcs]
        if svcs and svcs != ["Any"]:
            # Invariant I1: only reference services this push creates. CP's own
            # predefined groups (e.g. 'HTTPS_default_services' on the shipped
            # HTTPS rule) are data-domain objects we never push, so a verbatim
            # ref 404s the whole section (QA finding, CP self-deploy).
            svcs, _lost_svcs = _integ.prune_refs(svcs, pushable_svcs,
                                                 keep=("any", "Any"))
            if _lost_svcs:
                dropped.append(DroppedField(
                    rule_id=name, field="ssl_service",
                    reason=f"service ref(s) {_lost_svcs} are not objects this "
                           "push creates (vendor-predefined group)",
                    fallback=("service narrowed to Any" if not svcs
                              else "remaining services kept")))
        if svcs and svcs != ["Any"]:
            payload["service"] = svcs
        # URL categories → site-category, resolved cross-vendor via
        # resolve_category (custom→self, manual map > live name-match). A
        # category set IS the rule's match scope, so if ANY referenced category
        # can't resolve to a target category we DROP the whole rule rather than
        # push an altered/partial match (the push-modal gate normally prevents
        # reaching here; this is the API-push safety net).
        raw_cats = [x for x in (s.get("url_categories") or []) if x]
        if raw_cats:
            resolved: list[str] = []
            unmapped: list[str] = []
            for c in raw_cats:
                rc = resolve_category(c, name) if resolve_category else c
                if rc:
                    if rc not in resolved:
                        resolved.append(rc)
                else:
                    unmapped.append(c)
            if unmapped:
                _n = len(unmapped)
                dropped.append(DroppedField(
                    rule_id=name, field="site-category",
                    reason=(f"URL categor{'y' if _n == 1 else 'ies'} "
                            f"{', '.join(unmapped)} {'has' if _n == 1 else 'have'} "
                            f"no mapping to a target category - rule dropped"),
                    fallback=("attach " + ("it" if _n == 1 else "them")
                              + " in Enrichment > Decryption"),
                ))
                continue  # skip the whole rule; don't advance `prev`
            payload["site-category"] = resolved
        out.append({"command": "add-https-rule", "payload": payload})
        prev = name
    return out


# ── NAT-rule rendering ───────────────────────────────────────────

def _render_nat_rules(
    nat_rules: list[dict],
    settings: dict[str, str],
    addr_lookup: dict[str, str],
    svc_lookup: dict[tuple[str, str], str],
    section_lists: dict[str, list[dict]],
    dropped: list[DroppedField],
    any_svc_names: set[str] | None = None,
) -> list[dict]:
    """Convert agnostic NAT rules → CP add-nat-rule commands.

    Mapping notes:
      - CP's orig-/translated-* fields are SINGLE-object slots; if the
        agnostic rule lists multiple, we use the first and record the rest
        as dropped. Auto-creating a group per-rule is left as future work.
      - 'Original' is CP's special placeholder meaning "no translation".
      - SNAT static-ip → method=static (1:1). SNAT with any dynamic
        translation type → method=hide (PAT).
      - interface-address (hide NAT behind a gateway interface IP): CP
        has no native interface-source concept. We extract the IP from
        the agnostic ``"iface|ip"`` literal, synthesize a host object via
        ``_ensure_host``, and emit method=hide. If the gateway interface
        IP changes, the user must redeploy (static binding, not dynamic).
      - Zones don't apply to CP NAT - dropped.
      - destination-port translation: CP models it as a translated-service
        on the NAT rule. We auto-create a (proto, trans_dst_port) service
        object via ``_ensure_service`` and reference it. Synthesized
        services and hosts both flow into ``section_lists`` for emission;
        push-order keeps these sections before NAT rules.
    """
    package = settings.get("policy_package") or "Standard"
    out: list[dict] = []

    def _single(rule: dict, field: str, rid: str, label: str) -> str | None:
        vals = rule.get(field) or []
        if len(vals) > 1:
            dropped.append(DroppedField(
                rule_id=rid, field=field,
                reason=f"CP NAT accepts a single {label}; first used, rest dropped",
                fallback=f"used {vals[0]!r}, dropped {vals[1:]!r}",
            ))
        return vals[0] if vals else None

    for i, n in enumerate(nat_rules):
        rid = str(n.get("name") or f"nat-{i+1}")

        # Drop zones (CP NAT has no zone matching)
        for zfld in ("src_zones", "dst_zones"):
            zv = n.get(zfld)
            if zv and zv != ["any"]:
                dropped.append(DroppedField(
                    rule_id=rid, field=zfld,
                    reason="CP NAT rules don't match on zones - dropped",
                    fallback=f"{zfld}={zv}",
                ))

        # Reduce list-fields to a single item
        orig_src = _single(n, "orig_src", rid, "original-source")
        orig_dst = _single(n, "orig_dst", rid, "original-destination")
        svc_list = n.get("orig_service") or []
        if len(svc_list) > 1:
            dropped.append(DroppedField(
                rule_id=rid, field="orig_service",
                reason="CP NAT accepts a single service; first used, rest dropped",
                fallback=f"used {svc_list[0]!r}, dropped {svc_list[1:]!r}",
            ))
        orig_svc_raw = svc_list[0] if svc_list else None

        # Resolve the source rule's service to a CP service-object name.
        # PA-style sources emit "proto/port" literals (translate via lookup).
        # CP-style sources emit a service-name verbatim (use as-is - CP will
        # resolve it on target). Either way we capture orig_proto when it's
        # derivable so port-translation can default the proto sensibly.
        orig_proto: str | None = None
        if orig_svc_raw and "/" in orig_svc_raw:
            proto, port = orig_svc_raw.split("/", 1)
            orig_proto = proto.lower()
            orig_service = svc_lookup.get((orig_proto, port)) or "Any"
        elif orig_svc_raw and (orig_svc_raw or "").strip().lower() in (any_svc_names or set()):
            # Forti 'ALL' all-traffic service → CP builtin 'Any' (not an object).
            orig_service = "Any"
        elif orig_svc_raw:
            orig_service = _safe_name(orig_svc_raw)
        else:
            orig_service = "Any"

        original_source = _resolve_addr(orig_src, addr_lookup) if orig_src else "Any"
        original_destination = _resolve_addr(orig_dst, addr_lookup) if orig_dst else "Any"

        nat_type = (n.get("nat_type") or "snat").lower()
        trans_src = n.get("trans_src")
        trans_src_type = (n.get("trans_src_type") or "").lower()
        trans_dst = n.get("trans_dst")
        trans_dst_port = n.get("trans_dst_port")

        # Interface-address NAT - synthesize a host object from the
        # captured IP literal and emit method=hide. CP has no native
        # interface-source concept, so we materialize the IP at deploy
        # time. If the interface IP later changes the user redeploys.
        if trans_src_type == "interface-address":
            iface_ip = trans_src.split("|", 1)[1].strip() \
                if trans_src and "|" in trans_src else ""
            host_name = _ensure_host(iface_ip, addr_lookup, section_lists)
            if not host_name:
                dropped.append(DroppedField(
                    rule_id=rid, field="trans_src",
                    reason="interface-address NAT without resolvable IP "
                           "(expected 'iface|ip' literal) - rule dropped",
                ))
                continue
            translated_source = host_name
            translated_destination = "Original"
            method = "hide"
        # Decide method + translated fields based on nat_type
        elif nat_type == "snat" and trans_src:
            translated_source = _resolve_addr(trans_src, addr_lookup)
            translated_destination = "Original"
            method = "static" if trans_src_type == "static-ip" else "hide"
        elif nat_type == "dnat" and trans_dst:
            translated_source = "Original"
            translated_destination = _resolve_addr(trans_dst, addr_lookup)
            method = "static"
        elif nat_type == "static" and (trans_src or trans_dst):
            translated_source = _resolve_addr(trans_src, addr_lookup) \
                if trans_src else "Original"
            translated_destination = _resolve_addr(trans_dst, addr_lookup) \
                if trans_dst else "Original"
            method = "static"
        else:
            dropped.append(DroppedField(
                rule_id=rid, field="nat_type",
                reason=f"nat_type {nat_type!r} with no translation target - rule dropped",
            ))
            continue

        # Destination-port translation → CP translated-service. Default to
        # tcp if no orig_service (typical port-forward without explicit svc).
        # CP's policy installer rejects Original-Service=Any paired with a
        # specific Translated-Service ("Invalid <Any> in Service of NAT Rule
        # - valid only if matching Translated column is <Original>"), so we
        # skip the translation when the original side is wild.
        # A FULL-RANGE mapped port (Forti VIP without real port-forwarding
        # re-imports as trans_dst_port='0-65535') is an IDENTITY mapping -
        # rendering it literally pairs a single-port original with a
        # 65535-port translated service and CP verification refuses the
        # install ("range size of Original and Translated columns must be
        # the same", fgt2cp finding 2026-08-31). No rewrite → Original.
        _tp_norm = str(trans_dst_port or "").strip().replace(" ", "")
        if _tp_norm in ("0-65535", "1-65535", "0", "any", "*"):
            trans_dst_port = None
        translated_service = "Original"
        if trans_dst_port and orig_service == "Any":
            dropped.append(DroppedField(
                rule_id=rid, field="trans_dst_port",
                reason="orig_service=Any with port translation is rejected "
                       "by CP - translation dropped, rule keeps Original svc",
                fallback=f"port {trans_dst_port} not applied",
            ))
        elif trans_dst_port:
            tport = str(trans_dst_port).strip()
            tproto = orig_proto or "tcp"
            tname = _ensure_service(tproto, tport, svc_lookup, section_lists)
            if tname:
                translated_service = tname
            else:
                dropped.append(DroppedField(
                    rule_id=rid, field="trans_dst_port",
                    reason=f"port translation requires tcp/udp; orig_proto={orig_proto!r}",
                    fallback=f"port {trans_dst_port} not applied",
                ))

        # nat_schemas cp_* slots - vendor-specific overrides from
        # fw_nat_rules.properties. cp_method wins over the auto-derived
        # value; cp_packet_mangling adds the optional CP flag.
        props = n.get("properties") or {}
        if isinstance(props, str):
            try:
                import json as _json
                props = _json.loads(props) or {}
            except Exception:
                props = {}
        cp_method_override = (props.get("cp_method") or "").strip().lower()
        if cp_method_override in ("static", "hide", "nat-64"):
            method = cp_method_override
        # Phase-F cross-vendor mapping: cp_trans_src_ref / cp_trans_dst_ref
        # override the auto-resolved translated-source / -destination so a
        # foreign-source NAT-rule can be re-bound to a CP-target object.
        cp_ts_ref = (props.get("cp_trans_src_ref") or "").strip()
        if cp_ts_ref:
            translated_source = cp_ts_ref
        cp_td_ref = (props.get("cp_trans_dst_ref") or "").strip()
        if cp_td_ref:
            translated_destination = cp_td_ref

        payload: dict[str, Any] = {
            "package": package,
            "position": "bottom",
            "original-source": original_source,
            "original-destination": original_destination,
            "original-service": orig_service,
            "translated-source": translated_source,
            "translated-destination": translated_destination,
            "translated-service": translated_service,
            "method": method,
            "ignore-warnings": True,
        }
        if props.get("cp_packet_mangling"):
            payload["packet-mangling"] = True
        if n.get("disabled"):
            payload["enabled"] = False

        # CP NAT rejects all four negate spelling variants ("Unrecognized
        # parameter") - Live-API probe 2026-06-03 corrected V0. Warn per
        # flag, emit nothing.
        for aspect in ("negate_source", "negate_destination", "negate_service"):
            if n.get(aspect):
                dropped.append(DroppedField(
                    rule_id=rid, field=aspect,
                    reason="Check Point NAT rules do not support negation",
                    fallback="ignored",
                ))

        desc = n.get("description") or ""
        if desc:
            if len(desc) > _CP_COMMENT_MAX:
                dropped.append(DroppedField(
                    rule_id=rid, field="description",
                    reason=f"comment exceeds {_CP_COMMENT_MAX} chars ({len(desc)})",
                    fallback=f"truncated to {_CP_COMMENT_MAX}",
                ))
                desc = desc[:_CP_COMMENT_MAX]
            payload["comments"] = desc

        out.append({"command": "add-nat-rule", "payload": payload})

    return out


# ── Zone rendering ───────────────────────────────────────────────

def _render_zones(zones: list[dict], dropped: list[DroppedField]) -> list[dict]:
    """Convert agnostic zones → CP add-security-zone commands.

    CP security-zones are pure name+comment objects. Interface→zone binding
    is a per-gateway operation (set-simple-gateway with topology) and is
    handled separately in the push step, not here.
    """
    out: list[dict] = []
    seen: set[str] = set()
    for z in zones:
        raw_name = z.get("name") or z.get("zone_name") or ""
        name = _safe_name(raw_name)
        if not name or name in seen:
            continue
        if name.lower() == "default":
            # CP ships several predefined objects named 'default' → add-security-zone fails
            # validation ("More than one object named 'default' exists") and the set- fallback
            # 404s (none of them is a security-zone). The name is unusable on CP - and it is
            # also Gateshift's inferred no-zone placeholder - so skip it with a warn.
            dropped.append(DroppedField(
                rule_id=raw_name, field="zone",
                reason="'default' collides with multiple CP predefined objects - "
                       "zone not pushed"))
            continue
        seen.add(name)
        comments = (z.get("properties") or {}).get("description") \
            or z.get("description") or ""
        payload: dict[str, Any] = {
            "name": name, "ignore-warnings": True,
        }
        if comments:
            payload["comments"] = comments
        out.append({"command": "add-security-zone", "payload": payload})
    return out


# ── Network strand: interface + static-route rendering ────────────
#
# Unlike object/rule sections (which serialize to {command, payload} dicts
# consumed by _call_idempotent), Interfaces and Static Routes go through
# Gaia REST - push() dispatches by iface_type to a typed helper. The
# section payload here is the parameter pack each helper expects, plus
# a leading ``type`` discriminator for routing.

def _render_interfaces(
    interfaces: list[dict],
    dropped: list[DroppedField],
) -> list[dict]:
    """Emit Gaia-push dispatch records for physical / vlan / loopback / bond IFs.

    Tunnels, bridges and unclassified rows stay V1.5+ territory - DroppedField
    is appended so the pre-push dialog surfaces them. VLAN rows missing parent
    or vlan_tag are dropped (validation also blocks these earlier; defensive
    here). Bond records carry their member list; the bond push helper detaches
    members from physical config as part of add-bond-interface.
    """
    out: list[dict] = []
    import json as _j
    for iface in interfaces:
        name = (iface.get("interface_name") or "").strip()
        if not name:
            continue
        itype = (iface.get("iface_type") or "").lower()
        ips = iface.get("ip_addresses") or []
        comment = iface.get("description") or ""

        if itype in ("tunnel", "bridge"):
            dropped.append(DroppedField(
                rule_id=name, field="interface",
                reason=f"iface_type={itype!r} not in CP-Network-Push V1 scope",
                fallback="skipped - configure manually on gateway",
            ))
            continue
        if itype not in ("physical", "vlan", "loopback", "bond"):
            dropped.append(DroppedField(
                rule_id=name, field="interface",
                reason=f"iface_type={itype!r} unrecognized",
                fallback="skipped",
            ))
            continue

        ipv4 = ""
        mask_len: int | None = None
        for cidr in ips:
            if not cidr or "/" not in cidr:
                continue
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if isinstance(net, ipaddress.IPv4Network):
                ipv4 = str(net.network_address) if net.prefixlen == 32 \
                    else cidr.split("/", 1)[0]
                mask_len = net.prefixlen
                break

        dhcp_on = bool(iface.get("dhcp_enabled"))
        # DHCP-client only meaningful on physical IFs at the Gaia tier.
        # VLAN sub-IFs, loopbacks, and bonds carrying a DHCP flag get the
        # flag dropped with a hint; static-IP path applies as if dhcp was
        # off.
        if dhcp_on and itype != "physical":
            dropped.append(DroppedField(
                rule_id=name, field="dhcp_enabled",
                reason=(f"DHCP-client on iface_type={itype!r} not in "
                        "CP-Network-Push V1 scope"),
                fallback="dropped - static-IP / no-IP path used instead",
            ))
            dhcp_on = False

        record: dict[str, Any] = {
            "type": itype,
            "name": name,
            "ipv4": ipv4,
            "mask_len": mask_len,
            "comment": comment,
            "dhcp_enabled": dhcp_on,
            "enabled": bool(iface.get("enabled", True)),
        }
        if itype == "vlan":
            parent = (iface.get("parent_iface_name") or "").strip()
            tag = iface.get("vlan_tag")
            if not parent or tag in (None, ""):
                dropped.append(DroppedField(
                    rule_id=name, field="vlan_tag/parent_iface_name",
                    reason="VLAN missing parent or tag",
                    fallback="skipped",
                ))
                continue
            record["parent"] = parent
            record["vlan_tag"] = int(tag)
        elif itype == "bond":
            members = iface.get("member_iface_names") or []
            if isinstance(members, str):
                try:
                    members = _j.loads(members)
                except Exception:
                    members = []
            cleaned = [str(m) for m in (members or []) if m]
            if not cleaned:
                dropped.append(DroppedField(
                    rule_id=name, field="member_iface_names",
                    reason="bond has no members - Gaia rejects add-bond-interface without members",
                    fallback="skipped - add members in Network > Interfaces",
                ))
                continue
            record["members"] = cleaned
        out.append(record)
    return out


def _render_static_routes(
    routes: list[dict],
    dropped: list[DroppedField],
) -> list[dict]:
    """Emit Gaia-push dispatch records for static routes.

    Connected routes (auto-derived from IF IPs) and routes without an
    explicit next_hop are skipped - Gaia derives connecteds itself, and
    blackhole/reject/dynamic are out of V1 scope. ``vr_name`` is ignored
    (CP single-table; VRF on CP is VSX, V2 territory).

    Default routes (0.0.0.0/0, ::/0) are intentionally NOT pushed: the
    wipe phase preserves the existing default route to keep mgmt-API
    reachability across the push, so re-adding it would either conflict
    or disconnect the gateway. Default-route management stays manual on
    Gaia (clish ``set static-route default …``); Gateshift leaves it alone.
    """
    out: list[dict] = []
    for rt in routes:
        prefix = (rt.get("prefix") or "").strip()
        plen = rt.get("prefix_len")
        nh = (rt.get("next_hop") or "").strip()
        is_bh = (rt.get("route_type") or "static") == "blackhole"
        if rt.get("is_connected") or not prefix:
            continue
        # Blackhole routes don't need a next-hop - Gaia's `set static-route
        # <prefix> blackhole on` discards the traffic in the routing engine.
        if not is_bh and not nh:
            continue
        if "/" not in prefix and plen not in (None, ""):
            prefix = f"{prefix}/{int(plen)}"
        if prefix in ("0.0.0.0/0", "::/0"):
            dropped.append(DroppedField(
                rule_id=prefix, field="static_route",
                reason="default route preserved on gateway, not pushed",
                fallback="manage via clish on gateway directly",
            ))
            continue
        try:
            ipaddress.ip_network(prefix, strict=False)
        except (ValueError, TypeError):
            dropped.append(DroppedField(
                rule_id=prefix or "<unknown>", field="prefix",
                reason="invalid CIDR",
                fallback="skipped",
            ))
            continue
        rec: dict = {"prefix": prefix, "next_hop": nh, "comment": ""}
        if is_bh:
            rec["blackhole"] = True
            rec["next_hop"] = ""
        # Gaia static routes have no admin-distance/metric field (next-hop
        # priority is a 1-8 gateway-selection rank, not a metric), so a source
        # metric can't be migrated - drop it with a warn rather than forcing it
        # onto priority (which Gaia rejects).
        if rt.get("metric") is not None and not is_bh:
            dropped.append(DroppedField(
                rule_id=prefix, field="metric",
                reason="Gaia static routes have no admin-distance/metric",
                fallback="route installed at Gaia's default distance",
            ))
        out.append(rec)
    return out


def _rewrite_members_cp(
    members: list[str], addr_lookup: dict[str, str]
) -> list[str]:
    """Resolve raw IP literals to object names + apply _safe_name + dedup.

    CP's addr_lookup values are already _safe_name'd (see _build_addr_lookup),
    so calling _safe_name on the resolved string is idempotent for hits and
    catches raw object-names that fell through unchanged.
    """
    seen: set[str] = set()
    out: list[str] = []
    for m in members:
        if not m:
            continue
        safe = _safe_name(addr_lookup.get(m, m))
        if not safe or safe in seen:
            continue
        seen.add(safe)
        out.append(safe)
    return out


def _render_address_groups(
    groups: list[dict],
    dropped: list[DroppedField],
    addr_lookup: dict[str, str],
    emitted: set[str] | None = None,
) -> list[dict]:
    """Convert agnostic address groups → CP add-group commands.

    Dynamic / filter-based groups are dropped (CP's dynamic-objects model
    is filter-by-network-feed, not the same concept).

    ``emitted``: when given, the set of valid member names (addresses actually
    rendered + builtin Any + all address-group names). Members outside it
    point at a dropped object (e.g. FQDN - CP has none) → pruned to avoid a
    dangling reference; a group emptied this way is skipped (BUG-024).
    """
    out: list[dict] = []
    for grp in groups:
        raw_name = grp.get("name") or ""
        name = _safe_name(raw_name)
        if not name:
            continue
        val = grp.get("value") or {}
        gtype = (val.get("type") or "static").lower()
        comments = val.get("description") or ""

        if gtype == "static":
            members = _rewrite_members_cp(val.get("members") or [], addr_lookup)
            if emitted is not None:
                kept = [m for m in members if m in emitted]
                if len(kept) != len(members):
                    dropped.append(DroppedField(
                        rule_id=raw_name, field="member",
                        reason="pruned member(s) not among pushed objects "
                               "(dropped/FQDN - would dangle)",
                    ))
                members = kept
            if not members:
                dropped.append(DroppedField(
                    rule_id=raw_name, field="members",
                    reason="all members unresolved - group skipped",
                ))
                continue
            payload: dict[str, Any] = {
                "name": name,
                "members": members,
                "ignore-warnings": True,
            }
            if comments:
                payload["comments"] = comments
            out.append({"command": "add-group", "payload": payload})
        elif gtype == "dynamic":
            dropped.append(DroppedField(
                rule_id=raw_name, field="dynamic_filter",
                reason="dynamic / filter-based address-groups are not modeled "
                       "the same way on Check Point - group dropped",
            ))
        else:
            dropped.append(DroppedField(
                rule_id=raw_name, field="type",
                reason=f"unknown address-group type {gtype!r}",
            ))
    return _toposort_cp_groups(out)


def _toposort_cp_groups(cmds: list[dict]) -> list[dict]:
    """Order add-*-group commands member-first (invariant I2, shared impl).
    CP answers a forward reference with HTTP 404 'Requested object not found'."""
    return _integ.toposort_by_members(
        cmds,
        name_of=lambda c: (c.get("payload") or {}).get("name"),
        members_of=lambda c: (c.get("payload") or {}).get("members") or [],
    )


# ── IPSec VPN as Communities (CP-VPN plan CP-2) ──────────────────────────
# CP models VPN as a community (crypto is COMMUNITY-level, single-valued slots)
# + interoperable-devices (peers) + encryption-domains (network groups). Meshed-
# per-tunnel V1. Payloads + push order (gw-vpn-enable BEFORE community) are
# live-verified on gw1. PSK is a placeholder; the secret is never migrated.
_VPN_PSK_PLACEHOLDER = "GATESHIFT-PLACEHOLDER-PSK-CHANGE-ME"
_CANON_TO_CP_ENC = {
    "des": "des", "3des": "3des",
    "aes-128-cbc": "aes-128", "aes-192-cbc": "aes-192", "aes-256-cbc": "aes-256",
    "aes-128-gcm": "aes-gcm-128", "aes-256-gcm": "aes-gcm-256",
}
_CANON_TO_CP_HASH = {
    "md5": "md5", "sha1": "sha1", "sha256": "sha256",
    "sha384": "sha384", "sha512": "sha512", "aes-xcbc": "aes-xcbc",
}
_CANON_TO_CP_DH = {
    "group1": "group-1", "group2": "group-2", "group5": "group-5",
    "group14": "group-14", "group15": "group-15", "group16": "group-16",
    "group19": "group-19", "group20": "group-20", "group24": "group-24",
}


# ── CP-as-source (VR-4): CP→canonical reverse crypto maps ────────────
# Invert the forward maps; a CP token with no exact inverse passes through.
_CP_TO_CANON_ENC = {v: k for k, v in _CANON_TO_CP_ENC.items()}
_CP_TO_CANON_HASH = {v: k for k, v in _CANON_TO_CP_HASH.items()}
_CP_TO_CANON_DH = {v: k for k, v in _CANON_TO_CP_DH.items()}


def _cp_enc_method_to_ikever(em: str | None) -> str:
    """CP encryption-method enum → agnostic ike_version."""
    em = (em or "").lower()
    if em.startswith("ikev1"):
        return "ikev1"
    if "prefer ikev2" in em:
        return "ikev2-preferred"
    return "ikev2"


def flatten_cp_vpn(this_uid: str, this_name: str, this_domain_cidrs: list[str],
                   meshed: list[dict], star: list[dict], resolve,
                   this_domain_name: str | None = None) -> tuple[list[dict], list[dict]]:
    """Flatten CP communities → agnostic vpn_tunnels + synthesized crypto objects,
    from the perspective of THIS gateway (this_uid). `meshed`/`star` are full
    community dicts; `resolve(uid)` → {name, ipv4, domain_cidrs} | None for a peer
    member. Each gw↔peer pair becomes one tunnel; the community's single crypto is
    synthesized into named ike/ipsec_crypto_profile objects (CP→canonical reverse).
    The PSK is NEVER read (use-shared-secret → auth_type only). Mirrors the Forti
    collector's synth-crypto pattern. Returns (tunnels, crypto_objects)."""
    tunnels: list[dict] = []
    cryptos: list[dict] = []
    seen_crypto: set[str] = set()
    seen_tunnel: set[str] = set()
    gw_seen: dict[str, tuple] = {}   # gateway_name → (peer_ip, ike_profile)

    def _muid(m):
        return (m.get("uid") if isinstance(m, dict) else m)

    def _rev(mapping, tok):
        return mapping.get(tok, tok) if tok else None

    def _synth_crypto(comm: dict) -> tuple[str, str]:
        cname = _safe_name(comm.get("name") or "cp-comm")
        ike_name, ips_name = f"{cname}-ike", f"{cname}-ipsec"
        if ike_name in seen_crypto:
            return ike_name, ips_name
        seen_crypto.add(ike_name)
        p1 = comm.get("ike-phase-1") or {}
        p2 = comm.get("ike-phase-2") or {}
        ike_val = {
            "encryption": [x for x in [_rev(_CP_TO_CANON_ENC, p1.get("encryption-algorithm"))] if x],
            "hash":       [x for x in [_rev(_CP_TO_CANON_HASH, p1.get("data-integrity"))] if x],
            "dh_group":   [x for x in [_rev(_CP_TO_CANON_DH, p1.get("diffie-hellman-group"))] if x],
        }
        ips_val: dict = {
            "protocol": "esp",
            "encryption": [x for x in [_rev(_CP_TO_CANON_ENC, p2.get("encryption-algorithm"))] if x],
            "auth":       [x for x in [_rev(_CP_TO_CANON_HASH, p2.get("data-integrity"))] if x],
        }
        if p2.get("ike-p2-use-pfs") and p2.get("ike-p2-pfs-dh-grp"):
            g = _rev(_CP_TO_CANON_DH, p2.get("ike-p2-pfs-dh-grp"))
            if g:
                ips_val["pfs_group"] = [g]
        cryptos.append({"obj_type": "ike_crypto_profile", "name": ike_name, "value": ike_val})
        cryptos.append({"obj_type": "ipsec_crypto_profile", "name": ips_name, "value": ips_val})
        return ike_name, ips_name

    def _add_tunnel(comm: dict, peer: dict):
        tname = _safe_name(f"{_safe_name(comm.get('name') or 'cp')}-{_safe_name(peer.get('name') or 'peer')}")
        if tname in seen_tunnel:
            return
        seen_tunnel.add(tname)
        ike_name, ips_name = _synth_crypto(comm)
        sels = [{"local": loc, "remote": rem}
                for loc in (this_domain_cidrs or [])
                for rem in (peer.get("domain_cidrs") or [])]
        # NAMED enc-domain objects (this gw + the peer) → follow-up 1: an object used ONLY
        # by a VPN enc-domain counts as USED (refmodel reads fw_vpn_tunnels.domain_objects).
        dobj = [n for n in (this_domain_name, peer.get("domain_name")) if n]
        # gateway_name = the source-side IKE-GATEWAY analog (schema: "source
        # IKE-gateway name"). CP has no ike-gateway object; the interoperable
        # device (peer) is the closest equivalent and unique per peer. Using
        # THIS gateway's name here made every tunnel render the SAME PA
        # ike-gateway named after the local cluster - with 2+ tunnels the PA
        # push died with "'<cluster>' is already in use". If one peer shows
        # up again with different crypto (two communities), fall back to the
        # unique tunnel name (capped at 31 - PAN-OS ike-gateway name limit).
        gwn = _safe_name(peer.get("name") or "") or None
        if gwn:
            prev = gw_seen.get(gwn)
            if prev is not None and prev != (peer.get("ipv4"), ike_name):
                gwn = tname[:31]
            else:
                gw_seen[gwn] = (peer.get("ipv4"), ike_name)
        tunnels.append({
            "position": len(tunnels) + 1,
            "name": tname,
            "gateway_name": gwn,
            "peer_address": peer.get("ipv4") or "",
            "peer_type": "ip",
            "ike_version": _cp_enc_method_to_ikever(comm.get("encryption-method")),
            "auth_type": "psk" if comm.get("use-shared-secret") else "cert",
            "ike_crypto_profile": ike_name,
            "ipsec_crypto_profile": ips_name,
            "traffic_selectors": sels or None,
            "domain_objects": dobj or None,
            "raw_extras": {"cp_community": comm.get("name"),
                           "cp_topology": comm.get("_topology")},
        })

    for comm in (meshed or []):
        uids = [_muid(m) for m in (comm.get("gateways") or [])]
        if this_uid not in uids:
            continue
        for puid in uids:
            if puid and puid != this_uid:
                peer = resolve(puid)
                if peer:
                    _add_tunnel(comm, peer)
    for comm in (star or []):
        centers = [_muid(m) for m in (comm.get("center-gateways") or [])]
        sats = [_muid(m) for m in (comm.get("satellite-gateways") or [])]
        peers = sats if this_uid in centers else (centers if this_uid in sats else [])
        for puid in peers:
            if puid:
                peer = resolve(puid)
                if peer:
                    _add_tunnel(comm, peer)
    return tunnels, cryptos


def _cp_pick(vals, mapping, default, dropped, rid, field):
    """CP crypto slots are SINGLE-valued - take the first canonical token (mapped),
    drop-warn the rest (our model carries lists; PA/Forti propose several)."""
    vals = [v for v in (vals or []) if v]
    if not vals:
        return default
    chosen = mapping.get(vals[0], vals[0])
    if len(vals) > 1:
        dropped.append(DroppedField(
            rule_id=rid, field=field,
            reason=f"CP community is single-valued; kept {chosen!r}, dropped {vals[1:]}"))
    return chosen


def _cp_lifetime(lt: dict | None, want: str) -> int | None:
    """Agnostic {unit,value} → CP rekey (phase-1 in MINUTES, phase-2 in SECONDS)."""
    if not lt:
        return None
    try:
        v = int(lt.get("value"))
    except (TypeError, ValueError):
        return None
    secs = {"seconds": 1, "minutes": 60, "hours": 3600, "days": 86400}.get(lt.get("unit"), 1) * v
    return secs if want == "seconds" else max(1, secs // 60)


def _cp_phase1(ike: dict, dropped, rid: str) -> dict:
    p = {
        "encryption-algorithm": _cp_pick(ike.get("encryption"), _CANON_TO_CP_ENC, "aes-256", dropped, rid, "ike-encryption"),
        "diffie-hellman-group": _cp_pick(ike.get("dh_group"), _CANON_TO_CP_DH, "group-2", dropped, rid, "ike-dh-group"),
        "data-integrity": _cp_pick(ike.get("hash"), _CANON_TO_CP_HASH, "sha256", dropped, rid, "ike-integrity"),
    }
    rk = _cp_lifetime(ike.get("lifetime"), "minutes")
    if rk:
        p["ike-p1-rekey-time"] = rk
    return p


def _cp_phase2(ipsec: dict, dropped, rid: str) -> dict:
    p = {
        "encryption-algorithm": _cp_pick(ipsec.get("encryption"), _CANON_TO_CP_ENC, "aes-256", dropped, rid, "ipsec-encryption"),
        "data-integrity": _cp_pick(ipsec.get("auth"), _CANON_TO_CP_HASH, "sha256", dropped, rid, "ipsec-integrity"),
    }
    pfs = ipsec.get("pfs_group") or []
    if pfs:
        p["ike-p2-use-pfs"] = True
        p["ike-p2-pfs-dh-grp"] = _cp_pick(pfs, _CANON_TO_CP_DH, "group-2", dropped, rid, "pfs-group")
    rk = _cp_lifetime(ipsec.get("lifetime"), "seconds")
    if rk:
        p["ike-p2-rekey-time"] = rk
    return p


def _derive_vpn_domains(tunnel: dict, active_routes: list[dict],
                        interfaces: list[dict]) -> tuple[list[str], list[str]]:
    """(local_cidrs, remote_cidrs) for the tunnel's encryption domains. Explicit
    traffic_selectors win; else route-based - remote = active routes whose egress
    is the tunnel iface (excl. the tunnel's own connected transport), local =
    connected subnets of the internal interfaces (external = the tunnel egress +
    default-route iface)."""
    sels = tunnel.get("traffic_selectors") or []
    tun_if = tunnel.get("tunnel_interface")
    local_if = tunnel.get("local_interface")
    local: list[str] = []
    remote: list[str] = []
    if sels:
        for s in sels:
            r, l = (s.get("remote") or "").strip(), (s.get("local") or "").strip()
            if r and r != "0.0.0.0/0":
                remote.append(r)
            if l and l != "0.0.0.0/0":
                local.append(l)
    else:
        for rt in active_routes or []:
            if rt.get("interface_name") == tun_if and (rt.get("route_type") or "") != "connected":
                remote.append(f"{rt.get('prefix')}/{rt.get('prefix_len')}")
        ext = {local_if, tun_if}
        for rt in active_routes or []:
            if str(rt.get("prefix")) == "0.0.0.0" and int(rt.get("prefix_len") or 0) == 0 and rt.get("interface_name"):
                ext.add(rt["interface_name"])
        for i in interfaces or []:
            iname = i.get("interface_name")
            if iname in ext or (i.get("iface_type") or "").lower() == "tunnel":
                continue
            ips = i.get("ip_addresses")
            if isinstance(ips, str):
                try:
                    ips = json.loads(ips)
                except Exception:
                    ips = []
            for ip in (ips or []):
                parsed = _split_cidr(ip)
                if parsed and parsed[1] != 0:
                    local.append(f"{parsed[0]}/{parsed[1]}")
    return list(dict.fromkeys(local)), list(dict.fromkeys(remote))


def _render_vpn(vpn_tunnels: list[dict], ike_by_name: dict, ipsec_by_name: dict,
                active_routes: list[dict], interfaces: list[dict],
                gw_name: str, dropped: list[DroppedField],
                domain_mode: str = "manual",
                topology: str = "meshed",
                is_cluster: bool = False) -> dict[str, list[dict]]:
    """Agnostic vpn tunnels → CP command sections. Networks + domain groups +
    interoperable-devices + the gateway VPN-enable + communities. Crypto is
    inlined into each community (CP has no crypto objects). Topology:
    'meshed' (default, always-correct) = one meshed community per tunnel;
    'star' = one star community per crypto-group (center=local gw, satellites=
    the peers sharing that exact crypto/ike-version/auth - CP communities are
    single-crypto + community-wide, so tunnels can only share when identical).
    Returns {} when there's nothing to render."""
    tuns = [v for v in (vpn_tunnels or []) if not v.get("deleted")]
    if not tuns:
        return {}
    if not gw_name:
        dropped.append(DroppedField(rule_id="vpn", field="gateway",
            reason="no target CP gateway name - VPN not rendered"))
        return {}

    nets: list[dict] = []
    groups: list[dict] = []
    peers: list[dict] = []
    communities: list[dict] = []
    records: list[dict] = []        # per-tunnel crypto+peer, grouped into communities below
    emitted_nets: set[str] = set()
    local_members: list[str] = []   # union → the gateway's one VPN domain

    def _net_obj(cidr: str) -> str | None:
        parsed = _split_cidr(cidr)
        if not parsed:
            return None
        ip, plen = parsed
        nm = _safe_name(f"vpn-net-{ip}-{plen}")
        if nm in emitted_nets:
            return nm
        emitted_nets.add(nm)
        if plen == 32:
            nets.append({"command": "add-host", "payload": {
                "name": nm, "ip-address": ip, "ignore-warnings": True, "set-if-exists": True}})
        else:
            nets.append({"command": "add-network", "payload": {
                "name": nm, "subnet4": ip, "mask-length4": plen,
                "ignore-warnings": True, "set-if-exists": True}})
        return nm

    for v in tuns:
        name = _safe_name(v.get("name") or "")
        if not name:
            continue
        peer_ip = (v.get("peer_address") or "").strip()
        if not peer_ip or (v.get("peer_type") or "ip") != "ip":
            dropped.append(DroppedField(rule_id=name, field="peer_address",
                reason="CP interoperable-device needs a static peer IP (dynamic/ddns peer skipped)"))
            continue
        local_cidrs, remote_cidrs = _derive_vpn_domains(v, active_routes, interfaces)

        peer_members = [m for m in (_net_obj(c) for c in remote_cidrs) if m]
        iod = f"{name}-peer"
        iod_payload: dict[str, Any] = {"name": iod, "ipv4-address": peer_ip, "ignore-warnings": True}
        if peer_members:
            peer_grp = f"{name}-peer-dom"
            groups.append({"command": "add-group", "payload": {
                "name": peer_grp, "members": peer_members, "ignore-warnings": True}})
            iod_payload["vpn-settings"] = {"vpn-domain": peer_grp, "vpn-domain-type": "manual"}
        else:
            dropped.append(DroppedField(rule_id=name, field="peer_domain",
                reason="no peer encryption domain derivable (route-based, no tunnel routes / selectors) - set it on the target"))
        peers.append({"command": "add-interoperable-device", "payload": iod_payload})

        if domain_mode != "topology":   # manual: collect the local subnets
            for c in local_cidrs:
                m = _net_obj(c)
                if m and m not in local_members:
                    local_members.append(m)

        ike = ike_by_name.get(v.get("ike_crypto_profile") or "") or {}
        ipsec = ipsec_by_name.get(v.get("ipsec_crypto_profile") or "") or {}
        # CP encryption-method has no pure 'ikev1 only'; for an IKEv1 v4 tunnel
        # 'ikev1 for ipv4 …' uses ikev1 on our v4 traffic (live-verified enum).
        _ikev = v.get("ike_version")
        _enc_method = ("ikev1 for ipv4 and ikev2 for ipv6 only" if _ikev == "ikev1"
                       else "prefer ikev2 but support ikev1" if _ikev == "ikev2-preferred"
                       else "ikev2 only")
        rec: dict[str, Any] = {
            "name": name, "iod": iod, "enc_method": _enc_method,
            "phase1": _cp_phase1(ike, dropped, name),
            "phase2": _cp_phase2(ipsec, dropped, name),
            "psk_token": None,
        }
        if (v.get("auth_type") or "psk") == "psk":
            # Per-tunnel token (vpn_hash, no secret) → injected server-side at
            # push if a PSK was set in Gateshift, else resolves to the placeholder.
            _vh = v.get("vpn_hash")
            rec["psk_token"] = f"__GATESHIFT_PSK_{_vh}__" if _vh else _VPN_PSK_PLACEHOLDER
            dropped.append(DroppedField(rule_id=name, field="shared_secret",
                reason="PSK: a placeholder is pushed unless one is set in Gateshift "
                       "(then injected, encrypted, at push-time) - source secrets "
                       "are never migrated"))
        else:
            # CP gateways get their VPN identity cert from the management ICA
            # (there is no mgmt-API command to import an external cert+key - it's
            # done on the gateway via SmartConsole/cpca), so cert-auth can't be
            # provisioned the way PA/Forti are. Deferred: PSK is the CP path for
            # now; the operator configures cert-auth + peer-CA trust on the GW.
            dropped.append(DroppedField(rule_id=name, field="certificate",
                reason="cert-auth not migrated for CheckPoint - the gateway's VPN "
                       "cert is ICA-managed (configure cert-auth + trusted CA on "
                       "the gateway directly); use PSK to migrate via Gateshift"))
        records.append(rec)

    # Build communities from the per-tunnel records. Meshed = one community per
    # tunnel (gw + peer). Star = one community per crypto-group (center = the
    # local gw, satellites = every peer sharing that exact crypto/version/auth,
    # since a CP community is single-crypto + community-wide).
    def _shared_secrets(recs: list[dict]) -> list[dict] | None:
        ss = [{"external-gateway": r["iod"], "shared-secret": r["psk_token"]}
              for r in recs if r["psk_token"]]
        return ss or None

    if topology == "star":
        by_sig: dict[str, list[dict]] = {}
        for r in records:
            sig = json.dumps([r["enc_method"], r["phase1"], r["phase2"],
                              bool(r["psk_token"])], sort_keys=True)
            by_sig.setdefault(sig, []).append(r)
        for sig, recs in by_sig.items():
            r0 = recs[0]
            cname = "Gateshift-star-" + hashlib.md5(sig.encode()).hexdigest()[:8]
            comm: dict[str, Any] = {
                "name": cname,
                "center-gateways": [gw_name],
                "satellite-gateways": [r["iod"] for r in recs],
                "encryption-method": r0["enc_method"], "encryption-suite": "custom",
                "ike-phase-1": r0["phase1"], "ike-phase-2": r0["phase2"],
                "ignore-warnings": True,
            }
            ss = _shared_secrets(recs)
            if ss:
                comm["use-shared-secret"] = True
                comm["shared-secrets"] = ss
            communities.append({"command": "add-vpn-community-star", "payload": comm})
    else:
        for r in records:
            comm = {
                "name": f"{r['name']}-comm",
                "gateways": [gw_name, r["iod"]],
                "encryption-method": r["enc_method"], "encryption-suite": "custom",
                "ike-phase-1": r["phase1"], "ike-phase-2": r["phase2"],
                "ignore-warnings": True,
            }
            if r["psk_token"]:
                comm["use-shared-secret"] = True
                comm["shared-secrets"] = [{"external-gateway": r["iod"],
                                           "shared-secret": r["psk_token"]}]
            communities.append({"command": "add-vpn-community-meshed", "payload": comm})

    # The local gateway: enable VPN + its one encryption domain. 'topology' lets
    # CP compute it from the gateway's interface topology (connected-only); the
    # default 'manual' uses the derived internal-subnet group (also picks up
    # routed-internal nets). Peer domains are always manual groups.
    gw_payload: dict[str, Any] = {"name": gw_name, "vpn": True, "ignore-warnings": True}
    if domain_mode == "topology":
        gw_payload["vpn-settings"] = {"vpn-domain-type": "addresses_behind_gw"}
    elif local_members:
        local_grp = "Gateshift-vpn-local-domain"
        groups.append({"command": "add-group", "payload": {
            "name": local_grp, "members": local_members, "ignore-warnings": True}})
        gw_payload["vpn-settings"] = {"vpn-domain": local_grp, "vpn-domain-type": "manual"}
    # cluster objects reject set-simple-gateway (HTTP 400 incompatible UID)
    gw_cmds = [{"command": ("set-simple-cluster" if is_cluster
                            else "set-simple-gateway"), "payload": gw_payload}]

    return {
        "VPN Networks": nets,
        "VPN Groups": groups,
        "VPN Peers": peers,
        "VPN Gateway": gw_cmds,
        "VPN Communities": communities,
    }


# ═════════════════════════════════════════════════════════════════
#  Mgmt-API gateway topology helpers
# ═════════════════════════════════════════════════════════════════
#  Used by the gateway-as-device path (config.cp.gateway_uid set):
#  fetch the gateway's full topology object once, then derive zones
#  and connected routes from interface-level topology-settings without
#  needing a Gaia round-trip. Defined-by-routing interfaces still need
#  Gaia for static routes - the caller decides whether to fall back.

def _fetch_gateway_topology(base_url: str, sid: str,
                             gateway_uid: str, gateway_type: str) -> dict:
    """Fetch the full gateway/cluster object including interfaces[].

    The pinned ``gateway_uid`` can go STALE - re-creating the gateway on a
    fresh management server gives it a new uid, so show-simple-gateway 404s on
    the old one. On a not-found (or when no uid is pinned) we fall back to
    discovering the single gateway via show-simple-gateways and fetch it by
    name - the same 'one gateway per management' model resolve_gateway_name
    uses. Raises a clear error only when the management has zero or several
    gateways (genuinely ambiguous → re-pin via the Add-CP wizard)."""
    is_cluster = "cluster" in (gateway_type or "").lower()
    show_cmd  = "show-simple-cluster"  if is_cluster else "show-simple-gateway"
    list_cmd  = "show-simple-clusters" if is_cluster else "show-simple-gateways"
    if gateway_uid:
        try:
            return _call(base_url, sid, show_cmd,
                         {"uid": gateway_uid, "details-level": "full"})
        except Exception:
            pass  # stale / wrong-type uid → discover the gateway fresh
    resp  = _call(base_url, sid, list_cmd, {"limit": 50})
    names = [o.get("name") for o in (resp.get("objects") or []) if o.get("name")]
    if len(names) == 1:
        return _call(base_url, sid, show_cmd,
                     {"name": names[0], "details-level": "full"})
    raise RuntimeError(
        (f"pinned gateway not found and {len(names)} gateways exist on the "
         "management - can't auto-pick; re-add the device via the Add-CP "
         "wizard to pin the right one")
        if names else "no simple-gateway found on the management")


# Sub-blades that, when ON, make a gateway a TP-rule target. If none of
# these are set, adding TP-rules still succeeds on the Mgmt-Server but
# the gateway never inspects against them - surface a refusal up front.
_TP_BLADE_FLAGS = (
    "ips", "anti-bot", "anti-virus",
    "threat-emulation", "threat-extraction",
)


def _check_tp_blade(
    base_url: str, sid: str, device: dict,
) -> tuple[bool | None, str]:
    """Is at least one Threat-Prevention sub-blade enabled on the GW?

    Returns ``(True, detail)`` when verified on, ``(False, detail)`` when
    verifiably off, ``(None, detail)`` when we can't tell (no gateway_uid
    in config, or the show-* call failed - fail open in that case).
    """
    try:
        cfg = json.loads(device.get("config") or "{}")
    except Exception:
        cfg = {}
    cp_cfg = cfg.get("cp") or {}
    gw_uid = cp_cfg.get("gateway_uid")
    gw_type = cp_cfg.get("gateway_type") or ""
    if not gw_uid:
        return None, "no gateway_uid in config.cp - skipping blade check"
    try:
        gw = _fetch_gateway_topology(base_url, sid, gw_uid, gw_type)
    except Exception as e:
        return None, f"show-gateway failed: {e} - proceeding anyway"
    enabled = [b for b in _TP_BLADE_FLAGS if gw.get(b) is True]
    if enabled:
        return True, f"TP-blade(s) on: {', '.join(enabled)}"
    return False, (
        f"no Threat-Prevention sub-blade enabled on gateway "
        f"{gw.get('name') or gw_uid!r} (looked for "
        f"{', '.join(_TP_BLADE_FLAGS)}) - enable at least one blade in "
        "SmartConsole before pushing TP-rules"
    )


def _topology_zone(iface_obj: dict) -> str:
    """Map a CP interface to a Gateshift zone name.

    Preference: explicit security-zone object > topology external/internal
    > 'default'. At details-level=full the security-zone reference is
    inlined as a dict in security-zone-settings.specific-zone.
    """
    szs = iface_obj.get("security-zone-settings") or {}
    if szs.get("auto-calculated") is False:
        zone_obj = szs.get("specific-zone")
        if isinstance(zone_obj, dict) and zone_obj.get("name"):
            return zone_obj["name"]
        if isinstance(zone_obj, str) and zone_obj:
            return zone_obj
    topo = (iface_obj.get("topology") or "").lower()
    if topo == "external":
        return "untrust"
    if topo == "internal":
        return "trust"
    return "default"


def _expand_specific_network(spec: dict, add_route, iface_name: str) -> list[str]:
    """Expand a specific-network object (host/network/address-range/group)
    into route entries via add_route. Returns a list of warnings."""
    warnings: list[str] = []
    obj_type = (spec.get("type") or "").lower()
    name = spec.get("name") or "?"

    if obj_type == "host":
        ip = spec.get("ipv4-address") or spec.get("ipv6-address")
        if ip:
            suffix = "/128" if ":" in ip else "/32"
            try:
                add_route(ipaddress.ip_network(f"{ip}{suffix}", strict=False))
            except ValueError as exc:
                warnings.append(f"{iface_name}: host {name} bad ip: {exc}")
    elif obj_type == "network":
        v4 = spec.get("subnet4"); m4 = spec.get("mask-length4")
        v6 = spec.get("subnet6"); m6 = spec.get("mask-length6")
        try:
            if v4 and m4 is not None:
                add_route(ipaddress.ip_network(f"{v4}/{m4}", strict=False))
            elif v6 and m6 is not None:
                add_route(ipaddress.ip_network(f"{v6}/{m6}", strict=False))
            else:
                warnings.append(f"{iface_name}: network {name} missing subnet/mask")
        except ValueError as exc:
            warnings.append(f"{iface_name}: network {name} bad subnet: {exc}")
    elif obj_type == "address-range":
        first = spec.get("ipv4-address-first") or spec.get("ipv6-address-first")
        last  = spec.get("ipv4-address-last")  or spec.get("ipv6-address-last")
        if first and last:
            try:
                for net in ipaddress.summarize_address_range(
                        ipaddress.ip_address(first), ipaddress.ip_address(last)):
                    add_route(net)
            except (ValueError, TypeError) as exc:
                warnings.append(f"{iface_name}: range {name} {first}-{last} bad: {exc}")
    elif obj_type == "group":
        members = spec.get("members") or []
        for m in members:
            if isinstance(m, dict) and m.get("type"):
                warnings.extend(_expand_specific_network(m, add_route, iface_name))
            elif isinstance(m, str):
                warnings.append(f"{iface_name}: group {name} member is uid {m[:8]}… (not inlined)")
    elif obj_type:
        warnings.append(f"{iface_name}: unsupported specific-network type {obj_type!r}")
    return warnings


def _synthesize_routes_from_topology(iface_obj: dict, gateway_name: str
                                      ) -> tuple[list[dict], list[str]]:
    """Synthesize routes from an interface's topology-settings.

    Returns (routes, warnings). Each route is in collect-writer shape
    (prefix/plen/ip_from/ip_to/iface/next_hop/vr). Warnings are
    user-readable strings about cases needing Gaia (defined-by-routing)
    or unsupported group nesting.
    """
    routes: list[dict] = []
    warnings: list[str] = []
    iface_name = iface_obj.get("name") or ""
    ts = iface_obj.get("topology-settings") or {}
    behind = (ts.get("ip-address-behind-this-interface") or "").lower()

    def _add_route(net) -> None:
        routes.append({
            "prefix":   str(net),
            "plen":     net.prefixlen,
            "ip_from":  int(net.network_address),
            "ip_to":    int(net.broadcast_address),
            "iface":    iface_name,
            "next_hop": None,
            "vr":       "default",
        })

    if behind == "network defined by the interface ip and net mask" or (not behind and ts):
        ip = iface_obj.get("ipv4-address")
        mlen = iface_obj.get("ipv4-mask-length")
        if ip and mlen is not None:
            try:
                _add_route(ipaddress.ip_network(f"{ip}/{mlen}", strict=False))
            except ValueError as exc:
                warnings.append(f"{iface_name}: invalid iface IP {ip}/{mlen}: {exc}")
    elif behind == "specific":
        spec = ts.get("specific-network")
        if isinstance(spec, dict):
            warnings.extend(_expand_specific_network(spec, _add_route, iface_name))
        elif isinstance(spec, str) and spec:
            warnings.append(f"{iface_name}: specific-network is uid {spec[:8]}… (not inlined - re-fetch with full)")
    elif behind == "network defined by routing":
        warnings.append(f"{iface_name}: topology 'defined by routing' - needs Gaia for routes")
    elif behind == "not defined":
        # External/uplink - no connected subnet to derive
        pass
    elif behind:
        warnings.append(f"{iface_name}: unknown ip-address-behind value {behind!r}")

    return routes, warnings


# ── Curated CP Application-Site canonical-map ─────────────────────
#
# CP's Mgmt-API does NOT expose Match-By/Services data for App-Sites
# (SmartConsole shows it but pulls from local APPI-Data files, not REST).
# So we curate a small list of vendor-shipped L7 App-Sites that have a
# clean port-fingerprint, for the port→app auto-binder.
#
# Classical protocols (SSH, RDP, MySQL, SMTP, LDAP, …) are NOT App-Sites
# in CP - they stay Service-Objects. This map is intentionally narrow:
# only L7/Web-class apps where binding adds real value (App-Control +
# URL-Filtering inspection on the layer).
#
# All names verified against cpgw (CP R81+) - these App-Sites ship in
# the APPI-Data domain and exist across CP installations. If a customer
# strips APPI Data (unusual), the renderer skips on missing-app errors.
_CP_APP_CANONICAL_MAP: list[dict] = [
    {"name": "Web Browsing",                  "default_ports": ["tcp/80", "tcp/443"]},
    {"name": "FTP Protocol-upload",           "default_ports": ["tcp/21"]},
    {"name": "FTP Protocol-download",         "default_ports": ["tcp/21"]},
    {"name": "PostgreSQL Protocol",           "default_ports": ["tcp/5432"]},
    {"name": "DCE-RPC Protocol",              "default_ports": ["tcp/135"]},
    {"name": "Multicast DNS Protocol (mDNS)", "default_ports": ["udp/5353"]},
]

# Lowercased set of the App-Site names CP actually recognizes (the curated
# catalog above - the same list the CP enrichment UI / auto-binder bind from).
# The rule renderer filters rule `application` values against this so foreign
# names - PAN-OS App-IDs like ``ms-rdp`` that leak via target-independent,
# rule_hash-keyed overrides, or classical protocols that CP models as
# services - are dropped instead of being pushed as bogus App-Sites (404).
_CP_APP_SITE_NAMES: frozenset[str] = frozenset(
    e["name"].lower() for e in _CP_APP_CANONICAL_MAP
)


# ═════════════════════════════════════════════════════════════════
#  CheckPoint Driver
# ═════════════════════════════════════════════════════════════════

@register_driver
class CheckpointDriver(DeployDriver):
    platform = "checkpoint"
    migration_note = (
        "Network strand (needs Gaia credentials): interface addresses / "
        "cluster VIPs and static routes are pushed via Gaia; dynamic routing "
        "and system config are not. Policy strand: rules, address/service "
        "objects, security zones, NAT."
    )

    def default_settings(self) -> list[dict]:
        return [
            {
                "key": "rule_prefix",
                "label": "Rule Name Prefix",
                "type": "text",
                "default": "Gateshift-",
                "placeholder": "e.g. Gateshift-",
            },
            {
                "key": "policy_package",
                "label": "Policy Package",
                "type": "select_remote",
                "default": "Standard",
                "placeholder": "e.g. Standard",
            },
        ]

    def setting_options(
        self,
        *,
        device: dict,
        key: str,
        settings: dict[str, str],
    ) -> list[str]:
        """Live option lookup against CP Mgmt API.

        Only ``policy_package`` is user-selectable today. The access-control
        layer is auto-derived from the chosen package at push-time
        (``show-package`` returns its access-layers); a single-layer package
        is required (V1 produces L3/L4 only - multi-layer setups belong to
        V2 territory once App-Control / URL-Filtering migration is in scope).
        """
        if key != "policy_package":
            raise NotImplementedError(
                f"CheckpointDriver: no options for {key!r}"
            )
        sid, base_url = _login(device)
        try:
            resp = _call(base_url, sid, "show-packages",
                         {"limit": 200, "details-level": "standard"})
            return [p.get("name", "") for p in resp.get("packages", [])
                    if p.get("name")]
        finally:
            _logout(base_url, sid)

    def resolve_gateway_name(self, device: dict) -> str | None:
        """Discover the CP simple-gateway object name from the management.

        The wizard PINS the gateway on the row (config.cp.gateway_uid +
        gateway_type) - when pinned, resolve the name from that uid with the
        type-correct show command. The single-gateway discovery below is only
        the fallback for legacy rows without a pin: on a management hosting a
        single gateway AND a cluster it would pick the wrong object (QA
        finding - a cluster push attached the VPN to the wrong gateway). Returns the
        name, or None on zero/multiple (ambiguous) gateways or any error, so
        the caller falls back to host_name. Read-only Mgmt-API."""
        try:
            sid, base_url = _login(device)
        except Exception:
            return None
        try:
            cfg = device.get("config") or {}
            if isinstance(cfg, str):
                try:
                    cfg = json.loads(cfg or "{}")
                except Exception:
                    cfg = {}
            cp = cfg.get("cp") or {}
            uid = cp.get("gateway_uid")
            gtype = (cp.get("gateway_type") or "").lower()
            if uid:
                show_cmd = ("show-simple-cluster" if "cluster" in gtype
                            else "show-simple-gateway")
                try:
                    resp = _call(base_url, sid, show_cmd, {"uid": uid})
                    if resp.get("name"):
                        return resp["name"]
                except Exception:
                    pass   # stale uid -> single-gateway discovery below
            resp = _call(base_url, sid, "show-simple-gateways", {"limit": 50})
            names = [o.get("name") for o in (resp.get("objects") or [])
                     if o.get("name")]
            return names[0] if len(names) == 1 else None
        except Exception:
            return None
        finally:
            try:
                _logout(base_url, sid)
            except Exception:
                pass

    def list_url_categories(self, *, device: dict) -> list[str]:
        """The target's application-site CATEGORY catalog
        (show-application-site-categories) - the predefined names a decryption
        rule's site-category can reference. Read-only Mgmt-API, sorted + deduped.
        Feeds the URL-category mapping (project_cp_url_category_map_plan)."""
        sid, base_url = _login(device)
        try:
            resp = _call(base_url, sid, "show-application-site-categories",
                         {"limit": 500})
            return sorted({o.get("name") for o in (resp.get("objects") or [])
                           if o.get("name")})
        finally:
            _logout(base_url, sid)

    # ── Network discover (Gaia REST API) ──────────────────────────
    #
    # The Gaia API lives on the Gateway (not the Mgmt-Server), so the device
    # registered for these calls must be the Gateway with gaia_user /
    # gaia_password populated. _gaia_login raises NotImplementedError when
    # those creds are missing - main.py converts that into 400 supported:false
    # and the UI tab stays empty (same path as list_target_zones).

    def list_target_interfaces(self, *, device: dict) -> list[dict]:
        """Discover the Gateway's interface list.

        Gateway-as-device path (``config.cp.gateway_uid`` set): pulls
        ``show-simple-gateway`` via Mgmt-API and derives the zone from
        topology. No Gaia round-trip needed. Returns
        ``{name, type, ip_addresses, zone, description}`` with zone
        populated from the security-zone object or topology hint.

        Legacy path (no gateway_uid): falls back to Gaia
        ``show-*-interfaces`` and leaves zone=None - same behaviour as
        before the gateway-as-device refactor.
        """
        cfg = json.loads(device.get("config") or "{}")
        gw_uid = ((cfg.get("cp") or {}).get("gateway_uid"))
        if gw_uid:
            return self._list_target_interfaces_via_mgmt(device, cfg)
        sid, base_url = _gaia_login(device)
        try:
            out: list[dict] = []
            seen: set[str] = set()

            # (command, agnostic-type, response-key-candidates)
            # Bond endpoint name varies by Gaia build - try both. The list-only
            # show-bonding-interfaces returns null on newer builds; show-bond-
            # interfaces is the modern name. We list both so whichever one
            # answers wins (the other returns null and is skipped silently).
            categories = [
                ("show-physical-interfaces",  "ethernet", ("objects", "physical-interfaces", "interfaces")),
                ("show-vlan-interfaces",      "vlan",     ("objects", "vlan-interfaces", "interfaces")),
                ("show-bond-interfaces",      "bond",     ("objects", "bond-interfaces", "interfaces")),
                ("show-bonding-interfaces",   "bond",     ("objects", "bonding-interfaces", "interfaces")),
                ("show-loopback-interfaces",  "loopback", ("objects", "loopback-interfaces", "interfaces")),
                ("show-bridge-interfaces",    "bridge",   ("objects", "bridge-interfaces", "interfaces")),
            ]

            for command, itype, keys in categories:
                resp = _gaia_call_optional(base_url, sid, command, {})
                if not resp:
                    continue
                items = None
                for key in keys:
                    if isinstance(resp.get(key), list):
                        items = resp[key]
                        break
                if items is None:
                    # If the response is itself a flat list (rare), use it.
                    if isinstance(resp, list):
                        items = resp
                    else:
                        continue
                for it in items:
                    name = (it.get("name") or "").strip()
                    if not name or name in seen:
                        continue
                    seen.add(name)
                    # Gaia exposes the DHCP-client state as a sub-object
                    # `{"dhcp": {"enabled": true, "server-id": "..."}}`. We
                    # collapse it to a boolean for fw_interfaces; the
                    # vendor-specific bits stay on the gateway.
                    dhcp_state = it.get("dhcp") or {}
                    dhcp_on = bool(dhcp_state.get("enabled"))
                    # Gaia exposes admin-state as `enabled` (boolean) at the
                    # iface level. Missing field = True (Gaia's default for a
                    # configured iface). Mgmt-API path (_list_target_interfaces_via_mgmt)
                    # has no equivalent, so the gap is documented in the plan
                    # - only the Gaia-direct path tracks admin-state in V1.
                    cp_enabled = bool(it.get("enabled", True))
                    row: dict = {
                        "name": name,
                        "type": itype,
                        "ip_addresses": _gaia_iface_ips(it),
                        "zone": None,
                        "description": _gaia_comment(it),
                        "dhcp_enabled": dhcp_on,
                        "enabled": cp_enabled,
                    }
                    # show-bonding-interfaces returns members[]; surface them
                    # so the source-side import + target-discover overlay can
                    # store them on fw_interfaces.member_iface_names. Pre-V1.5
                    # the field is observed-only; push reads it later.
                    if itype == "bond":
                        members = _gaia_bond_members(it)
                        if members:
                            row["members"] = members
                    out.append(row)
            return out
        finally:
            _gaia_logout(base_url, sid)

    def _list_target_interfaces_via_mgmt(self, device: dict, cfg: dict) -> list[dict]:
        """Mgmt-API path: pull interfaces from show-simple-gateway.

        ``show-simple-gateway`` reports IPs and topology (zone), but does NOT
        expose bond membership or distinguish bond/loopback/vlan from physical
        IFs. When Gaia creds are configured we issue ONE extra Gaia call
        (``show-bonding-interfaces``) so the writer can stamp bond rows with
        the correct ``iface_type='bond'`` and member list. Without Gaia creds
        the writer falls back to name-based classification (``ae*`` / ``bondN``
        still detected, members stay NULL).
        """
        cp = cfg.get("cp") or {}
        gw_uid = cp.get("gateway_uid")
        gw_type = cp.get("gateway_type") or "simple-gateway"
        sid, base_url = _login(device)
        try:
            gw = _fetch_gateway_topology(base_url, sid, gw_uid, gw_type)
        finally:
            _logout(base_url, sid)

        bond_map = _fetch_bond_membership_optional(device)
        bond_ips = _fetch_bond_ips_optional(device) if bond_map else {}

        out: list[dict] = []
        seen: set[str] = set()
        _ifs = gw.get("interfaces") or []
        # simple-CLUSTER paginates interfaces ({total, objects:[...]});
        # simple-gateway returns a plain list - normalize (CE FGT->CP find).
        if isinstance(_ifs, dict):
            _ifs = _ifs.get("objects") or []
        for iface in [i for i in _ifs if isinstance(i, dict)]:
            name = (iface.get("name") or "").strip()
            if not name:
                continue
            ips: list[str] = []
            v4 = iface.get("ipv4-address"); m4 = iface.get("ipv4-mask-length")
            if v4 and m4 is not None:
                ips.append(f"{v4}/{m4}")
            v6 = iface.get("ipv6-address"); m6 = iface.get("ipv6-mask-length")
            if v6 and m6 is not None:
                ips.append(f"{v6}/{m6}")
            zone = _topology_zone(iface)
            if zone == "default":
                zone = None
            row: dict = {
                "name": name,
                "type": "bond" if name in bond_map else "ethernet",
                "ip_addresses": ips,
                "zone": zone,
                "description": iface.get("comments") or None,
            }
            if name in bond_map and bond_map[name]:
                row["members"] = bond_map[name]
            out.append(row)
            seen.add(name)

        # Bonds whose parent name doesn't appear in show-simple-gateway
        # (because only VLAN sub-IFs carry layer3 / topology) still need a
        # row so VLAN sub-IFs can resolve their parent and bond-push has a
        # member list to work from.
        for bond_name, members in bond_map.items():
            if bond_name in seen:
                continue
            out.append({
                "name": bond_name,
                "type": "bond",
                "ip_addresses": bond_ips.get(bond_name, []),
                "zone": None,
                "description": None,
                "members": members,
            })
            seen.add(bond_name)

        # show-simple-gateway only carries IFs that are part of the firewall
        # topology (zone-bound). Loopbacks, VLAN sub-IFs without zone binding,
        # and other untyped extras are invisible there. Mirror the source-side
        # behaviour (see _collect_checkpoint_via_mgmt) and append everything
        # Gaia reports that we haven't seen yet. Best-effort; missing creds →
        # skip silently.
        rows_by_name = {r["name"]: r for r in out}
        for extra in _fetch_all_gaia_interfaces_optional(device):
            name = (extra.get("name") or "").strip()
            if not name:
                continue
            if name in seen:
                # Mgmt-API rows carry no Gaia comments - backfill the
                # description from Gaia when the Mgmt side left it empty
                # (Mgmt-provided comments, if any, win).
                row = rows_by_name.get(name)
                if row is not None and not row.get("description"):
                    row["description"] = extra.get("description")
                continue
            out.append({
                "name": name,
                "type": extra.get("type") or "ethernet",
                "ip_addresses": extra.get("ips") or [],
                "zone": None,
                "description": extra.get("description"),
            })
            seen.add(name)
        return out

    def list_target_zones(self, *, device: dict) -> list[dict]:
        """Discover the Gateway's zone-binding via topology.

        Gateway-as-device only: the Mgmt-API exposes per-interface zone
        assignment on ``simple-gateway`` objects. We derive zone-name
        ``→ [interfaces]`` from the same payload we already use for
        ``list_target_interfaces`` so a single fetch covers both kinds.
        Returns ``{name, interfaces, zone_type}`` per zone. Legacy
        (no gateway_uid) path keeps the base-class NotImplementedError -
        Gaia has no zone concept and discover stays empty for those rows.
        """
        cfg = json.loads(device.get("config") or "{}")
        cp = cfg.get("cp") or {}
        gw_uid = cp.get("gateway_uid")
        if not gw_uid:
            return super().list_target_zones(device=device)
        gw_type = cp.get("gateway_type") or "simple-gateway"
        sid, base_url = _login(device)
        try:
            gw = _fetch_gateway_topology(base_url, sid, gw_uid, gw_type)
        finally:
            _logout(base_url, sid)
        zone_map: dict[str, list[str]] = {}
        _ifs = gw.get("interfaces") or []
        # simple-CLUSTER paginates interfaces ({total, objects:[...]});
        # simple-gateway returns a plain list - normalize (CE FGT->CP find).
        if isinstance(_ifs, dict):
            _ifs = _ifs.get("objects") or []
        for iface in [i for i in _ifs if isinstance(i, dict)]:
            name = (iface.get("name") or "").strip()
            if not name:
                continue
            zone = _topology_zone(iface)
            if zone == "default":
                continue
            zone_map.setdefault(zone, []).append(name)
        return [
            {"name": z, "interfaces": ifs, "zone_type": "layer3"}
            for z, ifs in sorted(zone_map.items())
        ]

    def list_target_routes(self, *, device: dict) -> list[dict]:
        """Read static + connected routes from the Gateway.

        Gateway-as-device path (``config.cp.gateway_uid`` set): pulls
        ``show-simple-gateway`` and synthesizes connected routes from
        topology-settings. Falls back to Gaia ``show-static-routes``
        for static routes when Gaia creds are configured AND/OR an
        interface declares 'defined by routing'.

        Legacy path (no gateway_uid): Gaia-only static routes, same
        as before the gateway-as-device refactor.
        """
        cfg = json.loads(device.get("config") or "{}")
        gw_uid = ((cfg.get("cp") or {}).get("gateway_uid"))
        if gw_uid:
            return self._list_target_routes_via_mgmt(device, cfg)
        sid, base_url = _gaia_login(device)
        try:
            out: list[dict] = []
            seen: set[str] = set()
            page = 100
            offset = 0
            for _ in range(200):  # hard cap = 20k routes; far beyond realistic CP
                resp = _gaia_call(base_url, sid, "show-static-routes",
                                  {"limit": page, "offset": offset})
                items = (resp.get("objects") or resp.get("static-routes")
                         or resp.get("routes") or [])
                if not isinstance(items, list) or not items:
                    break
                for rt in items:
                    addr = (rt.get("address") or rt.get("destination")
                            or "").strip()
                    mask = rt.get("mask-length")
                    if mask in (None, ""):
                        mask = rt.get("prefix-length")
                    if not addr or mask in (None, ""):
                        continue
                    try:
                        prefix = f"{addr}/{int(mask)}"
                        ipaddress.ip_network(prefix, strict=False)
                    except (ValueError, TypeError):
                        continue

                    # Skip non-forwarding entries - blackhole/reject have no
                    # next-hop and the agnostic schema can't represent them.
                    rtype = (rt.get("type") or "").lower()
                    if rtype in ("blackhole", "reject"):
                        continue

                    next_hop = _extract_static_next_hop(rt)
                    if not next_hop:
                        # No usable next-hop literal - skip rather than store
                        # NULL, which would later confuse cascade-rename.
                        continue

                    key = (prefix, next_hop)
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append({
                        "prefix": prefix,
                        "interface_name": None,  # CP static routes carry only NH, no egress iface
                        "next_hop": next_hop,
                        "vr_name": "default",
                        "is_connected": False,
                    })
                total = resp.get("total")
                offset += page
                if isinstance(total, int) and offset >= total:
                    break
                if len(items) < page:
                    break
            return out
        finally:
            _gaia_logout(base_url, sid)

    def _list_target_routes_via_mgmt(self, device: dict, cfg: dict) -> list[dict]:
        """Mgmt-API path: synthesize connected routes from topology, then
        optionally extend with Gaia static routes when creds are set."""
        cp = cfg.get("cp") or {}
        gw_uid = cp.get("gateway_uid")
        gw_type = cp.get("gateway_type") or "simple-gateway"
        sid, base_url = _login(device)
        try:
            gw = _fetch_gateway_topology(base_url, sid, gw_uid, gw_type)
        finally:
            _logout(base_url, sid)
        gw_name = gw.get("name") or device.get("host_name") or ""
        out: list[dict] = []
        seen: set[tuple] = set()
        _ifs = gw.get("interfaces") or []
        # simple-CLUSTER paginates interfaces ({total, objects:[...]});
        # simple-gateway returns a plain list - normalize (CE FGT->CP find).
        if isinstance(_ifs, dict):
            _ifs = _ifs.get("objects") or []
        for iface in [i for i in _ifs if isinstance(i, dict)]:
            r, _w = _synthesize_routes_from_topology(iface, gw_name)
            for rt in r:
                key = (rt["prefix"], rt.get("iface"), rt.get("next_hop"))
                if key in seen:
                    continue
                seen.add(key)
                out.append({
                    "prefix":         rt["prefix"],
                    "interface_name": rt.get("iface"),
                    "next_hop":       rt.get("next_hop"),
                    "vr_name":        rt.get("vr") or "default",
                    "is_connected":   True,
                })
        # Extend with Gaia static routes when creds are configured -
        # never raise on missing creds (connected routes alone are useful).
        if device.get("gaia_user") and device.get("gaia_password"):
            try:
                static_routes = self._list_static_routes_via_gaia(device)
            except NotImplementedError:
                static_routes = []
            for rt in static_routes:
                key = (rt["prefix"], rt.get("interface_name"), rt.get("next_hop"))
                if key in seen:
                    continue
                seen.add(key)
                out.append(rt)
        return out

    def _list_static_routes_via_gaia(self, device: dict) -> list[dict]:
        """Pull static routes via Gaia ``show-static-routes`` - used as
        fallback by both the gateway-as-device path and the legacy path."""
        sid, base_url = _gaia_login(device)
        try:
            out: list[dict] = []
            seen: set[tuple] = set()
            page = 100
            offset = 0
            for _ in range(200):
                resp = _gaia_call(base_url, sid, "show-static-routes",
                                  {"limit": page, "offset": offset})
                items = (resp.get("objects") or resp.get("static-routes")
                         or resp.get("routes") or [])
                if not isinstance(items, list) or not items:
                    break
                for rt in items:
                    addr = (rt.get("address") or rt.get("destination")
                            or "").strip()
                    mask = rt.get("mask-length")
                    if mask in (None, ""):
                        mask = rt.get("prefix-length")
                    if not addr or mask in (None, ""):
                        continue
                    try:
                        prefix = f"{addr}/{int(mask)}"
                        ipaddress.ip_network(prefix, strict=False)
                    except (ValueError, TypeError):
                        continue
                    rtype = (rt.get("type") or "").lower()
                    if rtype in ("blackhole", "reject"):
                        continue
                    next_hop = _extract_static_next_hop(rt)
                    if not next_hop:
                        continue
                    key = (prefix, next_hop)
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append({
                        "prefix": prefix,
                        "interface_name": None,
                        "next_hop": next_hop,
                        "vr_name": "default",
                        "is_connected": False,
                    })
                total = resp.get("total")
                offset += page
                if isinstance(total, int) and offset >= total:
                    break
                if len(items) < page:
                    break
            return out
        finally:
            _gaia_logout(base_url, sid)

    def list_target_vrfs(self, *, device: dict) -> list[dict]:
        """Read VSX Virtual Systems via the Mgmt-API ``show-gateways-and-servers``.

        Unlike Interfaces and Routes (which run on the Gateway via Gaia),
        VS topology is owned by the Mgmt-Server - so this method uses the
        Mgmt-API helpers (``_login``/``_call``) and the ``api_key`` field,
        not Gaia. The device registered for this discover run must therefore
        be the Mgmt-Server entry.

        Filtering: classic VSX (R80–R81.20) reports each VS with one of
        ``CpmiVsClusterNetobj`` / ``CpmiVsNetobj`` / ``CpmiVsxClusterNetobj``.
        ``CpmiVsxClusterMember`` is the underlying physical/cluster node,
        not a VS, and gets dropped. R82 VSNext lists each VS as a regular
        ``simple-gateway`` / ``simple-cluster`` and there's no flag we can
        rely on to distinguish "this gateway is a VS"; we keep the strict
        ``"Vs"`` substring match for V1 - VSNext support is V2 territory
        once the lab has it.

        On a non-VSX Mgmt-Server the call returns no Vs* objects: the method
        legitimately returns ``[]`` (no error). The VRF tab then renders
        empty, exactly like a non-VR PANW box.
        """
        sid, base_url = _login(device)
        try:
            out: list[dict] = []
            seen: set[str] = set()
            page = 200
            offset = 0
            for _ in range(50):  # 10k objects max - far above realistic CP
                resp = _call(base_url, sid, "show-gateways-and-servers", {
                    "details-level": "full", "limit": page, "offset": offset,
                })
                items = resp.get("objects") or []
                if not isinstance(items, list) or not items:
                    break
                for obj in items:
                    otype = (obj.get("type") or "")
                    # VS-cluster-members are platform nodes, not VSs.
                    if otype == "CpmiVsxClusterMember":
                        continue
                    # Strict "Vs" substring match - picks up the three classic
                    # VSX object-classes and ignores normal gateways/clusters.
                    if "Vs" not in otype:
                        continue
                    name = (obj.get("name") or "").strip()
                    if not name or name in seen:
                        continue
                    seen.add(name)
                    properties: dict[str, Any] = {"type": otype}
                    vsid = obj.get("vsid") or obj.get("vs-id")
                    if vsid is not None:
                        properties["vsid"] = vsid
                    out.append({
                        "name": name,
                        "interface_members": [],
                        "properties": properties or None,
                    })
                total = resp.get("total")
                offset += page
                if isinstance(total, int) and offset >= total:
                    break
                if len(items) < page:
                    break
            return out
        finally:
            _logout(base_url, sid)

    def list_applications(self, *, device: dict) -> dict[str, list[dict]]:
        """Return CP's curated L7 App-Site catalog for port→app auto-binding.

        CP's Mgmt-API exposes no per-App-Site Match-By/Services data, so we
        ship a hand-curated map (``_CP_APP_CANONICAL_MAP``) of vendor-shipped
        APPI-Data App-Sites that have a clean port-fingerprint. Classical
        protocols (SSH, RDP, MySQL, …) are NOT App-Sites in CP and stay
        Service-Objects - they intentionally aren't in this list.

        Shape mirrors PA's ``list_applications``: ``{category: [entries]}``
        where each entry has ``name``, ``predefined``, ``default_ports``. All
        entries land under ``application-predefined`` since they're shipped
        in the APPI Data domain and are read-only on the gateway.
        """
        items = [
            {"name": e["name"], "predefined": True, "default_ports": list(e["default_ports"])}
            for e in _CP_APP_CANONICAL_MAP
        ]
        items.sort(key=lambda d: d["name"].lower())
        return {"application-predefined": items}

    # ── Threat-Prevention catalog (Mgmt-API) ───────────────────────
    #
    # CP TP is a separate rulebase per TP-Layer (see
    # project_cp_tp_separate_rulebase). Gateshift stores ONE strategy + params
    # per (device, layer) and the generator produces TP-rules
    # deterministically - Preview + Push call the same code.

    def list_threat_layers(self, *, device: dict) -> list[dict]:
        """Pull all TP-Layers on the Mgmt-Server.
        Uses ``show-threat-layers`` (system-wide); a Mgmt-Server typically
        carries one TP-Layer per Policy-Package plus any user-built layers.
        """
        sid, base_url = _login(device)
        try:
            out: list[dict] = []
            seen: set[str] = set()
            page = 200
            offset = 0
            for _ in range(50):
                resp = _call(base_url, sid, "show-threat-layers", {
                    "limit": page, "offset": offset, "details-level": "standard",
                })
                items = resp.get("threat-layers") or resp.get("objects") or []
                if not isinstance(items, list) or not items:
                    break
                for it in items:
                    name = (it.get("name") or "").strip()
                    if not name or name in seen:
                        continue
                    seen.add(name)
                    out.append({
                        "name":   name,
                        "uid":    it.get("uid"),
                        "shared": bool(it.get("shared", False)),
                    })
                total = resp.get("total")
                offset += page
                if isinstance(total, int) and offset >= total:
                    break
                if len(items) < page:
                    break
            out.sort(key=lambda d: d["name"].lower())
            return out
        finally:
            _logout(base_url, sid)

    def list_threat_profiles(self, *, device: dict) -> list[dict]:
        """Pull TP-Profiles via ``show-threat-profiles``.

        Default catalog has 3 vendor-shipped profiles (Basic, Optimized,
        Strict). All in domain ``data domain`` → ``predefined=True``. User-
        created profiles (``add-threat-profile``) land in the active package
        domain and surface as ``predefined=False``.
        """
        sid, base_url = _login(device)
        try:
            out: list[dict] = []
            seen: set[str] = set()
            page = 200
            offset = 0
            for _ in range(20):
                resp = _call(base_url, sid, "show-threat-profiles", {
                    "limit": page, "offset": offset, "details-level": "standard",
                })
                # CP API quirk: show-threat-profiles returns "profiles" (NOT
                # "threat-profiles" like show-threat-layers does). Check both
                # for forward-compat plus the generic "objects" fallback.
                items = (resp.get("profiles") or resp.get("threat-profiles")
                         or resp.get("objects") or [])
                if not isinstance(items, list) or not items:
                    break
                for it in items:
                    name = (it.get("name") or "").strip()
                    if not name or name in seen:
                        continue
                    seen.add(name)
                    dom = (it.get("domain") or {}).get("domain-type") or ""
                    out.append({
                        "name":       name,
                        "uid":        it.get("uid"),
                        "predefined": dom == "data domain",
                    })
                total = resp.get("total")
                offset += page
                if isinstance(total, int) and offset >= total:
                    break
                if len(items) < page:
                    break
            out.sort(key=lambda d: (not d["predefined"], d["name"].lower()))
            return out
        finally:
            _logout(base_url, sid)

    def generate_tp_rules(
        self,
        *,
        layer_name: str,
        strategy: str,
        params: dict,
        rules: list[dict],
        zones: list[dict],
        address_objects: list[dict],
        address_groups: list[dict],
    ) -> list[dict]:
        """Deterministic TP-rule generation. Pure function - Preview + Push
        call this same code so what the user saw == what gets pushed.

        Strategy ``security-ruleset`` (V1):
          - Group source rules by destination set; emit one TP-rule per
            distinct destination group. ``src``/``dst``/``svc`` stay ``Any``
            (CP-idiomatic), ``protected-scope`` is the destination set.
          - Disabled source rules are skipped.
          - ``action`` (TP-profile) comes from ``params['default_profile']``.

        ``params`` shape for ``security-ruleset``:
          - ``default_profile`` (str, required) - TP-profile name
          - ``track`` (str, optional)           - defaults to "Log"
          - ``rule_prefix`` (str, optional)     - defaults to "gateshift-tp-"
        """
        if strategy != "security-ruleset":
            raise NotImplementedError(
                f"TP strategy {strategy!r} not implemented in V1"
            )
        default_profile = (params.get("default_profile") or "").strip()
        if not default_profile:
            raise ValueError(
                "params.default_profile is required for strategy "
                "'security-ruleset'"
            )
        track  = (params.get("track") or "Log").strip()
        prefix = (params.get("rule_prefix") or "gateshift-tp-").strip()

        addr_lookup = _build_addr_lookup(address_objects, address_groups)

        # Group rules by destination-set (frozenset of resolved names).
        # Order: emit in the order we first observe each group, so rule
        # ordering is stable across regenerations.
        groups: list[tuple[frozenset[str], list[str]]] = []
        seen_keys: dict[frozenset[str], int] = {}
        for r in rules:
            if r.get("disabled"):
                continue
            dsts = [
                _resolve_addr(d, addr_lookup)
                for d in (r.get("destinations") or [])
            ]
            if not dsts:
                dsts = ["Any"]
            key = frozenset(dsts)
            if key in seen_keys:
                continue
            seen_keys[key] = len(groups)
            groups.append((key, dsts))

        # Marker tag in comments - push will use this to identify Gateshift-managed
        # TP-rules for wipe-and-replace.
        tag = {
            "tag":      "gateshift",
            "strategy": strategy,
            "layer":    layer_name,
        }
        tag_json = json.dumps(tag, separators=(",", ":"))

        out: list[dict] = []
        for i, (_key, dsts) in enumerate(groups, start=1):
            # Sort destinations for stable, readable output. "Any" alone stays "Any".
            scope = sorted(dsts, key=str.lower) if dsts != ["Any"] else ["Any"]
            rule = {
                "name":             f"{prefix}{i:03d}",
                "layer":            layer_name,
                "position":         "bottom",
                "source":           ["Any"],
                "destination":      ["Any"],
                "service":          ["Any"],
                "protected-scope":  scope,
                "action":           default_profile,
                "track":            track,
                "install-on":       ["Policy Targets"],
                "comments":         tag_json,
                "enabled":          True,
            }
            out.append(rule)
        return out

    def generate(
        self,
        *,
        rules: list[dict],
        address_objects: list[dict],
        address_groups: list[dict],
        service_objects: list[dict],
        service_groups: list[dict],
        zones: list[dict],
        interfaces: list[dict],
        routes: list[dict],
        vrfs: list[dict],
        nat_rules: list[dict],
        settings: dict[str, str],
        tp_configs: list[dict] = (),
        nat_vips: list[dict] = (),
        nat_ippools: list[dict] = (),
        tags: list[dict] = (),
        url_categories: list[dict] = (),
        schedules: list[dict] = (),
        pbf_rules: list[dict] = (),
        ssl_rules: list[dict] = (),   # Phase 5b (accepted; used in this vendor's SSL step)
        vpn_tunnels: list[dict] = (),            # IPSec VPN as Communities (CP-VPN plan CP-2)
        ike_crypto_profiles: list[dict] = (),    # inlined into the community ike-phase-1
        ipsec_crypto_profiles: list[dict] = (),  # inlined into the community ike-phase-2
        active_routes: list[dict] = (),          # for route-based encryption-domain derivation
        nat_mode: str = "central",   # Forti-only NAT mode; ignored here
        routing_mode: str = "legacy",  # PA-only render mode (legacy VR / advanced LR); ignored here
    ) -> tuple[dict[str, str], list[dict]]:
        del routing_mode
        # CP virtual-systems are Gaia-managed; no push step here.
        # nat_ippools are Forti SNAT pools - CP's native NAT rulebase needs no
        # separate pool object. A Forti VIP, however, is DUAL-purpose: its DNAT
        # is already synthesized into a NAT rule (orig-dst = ext_ip), but the
        # VIP NAME is also used as a policy DESTINATION (and TP protected-scope).
        # CP has no VIP object, so materialize each VIP as a host on its
        # external IP (same name) - the access rule then matches the pre-NAT
        # external address and the synth NAT rule translates it. Without this the
        # rule's destination ref dangles → add-access-rule HTTP 404.
        # ...and a Forti SNAT POOL is likewise referenced BY NAME as a NAT
        # rule's translated-source. CP's rulebase needs no pool *concept*, but
        # it does need an object to point at - materialize each pool as a host
        # (single IP) or address-range (QA finding: add-nat-rule 404 'gfgt-pool').
        del vrfs
        _pool_objs: list[dict] = []
        _pool_ranges: list[dict] = []
        for _pool in (nat_ippools or []):
            _pname = (_pool.get("name") or "").strip()
            _pv = _pool.get("value") or {}
            _s = str(_pv.get("start_ip") or "").strip()
            _e = str(_pv.get("end_ip") or "").strip() or _s
            if not (_pname and _s):
                continue
            if _s == _e:
                _pool_objs.append({
                    "name": _pname,
                    "value": {"type": "ip-netmask", "value": f"{_s}/32",
                              "description": "SNAT pool (hide-NAT target)"},
                })
            else:
                _pool_ranges.append({
                    "name": _pname,
                    "value": {"type": "ip-range", "value": f"{_s}-{_e}",
                              "description": "SNAT pool (hide-NAT target)"},
                })
        if _pool_objs or _pool_ranges:
            address_objects = _pool_objs + _pool_ranges + list(address_objects or [])
        dropped: list[DroppedField] = []
        _vip_hosts: list[dict] = []
        for _vip in (nat_vips or []):
            _vname = (_vip.get("name") or "").strip()
            _ext = str(((_vip.get("value") or {}).get("ext_ip") or "")).strip()
            if _vname and _ext:
                _vip_hosts.append({
                    "name": _vname,
                    "value": {"type": "ip-netmask", "value": f"{_ext}/32",
                              "description": "Forti VIP external IP "
                                             "(DNAT handled by a NAT rule)"},
                })
        if _vip_hosts:
            address_objects = _vip_hosts + list(address_objects or [])

        # Policy-Based Forwarding is Gaia-OS tier on Check Point (route-policy),
        # not a Mgmt-API rulebase - deferred per project_phase_3_pbf (CP source
        # AND target out of scope). Accept the kwarg so the shared
        # driver.generate() call signature holds, and emit a drop-warn per PBF
        # rule so the non-migration is visible rather than a silent loss.
        for _pbf in (pbf_rules or []):
            dropped.append(DroppedField(
                rule_id=_pbf.get("name") or "pbf-rule",
                field="pbf_rule",
                reason="Check Point PBR is Gaia-OS tier (route-policy), not a "
                       "Mgmt-API rulebase - not migrated",
            ))

        # All sections accumulate here as command-dict lists; NAT rendering
        # may extend Hosts / Services-TCP / Services-UDP via _ensure_host /
        # _ensure_service. Serialization to JSON happens once at the end.
        section_lists: dict[str, list[dict]] = {}

        # Multi-protocol services (Forti TCP+UDP+SCTP in one object) → fan out
        # into single-proto CP services + a synthetic same-named group, before
        # lookups/rendering see them (BUG-024).
        service_objects, service_groups = expand_multiproto_services(
            service_objects, service_groups)

        # Lookups built upfront so address-group members can rewrite raw IPs
        # to object names (symmetry with security-rule rendering below).
        addr_lookup = _build_addr_lookup(address_objects, address_groups)
        svc_lookup = _build_svc_lookup(service_objects, service_groups)
        # Forti 'ALL' (all-traffic) services → CP builtin 'Any'. Collect their
        # names (+ the literals) so rule / decryption service refs resolve to
        # 'Any' instead of a missing object (_is_any_service skips creating them).
        any_svc_names = {(o.get("name") or "").strip().lower()
                         for o in (service_objects or [])
                         if _is_any_service(o.get("value") or {})}
        any_svc_names |= {"all", "any"}

        # ── Address objects + groups ────────────────────────────
        hosts, networks, ranges = _render_address_objects(address_objects, dropped)
        section_lists["Hosts"] = hosts
        section_lists["Networks"] = networks
        section_lists["Address Ranges"] = ranges
        emitted_addr = ({c["payload"]["name"] for c in hosts + networks + ranges}
                        | {"Any"}
                        | {_safe_name(g.get("name") or "") for g in address_groups})
        section_lists["Address Groups"] = _render_address_groups(
            address_groups, dropped, addr_lookup, emitted_addr)

        # ── Service objects + groups ────────────────────────────
        svc_sections = _render_service_objects(service_objects, dropped)
        # neq services synthesize their own group (two range members) - pull
        # it out so the groups render below doesn't overwrite the bucket.
        _neq_groups = svc_sections.pop("Service Groups", [])
        for label, items in svc_sections.items():
            section_lists[label] = items
        emitted_svc = ({c["payload"]["name"]
                        for items in svc_sections.values() for c in items}
                       | {c["payload"]["name"] for c in _neq_groups}
                       | {"Any"}
                       | {_safe_name(g.get("name") or "") for g in service_groups})
        section_lists["Service Groups"] = _neq_groups + _render_service_groups(
            service_groups, dropped, emitted_svc)

        # ── Zones ───────────────────────────────────────────────
        section_lists["Zones"] = _render_zones(zones, dropped)

        # ── Interfaces (Gaia-pushed) ────────────────────────────
        # Emits a flat dispatch list: each item carries the canonical
        # iface_type so push() can call the right Gaia helper. Bonds /
        # tunnels / bridges are V1.5 - generate() emits a DroppedField for
        # visibility but skips the row. Mgmt-IF detection is push-time
        # (needs device.mgmt_ip).
        section_lists["Interfaces"] = _render_interfaces(interfaces, dropped)

        # ── Static routes (Gaia-pushed) ─────────────────────────
        # Connected routes auto-derive from interface IPs and are skipped.
        # Dynamic / blackhole / reject not in V1 scope; only single-NH
        # static routes with an explicit next_hop survive.
        section_lists["Static Routes"] = _render_static_routes(routes, dropped)

        # ── Tags (push pre-rules so rule.tags refs resolve) ──────
        section_lists["Tags"] = _render_tags(list(tags or []), dropped)

        # ── URL Categories (Phase 1a) - custom URL categories as
        # application-sites with url-list. Available on the target as
        # building blocks for manual webfilter profiles. ─────────
        section_lists["URL Categories"] = _render_url_categories(
            list(url_categories or []), dropped,
        )

        # ── Schedules (Phase 1b) - time objects via add-time. Pushed
        # before access rules so rule.time refs (emitted in
        # _render_security_rules below) resolve cleanly. ─────────
        section_lists["Schedules"], _sched_name_map = _render_schedules(
            list(schedules or []), dropped,
        )
        # Names of schedules that actually made it into add-time /
        # add-time-group commands - rule renderer below skips time-refs to
        # schedules that got dropped (e.g. cross-vendor import without any
        # intervals mapping).
        pushable_schedules: set[str] = {
            (cmd.get("payload") or {}).get("name", "")
            for cmd in section_lists["Schedules"]
            if cmd.get("command") in ("add-time", "add-time-group")
        }
        pushable_schedules.discard("")

        # ── Security rules ──────────────────────────────────────
        # addr_lookup / svc_lookup built upfront (see address-groups block).
        # A rule may only reference objects this push actually CREATES -
        # otherwise add-access-rule 404s on a dropped object (QA finding: the
        # IPv6 address 'h-::' that the object renderer skipped). Same
        # materialize-or-map rule the group renderers already follow.
        pushable_addrs: set[str] = {
            (cmd.get("payload") or {}).get("name", "")
            for sec in ("Hosts", "Networks", "Address Ranges", "Address Groups")
            for cmd in section_lists.get(sec) or []
        }
        pushable_addrs.discard("")
        section_lists["Access Rules"] = _render_security_rules(
            rules, settings, addr_lookup, svc_lookup, dropped,
            pushable_schedules=pushable_schedules,
            schedule_name_map=_sched_name_map,
            any_svc_names=any_svc_names,
            pushable_addrs=pushable_addrs,
        )

        # ── NAT rules (may extend Hosts / Services-* via section_lists) ──
        section_lists["NAT Rules"] = _render_nat_rules(
            nat_rules, settings, addr_lookup, svc_lookup,
            section_lists, dropped, any_svc_names=any_svc_names,
        )

        # ── Decryption (HTTPS-Inspection) rules (Phase 5) ──
        # Cross-vendor URL-category resolution (project_cp_url_category_map_plan):
        #   custom category  → itself (migrated as an application-site, same name)
        #   else  → operator manual map  >  live name-match vs the target catalog
        #   else  → None (unmapped → the rule is dropped + warned)
        try:
            _cat_catalog = json.loads(settings.get("cp_url_category_catalog") or "[]")
        except Exception:
            _cat_catalog = []
        try:
            _cat_map = json.loads(settings.get("cp_url_category_map") or "{}")
        except Exception:
            _cat_map = {}
        _cat_by_canon = {_canon_category(c): c for c in _cat_catalog if c}
        # Only customs that will actually be CREATED on CP (have a usable
        # cp_list) resolve to themselves; a cross-vendor custom without one is
        # dropped by _render_url_categories, so a decryption rule must treat it
        # as unmapped (→ map > name-match > None → drop+warn), not reference a
        # non-existent application-site (would 404 at add-https-rule).
        _custom_cats  = {(c.get("name") or "") for c in (url_categories or [])
                         if _cp_url_list(c)}

        def _resolve_site_category(src: str, rule_id: str) -> str | None:
            if not src:
                return None
            if src in _custom_cats:          # created on CP as an application-site
                return src
            if src in _cat_map:              # operator-attached (P3)
                return _cat_map[src]
            return _cat_by_canon.get(_canon_category(src))   # live name-match | None

        # Services this push creates (objects + groups) - the decryption rules
        # may only reference those (invariant I1).
        _pushable_svcs = {
            (c.get("payload") or {}).get("name", "")
            for _sec in ("Services-TCP", "Services-UDP", "Services-ICMP",
                         "Services-ICMP6", "Services-Other", "Service Groups")
            for c in section_lists.get(_sec) or []
        }
        _pushable_svcs.discard("")
        section_lists["Decryption Rules"] = _render_https_rules(
            list(ssl_rules or []), addr_lookup, dropped,
            resolve_category=_resolve_site_category,
            any_svc_names=any_svc_names,
            pushable_svcs=_pushable_svcs,
        )

        # ── TP-Rules per configured TP-Layer ────────────────────
        # tp_configs comes from fw_tp_layer_config rows for the target.
        # Each entry: {layer_name, strategy, params}. We emit one wrapper
        # dict per layer carrying the generated TP-rule list; push() iterates
        # this section to wipe + add per layer.
        tp_section: list[dict] = []
        for cfg in (tp_configs or ()):
            layer = (cfg.get("layer_name") or "").strip()
            strat = (cfg.get("strategy") or "").strip()
            params = cfg.get("params") or {}
            if not layer or not strat:
                continue
            try:
                tp_rules = self.generate_tp_rules(
                    layer_name=layer,
                    strategy=strat,
                    params=params,
                    rules=rules,
                    zones=zones,
                    address_objects=address_objects,
                    address_groups=address_groups,
                )
            except (NotImplementedError, ValueError) as e:
                dropped.append(DroppedField(
                    section="TP Rules",
                    item=layer,
                    field="strategy",
                    value=strat,
                    reason=str(e),
                ))
                continue
            tp_section.append({
                "layer_name": layer,
                "strategy":   strat,
                "params":     params,
                "rules":      tp_rules,
            })
        if tp_section:
            section_lists["TP Rules"] = tp_section

        # IPSec VPN as Communities (CP-VPN plan CP-2). Crypto inlined into the
        # community (CP has no crypto-profile objects), so the collected profiles
        # are name→value lookups. Domains derived from traffic_selectors / the
        # source active RIB; gateway name from settings (the target host_name).
        _ike_by = {p.get("name"): (p.get("value") or {}) for p in (ike_crypto_profiles or [])}
        _ipsec_by = {p.get("name"): (p.get("value") or {}) for p in (ipsec_crypto_profiles or [])}
        for _label, _cmds in _render_vpn(
            list(vpn_tunnels or []), _ike_by, _ipsec_by,
            list(active_routes or []), interfaces,
            settings.get("cp_gateway_name") or "", dropped,
            domain_mode=(settings.get("cp_vpn_domain_mode") or "manual"),
            topology=(settings.get("cp_vpn_topology") or "meshed"),
            is_cluster=bool(settings.get("cp_gateway_is_cluster")),
        ).items():
            section_lists[_label] = _cmds

        # Serialize non-empty sections
        sections: dict[str, str] = {}
        for label, items in section_lists.items():
            if items:
                sections[label] = json.dumps(items)
        return sections, [d.to_dict() for d in dropped]

    # Order matters: each section's items may reference items from earlier
    # sections (groups → objects, rules → everything), so we push in this
    # dependency order. Each entry: (section, strand). Network-strand splits
    # transports: Zones go through Mgmt-API (session-staged, user publishes);
    # Interfaces + Static Routes go through Gaia REST (immediate, persisted
    # via save-config). push() dispatches accordingly.
    #
    # Tags / URL Categories / Schedules are pre-rule object types referenced
    # by name from rule.tags / rule.url-category / rule.time. They MUST push
    # before Access Rules (and NAT/TP) or the rule add-* call 404s on the
    # missing reference. Were missing pre-Phase-1c - Schedule push of "jona"
    # surfaced the gap.
    _PUSH_ORDER = (
        ("Hosts",            "policy"),
        ("Networks",         "policy"),
        ("Address Ranges",   "policy"),
        ("Address Groups",   "policy"),
        ("Services-TCP",     "policy"),
        ("Services-UDP",     "policy"),
        ("Services-ICMP",    "policy"),
        ("Services-ICMP6",   "policy"),
        ("Services-Other",   "policy"),
        ("Service Groups",   "policy"),
        ("Tags",             "policy"),
        ("URL Categories",   "policy"),
        ("Schedules",        "policy"),
        ("Interfaces",       "network"),
        ("Static Routes",    "network"),
        ("Zones",            "network"),
        # IPSec VPN (CP-VPN plan CP-2b) - network strand, in dependency order:
        # domain networks → groups → interoperable-devices → gateway VPN-enable →
        # communities (the community needs the VPN-enabled gw + the peer + the
        # domain groups; live-verified sequence on gw1).
        ("VPN Networks",     "network"),
        ("VPN Groups",       "network"),
        ("VPN Peers",        "network"),
        ("VPN Gateway",      "network"),
        ("VPN Communities",  "network"),
        ("Access Rules",     "policy"),
        ("NAT Rules",        "policy"),
        ("TP Rules",         "policy"),
        ("Decryption Rules", "policy"),
    )

    # UI-label → internal section names for per-section push toggles.
    # Network strand stays atomic in V1 (_gaia_wipe_network is whole-strand)
    # - only policy strand exposes toggles. Frontend mirrors this list as a
    # JS constant to render the modal; backend authoritative copy lives
    # here so the resolver is one place. Order matches modal display order.
    _SECTION_LABELS: dict[str, list[tuple[str, str, list[str]]]] = {
        "policy": [
            ("address_objects", "Address Objects",
                ["Hosts", "Networks", "Address Ranges", "Address Groups"]),
            ("services",        "Services",
                ["Services-TCP", "Services-UDP", "Services-ICMP",
                 "Services-ICMP6", "Services-Other", "Service Groups"]),
            ("tags",            "Tags",            ["Tags"]),
            ("url_categories",  "URL Categories",  ["URL Categories"]),
            ("schedules",       "Schedules",       ["Schedules"]),
            ("access_rules",    "Access Rules",    ["Access Rules"]),
            ("nat_rules",       "NAT Rules",       ["NAT Rules"]),
            ("tp_rules",        "TP Rules",        ["TP Rules"]),
            ("decryption_rules", "Decryption Rules", ["Decryption Rules"]),
        ],
        # V1: Network-strand atomic - no toggles. Listed for completeness.
        "network": [],
    }

    @classmethod
    def _resolve_skip_internal(cls, strand: str,
                                skip_labels: set[str] | None) -> set[str]:
        """Map UI-label-keys to the internal section names that should be
        skipped during push() + wipe-phase. Empty / None → empty set
        (no-op, push everything as today)."""
        if not skip_labels:
            return set()
        out: set[str] = set()
        for key, _ui, internals in cls._SECTION_LABELS.get(strand, []):
            if key in skip_labels:
                out.update(internals)
        return out

    def push(
        self,
        *,
        device: dict,
        config: dict[str, str],
        strand: str = "policy",
        skip_sections: set[str] | None = None,
        mgmt_override: bool = False,   # per-push opt-in: force-set the mgmt iface last
        vpn_certs: dict | None = None,  # VPN identity certs - consumed in CR-4
    ) -> Iterator[StepResult]:
        """Stage all sections in a CP web_api session.

        Does NOT publish, does NOT log out on success - the staged changes
        are pinned to the session UID. The final ``staged`` StepResult
        carries ``data["session_handle"]`` with everything the caller
        needs to call ``commit_session`` / ``discard_session`` later.

        On any failure mid-push we discard + logout the partial session so
        nothing orphans.

        skip_sections: set of UI-label keys (see _SECTION_LABELS) that the
        user opted out of in the push-scope modal. Resolved to internal
        section names that gate BOTH the wipe-phase guards AND the push
        loop. None / empty → push everything (default, backwards-compat).
        """
        skip_internal: set[str] = self._resolve_skip_internal(
            strand, skip_sections)

        try:
            sid, base_url = _login(device)
        except Exception as e:
            yield StepResult(step="auth", success=False, detail=str(e))
            return

        yield StepResult(step="auth", success=True,
                         detail="session established")

        # Pre-flight: discard any orphan sessions our user still holds
        # (prior pushes that crashed before publish/discard). Assumes Gateshift
        # runs under its own dedicated CP API user per device, so wiping
        # all other sessions of that user is safe.
        discarded, derr = _discard_orphan_sessions(base_url, sid)
        if discarded > 0 or derr:
            detail = f"discarded {discarded} orphan session(s)"
            if derr:
                detail += f"; last error: {derr}"
            yield StepResult(step="cleanup orphan sessions",
                             success=True, detail=detail)

        # Reserved-name collisions (BUG-023): rename custom objects/services
        # whose name clashes with a CP predefined (incl. fuzzy match) to FF_*
        # and rewrite all references, BEFORE the wipe/push phases use them.
        # Non-fatal - a fetch hiccup degrades to the prior behavior.
        if strand == "policy":
            try:
                n_renamed, sample = _remap_reserved_collisions(config, base_url, sid)
                if n_renamed:
                    yield StepResult(
                        step="remap reserved-name collisions", success=True,
                        detail=f"renamed {n_renamed} colliding object(s) → FF_* "
                               f"(e.g. {', '.join(sample)})",
                    )
                _tp_pruned, _tp_dropped, _tp_sample = _prune_tp_dangling_refs(config)
                if _tp_pruned or _tp_dropped:
                    yield StepResult(
                        step="tp: prune dangling refs", success=True,
                        detail=(f"{_tp_pruned} ref(s) to never-materialized objects "
                                f"pruned (e.g. {', '.join(_tp_sample)}); "
                                f"{_tp_dropped} rule(s) with emptied scope skipped"),
                    )
            except Exception as e:
                yield StepResult(step="remap reserved-name collisions",
                                 success=True, detail=f"skipped (non-fatal): {e}")

        # Network-strand only: open a parallel Gaia session for the
        # interface + static-route phases. Missing creds is non-fatal -
        # Zones still stage via Mgmt-API. Other Gaia errors abort the
        # network slice but leave Mgmt-API session intact for Zones.
        gaia_sid: str | None = None
        gaia_base: str | None = None
        gaia_committed = False
        mgmt_ip = (device.get("mgmt_ip") or "").strip()
        # Cluster target: the network strand pushes static routes to EACH
        # member's Gaia (the cluster VIP is not a Gaia endpoint - F4) and skips
        # interface push in V1 (member/VIP config lives on the pre-formed
        # cluster - CP-4). Resolve the members up front via the open Mgmt
        # session; the single-VIP Gaia login below is bypassed for a cluster.
        try:
            _cp_cfg = json.loads(device.get("config") or "{}").get("cp") or {}
        except Exception:
            _cp_cfg = {}
        is_cluster = "cluster" in (_cp_cfg.get("gateway_type") or "").lower()
        cluster_members: list[dict] = []
        cluster_name: str | None = None
        cluster_iface_names: set[str] = set()
        if is_cluster and strand == "network":
            try:
                _gw = _fetch_gateway_topology(
                    base_url, sid, _cp_cfg.get("gateway_uid"),
                    _cp_cfg.get("gateway_type") or "simple-cluster")
                cluster_members = _cp_cluster_members(_gw)
                cluster_name = _gw.get("name")
                cluster_iface_names = {
                    o.get("name")
                    for o in ((_gw.get("interfaces") or {}).get("objects") or [])
                    if o.get("name")
                }
            except Exception as e:
                yield StepResult(step="cluster members", success=False,
                                 detail=f"could not resolve cluster topology: {e}")
        wants_gaia = strand == "network" and not is_cluster and bool(
            config.get("Interfaces") or config.get("Static Routes")
        )
        if wants_gaia:
            if not (device.get("gaia_user") and device.get("gaia_password")):
                yield StepResult(
                    step="gaia auth", success=False,
                    detail="Gaia credentials missing - IFs/Routes skipped, "
                           "Zones still pushed",
                )
            else:
                try:
                    gaia_sid, gaia_base = _gaia_login(device)
                    yield StepResult(step="gaia auth", success=True,
                                     detail="Gaia session established")
                except Exception as e:
                    yield StepResult(step="gaia auth", success=False,
                                     detail=str(e))

        # Resolve the mgmt iface by NAME (the iface currently carrying mgmt_ip)
        # so protection + the optional force-override survive a remap that
        # changes its IP - the IP-match alone misses that case (it'd push the
        # remapped mgmt iface mid-stream and drop the control channel). Best-
        # effort: a probe failure falls back to the IP-match. ``deferred_mgmt``
        # collects the mgmt iface row when the force opt-in is on, to set it
        # dead-last (after save-config - that set drops our Gaia session).
        mgmt_iface_name: str | None = None
        deferred_mgmt: list[dict] = []
        if gaia_sid is not None and mgmt_ip:
            try:
                _pr = _gaia_call_optional(
                    gaia_base, gaia_sid, "show-physical-interfaces", {}) or {}
                _pitems = (_pr.get("objects") or _pr.get("physical-interfaces")
                           or _pr.get("interfaces") or [])
                for _it in (_pitems if isinstance(_pitems, list) else []):
                    if _has_mgmt_ip(_it, mgmt_ip):
                        mgmt_iface_name = (_it.get("name") or "").strip() or None
                        break
            except Exception:
                mgmt_iface_name = None

        # ``session_handed_off`` flips True only after the final ``staged``
        # yield is delivered to the caller. Until then, ANY way out of this
        # generator - normal return, raised Exception, or GeneratorExit from
        # an SSE client disconnect - must roll back the partial session, or
        # CP will hold the session open with all our pending changes and
        # locks until its ~10 min idle timeout.
        session_handed_off = False
        ok = True
        try:
            # ── Resolve target layer from the chosen package ─────────
            # Layer-name is global on CP, so user-pickable layer names made
            # it trivial to wipe the wrong package's rules. We pin the layer
            # to whatever ``show-package <pkg>`` reports - exactly one layer
            # per package in our scope (V1 = L3/L4 only). 0 or >1 layers is
            # a refusal: 0 means a misconfigured package, >1 means multi-layer
            # (App-Control / URL-Filtering / Content-Awareness stack) which
            # is V2 territory.
            resolved_layer: str | None = None
            if strand == "policy" and config.get("Access Rules"):
                rule_cmds = json.loads(config["Access Rules"])
                if rule_cmds:
                    package = (rule_cmds[0]["payload"].get("__package__")
                               or "Standard")
                    try:
                        pkg_resp = _call(base_url, sid, "show-package",
                                         {"name": package, "details-level": "full"})
                    except Exception as e:
                        yield StepResult(
                            step="resolve layer", success=False,
                            detail=f"show-package {package!r} failed: {e}",
                        )
                        ok = False
                    else:
                        layers = [l.get("name", "")
                                  for l in (pkg_resp.get("access-layers") or [])
                                  if l.get("name")]
                        if len(layers) == 1:
                            resolved_layer = layers[0]
                            yield StepResult(
                                step="resolve layer", success=True,
                                detail=f"package {package!r} → layer {resolved_layer!r}",
                            )
                            # Apps-blade check: if the resolved layer has no
                            # ``applications-and-url-filtering`` slot enabled,
                            # CP rejects rules that reference Application-Sites
                            # in `service`. Strip them across all rule_cmds
                            # rather than abort the push - Service-Objects
                            # alone still produce a functioning rule.
                            apps_blade = True
                            try:
                                layer_resp = _call(
                                    base_url, sid, "show-access-layer",
                                    {"name": resolved_layer,
                                     "details-level": "full"},
                                )
                                apps_blade = bool(layer_resp.get(
                                    "applications-and-url-filtering"))
                            except Exception:
                                apps_blade = True  # fail open
                            # Identity-ref gate (Phase 2.5): fetch the
                            # target's existing Access-Roles once, then drop
                            # any rule identity-ref that doesn't exist there
                            # (else add-access-rule 404s). Roles are pushed
                            # by reference only - definition not migrated.
                            target_roles = _fetch_cp_access_roles(base_url, sid)
                            stripped_apps = 0
                            stripped_rules = 0
                            stripped_idents = 0
                            stripped_ident_rules = 0
                            for cmd in rule_cmds:
                                pld = cmd["payload"]
                                pld["layer"] = resolved_layer
                                pld.pop("__package__", None)
                                apps = pld.pop("__applications__", []) or []
                                if apps and not apps_blade:
                                    svc = pld.get("service") or []
                                    new_svc = [s for s in svc if s not in apps]
                                    if not new_svc:
                                        new_svc = ["Any"]
                                    pld["service"] = new_svc
                                    stripped_apps += len(apps)
                                    stripped_rules += 1
                                # Identity-refs: keep only roles that exist at
                                # the target; remove the rest from `source`.
                                idents = pld.pop("__identity_refs__", []) or []
                                missing = [r for r in idents if r not in target_roles]
                                if missing:
                                    src = pld.get("source") or []
                                    new_src = [s for s in src if s not in missing]
                                    if not new_src:
                                        new_src = ["Any"]
                                    pld["source"] = new_src
                                    stripped_idents += len(missing)
                                    stripped_ident_rules += 1
                            if stripped_apps:
                                yield StepResult(
                                    step="strip apps", success=True,
                                    detail=(
                                        f"layer {resolved_layer!r} has no "
                                        "applications-and-url-filtering blade; "
                                        f"stripped {stripped_apps} app(s) from "
                                        f"{stripped_rules} rule(s)"
                                    ),
                                )
                            if stripped_idents:
                                yield StepResult(
                                    step="gate identity refs", success=True,
                                    detail=(
                                        f"dropped {stripped_idents} Access-Role "
                                        f"ref(s) absent at target from "
                                        f"{stripped_ident_rules} rule(s) - rule "
                                        "pushed without that identity constraint"
                                    ),
                                )
                            config["Access Rules"] = json.dumps(rule_cmds)
                        else:
                            yield StepResult(
                                step="resolve layer", success=False,
                                detail=(
                                    f"package {package!r} has {len(layers)} "
                                    f"access-layers ({layers!r}); Gateshift requires "
                                    "exactly one (multi-layer policies are V2 "
                                    "territory)"
                                ),
                            )
                            ok = False

            # ── Wipe phase: clear existing rules in the resolved layer ──
            # Simple objects (host/network/range/service-tcp/-udp/-icmp) get
            # set-if-exists for idempotent re-pushes. Groups (add-group,
            # add-service-group) and zones (add-security-zone) reject that
            # parameter on R8x - _call_idempotent falls back to set-* on
            # name conflicts so re-pushes still succeed.
            # Skip-aware wipe: user opted out of Access Rules → don't wipe
            # the layer (else we'd erase rules the user explicitly chose to
            # keep). Symmetric for NAT and TP below.
            if ok and resolved_layer and "Access Rules" not in skip_internal:
                for step in _wipe_access_layer(base_url, sid, resolved_layer):
                    yield step
                    if not step.success:
                        ok = False
                        break

            if (ok and strand == "policy" and config.get("NAT Rules")
                    and "NAT Rules" not in skip_internal):
                nat_cmds = json.loads(config["NAT Rules"])
                if nat_cmds:
                    package = nat_cmds[0]["payload"].get("package") or "Standard"
                    for step in _wipe_nat_rulebase(base_url, sid, package):
                        yield step
                        if not step.success:
                            ok = False
                            break

            # ── Wipe Gateshift-managed TP-rules per configured TP-Layer ────
            # TP-Layer is global on CP (not tied to a package), so we
            # wipe each layer independently. Marker-tag filter ensures
            # user-authored TP-rules survive (analogous to NAT's
            # ``auto-generated`` filter).
            #
            # Pre-flight: TP-blade check on the gateway. Adding TP-rules
            # without any TP blade enabled on the GW is harmless on the
            # Mgmt-Server but pointless - refuse with a clear message so
            # the user enables the blade in SmartConsole first instead of
            # debugging "no inspection happens" later.
            tp_entries: list[dict] = []
            if (ok and strand == "policy" and config.get("TP Rules")
                    and "TP Rules" not in skip_internal):
                tp_entries = json.loads(config["TP Rules"])
                blade_ok, blade_detail = _check_tp_blade(base_url, sid, device)
                if blade_ok is False:
                    yield StepResult(
                        step="tp: blade check", success=False,
                        detail=blade_detail,
                    )
                    ok = False
                elif blade_ok is True:
                    yield StepResult(
                        step="tp: blade check", success=True,
                        detail=blade_detail,
                    )
                # blade_ok is None → unverifiable (no gateway_uid, call
                # failed); fail open and let the actual add-threat-rule
                # surface any real issue.

            tp_stranded: dict[str, str] = {}
            tp_missing_layers: set[str] = set()
            if ok and tp_entries:
                for entry in tp_entries:
                    layer = (entry.get("layer_name") or "").strip()
                    if not layer:
                        continue
                    for step in _wipe_tp_layer(base_url, sid, layer):
                        yield step
                        if step.data and step.data.get("stranded_uid"):
                            tp_stranded[layer] = step.data["stranded_uid"]
                        if step.data and step.data.get("layer_missing"):
                            tp_missing_layers.add(layer)
                        if not step.success:
                            ok = False
                            break
                    if not ok:
                        break

            # ── Stale-TP sweep: marker-based, across ALL TP layers ────
            # The per-entry scope wipe above only covers layers the NEW
            # generate references. Sweep the rest for leftover Gateshift
            # rules (source without TP, renamed layer, prior instance).
            if ok and strand == "policy" and "TP Rules" not in skip_internal:
                _swept = {(e.get("layer_name") or "").strip()
                          for e in tp_entries}
                _swept.discard("")
                for step in _wipe_stale_tp_rules(base_url, sid, _swept):
                    yield step
                    if not step.success:
                        ok = False
                        break

            # ── Wipe Gateshift-managed HTTPS-inspection rules ─────────
            # Runs whenever the policy strand pushes (not gated on the new
            # config HAVING Decryption Rules): wipe-and-replace semantics -
            # a re-push from a source without ssl rules must still clear
            # the previous push's https rules, else they hold object
            # references and break the object wipe (multi-rulebase gap).
            if (ok and strand == "policy"
                    and "Decryption Rules" not in skip_internal):
                _incoming_https: set = set()
                if config.get("Decryption Rules"):
                    try:
                        _incoming_https = {
                            (c.get("payload") or {}).get("name") or ""
                            for c in json.loads(config["Decryption Rules"])}
                        _incoming_https.discard("")
                    except Exception:
                        _incoming_https = set()
                for step in _wipe_https_layer(base_url, sid, "Default Layer",
                                              incoming_names=_incoming_https):
                    yield step
                    if not step.success:
                        ok = False
                        break

            # ── Gaia mgmt-IF-on-bond guard (network strand) ──
            # If the source declares the target's mgmt-IF as a bond member,
            # add-bond-interface would detach the mgmt IP mid-push and the
            # gateway becomes unreachable before save-config can persist
            # anything. Refuse early - user must fix the source bond
            # membership before pushing.
            if ok and gaia_sid is not None and strand == "network":
                bond_section = config.get("Interfaces")
                bond_members: set[str] = set()
                if bond_section:
                    try:
                        for r in json.loads(bond_section) or []:
                            if r.get("type") == "bond":
                                for m in r.get("members") or []:
                                    bond_members.add(str(m))
                    except Exception:
                        pass
                if bond_members and mgmt_ip:
                    try:
                        phys_resp = _gaia_call_optional(
                            gaia_base, gaia_sid,
                            "show-physical-interfaces", {},
                        ) or {}
                        phys_items = (phys_resp.get("objects")
                                      or phys_resp.get("physical-interfaces")
                                      or phys_resp.get("interfaces") or [])
                        mgmt_iface_name: str | None = None
                        for it in (phys_items
                                   if isinstance(phys_items, list) else []):
                            if _has_mgmt_ip(it, mgmt_ip):
                                mgmt_iface_name = (it.get("name") or "").strip()
                                break
                        if mgmt_iface_name and mgmt_iface_name in bond_members:
                            yield StepResult(
                                step="gaia: mgmt-IF guard", success=False,
                                detail=(f"refusing to push: source declares "
                                        f"{mgmt_iface_name!r} as a bond member, "
                                        "but it carries mgmt_ip on the target "
                                        "- mgmt would be lost"),
                            )
                            ok = False
                    except Exception as e:
                        yield StepResult(
                            step="gaia: mgmt-IF guard", success=False,
                            detail=f"could not verify mgmt-IF placement: {e}",
                        )
                        ok = False

            # ── Gaia wipe (network strand only, when Gaia is up) ──
            if ok and gaia_sid is not None:
                for step in _gaia_wipe_network(gaia_base, gaia_sid, mgmt_ip):
                    yield step
                    if not step.success:
                        ok = False
                        break

            # ── Push phase ────────────────────────────────────────
            # Names renamed mid-push because CP reported them ambiguous
            # ("More than one object named X exists" - invisible to every
            # show-* listing, so the pre-flight remap can't see them).
            # Applied to every payload pushed AFTER the rename, incl. rules.
            late_rename: dict[str, str] = {}

            # Custom-URL objects must land in a category this management
            # server actually has - the name differs across versions and a
            # wrong one 404s the whole URL-Categories section (QA finding).
            if strand == "policy" and config.get("URL Categories"):
                # Applied unconditionally when a category resolves: the
                # rendered payload may predate a driver default change.
                _cat = _resolve_url_category(base_url, sid)
                if _cat:
                    try:
                        _uc = json.loads(config["URL Categories"])
                        for _c in _uc:
                            if (_c.get("payload") or {}).get("primary-category"):
                                _c["payload"]["primary-category"] = _cat
                        config["URL Categories"] = json.dumps(_uc)
                        yield StepResult(
                            step="resolve URL category", success=True,
                            detail=f"custom URL objects land in '{_cat}' on this target")
                    except Exception:
                        pass
            if ok:
                for section, sect_strand in self._PUSH_ORDER:
                    if sect_strand != strand:
                        continue
                    # Skip-toggle from the push-scope modal.
                    if section in skip_internal:
                        yield StepResult(
                            step=f"Push {section}", success=True,
                            detail="skipped (user opt-out)",
                        )
                        continue
                    raw = config.get(section)
                    if not raw:
                        continue
                    cmds = json.loads(raw)
                    if not cmds:
                        continue

                    # Gaia-routed network sections dispatch to typed helpers.
                    # If the Gaia session never came up we yield a soft skip
                    # rather than failing the whole network push (Zones still
                    # need to land via Mgmt-API).
                    if section == "Interfaces":
                        if is_cluster:
                            # CP-4: push cluster interface VIPs via the Mgmt-API
                            # (set-simple-cluster update); member physical IPs +
                            # topology stay the operator's. Stages in this Mgmt
                            # session alongside Zones (operator publishes).
                            for step in _push_cluster_interfaces(
                                    base_url, sid, cluster_name, cmds,
                                    cluster_iface_names):
                                yield step
                                if not step.success:
                                    ok = False
                                    break
                            if not ok:
                                break
                            continue
                        if gaia_sid is None:
                            yield StepResult(
                                step="Push Interfaces", success=False,
                                detail="skipped - no Gaia session",
                            )
                            continue
                        for step in _gaia_push_interfaces(
                                gaia_base, gaia_sid, cmds, mgmt_ip,
                                mgmt_iface_name=mgmt_iface_name,
                                mgmt_override=mgmt_override,
                                deferred_out=deferred_mgmt):
                            yield step
                            if not step.success:
                                ok = False
                                break
                        if not ok:
                            break
                        continue
                    if section == "Static Routes":
                        if is_cluster:
                            for step in _push_cluster_routes(
                                    device, cluster_members, cmds):
                                yield step
                                if not step.success:
                                    ok = False
                                    break
                            if not ok:
                                break
                            continue
                        if gaia_sid is None:
                            yield StepResult(
                                step="Push Static Routes", success=False,
                                detail="skipped - no Gaia session",
                            )
                            continue
                        for step in _gaia_push_static_routes(
                                gaia_base, gaia_sid, cmds):
                            yield step
                            if not step.success:
                                ok = False
                                break
                        if not ok:
                            break
                        continue

                    # TP Rules: shape is [{layer_name, strategy, params,
                    # rules: [...]}, ...] - not the {command, payload} shape
                    # the generic branch expects.
                    if section == "TP Rules":
                        for entry in cmds:
                            layer = (entry.get("layer_name") or "").strip()
                            rules = entry.get("rules") or []
                            if not layer or not rules:
                                continue
                            if layer in tp_missing_layers:
                                # Wipe found this layer absent on the target
                                # (stale config) → can't add rules to it either.
                                yield StepResult(
                                    step=f"Push TP Rules [{layer}]",
                                    success=True,
                                    detail="layer not present on target - skipped")
                                continue
                            for step in _push_tp_rules_for_layer(
                                    base_url, sid, layer, rules,
                                    stranded_uid=tp_stranded.get(layer)):
                                yield step
                                if not step.success:
                                    ok = False
                                    break
                            if not ok:
                                break
                        if not ok:
                            break
                        continue

                    step = f"Push {section}"
                    pushed = 0
                    skipped_ro = 0
                    first_ro: str | None = None
                    for cmd in cmds:
                        # Apply renames decided earlier in THIS push (see the
                        # ambiguity handler below) to the payload's own name +
                        # member refs before sending it.
                        if late_rename:
                            _p = cmd.get("payload") or {}
                            if _p.get("name") in late_rename:
                                _p["name"] = late_rename[_p["name"]]
                            for _lf in ("members", "source", "destination",
                                        "service"):
                                if isinstance(_p.get(_lf), list):
                                    _p[_lf] = [late_rename.get(m, m)
                                               for m in _p[_lf]]
                            for _sf in ("original-source", "original-destination",
                                        "original-service", "translated-source",
                                        "translated-destination",
                                        "translated-service"):
                                if isinstance(_p.get(_sf), str):
                                    _p[_sf] = late_rename.get(_p[_sf], _p[_sf])
                        name = cmd.get("payload", {}).get("name") or "<unnamed>"
                        try:
                            _call_idempotent(base_url, sid,
                                             cmd["command"], cmd["payload"])
                            pushed += 1
                        except Exception as e:
                            # CP AMBIGUOUS predefined names (QA finding, 'MMS'):
                            # add-* fails "More than one object named X exists"
                            # and the set-fallback 404s because X isn't of this
                            # type - such names are invisible to every show-*
                            # listing, so the pre-flight remap can't catch them.
                            # Rename to FF_<name> here and remember it for the
                            # remaining payloads/rules of this push.
                            if ("more than one object named" in str(e).lower()
                                    and name != "<unnamed>"
                                    and name not in late_rename.values()):
                                new_name = _safe_name(f"FF_{name}")
                                late_rename[name] = new_name
                                cmd["payload"]["name"] = new_name
                                try:
                                    _call_idempotent(base_url, sid,
                                                     cmd["command"], cmd["payload"])
                                    pushed += 1
                                    continue
                                except Exception as e2:
                                    e = e2
                            # Vendor-shipped / data-domain objects (IPS Data,
                            # APPI Data, predefined groups like
                            # AD_Dcerpc_services) reject set-/add-* with
                            # "Object … is read-only". They already exist on
                            # the target under the same name, so rules that
                            # reference them resolve correctly without us
                            # pushing them. Treat as a skip, not a failure.
                            # Belt-and-suspenders for stored data that
                            # predates the importer's _cp_is_pushable filter.
                            if "is read-only" in str(e):
                                skipped_ro += 1
                                if first_ro is None:
                                    first_ro = name
                                continue
                            yield StepResult(
                                step=step, success=False,
                                detail=f"failed at {name!r} (item {pushed + 1}/"
                                       f"{len(cmds)}): {e}",
                            )
                            ok = False
                            break
                    if not ok:
                        break
                    detail = f"{pushed} item(s) pushed"
                    if skipped_ro:
                        detail += (f"; skipped {skipped_ro} read-only "
                                   f"(first: {first_ro!r})")
                    yield StepResult(step=step, success=True, detail=detail)

            # ── Persist Gaia config (immediate writes already live) ──
            if ok and gaia_sid is not None:
                try:
                    saved = _gaia_save_config(gaia_base, gaia_sid)
                    gaia_committed = True
                    if saved is None:
                        yield StepResult(
                            step="gaia: save-config", success=True,
                            detail="auto-persisted (save-config not exposed "
                                   "on this Gaia version)",
                        )
                    else:
                        yield StepResult(step="gaia: save-config", success=True,
                                         detail="running config persisted")
                except Exception as e:
                    yield StepResult(step="gaia: save-config", success=False,
                                     detail=str(e))
                    ok = False

            # Force-reconfigure the mgmt iface dead-last (opt-in) - after
            # save-config so everything else is persisted; this set drops our
            # Gaia session so it can't be saved from here (re-attach + manual
            # save-config). The normal interface push deferred it here.
            if ok and mgmt_override and deferred_mgmt and gaia_sid is not None:
                for step in _gaia_force_mgmt_iface(
                        gaia_base, gaia_sid, deferred_mgmt):
                    yield step

            if not ok:
                return

            # Success: hand the session handle back to the caller. The UI
            # uses this to wire Publish / Discard buttons that operate on
            # the same session that staged the changes (CP requirement -
            # publishing from any other session would commit empty work
            # and leave our staged changes orphaned).
            handle = {"sid": sid, "base_url": base_url}
            detail = "All changes staged. Awaiting Publish or Discard."
            if gaia_committed:
                detail = ("Gaia changes already live (save-config OK). "
                          "Mgmt-API changes staged - Publish or Discard.")
            yield StepResult(
                step="staged", success=True, detail=detail,
                data={"session_handle": handle,
                      "gaia_committed": gaia_committed},
            )
            session_handed_off = True
        except Exception as e:
            yield StepResult(step="staged", success=False,
                             detail=f"unexpected error: {e}")
        finally:
            # Gaia session is independent of the Mgmt-API session - log it
            # out either way so the SID doesn't sit on the gateway.
            if gaia_sid is not None:
                _gaia_logout(gaia_base, gaia_sid)
            if not session_handed_off:
                try:
                    _call(base_url, sid, "discard", {})
                except Exception:
                    pass
                try:
                    _logout(base_url, sid)
                except Exception:
                    pass

    # ── Session lifecycle: caller drives commit/discard ──────────────

    def commit_session(
        self,
        *,
        device: dict,  # accepted for API symmetry; not used (handle has all)
        handle: dict,
    ) -> Iterator[StepResult]:
        """Publish a session previously returned by push().

        Polls publish-task to completion before yielding success. Logs out
        the session at the end (whether publish succeeded or not).
        """
        sid = handle["sid"]
        base_url = handle["base_url"]
        try:
            try:
                resp = _call(base_url, sid, "publish", {})
            except Exception as e:
                yield StepResult(step="publish", success=False,
                                 detail=f"publish call failed: {e}")
                return
            task_id = resp.get("task-id")
            if not task_id:
                yield StepResult(step="publish", success=True,
                                 detail="publish accepted (no task-id)")
                return
            for _ in range(120):  # ~4 min max
                try:
                    t = _call(base_url, sid, "show-task",
                              {"task-id": task_id, "details-level": "full"})
                except Exception as e:
                    yield StepResult(step="publish", success=False,
                                     detail=f"show-task failed: {e}")
                    return
                tasks = t.get("tasks") or []
                if not tasks:
                    yield StepResult(step="publish", success=False,
                                     detail="task list empty")
                    return
                status = tasks[0].get("status")
                if status == "succeeded":
                    yield StepResult(step="publish", success=True,
                                     detail="publish succeeded (100%)")
                    return
                if status in ("failed", "partially succeeded"):
                    yield StepResult(step="publish", success=False,
                                     detail=f"publish status={status}")
                    return
                time.sleep(2)
            yield StepResult(step="publish", success=False,
                             detail="publish task still running after 4 min")
        finally:
            _logout(base_url, sid)

    def discard_session(
        self,
        *,
        device: dict,
        handle: dict,
    ) -> Iterator[StepResult]:
        """Drop staged changes from a session returned by push()."""
        sid = handle["sid"]
        base_url = handle["base_url"]
        try:
            try:
                _call(base_url, sid, "discard", {})
                yield StepResult(step="discard", success=True,
                                 detail="staged changes dropped")
            except Exception as e:
                yield StepResult(step="discard", success=False,
                                 detail=f"discard call failed: {e}")
        finally:
            _logout(base_url, sid)


# ── Push helpers ─────────────────────────────────────────────────

def _wipe_access_layer(
    base_url: str, sid: str, layer: str
) -> Iterator[StepResult]:
    """Delete every access-rule in the given layer.

    Yields StepResults for visibility. Skips rules that the API refuses to
    delete (e.g. the default Cleanup rule on a fresh package - CP marks it
    `available-actions.delete: false`); push continues with what's left.
    """
    rule_uids: list[str] = []
    offset = 0
    page = 50
    try:
        while True:
            resp = _call(base_url, sid, "show-access-rulebase", {
                "name": layer, "limit": page, "offset": offset,
                "details-level": "uid",
            })
            for item in resp.get("rulebase") or []:
                if item.get("type") == "access-rule":
                    uid = item.get("uid")
                    if uid:
                        rule_uids.append(uid)
                # 'access-section' items have nested 'rulebase' - flatten
                for sub in item.get("rulebase") or []:
                    if sub.get("type") == "access-rule":
                        uid = sub.get("uid")
                        if uid:
                            rule_uids.append(uid)
            total = resp.get("total") or 0
            offset += page
            if offset >= total:
                break
    except Exception as e:
        yield StepResult(step=f"Wipe {layer!r}", success=False,
                         detail=f"could not list rules: {e}")
        return

    if not rule_uids:
        yield StepResult(step=f"Wipe {layer!r}", success=True,
                         detail="layer was already empty")
        return

    deleted = 0
    skipped = 0
    first_err: str | None = None
    cleanup_blocked = False
    for uid in rule_uids:
        try:
            _call(base_url, sid, "delete-access-rule",
                  {"uid": uid, "layer": layer})
            deleted += 1
        except Exception as e:
            skipped += 1
            msg = str(e)
            # CP refuses to delete the last rule of a layer (the Cleanup
            # rule). That's not a real failure for our wipe purpose - the
            # layer is effectively empty of user rules and inserts will
            # land above the Cleanup rule. Detect this and continue.
            if ("has only one rule" in msg) or ("Cleanup rule" in msg):
                cleanup_blocked = True
                continue
            if first_err is None:
                first_err = msg
    # If nothing got deleted but rules existed, the wipe didn't actually
    # do its job - report failure so the caller stops before the push
    # phase fails confusingly on the same lock/permission error. Exception:
    # the only blocker was the unavoidable Cleanup-rule guardrail.
    if deleted == 0 and first_err:
        yield StepResult(
            step=f"Wipe {layer!r}", success=False,
            detail=f"could not delete any of {len(rule_uids)} rule(s); "
                   f"first error: {first_err}",
        )
        return
    if deleted == 0 and cleanup_blocked:
        yield StepResult(
            step=f"Wipe {layer!r}", success=True,
            detail="layer holds only the Cleanup rule (kept by CP) - "
                   "treated as empty",
        )
        return
    detail = f"deleted {deleted}, skipped {skipped}"
    if first_err:
        detail += f"; first error: {first_err}"
    elif cleanup_blocked:
        detail += " (Cleanup rule kept by CP)"
    else:
        detail += " (undeletable / builtin)"
    yield StepResult(step=f"Wipe {layer!r}", success=True, detail=detail)


def _wipe_nat_rulebase(
    base_url: str, sid: str, package: str
) -> Iterator[StepResult]:
    """Delete all user-defined NAT rules in the package.

    Auto-generated rules (those marked ``auto-generated: true``) are kept
    - they come from object NAT settings and would just regenerate.
    """
    rule_uids: list[str] = []
    offset = 0
    page = 50
    try:
        while True:
            resp = _call(base_url, sid, "show-nat-rulebase", {
                "package": package, "limit": page, "offset": offset,
                "details-level": "standard",
            })
            for sec in resp.get("rulebase") or []:
                # NAT rulebase is structured as sections; descend into each
                for item in sec.get("rulebase") or []:
                    if item.get("type") != "nat-rule":
                        continue
                    if item.get("auto-generated"):
                        continue
                    uid = item.get("uid")
                    if uid:
                        rule_uids.append(uid)
            total = resp.get("total") or 0
            offset += page
            if offset >= total:
                break
    except Exception as e:
        yield StepResult(step=f"Wipe NAT in {package!r}", success=False,
                         detail=f"could not list rules: {e}")
        return

    if not rule_uids:
        yield StepResult(step=f"Wipe NAT in {package!r}", success=True,
                         detail="no user NAT rules to clear")
        return

    deleted = 0
    skipped = 0
    first_err: str | None = None
    for uid in rule_uids:
        try:
            _call(base_url, sid, "delete-nat-rule",
                  {"uid": uid, "package": package})
            deleted += 1
        except Exception as e:
            skipped += 1
            if first_err is None:
                first_err = str(e)
    if deleted == 0 and first_err:
        yield StepResult(
            step=f"Wipe NAT in {package!r}", success=False,
            detail=f"could not delete any of {len(rule_uids)} rule(s); "
                   f"first error: {first_err}",
        )
        return
    detail = f"deleted {deleted}, skipped {skipped}"
    if first_err:
        detail += f"; first error: {first_err}"
    yield StepResult(step=f"Wipe NAT in {package!r}",
                     success=True, detail=detail)


def _is_ff_tp_rule(item: dict) -> bool:
    """Was this TP-rule produced by Gateshift? Match by marker tag in
    ``comments``. Anything else (user-authored rules, vendor defaults) is
    left alone by the wipe phase."""
    raw = item.get("comments") or ""
    if not isinstance(raw, str) or not raw.strip():
        return False
    s = raw.strip()
    if not s.startswith("{"):
        return False
    try:
        meta = json.loads(s)
    except Exception:
        return False
    return isinstance(meta, dict) and meta.get("tag") == "gateshift"


_HTTPS_MARKER = "gateshift-managed"


def _wipe_https_layer(
    base_url: str, sid: str, layer: str, incoming_names: set | None = None,
) -> Iterator[StepResult]:
    """Delete Gateshift-managed HTTPS-inspection rules in ``layer``.

    Unlike the TP layer, the HTTPS "Default Layer" is CP's SHIPPED layer -
    the predefined rule and possible user-authored rules live there, so
    this wipe is marker-based, never scope-based: only rules whose
    comments carry ``_HTTPS_MARKER`` are deleted, plus rules whose name
    matches an incoming rendered rule (covers rules pushed before the
    marker existed - same-name re-push would otherwise duplicate).
    Closes the multi-rulebase re-push gap: stale gs https-rules held
    object references and broke the object wipe on the second push.
    """
    doomed: list[tuple[str, str]] = []
    offset = 0
    page = 50
    try:
        while True:
            resp = _call(base_url, sid, "show-https-rulebase", {
                "name": layer, "limit": page, "offset": offset,
                "details-level": "standard",
            })
            items = []
            for item in resp.get("rulebase") or []:
                items.append(item)
                items.extend(item.get("rulebase") or [])
            for item in items:
                if "rule-number" not in item and item.get("type", "").endswith("section"):
                    continue
                uid = item.get("uid")
                if not uid:
                    continue
                cm = (item.get("comments") or "").strip()
                nm = (item.get("name") or "").strip()
                if _HTTPS_MARKER in cm or (incoming_names and nm in incoming_names):
                    doomed.append((uid, nm))
            total = resp.get("total") or 0
            offset += page
            if offset >= total:
                break
    except Exception as e:
        if "not found" in str(e).lower():
            yield StepResult(step=f"https: wipe {layer!r}", success=True,
                             detail="layer not present on target - skipped")
            return
        yield StepResult(step=f"https: wipe {layer!r}", success=False,
                         detail=f"could not list rules: {e}")
        return

    if not doomed:
        yield StepResult(step=f"https: wipe {layer!r}", success=True,
                         detail="no Gateshift-managed rules present")
        return

    deleted = 0
    first_err: str | None = None
    for uid, nm in doomed:
        try:
            _call(base_url, sid, "delete-https-rule", {"uid": uid, "layer": layer})
            deleted += 1
        except Exception as e:
            if first_err is None:
                first_err = f"{nm}: {e}"
    detail = f"deleted {deleted}/{len(doomed)} Gateshift-managed rule(s)"
    if first_err:
        detail += f"; first error: {first_err[:120]}"
    yield StepResult(step=f"https: wipe {layer!r}",
                     success=first_err is None, detail=detail)


def _wipe_stale_tp_rules(
    base_url: str, sid: str, skip_layers: set,
) -> Iterator[StepResult]:
    """Sweep ALL TP-layers for stale Gateshift-managed rules.

    Closes the re-push gap the per-layer scope wipe cannot: when the new
    generate carries no TP section (source without TP enrichment, layer
    renamed, different source), the previous push's rules linger and hold
    object references. Discovery-based instead of persisted layer names -
    rendered TP rules carry the ``{"tag":"gateshift",...}`` comments marker,
    so every marker-carrying rule (plus the tombstone) in any layer that is
    NOT already being scope-wiped is deleted. A rule CP refuses to delete
    (layer would become empty) is neutralized instead: scope/source/dest to
    Any and the marker cleared, so it holds no object references.
    """
    layers: list[str] = []
    try:
        offset = 0
        page = 200
        for _ in range(50):
            resp = _call(base_url, sid, "show-threat-layers", {
                "limit": page, "offset": offset, "details-level": "standard"})
            items = resp.get("threat-layers") or resp.get("objects") or []
            if not isinstance(items, list) or not items:
                break
            for it in items:
                name = (it.get("name") or "").strip()
                if name and name not in skip_layers and name not in layers:
                    layers.append(name)
            total = resp.get("total")
            offset += page
            if isinstance(total, int) and offset >= total:
                break
            if len(items) < page:
                break
    except Exception as e:
        yield StepResult(step="tp: stale sweep", success=False,
                         detail=f"could not list TP layers: {e}")
        return

    deleted = 0
    neutralized = 0
    first_err: str | None = None
    for layer in layers:
        doomed: list[str] = []
        try:
            offset = 0
            page = 50
            while True:
                resp = _call(base_url, sid, "show-threat-rulebase", {
                    "name": layer, "limit": page, "offset": offset,
                    "details-level": "standard"})
                items = []
                for item in resp.get("rulebase") or []:
                    items.append(item)
                    items.extend(item.get("rulebase") or [])
                for item in items:
                    uid = item.get("uid")
                    if not uid:
                        continue
                    cm = (item.get("comments") or "")
                    nm = (item.get("name") or "")
                    if '"tag":"gateshift"' in cm or nm == _TP_TOMBSTONE_NAME:
                        doomed.append(uid)
                total = resp.get("total") or 0
                offset += page
                if offset >= total:
                    break
        except Exception:
            continue  # layer unreadable (permissions/domain) - not ours to sweep
        for uid in doomed:
            try:
                _call(base_url, sid, "delete-threat-rule",
                      {"uid": uid, "layer": layer})
                deleted += 1
            except Exception as e:
                if "has only one rule" in str(e):
                    try:
                        _call(base_url, sid, "set-threat-rule", {
                            "uid": uid, "layer": layer,
                            "protected-scope": ["Any"], "source": ["Any"],
                            "destination": ["Any"], "service": ["Any"],
                            "comments": ""})
                        neutralized += 1
                    except Exception as e2:
                        if first_err is None:
                            first_err = str(e2)
                elif first_err is None:
                    first_err = str(e)
    if not (deleted or neutralized or first_err):
        yield StepResult(step="tp: stale sweep", success=True,
                         detail=f"{len(layers)} layer(s) checked - clean")
        return
    detail = f"{deleted} stale rule(s) deleted across {len(layers)} layer(s)"
    if neutralized:
        detail += f", {neutralized} neutralized (layer would become empty)"
    if first_err:
        detail += f"; first error: {first_err[:120]}"
    yield StepResult(step="tp: stale sweep", success=first_err is None,
                     detail=detail)


def _wipe_tp_layer(
    base_url: str, sid: str, layer: str
) -> Iterator[StepResult]:
    """Delete every TP-rule in the given layer.

    Scope-based wipe analog to ``_wipe_access_layer``: Gateshift owns the TP-Layer,
    so user-authored rules in the same layer are *not* preserved. Anything
    the API refuses to delete (e.g. the default Cleanup-Rule when CP marks
    it ``available-actions.delete: false``) is skipped and reported.
    """
    rule_uids: list[str] = []
    offset = 0
    page = 50
    try:
        while True:
            # ``show-threat-rulebase`` (no hyphen - sibling spelling
            # ``show-threat-rule-base`` 404s; see project_cp_tp_rulebase_api).
            resp = _call(base_url, sid, "show-threat-rulebase", {
                "name": layer, "limit": page, "offset": offset,
                "details-level": "uid",
            })
            for item in resp.get("rulebase") or []:
                if item.get("type") == "threat-rule":
                    uid = item.get("uid")
                    if uid:
                        rule_uids.append(uid)
                # TP-rulebase can have section wrappers like access - flatten.
                for sub in item.get("rulebase") or []:
                    if sub.get("type") == "threat-rule":
                        uid = sub.get("uid")
                        if uid:
                            rule_uids.append(uid)
            total = resp.get("total") or 0
            offset += page
            if offset >= total:
                break
    except Exception as e:
        # A TP layer that doesn't exist on this target (e.g. a stale layer-config
        # row left from a previous / re-provisioned management where the package
        # was named differently) 404s with "not found". There's nothing to wipe
        # - signal the caller to skip the ADD for this layer too instead of
        # hard-failing the whole push.
        if "not found" in str(e).lower():
            yield StepResult(
                step=f"tp: wipe {layer!r}", success=True,
                detail="layer not present on target - skipped",
                data={"layer_missing": True})
            return
        yield StepResult(step=f"tp: wipe {layer!r}", success=False,
                         detail=f"could not list rules: {e}")
        return

    if not rule_uids:
        yield StepResult(step=f"tp: wipe {layer!r}", success=True,
                         detail="layer was already empty")
        return

    deleted = 0
    skipped = 0
    first_err: str | None = None
    cleanup_blocked = False
    stranded_uid: str | None = None
    for uid in rule_uids:
        try:
            _call(base_url, sid, "delete-threat-rule",
                  {"uid": uid, "layer": layer})
            deleted += 1
        except Exception as e:
            skipped += 1
            msg = str(e)
            if ("has only one rule" in msg) or ("Cleanup rule" in msg):
                cleanup_blocked = True
                # CP enforces "TP-Layer must have at least 1 rule" - the
                # delete that triggered this is the stranded one. Hand its
                # UID to the caller so it can rename/tombstone before push.
                if stranded_uid is None:
                    stranded_uid = uid
                continue
            if first_err is None:
                first_err = msg
    data = {"stranded_uid": stranded_uid} if stranded_uid else None
    if deleted == 0 and first_err:
        yield StepResult(
            step=f"tp: wipe {layer!r}", success=False,
            detail=f"could not delete any of {len(rule_uids)} rule(s); "
                   f"first error: {first_err}",
        )
        return
    if deleted == 0 and cleanup_blocked:
        yield StepResult(
            step=f"tp: wipe {layer!r}", success=True,
            detail="layer holds only the Cleanup-Rule (kept by CP) - "
                   "treated as empty",
            data=data,
        )
        return
    detail = f"deleted {deleted}, skipped {skipped}"
    if first_err:
        detail += f"; first error: {first_err}"
    elif cleanup_blocked:
        detail += " (Cleanup-Rule kept by CP)"
    yield StepResult(step=f"tp: wipe {layer!r}", success=True, detail=detail,
                     data=data)


_TP_TOMBSTONE_NAME = "_gateshift-tp-tombstone"


def _push_tp_rules_for_layer(
    base_url: str, sid: str, layer: str, tp_rules: list[dict],
    stranded_uid: str | None = None,
) -> Iterator[StepResult]:
    """``add-threat-rule`` per generated rule. Names/refs come through as
    strings so the Mgmt-API resolves them itself - no UID-pre-resolve.

    Tombstone-Pattern: CP refuses to leave a TP-Layer empty, so the wipe
    phase leaves one rule stranded. We rename it to ``_gateshift-tp-tombstone``
    before push to pre-empt any name-collision (a stranded gateshift-tp-031
    would clash with the new gateshift-tp-031), then delete it once the layer
    has fresh rules and CP allows the final delete.
    """
    step = f"tp: push {layer!r}"
    if stranded_uid:
        try:
            _call(base_url, sid, "set-threat-rule", {
                "uid": stranded_uid, "layer": layer,
                "new-name": _TP_TOMBSTONE_NAME,
            })
        except Exception as e:
            yield StepResult(
                step=step, success=False,
                detail=f"could not tombstone stranded rule "
                       f"{stranded_uid}: {e}",
            )
            return
    pushed = 0
    for rule in tp_rules:
        name = rule.get("name") or "<unnamed>"
        try:
            _call(base_url, sid, "add-threat-rule", rule)
            pushed += 1
        except Exception as e:
            yield StepResult(
                step=step, success=False,
                detail=f"failed at {name!r} (item {pushed + 1}/"
                       f"{len(tp_rules)}): {e}",
            )
            return
    tombstone_detail = ""
    if stranded_uid:
        try:
            _call(base_url, sid, "delete-threat-rule",
                  {"uid": stranded_uid, "layer": layer})
            tombstone_detail = "; tombstone cleared"
        except Exception as e:
            # Non-fatal - tombstone stays but push succeeded. User sees
            # an extra _gateshift-tp-tombstone rule that the next wipe cleans up.
            tombstone_detail = f"; tombstone left ({e})"
    yield StepResult(step=step, success=True,
                     detail=f"{pushed} rule(s) pushed{tombstone_detail}")


# ── Gaia push helpers (CP-Network-Push V1) ───────────────────────
#
# Gaia writes are immediate; there is no rollback. Order matters:
# routes first (depend on IFs), then VLANs (depend on parent IFs),
# then loopbacks. Physical IFs are HW-bound - never delete; only
# set-* updates.
#
# Mgmt-IF protection: any IF whose ipv4-address equals device.mgmt_ip
# is excluded from BOTH wipe and push to avoid disconnecting the
# control channel mid-operation.


def _has_mgmt_ip(item: dict, mgmt_ip: str) -> bool:
    """Does this Gaia interface item carry the gateway's mgmt IP?"""
    if not mgmt_ip:
        return False
    addr = (item.get("ipv4-address") or "").strip()
    return bool(addr) and addr == mgmt_ip


def _is_already_gone(err: Exception) -> bool:
    """``delete-*`` is idempotent: if Gaia reports the object isn't there,
    our state has already converged. Distinguishes 'idempotent success'
    from real errors (perm/lock/conflict)."""
    msg = str(err).lower()
    return ("object not found" in msg
            or "does not exist" in msg
            or "no such" in msg)


def _gaia_wipe_routes(
    base_url: str, sid: str, mgmt_ip: str,
) -> Iterator[StepResult]:
    """Drop all static routes except the default route guarding
    mgmt-reachability. The routes-only slice of _gaia_wipe_network - reused by
    the per-member cluster route push, where wiping VLAN/loopback/bond IFs (as
    the full wipe does) would clobber the operator-formed cluster member
    interfaces."""
    deleted = 0
    skipped = 0
    first_err: str | None = None
    try:
        offset = 0
        page = 100
        for _ in range(200):
            resp = _gaia_call(base_url, sid, "show-static-routes",
                              {"limit": page, "offset": offset})
            items = (resp.get("objects") or resp.get("static-routes")
                     or resp.get("routes") or [])
            if not isinstance(items, list) or not items:
                break
            for rt in items:
                addr = (rt.get("address") or rt.get("destination")
                        or "").strip()
                mask = rt.get("mask-length")
                if mask in (None, ""):
                    mask = rt.get("prefix-length")
                if not addr or mask in (None, ""):
                    continue
                # Skip the default route guarding mgmt-reachability.
                if addr in ("0.0.0.0", "::") and int(mask) == 0:
                    skipped += 1
                    continue
                try:
                    _gaia_call(base_url, sid, "delete-static-route",
                               {"address": addr, "mask-length": int(mask)})
                    deleted += 1
                except Exception as e:
                    skipped += 1
                    if first_err is None:
                        first_err = str(e)
            total = resp.get("total")
            offset += page
            if isinstance(total, int) and offset >= total:
                break
            if len(items) < page:
                break
    except Exception as e:
        yield StepResult(step="gaia: wipe static-routes", success=False,
                         detail=str(e))
        return
    detail = f"deleted {deleted}, kept {skipped}"
    if first_err:
        detail += f"; first error: {first_err}"
    yield StepResult(step="gaia: wipe static-routes",
                     success=True, detail=detail)


def _push_cluster_routes(
    device: dict, members: list[dict], route_cmds: list,
) -> Iterator[StepResult]:
    """Push static routes to EACH ClusterXL member's Gaia (CP-2 / F4).

    The cluster VIP is not a Gaia endpoint, so the route push targets each
    member's own Gaia IP (``_cp_cluster_members`` → gaia_ip). Routes are
    cluster-wide identical → the same set is wiped + pushed + saved on every
    member. Member interfaces are deliberately NOT touched (V1; CP-4). Fail-fast:
    a member error stops the push so the caller marks the strand failed."""
    if not members:
        yield StepResult(step="Push Static Routes", success=False,
                         detail="no cluster members resolved - cannot push routes")
        return
    for mem in members:
        who = mem.get("name") or mem.get("gaia_ip") or "?"
        mdev = {**device, "mgmt_ip": mem["gaia_ip"]}
        try:
            g_sid, g_base = _gaia_login(mdev)
        except Exception as e:
            yield StepResult(step=f"cluster member {who}", success=False,
                             detail=f"Gaia login {mem['gaia_ip']} failed: {e}")
            return
        yield StepResult(step=f"cluster member {who}", success=True,
                         detail=f"Gaia session on {mem['gaia_ip']}")
        try:
            for step in _gaia_wipe_routes(g_base, g_sid, mem["gaia_ip"]):
                yield step
                if not step.success:
                    return
            for step in _gaia_push_static_routes(g_base, g_sid, route_cmds):
                yield step
                if not step.success:
                    return
            _gaia_save_config(g_base, g_sid)
            yield StepResult(step=f"Push Static Routes [{who}]", success=True,
                             detail="routes pushed + saved on the member")
        finally:
            try:
                _gaia_logout(g_base, g_sid)
            except Exception:
                pass


def _push_cluster_interfaces(
    base_url: str, sid: str, cluster_name: str | None,
    rendered: list, existing_names: set,
) -> Iterator[StepResult]:
    """Stage cluster interface VIP updates via set-simple-cluster (CP-4 / design A).

    Maps each rendered source interface to the cluster interface of the SAME name
    and sets the cluster VIP = the source interface IP (+ mask) via the
    `interfaces.update` operation. Member physical IPs + topology/zone are left
    intact (the operator owns the cluster infra). The Mgmt-API requires the VIP on
    the SAME subnet as the member IPs (else SmartConsole-only) - a mismatch
    surfaces as the call's error. Source interfaces with no name-match on the
    cluster are skipped with a warning (the operator renames source IFs to the
    cluster's names, exactly as for a standalone CP gateway). Stages in the Mgmt
    session; the operator publishes (no-auto-commit). Topology/zone changes need
    interface REPLACE - out of CP-4 V1 scope."""
    if not cluster_name:
        yield StepResult(step="Push Interfaces", success=False,
                         detail="cluster topology not resolved - cannot push interfaces")
        return
    pushed = 0
    skipped: list[str] = []
    for c in rendered:
        name = c.get("name")
        ip = c.get("ipv4")
        if not name:
            continue
        if name not in existing_names:
            skipped.append(name)
            continue
        if not ip:
            continue  # no IP to set (e.g. a VLAN parent) - nothing to push
        try:
            _call(base_url, sid, "set-simple-cluster", {
                "name": cluster_name,
                "interfaces": {"update": {
                    "name": name, "interface-type": "cluster",
                    "ip-address": ip,
                    "ipv4-mask-length": str(c.get("mask_len") or ""),
                }},
            })
            pushed += 1
        except Exception as e:
            yield StepResult(step=f"Push Interface {name}", success=False,
                             detail=str(e)[:240])
            return
    detail = f"{pushed} cluster interface VIP(s) staged"
    if skipped:
        detail += (f"; {len(skipped)} skipped - no name-match on the cluster "
                   f"(rename source IFs to the cluster's names): "
                   f"{', '.join(skipped[:6])}")
    yield StepResult(step="Push Interfaces", success=True, detail=detail)


def _gaia_wipe_network(
    base_url: str, sid: str, mgmt_ip: str,
) -> Iterator[StepResult]:
    """Drop all static routes, VLAN sub-IFs, and loopback IFs except
    those carrying the management IP. Physical IFs are never deleted.
    Yields one StepResult per category."""

    # Static routes - paginated like the read path.
    yield from _gaia_wipe_routes(base_url, sid, mgmt_ip)

    # VLAN sub-interfaces.
    deleted = 0
    skipped = 0
    first_err = None
    try:
        resp = _gaia_call_optional(base_url, sid,
                                   "show-vlan-interfaces", {}) or {}
        items = (resp.get("objects") or resp.get("vlan-interfaces")
                 or resp.get("interfaces") or [])
        for it in items if isinstance(items, list) else []:
            name = (it.get("name") or "").strip()
            if not name:
                continue
            if _has_mgmt_ip(it, mgmt_ip):
                skipped += 1
                continue
            try:
                _gaia_call(base_url, sid, "delete-vlan-interface",
                           {"name": name})
                deleted += 1
            except Exception as e:
                if _is_already_gone(e):
                    deleted += 1
                    continue
                skipped += 1
                if first_err is None:
                    first_err = str(e)
    except Exception as e:
        yield StepResult(step="gaia: wipe vlan-interfaces",
                         success=False, detail=str(e))
        return
    detail = f"deleted {deleted}, kept {skipped}"
    if first_err:
        detail += f"; first error: {first_err}"
    yield StepResult(step="gaia: wipe vlan-interfaces",
                     success=True, detail=detail)

    # Bond interfaces. Must come AFTER vlan-interfaces (VLAN-on-bond would
    # block delete-bond) and BEFORE physical IFs are reconfigured (deleting
    # the bond detaches member ethX/Y so set-physical can address them).
    # A bond carrying mgmt_ip is skipped - modifying it would drop the
    # control plane between push and save-config.
    deleted = 0
    skipped = 0
    first_err = None
    try:
        resp = _gaia_call_optional(base_url, sid,
                                   "show-bond-interfaces", {}) or {}
        if not resp:
            resp = _gaia_call_optional(base_url, sid,
                                       "show-bonding-interfaces", {}) or {}
        items = (resp.get("objects") or resp.get("bond-interfaces")
                 or resp.get("bonding-interfaces") or resp.get("interfaces")
                 or [])
        for it in items if isinstance(items, list) else []:
            name = (it.get("name") or "").strip()
            if not name:
                continue
            if _has_mgmt_ip(it, mgmt_ip):
                skipped += 1
                continue
            try:
                _gaia_call(base_url, sid, "delete-bond-interface",
                           {"name": name})
                deleted += 1
            except Exception as e:
                if _is_already_gone(e):
                    deleted += 1
                    continue
                skipped += 1
                if first_err is None:
                    first_err = str(e)
    except Exception as e:
        yield StepResult(step="gaia: wipe bond-interfaces",
                         success=False, detail=str(e))
        return
    detail = f"deleted {deleted}, kept {skipped}"
    if first_err:
        detail += f"; first error: {first_err}"
    yield StepResult(step="gaia: wipe bond-interfaces",
                     success=True, detail=detail)

    # Loopback interfaces. Gaia ships a system loopback (lo0) with a
    # builtin assignment that show-* lists but delete-* refuses with
    # "Object Not Found". _is_already_gone() folds that into the
    # idempotent path so the wipe step doesn't surface it as an error.
    deleted = 0
    skipped = 0
    first_err = None
    try:
        resp = _gaia_call_optional(base_url, sid,
                                   "show-loopback-interfaces", {}) or {}
        items = (resp.get("objects") or resp.get("loopback-interfaces")
                 or resp.get("interfaces") or [])
        for it in items if isinstance(items, list) else []:
            name = (it.get("name") or "").strip()
            if not name:
                continue
            if _has_mgmt_ip(it, mgmt_ip):
                skipped += 1
                continue
            try:
                _gaia_call(base_url, sid, "delete-loopback-interface",
                           {"name": name})
                deleted += 1
            except Exception as e:
                if _is_already_gone(e):
                    skipped += 1
                    continue
                skipped += 1
                if first_err is None:
                    first_err = str(e)
    except Exception as e:
        yield StepResult(step="gaia: wipe loopback-interfaces",
                         success=False, detail=str(e))
        return
    detail = f"deleted {deleted}, kept {skipped}"
    if first_err:
        detail += f"; first error: {first_err}"
    yield StepResult(step="gaia: wipe loopback-interfaces",
                     success=True, detail=detail)


def _gaia_push_interfaces(
    base_url: str, sid: str, records: list[dict], mgmt_ip: str,
    mgmt_iface_name: str | None = None,
    mgmt_override: bool = False,
    deferred_out: list[dict] | None = None,
) -> Iterator[StepResult]:
    """Apply interface dispatch records produced by _render_interfaces.

    Push order: physical → bond → loopback → vlan. Bonds run after
    physical because add-bond-interface detaches its members from any
    pre-existing physical config - pushing the bond second lets the
    physical phase configure non-member ethX/Y first, then bonds claim
    their slaves. Loopback and VLAN come last so VLAN-on-bond resolves
    its parent. Mgmt-IF rows are skipped (matched by ipv4 equality with
    mgmt_ip), and physical rows that the source declares as bond members
    are skipped - bonding strips their config anyway.
    """
    by_type: dict[str, list[dict]] = {
        "physical": [], "bond": [], "loopback": [], "vlan": []
    }
    for r in records:
        t = r.get("type")
        if t in by_type:
            by_type[t].append(r)

    declared_members: set[str] = set()
    for r in by_type["bond"]:
        for m in r.get("members") or []:
            declared_members.add(str(m))

    # ── Pre-clear: release desired IPs held by OTHER physicals ──
    # Gaia rejects set-physical-interface when the address is "already in
    # use as the local address of <other-if>" - which is exactly what an
    # IP that MOVES between interfaces looks like (fgt2cp finding
    # 2026-08-31: the wiped box still carried the old estate addressing).
    # Clear the current holder first (set ipv4-address:'' - live-verified);
    # its own desired address, if any, lands in the normal loop below.
    # The mgmt interface is never cleared.
    try:
        _cur_resp = _gaia_call_optional(
            base_url, sid, "show-physical-interfaces", {}) or {}
        _cur_items = (_cur_resp.get("objects")
                      or _cur_resp.get("physical-interfaces")
                      or _cur_resp.get("interfaces") or [])
        _holder: dict[str, str] = {}
        for _it in (_cur_items if isinstance(_cur_items, list) else []):
            _ip = str(_it.get("ipv4-address") or "").strip()
            _nm = str(_it.get("name") or "").strip()
            if _nm and _ip and _ip[0].isdigit():
                _holder[_ip] = _nm
        _cleared = []
        for _r in by_type["physical"]:
            _want_ip = str(_r.get("ipv4") or "").strip()
            _want_nm = str(_r.get("name") or "").strip()
            if not _want_ip or _want_ip == mgmt_ip:
                continue
            _own = _holder.get(_want_ip)
            if (_own and _own != _want_nm and _own != mgmt_iface_name
                    and _own not in _cleared):
                _gaia_call(base_url, sid, "set-physical-interface",
                           {"name": _own, "ipv4-address": ""})
                _cleared.append(_own)
        if _cleared:
            yield StepResult(
                step="gaia: pre-clear moved addresses", success=True,
                detail=("released " + ", ".join(_cleared)
                        + " (address moves to another interface)"),
            )
    except Exception as e:
        yield StepResult(
            step="gaia: pre-clear moved addresses", success=False,
            detail=f"could not resolve current addressing: {e}",
        )
        return

    for itype in ("physical", "bond", "loopback", "vlan"):
        rows = by_type[itype]
        if not rows:
            continue
        pushed = 0
        skipped = 0
        first_err: str | None = None
        for r in rows:
            name = r.get("name") or "<unnamed>"
            ipv4 = r.get("ipv4") or ""
            mask = r.get("mask_len")
            comment = r.get("comment") or None
            # Mgmt iface protection - by NAME (survives a remap that changes its
            # IP) UNION the legacy IP-match (fallback when the name probe found
            # nothing). With the force opt-in, collect it for a final dead-last
            # set instead of just skipping (it can't be pushed mid-stream - the
            # IP change drops our Gaia session and would fail every later step).
            if ((mgmt_ip and ipv4 == mgmt_ip)
                    or (mgmt_iface_name and name == mgmt_iface_name)):
                if mgmt_override and deferred_out is not None:
                    deferred_out.append(r)
                skipped += 1
                continue
            if itype == "physical" and name in declared_members:
                # Will become a bond slave below - let add-bond detach + own it.
                skipped += 1
                continue
            # Gaia's add-loopback-interface auto-allocates the name (loopXX);
            # the system loopback at 127.0.0.0/8 isn't user-creatable. Skip
            # both the system row and any 127/8 entry that would otherwise
            # try to add a loopback Gaia immediately rejects.
            if itype == "loopback" and (
                name in ("lo", "lo0") or ipv4.startswith("127.")
            ):
                skipped += 1
                continue
            # Admin-state: explicit True/False on disable, None otherwise so
            # we don't toggle the field on every push (Gaia keeps prior state).
            en = r.get("enabled", True)
            en_arg: bool | None = False if en is False else None
            try:
                if itype == "physical":
                    if r.get("dhcp_enabled"):
                        _gaia_set_physical_dhcp(base_url, sid, name=name,
                                                comment=comment,
                                                enabled=en_arg)
                    else:
                        _gaia_set_physical(base_url, sid, name=name, ipv4=ipv4,
                                           mask_len=mask, comment=comment,
                                           enabled=en_arg)
                elif itype == "bond":
                    _gaia_add_bond(base_url, sid, name=name,
                                   members=r.get("members") or [],
                                   ipv4=ipv4, mask_len=mask, comment=comment,
                                   enabled=en_arg)
                elif itype == "loopback":
                    _gaia_add_loopback(base_url, sid, name=name, ipv4=ipv4,
                                       mask_len=mask, comment=comment,
                                       enabled=en_arg)
                elif itype == "vlan":
                    _gaia_add_vlan(base_url, sid,
                                   parent=r.get("parent"),
                                   vlan_id=r.get("vlan_tag"),
                                   ipv4=ipv4, mask_len=mask,
                                   comment=comment,
                                   enabled=en_arg)
                pushed += 1
            except Exception as e:
                if first_err is None:
                    first_err = f"{name}: {e}"
                # First error is fatal - IFs must converge for routes to land.
                yield StepResult(
                    step=f"gaia: push {itype}-interfaces",
                    success=False,
                    detail=f"failed at {name!r} after {pushed} pushed: {e}",
                )
                return
        detail = f"{pushed} pushed"
        if skipped:
            detail += f", {skipped} skipped (mgmt-IF or bond member)"
        yield StepResult(step=f"gaia: push {itype}-interfaces",
                         success=True, detail=detail)


def _gaia_force_mgmt_iface(
    base_url: str, sid: str, rows: list[dict],
) -> Iterator[StepResult]:
    """Set the deferred mgmt interface(s) dead-last (force opt-in). Reconfiguring
    the iface that carries our Gaia session drops it - so this runs AFTER
    save-config (everything else is already persisted) and a connection error
    right after the set is the EXPECTED success path. The mgmt change lands in
    the running config but can't be save-config'd from here (session gone) - the
    user re-attaches at the new IP and persists manually. Only physical mgmt
    ifaces are handled (the name probe is show-physical-interfaces)."""
    step = "gaia: force mgmt-IF"
    for r in rows:
        name = r.get("name") or "<mgmt>"
        if (r.get("type") or "physical") != "physical":
            yield StepResult(step=step, success=False,
                             detail=f"{name}: only physical mgmt ifaces can be "
                                    "force-set (V1) - reconfigure manually")
            continue
        ipv4 = r.get("ipv4") or ""
        mask = r.get("mask_len")
        comment = r.get("comment") or None
        try:
            if r.get("dhcp_enabled"):
                _gaia_set_physical_dhcp(base_url, sid, name=name,
                                        comment=comment, enabled=None)
            else:
                # Short timeout: we EXPECT the IP change to hang+drop the
                # session (lab-measured: the full 120s read-timeout otherwise),
                # so cap the wait at 20s instead of blocking the push for 2 min.
                _gaia_set_physical(base_url, sid, name=name, ipv4=ipv4,
                                   mask_len=mask, comment=comment, enabled=None,
                                   timeout=20)
        except Exception:
            # Session dropped right after the set landed - the new IP cut us off.
            # This is the success path: the change is in the running config.
            yield StepResult(
                step=step, success=True,
                detail=(f"{name} reconfigured (force) - Gaia session dropped as "
                        "expected (its IP changed). The change is in the running "
                        "config but NOT yet saved: re-attach at the new IP, run "
                        "save-config to persist, and update the device's mgmt IP "
                        "in Gateshift."))
            continue
        # Set returned without dropping us (e.g. same IP) - try to persist.
        try:
            _gaia_save_config(base_url, sid)
            yield StepResult(step=step, success=True,
                             detail=f"{name} reconfigured (force) + persisted. "
                                    "If its IP changed, update the device's mgmt "
                                    "IP in Gateshift.")
        except Exception:
            yield StepResult(step=step, success=True,
                             detail=f"{name} reconfigured (force) - session "
                                    "dropped before save-config; re-attach at the "
                                    "new IP and run save-config to persist.")


def _gaia_push_static_routes(
    base_url: str, sid: str, records: list[dict],
) -> Iterator[StepResult]:
    """Apply static-route dispatch records."""
    pushed = 0
    for r in records:
        prefix = r.get("prefix") or ""
        nh = r.get("next_hop") or ""
        bh = bool(r.get("blackhole"))
        if not prefix:
            continue
        if not bh and not nh:
            continue
        try:
            _gaia_add_static_route(base_url, sid, prefix=prefix,
                                   next_hop=nh, blackhole=bh)
            pushed += 1
        except Exception as e:
            yield StepResult(
                step="gaia: push static-routes", success=False,
                detail=f"failed at {prefix!r} after {pushed} pushed: {e}",
            )
            return
    yield StepResult(step="gaia: push static-routes",
                     success=True, detail=f"{pushed} pushed")
