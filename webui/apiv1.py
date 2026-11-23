# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
"""The automation API, version 1.

A FastAPI sub-application mounted at /api/v1 by main.py with its own OpenAPI
document (/api/v1/openapi.json, /api/v1/docs). Every route calls the
functions the pages call (D3, one truth), names its project or tenant
explicitly (D6), authenticates with a bearer token alone (D4, D12) and answers
errors as sentences in JSON (D5). The main module is reached through
sys.modules at call time: main imports this module after its own definitions
and mounts what build() returns.

Phase 2 (the writes of a project, D19 to D23): every write calls the function
the page's route calls, with the project or Device named in the path, and lands
one row of the audit (D8 revised) with the token's name.
"""
from __future__ import annotations

import contextvars
import json
import logging
import os
import sys
import uuid
from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, create_model
from sqlalchemy import bindparam, text

import apitokens
from gateshift_mcp import kinds as _kinds

API_PREFIX = "/api/v1"
# the API's own document (D28): without a bearer header these read like a page,
# through the login middleware's session gate; main.py consults the tuple
DOCUMENT_PATHS = (API_PREFIX + "/openapi.json", API_PREFIX + "/docs", API_PREFIX + "/docs/oauth2-redirect")
# the shipped documents the API serves (D29): name -> (directory, file). The
# docs/ tree is mounted at GATESHIFT_DOCS_DIR, the tree's root file at
# GATESHIFT_ROOT_DOCS_DIR (a file cannot be mounted into a read-only directory)
DOCUMENTS = {"operating": ("docs", "OPERATING.md"), "api": ("docs", "API.md"),
             "known-limitations": ("root", "KNOWN_LIMITATIONS.md")}
DOC_DIRS = {"docs": os.environ.get("GATESHIFT_DOCS_DIR", "/docs"),
            "root": os.environ.get("GATESHIFT_ROOT_DOCS_DIR", "/docs-root")}
# the token of the current call (scope, tenant), for the helpers the routes share
_TOKEN_CTX: contextvars.ContextVar = contextvars.ContextVar("gs_api_token", default=None)
_log = logging.getLogger("gateshift.api")


def _m():
    """The main module (loaded before this sub-application is built)."""
    return sys.modules["main"]


# ── the error envelope (D5) ───────────────────────────────────────────

def _envelope(status: int, error: str, hint: str | None = None, **extra) -> JSONResponse:
    body: dict[str, Any] = {"error": error}
    if hint:
        body["hint"] = hint
    body.update(extra)
    return JSONResponse(body, status_code=status)


async def _http_error(request: Request, exc: HTTPException):
    detail = exc.detail
    if isinstance(detail, dict):
        return _envelope(exc.status_code, str(detail.get("error") or "request refused"),
                         detail.get("hint"), **{k: v for k, v in detail.items() if k not in ("error", "hint")})
    return JSONResponse({"error": str(detail or "request refused")}, status_code=exc.status_code,
                        headers=getattr(exc, "headers", None))


async def _validation_error(request: Request, exc: RequestValidationError):
    first = (exc.errors() or [{}])[0]
    where = ".".join(str(p) for p in (first.get("loc") or []) if p not in ("body", "query", "path"))
    msg = str(first.get("msg") or "invalid value")
    return _envelope(422, "the request is not valid", f"{where}: {msg}" if where else msg)


async def _unexpected(request: Request, exc: Exception):
    """A failure inside Gateshift (D27): the caller gets a correlation id, the
    log gets the type and the text under that id; nothing of the exception
    reaches the caller."""
    ref = uuid.uuid4().hex[:12]
    _log.error("api %s %s ref %s: %s: %s", request.method, _full_path(request), ref,
               type(exc).__name__, str(exc)[:500])
    return _envelope(500, "the request failed inside Gateshift", ref=ref)


# ── the bearer gate (D4, D12) ─────────────────────────────────────────

async def require_token(request: Request) -> dict:
    """The token of this call: a live row of fw_api_tokens with its scope and
    tenant (D24), expired rows count as revoked. No session, no cookie. A
    failed token counts per address like a failed login. The one exception
    (D28): the API's own document opens for a signed-in browser too, the
    login middleware set the user on the request."""
    m = _m()
    if not m._users_exist():
        raise HTTPException(503, "setup pending: the installation has no account yet, open /setup in a browser first")
    if _full_path(request) in DOCUMENT_PATHS and getattr(request.state, "user_id", None) is not None:
        row = {"id": None, "name": "session", "scope": "read", "tenant_id": None}
        request.state.api_client = row["name"]
        request.state.api_token = row
        _TOKEN_CTX.set(row)
        return row
    addr = request.client.host if request.client else "?"
    wait = m.auth.login_wait(addr)
    if wait > 0:
        raise HTTPException(429, f"too many failed tokens from this address, try again in {int(wait) + 1} s")
    hdr = request.headers.get("authorization") or ""
    if not hdr.lower().startswith("bearer "):
        raise HTTPException(401, "a token is required: Authorization: Bearer <token>",
                            headers={"WWW-Authenticate": "Bearer"})
    token = hdr[7:].strip()
    with m.get_engine().begin() as conn:
        row = apitokens.lookup(conn, token)
        if row:
            apitokens.touch(conn, row["id"])
    if not row:
        m.auth.login_failed(addr)
        raise HTTPException(401, "the token is unknown or revoked", headers={"WWW-Authenticate": "Bearer"})
    m.auth.login_ok(addr)
    request.state.api_client = row["name"]
    request.state.api_token = row
    _TOKEN_CTX.set(row)
    return row


def need(scope: str):
    """The scope a route needs (D24): a dependency that answers 403 with the
    sentence when the call's token falls short."""
    async def _dep(request: Request, tok: dict = Depends(require_token)) -> dict:
        if not apitokens.scope_allows(tok.get("scope"), scope):
            raise HTTPException(403, f"this token's scope does not allow that: scope {scope} is needed, "
                                     f"the token has {tok.get('scope')}")
        return tok
    return _dep


def _tok() -> dict:
    return _TOKEN_CTX.get() or {}


def _token_tenant() -> int | None:
    """The tenant a tenant-bound token is limited to, else None."""
    t = _tok().get("tenant_id")
    return int(t) if t else None


# ── helpers ───────────────────────────────────────────────────────────

def _tenant(conn, tenant_id: int | None) -> int:
    """The tenant a tenant-scoped call means: the token's own when it is bound
    to one (the parameter is ignored, D24), else the named one (404 when it
    does not exist), else the installation's first tenant."""
    bound = _token_tenant()
    if bound:
        return bound
    if tenant_id:
        if not conn.execute(text("SELECT 1 FROM fw_tenants WHERE id = :t"), {"t": int(tenant_id)}).fetchone():
            raise HTTPException(404, f"no tenant with id {int(tenant_id)}")
        return int(tenant_id)
    row = conn.execute(text("SELECT MIN(id) FROM fw_tenants")).scalar()
    if row is None:
        raise HTTPException(404, "the installation has no tenant yet")
    return int(row)


def _device_view(d: dict) -> dict:
    return {
        "id": int(d.get("id")),
        "name": d.get("display_name") or d.get("host_name"),
        "host_name": d.get("host_name"),
        "display_name": d.get("display_name"),
        "platform": d.get("platform"),
        "role": d.get("role"),
        "device_kind": d.get("device_kind"),
        "mgmt_ip": d.get("mgmt_ip"),
        "mgmt_port": d.get("mgmt_port"),
        "has_api_key": bool(d.get("has_api")),
        "tenant_id": d.get("tenant_id"),
        "notes": d.get("notes"),
    }


def _device_detail(conn, device_id: int) -> dict:
    """One Device as GET /devices/{id} answers it: the view, its manager
    scopes, its last import and collect jobs. 404 when there is none, or
    none the token's tenant may see."""
    _device_guard(conn, device_id)
    row = conn.execute(text(
        "SELECT id, host_name, display_name, platform, role, mgmt_ip, mgmt_port, notes, "
        "(api_key IS NOT NULL AND api_key != '') AS has_api, device_kind, tenant_id "
        "FROM fw_devices WHERE id = :id"), {"id": device_id}).mappings().fetchone()
    if not row:
        raise HTTPException(404, f"no Device with id {device_id}")
    scopes = conn.execute(text(
        "SELECT s.scope_device_id, s.scope_role, s.position, COALESCE(d.display_name, d.host_name) AS name "
        "FROM fw_scopes s JOIN fw_devices d ON d.id = s.scope_device_id "
        "WHERE s.manager_device_id = :id ORDER BY s.position, s.id"), {"id": device_id}).mappings().all()
    last = conn.execute(text(
        "SELECT job_id, kind, status, success, created_at FROM fw_deploy_jobs "
        "WHERE source_id = :id AND kind IN ('import', 'collect') ORDER BY created_at DESC LIMIT 2"),
        {"id": device_id}).mappings().all()
    out = _device_view(dict(row))
    out["scopes"] = [{"device_id": int(s["scope_device_id"]), "role": s["scope_role"],
                      "position": s["position"], "name": s["name"]} for s in scopes]
    out["last_jobs"] = [{"job_id": j["job_id"], "kind": j["kind"], "status": j["status"],
                         "success": (bool(j["success"]) if j["success"] is not None else None),
                         "created_at": str(j["created_at"])} for j in last]
    return out


def _project_view(p: dict) -> dict:
    keys = ("id", "name", "status", "tenant_id", "tenant_name", "source_ref_id", "target_ref_id",
            "source_name", "target_name", "created_at", "updated_at")
    return {k: (str(p[k]) if k in ("created_at", "updated_at") and p.get(k) is not None else p.get(k))
            for k in keys if k in p}


def _project_row(conn, project_id: int) -> dict:
    """The project a call names; a tenant-bound token sees only its tenant's
    projects, the others answer 404 like projects that do not exist (D24)."""
    row = conn.execute(text(
        "SELECT id, name, status, tenant_id, source_ref_id, target_ref_id FROM fw_projects WHERE id = :p"),
        {"p": project_id}).mappings().fetchone()
    bound = _token_tenant()
    if not row or (bound and int(row["tenant_id"] or 0) != bound):
        raise HTTPException(404, f"no project with id {project_id}")
    return dict(row)


def _device_guard(conn, device_id: int) -> None:
    """404 for a Device that does not exist or lies outside a tenant-bound
    token's tenant (D24)."""
    row = conn.execute(text("SELECT 1 FROM fw_devices WHERE id = :id"), {"id": device_id}).fetchone()
    bound = _token_tenant()
    if not row or (bound and _m()._device_tenant(conn, device_id) != bound):
        raise HTTPException(404, f"no Device with id {device_id}")


def _net_scope(conn, project: dict) -> tuple[int, list, Any, dict]:
    """The project's network scope: the device whose interfaces and zones the
    tab shows, its stack layers, the project view and the name map."""
    m = _m()
    source_id = int(project["source_ref_id"])
    net_did = m._pano_net_device_id(conn, source_id) or source_id
    layers = m._stack_layers(conn, net_did) or [(net_did, None)]
    view = m.projview.load(conn, int(project["id"]))
    name_map = m.namemap.load_name_map(conn, int(project["id"]))
    return net_did, layers, view, name_map


def _scalar(v) -> bool:
    return v is None or isinstance(v, (str, int, float, bool))


def _own(row: dict, project_id: int) -> bool:
    """Whether a network or NAT row is this project's own addition (its
    `project_id` is the project's); a fact of the Device or another
    project's addition is not."""
    try:
        return row.get("project_id") is not None and int(row["project_id"]) == int(project_id)
    except (TypeError, ValueError):
        return False


def _rule_view(r: dict) -> dict:
    """A rule as the rules table knows it: its identity (`rule_hash`, the
    content hash) and every plain field the page's
    row carries; nested renderings and private keys stay out."""
    out: dict[str, Any] = {"rule_hash": r.get("rhash")}
    for key, val in r.items():
        if key in ("rhash", "html") or key.startswith("_"):
            continue
        if _scalar(val) or (isinstance(val, list) and all(_scalar(x) for x in val)):
            out[key] = val
    return out


# ── the bodies of the writes (phase 3) ────────────────────────────────

class BuildBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(None, max_length=200, description="why, one sentence for the audit (D25)")
    target_cp_package: str | None = Field(None, description="Check Point: the policy package, when not the Device's")


class PushBody(BaseModel):
    # an unknown field answers 422: a misspelt build_id must not drop the review gate silently
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(None, max_length=200, description="why, one sentence for the audit (D25)")
    strand: str = Field("policy", description="policy or network")
    build_id: str | None = Field(None, description="the build this push was reviewed on, the project's build job id. The push refuses when the artefact changed since.")
    skip_sections: list[str] = Field(default_factory=list, description="section keys to leave out, as the push dialog offers them")
    push_options: dict[str, bool] = Field(default_factory=dict, description="the push options of the register, by key")
    mgmt_override: bool = Field(False, description="rewrite the management interface too (the operator's opt-in)")


class ReviewedBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(None, max_length=200, description="why, one sentence for the audit (D25)")
    job_id: str = Field(..., description="the build job the operator reviewed")


def _client(request: Request) -> str | None:
    return getattr(request.state, "api_client", None)


# ── the bodies of the writes (phase 2, D21) ───────────────────────────

class CheckpointGateway(BaseModel):
    model_config = ConfigDict(extra="forbid")
    gateway_uid: str = Field(..., description="the gateway or cluster object, from the probe")
    gateway_type: str = Field(..., description="its type as the probe lists it (simple-gateway, simple-cluster, ...)")
    policy_package: str = Field(..., description="the policy package the Device is pinned to")
    domain: str | None = Field(None, description="Multi-Domain management: the domain")


class RegisterBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(None, max_length=200, description="why, one sentence for the audit (D25)")
    platform: str = Field(..., description="the platform key as the add dialog posts it (panw, checkpoint, fortigate, firepower, opnsense, asa, a manager or cloud entry)")
    mgmt_ip: str | None = Field(None, description="the management address (a Check Point gateway: the management server)")
    mgmt_port: int = Field(443, ge=1, le=65535)
    api_key: str | None = Field(None, description="the API key or password, write-only")
    gaia_user: str | None = None
    gaia_password: str | None = Field(None, description="write-only")
    notes: str | None = None
    role: str = Field("both", description="source, target or both")
    tenant_id: int | None = Field(None, description="the tenant, the first one when absent")
    options: dict[str, str] = Field(default_factory=dict, description="the add dialog's further fields by their form names (ftd_username, opn_api_key_id, the FortiGate Cloud fields fgc_*, the manager fields of the Enterprise Edition)")
    checkpoint: CheckpointGateway | None = Field(None, description="a Check Point gateway as the wizard's last step registers it: the gateway and its package, read from the management first (POST /devices/checkpoint/probe)")


class CheckpointProbeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mgmt_ip: str = Field(..., description="the management server")
    mgmt_port: int = Field(443, ge=1, le=65535)
    api_key: str = Field(..., description="the management's API key, used for the read and not stored")
    domain: str | None = None
    package: str | None = Field(None, description="list only the gateways that run this package or none yet")


class DeviceEditBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(None, max_length=200, description="why, one sentence for the audit (D25)")
    mgmt_ip: str | None = None
    mgmt_port: int | None = Field(None, ge=1, le=65535)
    api_key: str | None = Field(None, description="a new key or password, write-only. Absent keeps the stored one")
    gaia_user: str | None = None
    gaia_password: str | None = Field(None, description="write-only, absent keeps the stored one")
    notes: str | None = None
    role: str | None = Field(None, description="source, target or both")
    tenant_id: int | None = Field(None, description="move a Device no project binds to another tenant")
    options: dict[str, str] = Field(default_factory=dict, description="the edit dialog's further fields by their form names (nat_mode, routing_mode, ftd_username, opn_api_key_id, cloud_*)")


class ProjectCreateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(None, max_length=200, description="why, one sentence for the audit (D25)")
    source_id: int
    target_id: int
    name: str | None = Field(None, description="the project's name, the pair's default when absent")


class ProjectPatchBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(None, max_length=200, description="why, one sentence for the audit (D25)")
    name: str | None = None
    status: str | None = Field(None, description="draft, verified or closed, the operator's own steps. The others follow the actions")


class InterfaceBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(None, max_length=200, description="why, one sentence for the audit (D25)")
    name: str | None = Field(None, description="the name the target gets (the project's rename)")
    zone: str | None = Field(None, description="the zone to bind, by its shown name. A zone that does not exist yet is created, null unbinds")
    skip: bool | None = Field(None, description="leave the interface out of the push")
    type: str | None = Field(None, description="physical, vlan, bond, loopback or tunnel")
    enabled: bool | None = None
    description: str | None = None
    role: str | None = Field(None, description="lan, wan, dmz or undefined")
    vr: str | None = Field(None, description="the virtual router")
    parent: str | None = Field(None, description="a VLAN interface's parent, by shown name")
    vlan_tag: int | None = Field(None, ge=1, le=4094)
    ip_addresses: list[str] | None = None
    dhcp: bool | None = None
    members: list[str] | None = Field(None, description="a bond's members, by shown name")
    zone_color: str | None = None
    confirm_empty_zone: bool = Field(False, description="skip the interface although it is the sole member of a zone rules still use")


_INTERFACE_FIELD_OF = {"name": "interface_name", "zone": "zone_name", "skip": "deploy_skip", "type": "iface_type",
                       "vr": "vr_name", "parent": "parent_iface_name", "members": "member_iface_names",
                       "dhcp": "dhcp_enabled", "enabled": "enabled", "description": "description", "role": "role",
                       "vlan_tag": "vlan_tag", "ip_addresses": "ip_addresses", "zone_color": "zone_color",
                       "confirm_empty_zone": "confirm_empty_zone"}
_REASON_Q = Query(None, max_length=200, description="why, one sentence for the audit (D25)")


class RuleHashesBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(None, max_length=200, description="why, one sentence for the audit (D25)")
    rule_hashes: list[str] = Field(..., min_length=1, description="the rules by rule_hash")


class RuleDisableBody(RuleHashesBody):
    disabled: bool = Field(True, description="true disables, false enables again")


class ExclusionRestoreBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(None, max_length=200, description="why, one sentence for the audit (D25)")
    device_id: int
    kind: str
    item_key: str


class SettingsBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(None, max_length=200, description="why, one sentence for the audit (D25)")
    settings: dict[str, str] = Field(..., description="the target's push settings by key, as GET lists them")


class ZoneCreateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(None, max_length=200, description="why, one sentence for the audit (D25)")
    name: str = Field(..., min_length=1, max_length=128, description="the zone's name as the target gets it")
    color: str | None = Field(None, description="a colour of the page's palette, blue when absent")


# ── the bodies of the curation stage ──────────

class ObjectRenameBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(None, max_length=200, description="why, one sentence for the audit (D25)")
    name: str = Field(..., min_length=1, max_length=255, description="the name the project shows the object under")


class ObjectItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str = Field(..., description="address, service, address_group, service_group or schedule")
    id: int


class ObjectsDeleteBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(None, max_length=200, description="why, one sentence for the audit (D25)")
    items: list[ObjectItem] = Field(..., min_length=1, max_length=500)
    dry_run: bool = Field(True, description="true answers the partition (deletable, blocked, not_found) without writing")


class MergeBucket(BaseModel):
    model_config = ConfigDict(extra="forbid")
    canonical: dict = Field(..., description='{"id": <row id>} the object the losers fold into')
    losers: list[dict] = Field(..., min_length=1, description='[{"id": <row id>}, ...]')


class ObjectsMergeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(None, max_length=200, description="why, one sentence for the audit (D25)")
    kind: str = Field(..., description="address or service")
    buckets: list[MergeBucket] = Field(..., min_length=1, max_length=50)
    dry_run: bool = Field(True, description="true answers the counts without writing")


class RenameBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(None, max_length=200, description="why, one sentence for the audit (D25)")
    kind: str = Field(..., description="object, service, interface, zone, vrf, nat_rule or rule")
    select: dict | None = Field(None, description='{"names": [...]}, {"hashes": [...]} (rules) or {"all": true, "contains": "..."}')
    pattern: str | None = Field(None, max_length=255,
                                description="the scheme: {name} {source} {n} {n:03} {device} {kind}, rules add {action} {src_zone} {dst_zone}")
    replace: list[dict] | None = Field(None, description='[{"from": "...", "to": "..."}] applied to {name} before the pattern')
    case: str = Field("keep", description="keep, lower or upper, applied to {name}")
    mapping: dict[str, str] | None = Field(None, description="an explicit map, source name (or rule hash) to the new name, instead of a pattern")
    dry_run: bool = Field(True, description="true answers the plan without writing")


class RuleZonesBody(RuleHashesBody):
    src_zone: str | None = Field(None, description="a zone (or interface on a FortiGate target) added to the source side, 'any' resets it, '__auto__' derives it from the routes, null keeps")
    dst_zone: str | None = Field(None, description="the destination side, the same way")


class RuleServiceBody(RuleHashesBody):
    service: str | None = Field(None, description="'any' or 'application-default', null clears the override")


class RuleApplicationsBody(RuleHashesBody):
    applications: list[str] | None = Field(None, description='["any"], names from the target\'s stored catalogue, [] clears to empty, null removes the override')


class RuleProfilesBody(RuleHashesBody):
    profile_group: str | None = Field(None, description="PAN-OS: a profile group (excludes slots)")
    slots: dict[str, str | None] | None = Field(None, description="PAN-OS or FortiGate: the slots by column, null clears a slot, neither field clears the row")


class RuleLoggingBody(RuleHashesBody):
    profile: str | None = Field(None, description="PAN-OS: the log forwarding profile")
    log_start: bool | None = None
    log_end: bool | None = Field(None, description="PAN-OS")
    log_traffic: str | None = Field(None, description="FortiGate: all, utm or disable")
    capture_packet: bool | None = Field(None, description="FortiGate")


class RuleTrackBody(RuleHashesBody):
    track_type: str | None = Field(None, description="Check Point: the track, none clears")
    accounting: bool | None = None
    per_session: bool | None = None
    per_connection: bool | None = None


class RuleScheduleBody(RuleHashesBody):
    schedule: str | None = Field(None, description="a schedule's name, 'none' for no schedule, null clears the override")


class RuleNegateBody(RuleHashesBody):
    aspect: str = Field(..., description="source, destination or service")
    value: bool


class RuleNamesBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(None, max_length=200, description="why, one sentence for the audit (D25)")
    names: dict[str, str] = Field(..., min_length=1, max_length=200, description="rule hash to name, an empty name clears")


class RuleMoveBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(None, max_length=200, description="why, one sentence for the audit (D25)")
    rule_hash: str
    before: str | None = Field(None, description="the rule this one is placed before")
    after: str | None = Field(None, description="the rule this one is placed after")


class AssignBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(None, max_length=200, description="why, one sentence for the audit (D25)")
    mode: str = Field(..., description="ports (by the rules' ports) or names (by the source's application names)")
    rule_hashes: list[str] | None = Field(None, max_length=500, description="the rules in scope, all when absent")


# ── the bodies of stage 2 ──

_PY_TYPES = {"str": str, "int": int, "bool": bool, "list": list[str], "dict": dict}


def _kind_body(name: str, kind: str, verb: str):
    """A write body built from the kind table (D7), so the API and the MCP
    tools cannot drift: the fields of the kind for the verb, each optional
    unless the table says required, an enum as a literal, `reason` for the
    audit (D25), and a field the table does not know refused (422)."""
    fields: dict = {"reason": (str | None, Field(None, max_length=200,
                                                   description="why, one sentence for the audit (D25)"))}
    for fname, spec in _kinds.KINDS[kind][verb].items():
        typ = Literal.__getitem__(tuple(spec["enum"])) if spec.get("enum") else _PY_TYPES[spec["type"]]
        if spec.get("required"):
            fields[fname] = (typ, Field(..., description=spec["doc"]))
        else:
            fields[fname] = (typ | None, Field(None, description=spec["doc"]))
    return create_model(name, __config__=ConfigDict(extra="forbid"), **fields)


InterfaceAddBody = _kind_body("InterfaceAddBody", "interface", "add")
RouteAddBody = _kind_body("RouteAddBody", "route", "add")
RouteEditBody = _kind_body("RouteEditBody", "route", "edit")
VrfAddBody = _kind_body("VrfAddBody", "vrf", "add")
ZoneEditBody = _kind_body("ZoneEditBody", "zone", "edit")
NatAddBody = _kind_body("NatAddBody", "nat_rule", "add")
NatEditBody = _kind_body("NatEditBody", "nat_rule", "edit")

# the API's field names against the page functions' (the kind table speaks the operator's words)
_PAGE_FIELD_OF = {
    "interface": {"name": "interface_name", "type": "iface_type", "parent": "parent_iface_name",
                  "zone": "zone_name", "dhcp": "dhcp_enabled"},
    "route": {"interface": "interface_name", "vr": "vr_name"},
    "nat_rule": {"interface": "interface_name"},
    "zone": {},
    "vrf": {},
}
_BULK_CAP = 50


class ZonesBulkBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(None, max_length=200, description="why, one sentence for the audit (D25)")
    zone_ids: list[int] = Field(..., min_length=1, max_length=_BULK_CAP)
    properties: dict = Field(..., description="the target's property keys, GET .../kinds/zone names them")


class NatBulkBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(None, max_length=200, description="why, one sentence for the audit (D25)")
    nat_hashes: list[str] = Field(..., min_length=1, max_length=_BULK_CAP)
    disabled: bool | None = None
    description: str | None = None
    properties: dict | None = Field(None, description="the target's property keys, GET .../kinds/nat_rule names them")
    src_zone: str | None = Field(None, description="the source zone overlay, an empty string clears it")
    dst_zone: str | None = Field(None, description="the destination zone overlay, an empty string clears it")


class NatNegateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(None, max_length=200, description="why, one sentence for the audit (D25)")
    nat_hashes: list[str] = Field(..., min_length=1, max_length=_BULK_CAP)
    aspect: Literal["source", "destination", "service"]
    value: bool


class SnapshotCreateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(None, max_length=200, description="why, one sentence for the audit (D25)")
    name: str = Field(..., min_length=1, max_length=128)
    note: str | None = Field(None, max_length=2000)


class BranchBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(None, max_length=200, description="why, one sentence for the audit (D25)")
    name: str = Field(..., min_length=1, max_length=120, description="the new project's name")


class PskBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(None, max_length=200, description="why, one sentence for the audit (D25)")
    psk: str = Field("", description="the pre-shared key, empty clears the stored one. Never read back.")


def _full_path(request: Request) -> str:
    p = request.scope.get("path") or ""
    rp = request.scope.get("root_path") or ""
    return p if (rp and p.startswith(rp)) else rp + p


def _audit(request: Request, detail: str, project_id: int | None = None, device_id: int | None = None,
           reason: str | None = None) -> None:
    """One row of fw_api_audit for a write that succeeded (D8 revised, D26):
    the token's name and id, the call, the items, the caller's reason."""
    try:
        tok = getattr(request.state, "api_token", None) or {}
        with _m().get_engine().begin() as conn:
            apitokens.audit(conn, _client(request) or "?", request.method, _full_path(request), detail,
                            project_id, device_id, token_id=tok.get("id"), reason=reason)
    except Exception:
        pass


def _json_of(res: JSONResponse) -> dict:
    try:
        return json.loads(res.body)
    except Exception:
        return {}


def _event_data(raw) -> dict | None:
    """An event's data as the job wrote it (the assign job's counters)."""
    try:
        d = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
    except Exception:
        return None
    return d if isinstance(d, dict) else None


def _push_id_of_job(conn, job_id: str) -> str:
    row = conn.execute(text("SELECT job_id, kind, push_id FROM fw_deploy_jobs WHERE job_id = :j"),
                       {"j": job_id}).fetchone()
    if not row:
        raise HTTPException(404, f"no job with id {job_id}")
    if row[1] != "push" or not row[2]:
        raise HTTPException(409, "this job holds nothing staged: only a push that awaits Publish or Discard can be published or discarded")
    return str(row[2])


# ── the sub-application ───────────────────────────────────────────────

def build() -> FastAPI:
    m = _m()
    api = FastAPI(title="Gateshift API", version=str(m.APP_VERSION),
                  description="The automation API of Gateshift: the nouns of a migration as JSON, "
                              "authenticated with a bearer token (docs/API.md).",
                  docs_url=None, openapi_url=None, redoc_url=None,
                  dependencies=[Depends(require_token)])
    api.add_exception_handler(HTTPException, _http_error)
    api.add_exception_handler(RequestValidationError, _validation_error)
    api.add_exception_handler(Exception, _unexpected)
    PROJECT = [Depends(need("project"))]
    FULL = [Depends(need("full"))]

    # the API's own document (D28): FastAPI's default routes sat outside the
    # bearer dependency, these two sit inside it, and require_token lets a
    # signed-in browser through for them
    @api.get("/openapi.json", include_in_schema=False)
    def openapi_document():
        return JSONResponse(api.openapi())

    @api.get("/docs", include_in_schema=False)
    def swagger_document():
        return get_swagger_ui_html(openapi_url=API_PREFIX + "/openapi.json", title="Gateshift API")

    @api.get("/whoami", tags=["tokens"], summary="The calling token: its name, scope, tenant and expiry")
    def whoami():
        """What the token in the Authorization header is:
        its id (the audit's `token_id`), name, scope, tenant binding and expiry.
        Never the token itself. Any scope."""
        t = _tok()
        return {"token_id": t.get("id"), "name": t.get("name"), "scope": t.get("scope"),
                "tenant_id": t.get("tenant_id"), "expires_at": t.get("expires_at")}

    @api.get("/tenants", tags=["tenants"], summary="The tenants of the installation")
    def list_tenants():
        with m.get_engine().connect() as conn:
            rows = m._tenants(conn)
        bound = _token_tenant()
        if bound:
            rows = [r for r in rows if int(r["id"]) == bound]
        return {"tenants": [{"id": int(r["id"]), "name": r["name"], "devices": int(r.get("devices") or 0),
                             "projects": int(r.get("projects") or 0)} for r in rows], "total": len(rows)}

    @api.get("/documents/{name}", tags=["documents"],
             summary="A shipped document of this installation: operating, api or known-limitations")
    def get_document(name: str):
        where = DOCUMENTS.get(name)
        if not where:
            raise HTTPException(404, f"no document named {name}: operating, api or known-limitations")
        fn = where[1]
        path = os.path.join(DOC_DIRS[where[0]], fn)
        try:
            with open(path, encoding="utf-8") as fh:
                body = fh.read()
        except OSError:
            raise HTTPException(404, f"the document {name} is not shipped with this installation")
        return {"name": name, "file": fn, "format": "markdown", "version": str(m.APP_VERSION), "text": body}

    @api.get("/devices", tags=["devices"], summary="The Devices of a tenant")
    def list_devices(tenant_id: int | None = Query(None, description="the tenant, the first one when absent")):
        with m.get_engine().connect() as conn:
            tid = _tenant(conn, tenant_id)
            rows, _s, _t = m._inventory_rows(conn, tid)
        return {"tenant_id": tid, "devices": [_device_view(d) for d in rows], "total": len(rows)}

    @api.get("/devices/{device_id}", tags=["devices"], summary="One Device with its manager scopes")
    def get_device(device_id: int):
        with m.get_engine().connect() as conn:
            return _device_detail(conn, device_id)

    @api.get("/projects", tags=["projects"], summary="The projects of a tenant")
    def list_projects(tenant_id: int | None = Query(None, description="the tenant, the first one when absent")):
        with m.get_engine().connect() as conn:
            tid = _tenant(conn, tenant_id)
            rows = m._project_rows(conn, tid)
        return {"tenant_id": tid, "projects": [_project_view(p) for p in rows], "total": len(rows)}

    @api.get("/projects/{project_id}", tags=["projects"], summary="One project with its progress and build state")
    def get_project(project_id: int):
        with m.get_engine().connect() as conn:
            rows = m._project_rows(conn, project_id=project_id)
            if not rows:
                raise HTTPException(404, f"no project with id {project_id}")
            p = rows[0]
            progress = m._project_progress(conn, _project_row(conn, project_id))
            deploy = m._target_config_state(conn, project_id)
            stamps = conn.execute(text(
                "SELECT reviewed_job_id, reviewed_at, pushed_policy_job_id, pushed_policy_at, "
                "pushed_network_job_id, pushed_network_at FROM fw_target_configs WHERE project_id = :p"),
                {"p": project_id}).mappings().fetchone() or {}
        out = _project_view(p)
        out["progress"] = progress
        out["build"] = {k: deploy.get(k) for k in ("state", "built_at", "job_id", "building_job_id",
                                                   "stale", "stale_version", "built_version", "summary", "platform")}
        # the review and push stamps of the artefact (the MCP server's confirmation message names them)
        out["build"]["reviewed"] = {"job_id": stamps.get("reviewed_job_id"),
                                    "at": str(stamps["reviewed_at"]) if stamps.get("reviewed_at") else None,
                                    "current": bool(stamps.get("reviewed_job_id")) and stamps.get("reviewed_job_id") == deploy.get("job_id")}
        out["build"]["pushed"] = {s: {"job_id": stamps.get(f"pushed_{s}_job_id"),
                                      "at": str(stamps[f"pushed_{s}_at"]) if stamps.get(f"pushed_{s}_at") else None}
                                  for s in ("network", "policy")}
        return out

    @api.get("/projects/{project_id}/interfaces", tags=["network"], summary="The project's interfaces as the Network tab shows them")
    def list_interfaces(project_id: int):
        with m.get_engine().connect() as conn:
            project = _project_row(conn, project_id)
            net_did, layers, view, name_map = _net_scope(conn, project)
            rows = m._load_interfaces(conn, layers, net_did, view=view, zone_sentinel_none=True)
            m.namemap.map_interfaces(name_map, rows)
            m._sort_network_rows(rows)
        out = [{"id": r.get("id"), "name": r.get("interface_name"), "source_name": r.get("import_interface_name"),
                "type": r.get("iface_type"), "parent": r.get("parent_iface_name"), "vlan_tag": r.get("vlan_tag"),
                "ip_addresses": r.get("ip_addresses") or [], "zone": r.get("zone_name"), "vr": r.get("vr_name"),
                "enabled": bool(r.get("enabled", True)), "dhcp": bool(r.get("dhcp_enabled")),
                "skip": bool(r.get("deploy_skip")), "description": r.get("description"),
                "own": _own(r, project_id)} for r in rows]
        return {"project_id": project_id, "network_device_id": net_did, "interfaces": out, "total": len(out)}

    @api.get("/projects/{project_id}/zones", tags=["network"], summary="The project's zones")
    def list_zones(project_id: int):
        with m.get_engine().connect() as conn:
            project = _project_row(conn, project_id)
            net_did, layers, view, name_map = _net_scope(conn, project)
            if len(layers) > 1:
                zones = m._merge_layers(
                    [(lid, lname, m._load_zones(conn, device_id=lid, name_map=name_map, view=view))
                     for lid, lname in layers], lambda z: z.get("name"), net_did)
            else:
                zones = m._load_zones(conn, device_id=net_did, name_map=name_map, view=view)
        out = [{**{k: z.get(k) for k in ("id", "name", "description", "color", "is_external", "members",
                                           "source_name", "properties") if k in z},
                "own": _own(z, project_id)} for z in zones]
        return {"project_id": project_id, "network_device_id": net_did, "zones": out, "total": len(out)}

    @api.get("/projects/{project_id}/rules", tags=["rules"], summary="The project's rules with its overrides, paged")
    def list_rules(project_id: int, limit: int = Query(200, ge=1, le=1000), offset: int = Query(0, ge=0),
                   hashes: str | None = Query(None, description="rule hashes, comma-separated: only these rows (D29)")):
        wanted = [h.strip().lower() for h in (hashes or "").split(",") if h.strip()]
        hash_bytes: list[bytes] = []
        for h in wanted:
            if len(h) != 40:
                raise HTTPException(400, f"not a rule hash: {h[:48]}")
            try:
                hash_bytes.append(bytes.fromhex(h))
            except ValueError:
                raise HTTPException(400, f"not a rule hash: {h[:48]}")
        if len(hash_bytes) > 200:
            raise HTTPException(400, "at most 200 hashes per call")
        if hash_bytes:
            limit, offset = len(hash_bytes), 0
        with m.get_engine().connect() as conn:
            project = _project_row(conn, project_id)
            display = m.load_display(conn)
            page = offset // limit + 1
            # the project's names on the rules' tokens, as the page shows them (model A;
            # the Objects read of the curation API design D8 shows the same names)
            r = m._fetch_rules_and_devices(conn, page=page, page_size=limit,
                                           device_id=int(project["source_ref_id"]), display=display,
                                           project_id=project_id, hashes=hash_bytes or None,
                                           name_map=m.namemap.load_name_map(conn, project_id))
        rules: list[dict] = []
        groups = r.get("devices") or {}
        for _label, rs in (groups.items() if isinstance(groups, dict) else []):
            for rule in (rs or []):
                if isinstance(rule, dict):
                    rules.append(_rule_view(rule))
        skip = offset - (page - 1) * limit
        with m.get_engine().connect() as conn:
            stale = bool(m.get_needs_generate(conn, "policy"))
        return {"project_id": project_id, "rules": rules[skip:skip + limit], "limit": limit, "offset": offset,
                "total": int(r.get("total") or 0), "needs_refresh": stale}

    @api.get("/projects/{project_id}/findings", tags=["review"], summary="The findings and summary of the last build")
    def get_findings(project_id: int):
        with m.get_engine().connect() as conn:
            _project_row(conn, project_id)
            state = m._target_config_state(conn, project_id)
            rep = conn.execute(text("SELECT report_json FROM fw_target_configs WHERE project_id = :p"),
                               {"p": project_id}).scalar()
        report = None
        if rep:
            try:
                report = json.loads(rep) if isinstance(rep, (str, bytes)) else rep
            except ValueError:
                report = None
        # the kinds of the step model (D29): title, tab, sub-tab and the sentence per finding kind
        kinds = {k: {"title": v[0], "tab": v[1], "subtab": v[2], "sentence": v[3]}
                 for k, v in (m.progress.KINDS or {}).items() if isinstance(v, (list, tuple)) and len(v) >= 4}
        return {"project_id": project_id, "state": state.get("state"), "built_at": state.get("built_at"),
                "job_id": state.get("job_id"), "summary": state.get("summary"), "report": report, "kinds": kinds}

    @api.get("/jobs/{job_id}", tags=["jobs"], summary="One job with its events")
    def get_job(job_id: str):
        with m.get_engine().connect() as conn:
            job = conn.execute(text(
                "SELECT job_id, kind, strand, status, success, push_id, needs_commit, error_text, "
                "source_id, target_id, project_id, created_at, updated_at FROM fw_deploy_jobs WHERE job_id = :j"),
                {"j": job_id}).mappings().fetchone()
            if not job:
                raise HTTPException(404, f"no job with id {job_id}")
            bound = _token_tenant()
            if bound and job["source_id"] and m._device_tenant(conn, int(job["source_id"])) != bound:
                raise HTTPException(404, f"no job with id {job_id}")
            events = conn.execute(text(
                "SELECT seq, step, success, detail, data_json FROM fw_deploy_job_events WHERE job_id = :j ORDER BY seq"),
                {"j": job_id}).fetchall()
        return {"job_id": job["job_id"], "kind": job["kind"], "strand": job["strand"], "status": job["status"],
                "success": (bool(job["success"]) if job["success"] is not None else None),
                "push_id": job["push_id"], "needs_commit": bool(job["needs_commit"]), "error": job["error_text"],
                "source_id": job["source_id"], "target_id": job["target_id"], "project_id": job["project_id"],
                "created_at": str(job["created_at"]), "updated_at": str(job["updated_at"]),
                "events": [{"seq": e[0], "step": e[1], "success": bool(e[2]), "detail": e[3] or "",
                            **({"data": _event_data(e[4])} if e[4] else {})} for e in events]}

    # ── phase 3: build, review, push, publish, discard through jobs (D7) ──

    @api.post("/projects/{project_id}/build", tags=["deploy"], status_code=202, dependencies=PROJECT,
              summary="Build the project's target configuration (a job)")
    def start_build(project_id: int, request: Request, body: BuildBody | None = None):
        with m.get_engine().connect() as conn:
            project = _project_row(conn, project_id)
        payload = {"target_id": int(project["target_ref_id"]), "project_id": project_id,
                   "target_cp_package": (body.target_cp_package if body else None) or ""}
        res = m._build_start(int(project["source_ref_id"]), payload, None, client=_client(request))
        if res.status_code in (200, 202):
            _audit(request, f"build started, job {_json_of(res).get('job_id')}", project_id=project_id,
                   reason=(body.reason if body else None))
        return res

    @api.post("/projects/{project_id}/reviewed", tags=["deploy"], dependencies=PROJECT,
              summary="Record that the build's findings were reviewed")
    def mark_reviewed(project_id: int, body: ReviewedBody, request: Request):
        with m.get_engine().connect() as conn:
            _project_row(conn, project_id)
        ok = m._mark_reviewed(project_id, body.job_id)
        if ok:
            _audit(request, f"build {body.job_id} marked reviewed", project_id=project_id, reason=body.reason)
        return {"project_id": project_id, "job_id": body.job_id, "reviewed": ok}

    @api.post("/projects/{project_id}/push", tags=["deploy"], status_code=202, dependencies=FULL,
              summary="Push one strand of the built configuration to the target (a job)")
    def start_push(project_id: int, body: PushBody, request: Request):
        with m.get_engine().connect() as conn:
            project = _project_row(conn, project_id)
        payload = {"target_id": int(project["target_ref_id"]), "project_id": project_id,
                   "strand": body.strand, "build_id": body.build_id or "",
                   "skip_sections": list(body.skip_sections), "push_options": dict(body.push_options),
                   "mgmt_override": bool(body.mgmt_override)}
        res = m._push_start(int(project["source_ref_id"]), payload, None, client=_client(request))
        if res.status_code in (200, 202):
            _audit(request, f"{body.strand} push started, job {_json_of(res).get('job_id')}, build {body.build_id}",
                   project_id=project_id, reason=body.reason)
        return res

    def _run_stream(gen) -> None:
        for _line in gen:
            pass

    def _job_project(conn, job_id: str) -> int | None:
        row = conn.execute(text("SELECT project_id, source_id FROM fw_deploy_jobs WHERE job_id = :j"),
                           {"j": job_id}).fetchone()
        if not row:
            raise HTTPException(404, f"no job with id {job_id}")
        bound = _token_tenant()
        if bound and row[1] and m._device_tenant(conn, int(row[1])) != bound:
            raise HTTPException(404, f"no job with id {job_id}")
        return int(row[0]) if row[0] else None

    @api.post("/jobs/{job_id}/publish", tags=["deploy"], status_code=202, dependencies=FULL,
              summary="Publish what a push staged on the management (a job's steps)")
    def publish_job(job_id: str, request: Request, reason: str | None = _REASON_Q):
        with m.get_engine().connect() as conn:
            pid = _job_project(conn, job_id)
            push_id = _push_id_of_job(conn, job_id)
        res = m._publish_stream(push_id)
        if isinstance(res, JSONResponse):
            return res
        m._DEPLOY_EXECUTOR.submit(_run_stream, res)
        _audit(request, f"publish of job {job_id} started", project_id=pid, reason=reason)
        return {"job_id": job_id, "status": "running", "step": "publish"}

    @api.post("/jobs/{job_id}/discard", tags=["deploy"], status_code=202, dependencies=FULL,
              summary="Discard what a push staged on the management (a job's steps)")
    def discard_job(job_id: str, request: Request, reason: str | None = _REASON_Q):
        with m.get_engine().connect() as conn:
            pid = _job_project(conn, job_id)
            push_id = _push_id_of_job(conn, job_id)
        res = m._discard_stream(push_id)
        if isinstance(res, JSONResponse):
            return res
        m._DEPLOY_EXECUTOR.submit(_run_stream, res)
        _audit(request, f"discard of job {job_id} started", project_id=pid, reason=reason)
        return {"job_id": job_id, "status": "running", "step": "discard"}

    # ── phase 2: Devices (D21) ─────────────────────────────────────────

    @api.post("/devices/checkpoint/probe", tags=["devices"], dependencies=FULL,
              summary="Read a Check Point management: its packages, gateways and the Devices registered against it")
    def probe_checkpoint(body: CheckpointProbeBody):
        pk = m._cp_probe_packages(body.mgmt_ip.strip(), body.mgmt_port, body.api_key.strip(), body.domain or None)
        if not pk.get("ok"):
            raise HTTPException(502, f"the management did not answer: {pk.get('error')}")
        gw = m._cp_list_gateways(body.mgmt_ip.strip(), body.mgmt_port, body.api_key.strip(),
                                 (body.package or "").strip() or None, body.domain or None)
        if not gw.get("ok"):
            raise HTTPException(502, f"the management did not answer: {gw.get('error')}")
        return {"packages": pk["packages"], "gateways": gw["gateways"], "existing_devices": pk["existing_devices"]}

    @api.post("/devices", tags=["devices"], status_code=201, dependencies=FULL,
              summary="Register a Device like the add dialog")
    def register_device(body: RegisterBody, request: Request):
        with m.get_engine().connect() as conn:
            tid = _tenant(conn, body.tenant_id)
        if body.checkpoint is not None:
            if body.platform != "checkpoint":
                raise HTTPException(400, "a gateway and package register a Check Point: platform must be checkpoint")
            cp = body.checkpoint
            form = {"mgmt_ip": body.mgmt_ip or "", "mgmt_port": str(body.mgmt_port), "api_key": body.api_key or "",
                    "package": cp.policy_package, "gateway_uid": cp.gateway_uid, "gateway_type": cp.gateway_type,
                    "domain": cp.domain or "", "gaia_user": body.gaia_user or "",
                    "gaia_password": body.gaia_password or "", "tenant_id": str(tid)}
            res = m._cp_register(form, None)
            if not res.get("ok"):
                st = int(res.get("status") or 200)
                if st == 409:
                    raise HTTPException(409, {"error": "this gateway and package are registered already",
                                              "existing_device_id": res.get("existing_device_id")})
                raise HTTPException(400 if st == 400 else 502, str(res.get("error")))
            did = int(res["device_id"])
        else:
            form = {"platform": body.platform, "mgmt_ip": body.mgmt_ip or "", "mgmt_port": str(body.mgmt_port),
                    "api_key": body.api_key or "", "gaia_user": body.gaia_user or "",
                    "gaia_password": body.gaia_password or "", "notes": body.notes or "", "role": body.role,
                    "tenant_id": str(tid), **{str(k): str(v) for k, v in (body.options or {}).items()}}
            res = m._device_register(form, None)
            if isinstance(res, str):
                raise HTTPException(400, res)
            did = int(res)
        _audit(request, f"registered {body.platform} Device {did}", device_id=did, reason=body.reason)
        with m.get_engine().connect() as conn:
            return _device_detail(conn, did)

    @api.patch("/devices/{device_id}", tags=["devices"], dependencies=FULL,
               summary="Edit a Device like the edit dialog, absent fields keep their values")
    def edit_device(device_id: int, body: DeviceEditBody, request: Request):
        with m.get_engine().connect() as conn:
            _device_guard(conn, device_id)
            row = conn.execute(text(
                "SELECT platform, mgmt_ip, mgmt_port, gaia_user, notes, role, config FROM fw_devices WHERE id = :id"),
                {"id": device_id}).mappings().fetchone()
            if not row:
                raise HTTPException(404, f"no Device with id {device_id}")
            # the tenant the call may name: a token bound to one gets its own
            # (D24, the parameter is ignored), never the body's raw value
            tenant_to = _tenant(conn, body.tenant_id) if body.tenant_id is not None else None
        given = body.model_dump(exclude_unset=True)
        given.pop("reason", None)
        if not given or (set(given) == {"options"} and not body.options):
            raise HTTPException(400, "nothing to change")
        form = {"mgmt_ip": body.mgmt_ip if "mgmt_ip" in given else (row["mgmt_ip"] or ""),
                "mgmt_port": str(body.mgmt_port if body.mgmt_port is not None else (row["mgmt_port"] or 443)),
                "gaia_user": body.gaia_user if "gaia_user" in given else (row["gaia_user"] or ""),
                "notes": body.notes if "notes" in given else (row["notes"] or ""),
                "role": body.role if body.role is not None else (row["role"] or "both"),
                "api_key": body.api_key or "", "gaia_password": body.gaia_password or ""}
        if tenant_to is not None:
            form["tenant_id"] = str(tenant_to)
        opts = {str(k): str(v) for k, v in (body.options or {}).items()}
        if row["platform"] == "firepower" and "ftd_username" not in opts:
            # the dialog always posts the field; absent in the API it keeps the stored name
            try:
                opts["ftd_username"] = str(((json.loads(row["config"] or "{}").get("ftd") or {}).get("username")) or "admin")
            except Exception:
                opts["ftd_username"] = "admin"
        form.update(opts)
        err, moved = m._device_edit(device_id, form)
        if err:
            raise HTTPException(400, err)
        _audit(request, "edited " + ", ".join(sorted(k for k in given if k != "options")
                                              + sorted(f"options.{k}" for k in (body.options or {})))
               + (f", moved to tenant {moved}" if moved else ""), device_id=device_id, reason=body.reason)
        with m.get_engine().connect() as conn:
            return _device_detail(conn, device_id)

    @api.delete("/devices/{device_id}", tags=["devices"], dependencies=FULL,
                summary="Delete a Device and what was imported from it")
    def delete_device(device_id: int, request: Request, reason: str | None = _REASON_Q):
        with m.get_engine().connect() as conn:
            _device_guard(conn, device_id)
            name = conn.execute(text("SELECT COALESCE(display_name, host_name) FROM fw_devices WHERE id = :id"),
                                {"id": device_id}).scalar()
        err = m._device_delete(device_id)
        if err:
            raise HTTPException(409, err)
        _audit(request, f"deleted Device {device_id} ({name})", device_id=device_id, reason=reason)
        return {"device_id": device_id, "deleted": True}

    def _device_job(device_id: int, kind: str, request: Request, reason: str | None, fn, *args) -> JSONResponse:
        with m.get_engine().connect() as conn:
            _device_guard(conn, device_id)
            row = conn.execute(text("SELECT platform FROM fw_devices WHERE id = :id"), {"id": device_id}).fetchone()
            running = conn.execute(text(
                "SELECT job_id FROM fw_deploy_jobs WHERE source_id = :d AND target_id = 0 AND kind = :k "
                "AND status = 'running' ORDER BY created_at DESC LIMIT 1"), {"d": device_id, "k": kind}).scalar()
        if running:
            return JSONResponse({"job_id": running, "status": "running", "already": True, "device_id": device_id},
                                status_code=202)
        job_id = m._start_device_job(device_id, kind, row[0], _client(request), fn, *args)
        _audit(request, f"{kind} started, job {job_id}", device_id=device_id, reason=reason)
        return JSONResponse({"job_id": job_id, "status": "running", "device_id": device_id}, status_code=202)

    @api.post("/devices/{device_id}/import", tags=["devices"], status_code=202, dependencies=FULL,
              summary="Import the Device's configuration (a job)")
    def import_device(device_id: int, request: Request, reason: str | None = _REASON_Q):
        return _device_job(device_id, "import", request, reason, m._import_work, device_id, None, "/devices")

    @api.post("/devices/{device_id}/collect", tags=["devices"], status_code=202, dependencies=FULL,
              summary="Collect the Device's interfaces and routes (a job)")
    def collect_device(device_id: int, request: Request, reason: str | None = _REASON_Q):
        return _device_job(device_id, "collect", request, reason, m._collect_work, device_id)

    # ── phase 2: projects ──────────────────────────────────────────────

    def _project_detail(project_id: int) -> dict:
        with m.get_engine().connect() as conn:
            rows = m._project_rows(conn, project_id=project_id)
        if not rows:
            raise HTTPException(404, f"no project with id {project_id}")
        return _project_view(rows[0])

    @api.post("/projects", tags=["projects"], status_code=201, dependencies=FULL,
              summary="Create a project of a source and a target")
    def create_project(body: ProjectCreateBody, request: Request):
        with m.get_engine().connect() as conn:
            _device_guard(conn, body.source_id)
            _device_guard(conn, body.target_id)
        res = m._project_create(body.source_id, body.target_id, body.name or "")
        if res.status_code != 200:
            return res
        pid = int(_json_of(res).get("project_id") or 0)
        _audit(request, f"created project {pid} ({body.source_id} to {body.target_id})", project_id=pid,
               reason=body.reason)
        return _project_detail(pid)

    @api.patch("/projects/{project_id}", tags=["projects"], dependencies=PROJECT,
               summary="Rename a project or set its status")
    def patch_project(project_id: int, body: ProjectPatchBody, request: Request):
        with m.get_engine().connect() as conn:
            _project_row(conn, project_id)
        if body.name is None and body.status is None:
            raise HTTPException(400, "nothing to change: name or status")
        if body.name is not None:
            res = m._project_rename(project_id, body.name)
            if res.status_code != 200:
                return res
        if body.status is not None:
            res = m._project_set_status(project_id, body.status)
            if res.status_code != 200:
                return res
        _audit(request, "project " + ", ".join(f"{k} {v!r}" for k, v in (("name", body.name), ("status", body.status)) if v is not None),
               project_id=project_id, reason=body.reason)
        return _project_detail(project_id)

    @api.delete("/projects/{project_id}", tags=["projects"], dependencies=FULL,
                summary="Delete a project and every decision it holds")
    def delete_project(project_id: int, request: Request, reason: str | None = _REASON_Q):
        with m.get_engine().connect() as conn:
            p = _project_row(conn, project_id)
        res = m._project_delete(project_id)
        if res.status_code != 200:
            return res
        _audit(request, f"deleted project {project_id} ({p.get('name')})", project_id=project_id, reason=reason)
        return {"project_id": project_id, "deleted": True, "decisions_removed": _json_of(res).get("decisions_removed")}

    @api.post("/projects/{project_id}/refresh", tags=["rules"], status_code=202, dependencies=PROJECT,
              summary="Refresh the ruleset after an import (a job). The build does this on its own")
    def refresh_project(project_id: int, request: Request, reason: str | None = _REASON_Q):
        with m.get_engine().connect() as conn:
            project = _project_row(conn, project_id)
            sid = int(project["source_ref_id"])
            plat = conn.execute(text("SELECT platform FROM fw_devices WHERE id = :id"), {"id": sid}).scalar()
            running = conn.execute(text(
                "SELECT job_id FROM fw_deploy_jobs WHERE source_id = :d AND target_id = 0 AND kind = 'pipeline' "
                "AND status = 'running' ORDER BY created_at DESC LIMIT 1"), {"d": sid}).scalar()
        if running:
            return JSONResponse({"job_id": running, "status": "running", "already": True, "project_id": project_id},
                                status_code=202)
        job_id = m._start_device_job(sid, "pipeline", plat, _client(request), m._pipeline_refresh_work, pass_job_id=True)
        _audit(request, f"ruleset refresh started, job {job_id}", project_id=project_id, device_id=sid, reason=reason)
        return JSONResponse({"job_id": job_id, "status": "running", "project_id": project_id}, status_code=202)

    # ── phase 2: interfaces, rules, exclusions ─────────────────────────

    @api.patch("/projects/{project_id}/interfaces/{iface_id}", tags=["network"], dependencies=PROJECT,
               summary="Rename, skip, bind or retype one interface of the project")
    def patch_interface(project_id: int, iface_id: int, body: InterfaceBody, request: Request):
        given = body.model_dump(exclude_unset=True)
        given.pop("confirm_empty_zone", None)
        given.pop("reason", None)
        if not given:
            raise HTTPException(400, "nothing to change")
        with m.get_engine().connect() as conn:
            _project, _net_did, layer_ids = _scope_of(conn, project_id)
            row = _row_or_404(conn, "fw_interfaces", iface_id, project_id, layer_ids, "interface")
        page_body = {_INTERFACE_FIELD_OF[k]: v for k, v in body.model_dump(exclude_unset=True).items()
                     if k in _INTERFACE_FIELD_OF}
        res = m._interface_update(iface_id, page_body, None, project_id=project_id)
        if res.status_code == 200:
            _audit(request, f"interface {row['interface_name']}: " + ", ".join(f"{k}={v!r}" for k, v in given.items()),
                   project_id=project_id, reason=body.reason)
        return res

    def _hashes_detail(hashes) -> str:
        return ", ".join(str(h)[:40] for h in hashes)

    @api.post("/projects/{project_id}/rules/disable", tags=["rules"], dependencies=PROJECT,
              summary="Disable rules in this project, or enable them again")
    def disable_rules(project_id: int, body: RuleDisableBody, request: Request):
        with m.get_engine().connect() as conn:
            _project_row(conn, project_id)      # the tenant's own project (D24), 404 otherwise
        res = m._rules_set_disabled(body.rule_hashes, body.disabled, None, project_id=project_id)
        if res.status_code == 200:
            _audit(request, f"{'disabled' if body.disabled else 'enabled'} {len(body.rule_hashes)} rule(s): "
                   + _hashes_detail(body.rule_hashes), project_id=project_id, reason=body.reason)
        return res

    @api.post("/projects/{project_id}/rules/exclude", tags=["rules"], dependencies=PROJECT,
              summary="Leave rules out of this project (the project's delete)")
    def exclude_rules(project_id: int, body: RuleHashesBody, request: Request):
        with m.get_engine().connect() as conn:
            _project_row(conn, project_id)
        res = m._rules_exclude(body.rule_hashes, None, project_id=project_id)
        if res.status_code == 200:
            _audit(request, f"excluded {len(body.rule_hashes)} rule(s): " + _hashes_detail(body.rule_hashes),
                   project_id=project_id, reason=body.reason)
        return res

    @api.post("/projects/{project_id}/rules/restore", tags=["rules"], dependencies=PROJECT,
              summary="Bring excluded rules back")
    def restore_rules(project_id: int, body: RuleHashesBody, request: Request):
        wanted = [h.strip().lower() for h in body.rule_hashes if isinstance(h, str) and h.strip()]
        with m.get_engine().connect() as conn:
            _project_row(conn, project_id)
            rows = conn.execute(text(
                "SELECT device_id, item_key FROM fw_project_exclusions "
                "WHERE project_id = :p AND kind = 'rule' AND item_key IN :keys"
            ).bindparams(bindparam("keys", expanding=True)), {"p": project_id, "keys": wanted or [""]}).fetchall()
        found = {str(k).lower(): int(d) for d, k in rows}
        restored = 0
        for h in wanted:
            if h in found:
                res = m._exclusion_restore(project_id, found[h], "rule", h)
                if res.status_code == 200:
                    restored += 1
        if restored:
            _audit(request, f"restored {restored} rule(s): " + _hashes_detail(h for h in wanted if h in found),
                   project_id=project_id, reason=body.reason)
        return {"project_id": project_id, "restored": restored,
                "not_excluded": [h for h in wanted if h not in found]}

    @api.get("/projects/{project_id}/exclusions", tags=["rules"], summary="What this project leaves out, by kind")
    def list_exclusions(project_id: int):
        with m.get_engine().connect() as conn:
            _project_row(conn, project_id)
            rows = m.projview.list_rows(conn, project_id)
        return {"project_id": project_id, "exclusions": rows, "total": len(rows)}

    @api.post("/projects/{project_id}/exclusions/restore", tags=["rules"], dependencies=PROJECT,
              summary="Bring one excluded item back")
    def restore_exclusion(project_id: int, body: ExclusionRestoreBody, request: Request):
        with m.get_engine().connect() as conn:
            _project_row(conn, project_id)
        res = m._exclusion_restore(project_id, body.device_id, body.kind, body.item_key)
        if res.status_code == 200:
            _audit(request, f"restored {body.kind} {body.item_key}", project_id=project_id, reason=body.reason)
        return res

    # ── phase 2c (the MCP catalogue's gaps): target inventory, zones, rule zones, VRFs ──

    _NET_KINDS = ("interfaces", "zones", "vrfs", "routes")

    @api.post("/projects/{project_id}/target-inventory", tags=["network"], dependencies=PROJECT,
              summary="Fetch the target's inventory (interfaces, zones, VRs, routes and the platform's catalogues) from the Device")
    def fetch_target_inventory(project_id: int, request: Request, reason: str | None = _REASON_Q):
        """The Network tab's refresh of the target snapshot: one catalogue after
        the other, as the page does it, a kind the platform has not is skipped,
        a kind the Device refused is named; nothing is written to the Device."""
        with m.get_engine().connect() as conn:
            tid, plat, _sid = _target_of(conn, project_id)
        kinds = list(_NET_KINDS)
        if plat == "panw":
            kinds.append("zone_protection_profiles")
        if plat in ("panw", "fortigate"):
            kinds += ["address_objects", "service_objects"]
        done, skipped, failed, warnings = [], [], [], []
        for kind in kinds:
            res = m.network_discover_run(tid, kind)
            body = _json_of(res) if isinstance(res, JSONResponse) else (res or {})
            if res.status_code < 400:
                done.append(kind)
                for w in body.get("warnings") or []:
                    if w not in warnings:
                        warnings.append(str(w))
            elif body.get("supported") is False:
                skipped.append(kind)
            else:
                failed.append({"kind": kind, "error": str(body.get("error") or f"HTTP {res.status_code}")})
        if done:
            _audit(request, f"target inventory fetched: {', '.join(done)}" + (f", failed: {', '.join(f['kind'] for f in failed)}" if failed else ""),
                   project_id=project_id, device_id=tid, reason=reason)
        if failed and not done:
            raise HTTPException(502, "the target did not answer: " + "; ".join(f"{f['kind']}: {f['error']}" for f in failed)[:600])
        return {"project_id": project_id, "target_id": tid, "platform": plat, "fetched": done, "not_on_this_platform": skipped,
                "failed": failed, "warnings": warnings}

    @api.post("/projects/{project_id}/zones", tags=["network"], status_code=201, dependencies=PROJECT,
              summary="Create the project's own zone")
    def create_zone(project_id: int, body: ZoneCreateBody, request: Request):
        with m.get_engine().connect() as conn:
            project = _project_row(conn, project_id)
            net_did, _layers, _view, _nm = _net_scope(conn, project)
        res = m._zone_create(body.name, body.color or "blue", net_did, None, project_id=project_id)
        if res.status_code != 200:
            return res
        _audit(request, f"zone {body.name} created", project_id=project_id, reason=body.reason)
        return JSONResponse({"project_id": project_id, "zone": body.name, "id": _json_of(res).get("id")}, status_code=201)

    @api.delete("/projects/{project_id}/rule-zones", tags=["rules"], dependencies=PROJECT,
                summary="Reset the project's rule zone overrides, derived and manual")
    def reset_rule_zones(project_id: int, request: Request, reason: str | None = _REASON_Q):
        with m.get_engine().connect() as conn:
            project = _project_row(conn, project_id)
        res = m._zone_overrides_reset(int(project["source_ref_id"]), None, project_id=project_id)
        if res.status_code == 200:
            _audit(request, f"rule zone overrides reset: {_json_of(res).get('deleted')} removed", project_id=project_id, reason=reason)
        return res

    @api.post("/projects/{project_id}/rule-zones/auto", tags=["rules"], dependencies=PROJECT,
              summary="Derive every rule's zones from the routes (manual picks stay)")
    def derive_rule_zones(project_id: int, request: Request, reason: str | None = _REASON_Q):
        with m.get_engine().connect() as conn:
            project = _project_row(conn, project_id)
        res = m._zones_auto_map(int(project["source_ref_id"]), None, project_id=project_id)
        if res.status_code == 200:
            b = _json_of(res)
            _audit(request, f"rule zones derived: {b.get('mapped')} mapped, {b.get('skipped_manual')} manual kept, "
                            f"{b.get('no_match')} without a match", project_id=project_id, reason=reason)
        return res

    @api.get("/projects/{project_id}/vrfs", tags=["network"], summary="The project's virtual routers")
    def list_vrfs(project_id: int):
        with m.get_engine().connect() as conn:
            project = _project_row(conn, project_id)
            net_did, layers, view, _nm = _net_scope(conn, project)
            rows = m._load_vrfs(conn, layers, net_did, view=view)
        out = [{k: r.get(k) for k in ("id", "name", "description", "device_id", "project_id") if k in r} for r in rows]
        return {"project_id": project_id, "network_device_id": net_did, "vrfs": out, "total": len(out)}

    # ── the reads of stage 2 ───

    @api.get("/projects/{project_id}/routes", tags=["network"], summary="The project's routes as the Network tab shows them")
    def list_routes(project_id: int):
        with m.get_engine().connect() as conn:
            project = _project_row(conn, project_id)
            net_did, layers, view, name_map = _net_scope(conn, project)
            ifaces = m._load_interfaces(conn, layers, net_did, view=view, zone_sentinel_none=True)
            rows = m._load_routes(conn, layers, net_did, view=view, interfaces=ifaces)
            m.namemap.map_routes(name_map, rows)
        out = [{"id": r.get("id"), "prefix": r.get("prefix"), "interface": r.get("interface_name"),
                "next_hop": r.get("next_hop"), "vr": r.get("vr_name") or "default", "metric": r.get("metric"),
                "route_type": r.get("route_type") or "static", "zone": r.get("zone_name"),
                "device_id": r.get("device_id"), "edited": bool(r.get("edited")),
                "own": _own(r, project_id)} for r in rows]
        return {"project_id": project_id, "network_device_id": net_did, "routes": out, "total": len(out)}

    _NAT_KEYS = ("id", "nat_hash", "position", "name", "nat_type", "disabled", "src_zones", "dst_zones",
                 "orig_src", "orig_dst", "orig_service", "trans_src", "trans_src_type", "trans_dst",
                 "trans_dst_port", "description", "properties", "negate_source", "negate_destination",
                 "negate_service", "disabled_override_source", "zone_override_source",
                 "description_override_source", "properties_override_source", "negate_override_source")

    @api.get("/projects/{project_id}/nat-rules", tags=["network"], summary="The project's NAT rules as the NAT tab shows them")
    def list_nat_rules(project_id: int):
        with m.get_engine().connect() as conn:
            project = _project_row(conn, project_id)
            source_id = int(project["source_ref_id"])
            nat_did = m._nat_source_device_id(conn, source_id)
            name_map = m.namemap.load_name_map(conn, project_id)
            rows = m._load_nat_rules(conn, source_id, project_id, name_map)
        out = []
        for r in rows:
            row = {k: r.get(k) for k in _NAT_KEYS}
            row["interface"] = r.get("interface_name")
            for k in ("disabled", "negate_source", "negate_destination", "negate_service"):
                row[k] = bool(row.get(k))
            row["own"] = _own(r, project_id)
            out.append(row)
        return {"project_id": project_id, "nat_device_id": nat_did, "nat_rules": out, "total": len(out)}

    @api.get("/projects/{project_id}/snapshots", tags=["projects"], summary="The project's snapshots, newest first")
    def list_snapshots(project_id: int):
        with m.get_engine().connect() as conn:
            _project_row(conn, project_id)
            rows = m._snapshot_rows(conn, project_id)
            now = m._import_marks(conn, project_id)
        out = []
        for r in rows:
            try:
                then = json.loads(r.get("import_marks") or "{}")
            except Exception:
                then = {}
            out.append({"id": r.get("id"), "name": r.get("name"), "kind": r.get("kind"), "note": r.get("note"),
                        "created_at": str(r["created_at"]) if r.get("created_at") else None,
                        "rows": r.get("row_count"), "source_changed": bool(then) and then != now})
        return {"project_id": project_id, "snapshots": out, "total": len(out)}

    @api.get("/projects/{project_id}/kinds/{kind}", tags=["network"],
             summary="The fields of one kind for add, edit and delete, with the target's property keys")
    def describe_kind(project_id: int, kind: str):
        spec = _kinds.KINDS.get(str(kind or "").strip())
        if not spec:
            raise HTTPException(404, f"no kind {kind}, the kinds are {', '.join(_kinds.KINDS)}")
        with m.get_engine().connect() as conn:
            _tid, platform, _sid = _target_of(conn, project_id)
        out = {"project_id": project_id, "kind": kind, "key": spec["key"], "target_platform": platform,
               "add": spec.get("add"), "edit": spec.get("edit"), "delete": spec.get("delete")}
        schema = spec.get("properties_schema")
        if schema:
            table = m.zone_schema_for(platform) if schema == "zone" else m.nat_schema_for(platform)
            out["property_keys"] = [{"key": f.get("key"), "label": f.get("label"), "type": f.get("type"),
                                     "options": f.get("options")} for f in (table.get("fields") or []) if f.get("key")]
        return out

    # ── the writes of stage 2 ──

    def _scope_of(conn, project_id: int) -> tuple[dict, int, list[int]]:
        """The project, its network scope Device and the scope's layer ids."""
        project = _project_row(conn, project_id)
        net_did, layers, _view, _nm = _net_scope(conn, project)
        return project, net_did, [int(lid) for lid, _n in layers]

    def _row_or_404(conn, table: str, row_id: int, project_id: int, layer_ids: list[int], what: str) -> dict:
        """The row the project may address (D4): on its scope and a fact or
        its own addition, 404 otherwise (another tenant's row and another
        project's addition on the same Device read as absent)."""
        row = m._scoped_row(conn, table, row_id, project_id, layer_ids)
        if not row:
            raise HTTPException(404, f"no {what} with id {row_id} in this project")
        return row

    def _page_fields(given: dict, kind: str) -> dict:
        names = _PAGE_FIELD_OF.get(kind) or {}
        return {names.get(k, k): v for k, v in given.items() if k != "reason"}

    def _property_keys_check(properties, platform: str, schema: str) -> None:
        """400 with the platform's keys for a property key the target's
        schema does not know (the page keeps ignoring it, D4)."""
        if not isinstance(properties, dict):
            return
        allowed = m.zone_field_keys(platform) if schema == "zone" else m.nat_field_keys(platform)
        unknown = sorted(k for k in properties if k not in allowed)
        if unknown:
            raise HTTPException(400, f"{', '.join(unknown)}: not a {schema} property of {platform or 'this target'}, "
                                     f"the keys are {', '.join(sorted(allowed)) or 'none'}")

    def _hex40_or_400(h: str) -> str:
        s = str(h or "").strip().lower()
        if len(s) != 40 or any(c not in "0123456789abcdef" for c in s):
            raise HTTPException(400, "nat_hash must be 40 hex characters")
        return s

    def _nat_scope_of(conn, project_id: int) -> tuple[dict, int, str]:
        project = _project_row(conn, project_id)
        nat_did = m._nat_source_device_id(conn, int(project["source_ref_id"]))
        plat = conn.execute(text("SELECT platform FROM fw_devices WHERE id = :id"),
                            {"id": int(project["target_ref_id"])}).scalar() or ""
        return project, int(nat_did), str(plat)

    def _nat_rows_by_hash(conn, project_id: int, nat_did: int, hashes: list[str]) -> dict[str, list[dict]]:
        """The project's NAT rules under each hash (several when two imported
        rules share the inputs, the hash excludes the name)."""
        out: dict[str, list[dict]] = {h: [] for h in hashes}
        for h in hashes:
            out[h] = m._scoped_rows(conn, "fw_nat_rules", "device_id = :d AND nat_hash = UNHEX(:h)",
                                    {"d": nat_did, "h": h}, project_id, [nat_did])
        return out

    def _one_nat_row(conn, project_id: int, nat_did: int, nat_hash: str) -> dict:
        rows = _nat_rows_by_hash(conn, project_id, nat_did, [nat_hash])[nat_hash]
        if not rows:
            raise HTTPException(404, f"no NAT rule with hash {nat_hash} in this project")
        if len(rows) > 1:
            raise HTTPException(409, f"ambiguous: {len(rows)} NAT rules share this hash ("
                                     f"{', '.join(str(r.get('name')) for r in rows)}), delete and add instead")
        return rows[0]

    @api.post("/projects/{project_id}/interfaces", tags=["network"], status_code=201, dependencies=PROJECT,
              summary="Add the project's own interface (with its zone and connected routes)")
    def add_interface(project_id: int, body: InterfaceAddBody, request: Request):
        with m.get_engine().connect() as conn:
            _project, net_did, _layers = _scope_of(conn, project_id)
        res = m._interface_add(_page_fields(body.model_dump(exclude_unset=True), "interface"), None,
                               project_id=project_id, net_did=net_did)
        if res.status_code != 200:
            return res
        _audit(request, f"added 1 interface: {body.name}", project_id=project_id, reason=body.reason)
        return JSONResponse({"project_id": project_id, **_json_of(res)}, status_code=201)

    @api.delete("/projects/{project_id}/interfaces/{iface_id}", tags=["network"], dependencies=PROJECT,
                summary="Delete an interface in this project (an imported one becomes an exclusion)")
    def delete_interface(project_id: int, iface_id: int, request: Request,
                         confirm_empty_zone: int = Query(0, ge=0, le=1), reason: str | None = _REASON_Q):
        with m.get_engine().connect() as conn:
            project, net_did, layer_ids = _scope_of(conn, project_id)
            row = _row_or_404(conn, "fw_interfaces", iface_id, project_id, layer_ids, "interface")
        res = m._interface_delete(iface_id, None, project_id=project_id, net_did=net_did,
                                  confirm_empty_zone=bool(confirm_empty_zone),
                                  target_device_id=int(project["target_ref_id"]))
        return _answer(res, request, f"deleted 1 interface: {row['interface_name']}", project_id, reason)

    @api.post("/projects/{project_id}/routes", tags=["network"], status_code=201, dependencies=PROJECT,
              summary="Add the project's own route")
    def add_route(project_id: int, body: RouteAddBody, request: Request):
        with m.get_engine().connect() as conn:
            _project, net_did, _layers = _scope_of(conn, project_id)
        res = m._route_add(_page_fields(body.model_dump(exclude_unset=True), "route"), None,
                           project_id=project_id, net_did=net_did)
        if res.status_code != 200:
            return res
        out = _json_of(res)
        _audit(request, f"added 1 route: {out.get('prefix')} in {out.get('vr')}", project_id=project_id, reason=body.reason)
        return JSONResponse({"project_id": project_id, **out}, status_code=201)

    @api.patch("/projects/{project_id}/routes/{route_id}", tags=["network"], dependencies=PROJECT,
               summary="Edit a route in this project (a new prefix is an exclusion plus an addition)")
    def patch_route(project_id: int, route_id: int, body: RouteEditBody, request: Request):
        given = body.model_dump(exclude_unset=True)
        given.pop("reason", None)
        if not given:
            raise HTTPException(400, "nothing to change")
        with m.get_engine().connect() as conn:
            _project, _net_did, layer_ids = _scope_of(conn, project_id)
            row = _row_or_404(conn, "fw_routes", route_id, project_id, layer_ids, "route")
        res = m._route_update(route_id, _page_fields(given, "route"), None, project_id=project_id)
        return _answer(res, request, f"edited 1 route: {row['prefix']}: " + ", ".join(f"{k}={v!r}" for k, v in given.items()),
                       project_id, body.reason)

    @api.delete("/projects/{project_id}/routes/{route_id}", tags=["network"], dependencies=PROJECT,
                summary="Delete a route in this project (an imported one becomes an exclusion)")
    def delete_route(project_id: int, route_id: int, request: Request, reason: str | None = _REASON_Q):
        with m.get_engine().connect() as conn:
            _project, net_did, layer_ids = _scope_of(conn, project_id)
            row = _row_or_404(conn, "fw_routes", route_id, project_id, layer_ids, "route")
        res = m._route_delete(route_id, None, project_id=project_id, net_did=net_did)
        return _answer(res, request, f"deleted 1 route: {row['prefix']}", project_id, reason)

    @api.post("/projects/{project_id}/vrfs", tags=["network"], status_code=201, dependencies=PROJECT,
              summary="Add the project's own virtual router")
    def add_vrf(project_id: int, body: VrfAddBody, request: Request):
        with m.get_engine().connect() as conn:
            _project, net_did, _layers = _scope_of(conn, project_id)
        res = m._vrf_add({"name": body.name}, None, project_id=project_id, net_did=net_did)
        if res.status_code != 200:
            return res
        _audit(request, f"added 1 virtual router: {body.name}", project_id=project_id, reason=body.reason)
        return JSONResponse({"project_id": project_id, **_json_of(res)}, status_code=201)

    @api.patch("/projects/{project_id}/zones/{zone_id}", tags=["network"], dependencies=PROJECT,
               summary="Edit a zone's colour, external flag or properties in this project (the name goes through /rename)")
    def patch_zone(project_id: int, zone_id: int, body: ZoneEditBody, request: Request):
        given = body.model_dump(exclude_unset=True)
        given.pop("reason", None)
        if not given:
            raise HTTPException(400, "nothing to change")
        with m.get_engine().connect() as conn:
            _project, _net_did, layer_ids = _scope_of(conn, project_id)
            row = _row_or_404(conn, "fw_zones", zone_id, project_id, layer_ids, "zone")
            _tid, plat, _sid = _target_of(conn, project_id)
        _property_keys_check(given.get("properties"), plat, "zone")
        res = m._zone_patch(zone_id, {**given, "target_platform": plat}, None, project_id=project_id)
        return _answer(res, request, f"edited 1 zone: {row['name']}: " + ", ".join(f"{k}={v!r}" for k, v in given.items()),
                       project_id, body.reason)

    @api.post("/projects/{project_id}/zones/properties", tags=["network"], dependencies=PROJECT,
              summary="Set properties on up to fifty zones of this project")
    def zones_properties(project_id: int, body: ZonesBulkBody, request: Request):
        with m.get_engine().connect() as conn:
            _project, _net_did, layer_ids = _scope_of(conn, project_id)
            _tid, plat, _sid = _target_of(conn, project_id)
            rows = [r for zid in body.zone_ids
                    for r in m._scoped_rows(conn, "fw_zones", "id = :id", {"id": int(zid)}, project_id, layer_ids)]
        _property_keys_check(body.properties, plat, "zone")
        kept = [int(r["id"]) for r in rows]
        dropped = [int(z) for z in body.zone_ids if int(z) not in set(kept)]
        if not kept:
            raise HTTPException(404, "none of the zones is in this project")
        res = m._zones_bulk({"zone_ids": kept, "properties": body.properties, "target_platform": plat}, None,
                            project_id=project_id)
        if res.status_code != 200:
            return res
        out = _json_of(res)
        _audit(request, f"edited {out.get('updated', 0)} zones: properties {', '.join(sorted(body.properties))}",
               project_id=project_id, reason=body.reason)
        return {"project_id": project_id, "updated": out.get("updated", 0), "not_in_project": dropped}

    @api.delete("/projects/{project_id}/zones/{zone_id}", tags=["network"], dependencies=PROJECT,
                summary="Delete a zone in this project (cascade=1 moves its rules to the members first, after an auto-snapshot)")
    def delete_zone(project_id: int, zone_id: int, request: Request, cascade: int = Query(0, ge=0, le=1),
                    reason: str | None = _REASON_Q):
        with m.get_engine().connect() as conn:
            _project, net_did, layer_ids = _scope_of(conn, project_id)
            row = _row_or_404(conn, "fw_zones", zone_id, project_id, layer_ids, "zone")
        res = m._zone_delete(zone_id, None, project_id=project_id, net_did=net_did, cascade=bool(cascade))
        return _answer(res, request, f"deleted 1 zone: {row['name']}" + (" (cascade)" if cascade else ""), project_id, reason)

    @api.post("/projects/{project_id}/nat-rules", tags=["network"], status_code=201, dependencies=PROJECT,
              summary="Add the project's own NAT rule (names in project space)")
    def add_nat_rule(project_id: int, body: NatAddBody, request: Request):
        with m.get_engine().connect() as conn:
            _project, nat_did, _plat = _nat_scope_of(conn, project_id)
        res = m._nat_rule_add(_page_fields(body.model_dump(exclude_unset=True), "nat_rule"), None,
                              project_id=project_id, nat_did=nat_did)
        if res.status_code != 200:
            return res
        _audit(request, f"added 1 NAT rule: {body.name}", project_id=project_id, reason=body.reason)
        return JSONResponse({"project_id": project_id, **_json_of(res)}, status_code=201)

    @api.patch("/projects/{project_id}/nat-rules/{nat_hash}", tags=["network"], dependencies=PROJECT,
               summary="Edit a NAT rule in this project by its hash (name, description, disabled, properties, the zone overlay, the negates)")
    def patch_nat_rule(project_id: int, nat_hash: str, body: NatEditBody, request: Request):
        nat_hash = _hex40_or_400(nat_hash)
        given = body.model_dump(exclude_unset=True)
        given.pop("reason", None)
        if not given:
            raise HTTPException(400, "nothing to change")
        with m.get_engine().connect() as conn:
            _project, nat_did, plat = _nat_scope_of(conn, project_id)
            row = _one_nat_row(conn, project_id, nat_did, nat_hash)
        _property_keys_check(given.get("properties"), plat, "nat")
        res = m._nat_rule_patch(int(row["id"]), {**given, "target_platform": plat}, None, project_id=project_id)
        return _answer(res, request, f"edited 1 NAT rule: {row['name']}: " + ", ".join(f"{k}={v!r}" for k, v in given.items()),
                       project_id, body.reason)

    @api.post("/projects/{project_id}/nat-rules/bulk", tags=["network"], dependencies=PROJECT,
              summary="Set disabled, description, properties or the zone overlay on up to fifty NAT rules by hash")
    def nat_rules_bulk(project_id: int, body: NatBulkBody, request: Request):
        hashes = [_hex40_or_400(h) for h in body.nat_hashes]
        given = body.model_dump(exclude_unset=True)
        given.pop("reason", None)
        given.pop("nat_hashes", None)
        if not given:
            raise HTTPException(400, "nothing to change")
        with m.get_engine().connect() as conn:
            _project, nat_did, plat = _nat_scope_of(conn, project_id)
            found = _nat_rows_by_hash(conn, project_id, nat_did, hashes)
        _property_keys_check(given.get("properties"), plat, "nat")
        ids = [int(r["id"]) for h in hashes for r in found[h]]
        missing = [h for h in hashes if not found[h]]
        if not ids:
            raise HTTPException(404, "none of the NAT rules is in this project")
        page = {"rule_ids": ids, "target_platform": plat, **given}
        for key in ("src_zone", "dst_zone"):     # the page's word for clearing the overlay
            if key in page and not str(page[key] or "").strip():
                page[key] = "__clear__"
        res = m._nat_rules_bulk(page, None, project_id=project_id)
        if res.status_code != 200:
            return res
        out = _json_of(res)
        _audit(request, f"edited {out.get('updated', 0)} NAT rules: " + ", ".join(f"{k}={v!r}" for k, v in given.items()),
               project_id=project_id, reason=body.reason)
        return {"project_id": project_id, "updated": out.get("updated", 0), "not_in_project": missing}

    @api.put("/projects/{project_id}/nat-rules/negate", tags=["network"], dependencies=PROJECT,
             summary="Set one negate flag on up to fifty NAT rules by hash")
    def nat_rules_negate(project_id: int, body: NatNegateBody, request: Request):
        hashes = [_hex40_or_400(h) for h in body.nat_hashes]
        with m.get_engine().connect() as conn:
            _project, nat_did, _plat = _nat_scope_of(conn, project_id)
            found = _nat_rows_by_hash(conn, project_id, nat_did, hashes)
        ids = [int(r["id"]) for h in hashes for r in found[h]]
        missing = [h for h in hashes if not found[h]]
        if not ids:
            raise HTTPException(404, "none of the NAT rules is in this project")
        done = 0
        for rid in ids:
            res = m._nat_negate_set(rid, body.aspect, body.value, None, project_id=project_id)
            if res.status_code != 200:
                return res
            done += 1
        _audit(request, f"negated {done} NAT rules: {body.aspect}={body.value}", project_id=project_id, reason=body.reason)
        return {"project_id": project_id, "updated": done, "aspect": body.aspect, "value": body.value, "not_in_project": missing}

    @api.delete("/projects/{project_id}/nat-rules/{nat_hash}", tags=["network"], dependencies=PROJECT,
                summary="Delete a NAT rule in this project (an imported one becomes an exclusion)")
    def delete_nat_rule(project_id: int, nat_hash: str, request: Request, reason: str | None = _REASON_Q):
        nat_hash = _hex40_or_400(nat_hash)
        with m.get_engine().connect() as conn:
            _project, nat_did, _plat = _nat_scope_of(conn, project_id)
            row = _one_nat_row(conn, project_id, nat_did, nat_hash)
        res = m._nat_rule_delete(int(row["id"]), None, project_id=project_id)
        return _answer(res, request, f"deleted 1 NAT rule: {row['name']}", project_id, reason)

    @api.post("/projects/{project_id}/snapshots", tags=["projects"], status_code=201, dependencies=PROJECT,
              summary="Take a snapshot of the project's decisions")
    def create_snapshot(project_id: int, body: SnapshotCreateBody, request: Request):
        with m.get_engine().connect() as conn:
            _project_row(conn, project_id)
        res = m._snapshot_create_run(project_id, body.name, body.note)
        if res.status_code != 200:
            return res
        out = _json_of(res)
        _audit(request, f"created 1 snapshot: {body.name}", project_id=project_id, reason=body.reason)
        return JSONResponse({"project_id": project_id, **out}, status_code=201)

    @api.post("/projects/{project_id}/snapshots/{snapshot_id}/restore", tags=["projects"], dependencies=PROJECT,
              summary="Restore the project's decisions from a snapshot (an auto-snapshot is taken first)")
    def restore_snapshot(project_id: int, snapshot_id: int, request: Request, reason: str | None = _REASON_Q):
        with m.get_engine().connect() as conn:
            _project_row(conn, project_id)
        res = m._snapshot_restore_run(project_id, snapshot_id)
        return _answer(res, request, f"restored 1 snapshot: {_json_of(res).get('snapshot')}", project_id, reason)

    @api.delete("/projects/{project_id}/snapshots/{snapshot_id}", tags=["projects"], dependencies=PROJECT,
                summary="Delete a snapshot (the Original and the auto-snapshots stay)")
    def delete_snapshot(project_id: int, snapshot_id: int, request: Request, reason: str | None = _REASON_Q):
        with m.get_engine().connect() as conn:
            _project_row(conn, project_id)
        res = m._snapshot_delete_run(project_id, snapshot_id, refuse_auto=True)
        return _answer(res, request, f"deleted 1 snapshot: {_json_of(res).get('name')}", project_id, reason)

    @api.post("/projects/{project_id}/snapshots/{snapshot_id}/branch", tags=["projects"], status_code=201,
              dependencies=FULL, summary="A new project of the pair from this snapshot's decisions")
    def branch_snapshot(project_id: int, snapshot_id: int, body: BranchBody, request: Request):
        with m.get_engine().connect() as conn:
            _project_row(conn, project_id)
        res = m._snapshot_branch_run(project_id, snapshot_id, body.name)
        if res.status_code != 200:
            return res
        out = _json_of(res)
        _audit(request, f"branched 1 snapshot: {out.get('snapshot')} into project {out.get('project_id')}",
               project_id=project_id, reason=body.reason)
        return JSONResponse({"source_project_id": project_id, **out}, status_code=201)

    @api.delete("/projects/{project_id}/vrfs/{name}", tags=["network"], dependencies=PROJECT,
                summary="Delete a virtual router in this project (an imported one becomes an exclusion)")
    def delete_vrf(project_id: int, name: str, request: Request, reason: str | None = _REASON_Q):
        with m.get_engine().connect() as conn:
            project = _project_row(conn, project_id)
            net_did, layers, view, _nm = _net_scope(conn, project)
            rows = m._load_vrfs(conn, layers, net_did, view=view)
        hit = next((r for r in rows if r.get("name") == name), None)
        if not hit or not hit.get("id"):
            raise HTTPException(404, f"no virtual router named {name} in this project")
        res = m._vrf_delete(int(hit["id"]), None, project_id=project_id)
        if res.status_code == 200:
            _audit(request, f"virtual router {name} deleted", project_id=project_id, reason=reason)
        return res

    # ── phase 2: push settings and the keys of the tunnels ─────────────

    def _target_of(conn, project_id: int) -> tuple[int, str, int]:
        project = _project_row(conn, project_id)
        tid = int(project["target_ref_id"])
        plat = conn.execute(text("SELECT platform FROM fw_devices WHERE id = :id"), {"id": tid}).scalar() or ""
        return tid, str(plat), int(project["source_ref_id"])

    @api.get("/projects/{project_id}/settings", tags=["deploy"], summary="The target's push settings with the project's values")
    def get_settings(project_id: int):
        with m.get_engine().connect() as conn:
            tid, plat, _sid = _target_of(conn, project_id)
        return m._deploy_settings_view(tid, plat, project_id)

    @api.put("/projects/{project_id}/settings", tags=["deploy"], dependencies=PROJECT,
             summary="Set push settings of the target for this project")
    def put_settings(project_id: int, body: SettingsBody, request: Request):
        with m.get_engine().connect() as conn:
            tid, plat, _sid = _target_of(conn, project_id)
        res = m._deploy_settings_save(tid, plat, dict(body.settings), None, project_id=project_id)
        if res.status_code == 200:
            _audit(request, "settings " + ", ".join(f"{k}={v!r}" for k, v in sorted(body.settings.items())),
                   project_id=project_id, reason=body.reason)
        return res

    @api.get("/projects/{project_id}/vpn", tags=["network"], summary="The source's VPN tunnels and whether a key is stored")
    def list_vpn(project_id: int):
        with m.get_engine().connect() as conn:
            _tid, _plat, sid = _target_of(conn, project_id)
            rows = conn.execute(text(
                "SELECT LOWER(HEX(t.vpn_hash)) AS vpn_hash, t.name, t.disabled, t.peer_address, t.peer_type, "
                "t.auth_type, t.ike_version, t.local_interface, t.tunnel_interface, "
                "(s.tunnel_name IS NOT NULL) AS psk_set "
                "FROM fw_vpn_tunnels t LEFT JOIN fw_vpn_tunnel_secrets s "
                "  ON s.device_id = t.device_id AND s.tunnel_name = t.name "
                "WHERE t.device_id = :d ORDER BY t.position, t.id"), {"d": sid}).mappings().all()
        out = [{"vpn_hash": r["vpn_hash"], "name": r["name"], "disabled": bool(r["disabled"]),
                "peer_address": r["peer_address"], "peer_type": r["peer_type"], "auth_type": r["auth_type"],
                "ike_version": r["ike_version"], "local_interface": r["local_interface"],
                "tunnel_interface": r["tunnel_interface"], "psk_set": bool(r["psk_set"])} for r in rows]
        return {"project_id": project_id, "source_id": sid, "tunnels": out, "total": len(out)}

    @api.put("/projects/{project_id}/vpn/{vpn_hash}/psk", tags=["network"], dependencies=FULL,
             summary="Set or clear a tunnel's pre-shared key (never read back)")
    def put_psk(project_id: int, vpn_hash: str, body: PskBody, request: Request):
        with m.get_engine().connect() as conn:
            _tid, plat, sid = _target_of(conn, project_id)
        res = m._vpn_psk_set({"device_id": sid, "vpn_hash": vpn_hash, "psk": body.psk, "target_platform": plat})
        if res.status_code == 200:
            _audit(request, f"tunnel {vpn_hash[:12]}: key {'set' if body.psk.strip() else 'cleared'}",
                   project_id=project_id, reason=body.reason)
        return res

    # ── phase 2: the audit (D8) ────────────────────────────────────────


    # ── the curation stage: objects, names, rule fields, order, catalogues ──

    _OBJECT_KINDS = ("address", "service", "address_group", "service_group", "schedule")
    # the fields a target's renderer reads (D6): absent means every renderer reads it
    _FIELD_READERS = {
        "logging": {"panw": ("profile", "log_start", "log_end"), "fortigate": ("log_traffic", "log_start", "capture_packet")},
        "track": {"checkpoint": ()},
        "profiles": {"panw": (), "fortigate": ()},
    }

    def _field_platform_check(plat: str, field: str, given: list[str] | None = None) -> None:
        readers = _FIELD_READERS.get(field)
        if readers is None:
            return
        if plat not in readers:
            raise HTTPException(400, f"the {plat} renderer does not read {field}")
        allowed = readers[plat]
        for g in given or []:
            if allowed and g not in allowed:
                raise HTTPException(400, f"the {plat} renderer does not read {field}.{g} (it reads {', '.join(allowed)})")

    def _rule_hashes(raw: list, cap: int = 50) -> list[str]:
        out: list[str] = []
        for h in raw or []:
            s = str(h or "").strip().lower()
            if len(s) != 40 or any(c not in "0123456789abcdef" for c in s):
                raise HTTPException(400, f"not a rule hash: {s[:48]}")
            if s not in out:
                out.append(s)
        if not out:
            raise HTTPException(400, "rule_hashes is empty")
        if len(out) > cap:
            raise HTTPException(400, f"at most {cap} rules a call")
        return out

    def _pair_of(conn, project_id: int) -> tuple[int, int, str]:
        tid, plat, sid = _target_of(conn, project_id)
        return sid, tid, plat

    def _answer(res: JSONResponse, request: Request, detail: str, project_id: int, reason: str | None,
                device_id: int | None = None):
        """The shared function's answer passes through, a success is audited."""
        if res.status_code < 400:
            _audit(request, detail, project_id=project_id, device_id=device_id, reason=reason)
        return res

    @api.get("/projects/{project_id}/objects", tags=["objects"],
             summary="The project's objects of one kind as the Objects tab shows them, paged")
    def list_objects(project_id: int, kind: str = Query("address"), q: str = Query(""),
                     limit: int = Query(200, ge=1, le=1000), offset: int = Query(0, ge=0),
                     flags: int = Query(0, ge=0, le=1)):
        if kind not in _OBJECT_KINDS:
            raise HTTPException(400, f"kind must be one of {', '.join(_OBJECT_KINDS)}")
        with m.get_engine().connect() as conn:
            sid, _tid, _plat = _pair_of(conn, project_id)
            rows = m._objects_list(conn, sid, kind, q, 100000, project_id)
            lint = m._object_lint_flags(conn, sid, project_id).get(kind, {}).get("row_flags", {}) if flags else {}
        if flags:
            for r in rows:
                r["flags"] = lint.get(str(r.get("id")), [])
        return {"project_id": project_id, "device_id": sid, "kind": kind, "objects": rows[offset:offset + limit],
                "total": len(rows), "limit": limit, "offset": offset}

    @api.patch("/projects/{project_id}/objects/{kind}/{obj_id}", tags=["objects"], dependencies=PROJECT,
               summary="Rename an object in this project (a row of the project's name map)")
    def rename_object(project_id: int, kind: str, obj_id: int, body: ObjectRenameBody, request: Request):
        if kind not in ("address", "service", "address_group", "service_group"):
            raise HTTPException(400, "kind must be address, service, address_group or service_group")
        with m.get_engine().connect() as conn:
            sid, _tid, _plat = _pair_of(conn, project_id)
            info = m._resolve_object(conn, kind, obj_id)
        if not info or int(info[0]) != sid:
            raise HTTPException(404, f"no {kind} with id {obj_id} on the project's source")
        res = m._object_rename(kind, obj_id, body.name, project_id)
        return _answer(res, request, f"{kind} {info[1]} shown as {body.name}", project_id, body.reason, device_id=sid)

    @api.delete("/projects/{project_id}/objects/{kind}/{obj_id}", tags=["objects"], dependencies=PROJECT,
                summary="Leave one object out of this project (the project's delete)")
    async def delete_object(project_id: int, kind: str, obj_id: int, request: Request, reason: str | None = _REASON_Q):
        if kind not in _OBJECT_KINDS:
            raise HTTPException(400, f"kind must be one of {', '.join(_OBJECT_KINDS)}")
        with m.get_engine().connect() as conn:
            sid, _tid, _plat = _pair_of(conn, project_id)
            info = m._resolve_object(conn, kind, obj_id)
        if not info or int(info[0]) != sid:
            raise HTTPException(404, f"no {kind} with id {obj_id} on the project's source")
        res = await m._delete_object(kind, obj_id, None, project_id=project_id)
        return _answer(res, request, f"{kind} {info[1]} excluded", project_id, reason, device_id=sid)

    @api.post("/projects/{project_id}/objects/delete", tags=["objects"], dependencies=PROJECT,
              summary="Leave objects out of this project, with the partition first (dry_run)")
    def delete_objects(project_id: int, body: ObjectsDeleteBody, request: Request):
        with m.get_engine().connect() as conn:
            sid, _tid, _plat = _pair_of(conn, project_id)
        items = [{"kind": it.kind, "id": it.id} for it in body.items]
        res = m._objects_bulk_delete(sid, items, body.dry_run, None, project_id=project_id)
        if body.dry_run or res.status_code >= 400:
            return res
        b = _json_of(res)
        return _answer(res, request, f"excluded {len(b.get('deleted') or [])} object(s), {len(b.get('blocked') or [])} blocked",
                       project_id, body.reason, device_id=sid)

    @api.post("/projects/{project_id}/objects/merge", tags=["objects"], dependencies=PROJECT,
              summary="Merge objects into canonicals (the losers map to the canonical's name and leave the view)")
    def merge_objects(project_id: int, body: ObjectsMergeBody, request: Request):
        if body.kind not in ("address", "service"):
            raise HTTPException(400, "kind must be address or service")
        with m.get_engine().connect() as conn:
            sid, _tid, _plat = _pair_of(conn, project_id)
        buckets = [{"canonical": b.canonical, "losers": b.losers} for b in body.buckets]
        res = m._objects_merge(sid, body.kind, buckets, body.dry_run, None, project_id=project_id)
        if body.dry_run or res.status_code >= 400:
            return res
        b = _json_of(res)
        return _answer(res, request, f"merged {b.get('deleted')} {body.kind} object(s), {b.get('refs_rewritten')} references follow",
                       project_id, body.reason, device_id=sid)

    @api.get("/projects/{project_id}/names", tags=["objects"], summary="The project's name map (what it shows under another name)")
    def list_names(project_id: int, kind: str | None = Query(None)):
        with m.get_engine().connect() as conn:
            sid, _tid, _plat = _pair_of(conn, project_id)
            rows = m._project_names(conn, project_id, sid)
        if kind:
            rows = [r for r in rows if r.get("kind") == kind]
        for r in rows:
            if r.get("updated_at") is not None:
                r["updated_at"] = str(r["updated_at"])
        return {"project_id": project_id, "names": rows, "total": len(rows)}

    @api.post("/projects/{project_id}/rename", tags=["objects"], dependencies=PROJECT,
              summary="The naming workbench: a scheme over a selection, planned as a set, written when dry_run is false")
    def rename_items(project_id: int, body: RenameBody, request: Request):
        with m.get_engine().connect() as conn:
            sid, tid, plat = _pair_of(conn, project_id)
        res = m._rename_items(project_id, sid, tid, plat, body.model_dump(exclude={"reason"}))
        if body.dry_run or res.status_code >= 400:
            return res
        b = _json_of(res)
        return _answer(res, request, f"renamed {b.get('written')} {body.kind} name(s)" + (f" by pattern {body.pattern}" if body.pattern else " by mapping"),
                       project_id, body.reason, device_id=sid)

    # ── the per-rule fields (D6) ──

    @api.post("/projects/{project_id}/rules/zones", tags=["rules"], dependencies=PROJECT,
              summary="Set the rules' zones in this project (a literal adds, 'any' resets, '__auto__' derives from the routes)")
    def set_rule_zones(project_id: int, body: RuleZonesBody, request: Request):
        hashes = _rule_hashes(body.rule_hashes)
        if body.src_zone is None and body.dst_zone is None:
            raise HTTPException(400, "give src_zone, dst_zone or both")
        with m.get_engine().connect() as conn:
            sid, tid, _plat = _pair_of(conn, project_id)
        res = m._rule_zones_apply(hashes, body.src_zone, body.dst_zone, sid, str(tid), None, project_id=project_id)
        return _answer(res, request, f"zones of {len(hashes)} rule(s): src {body.src_zone!r}, dst {body.dst_zone!r}: " + _hashes_detail(hashes),
                       project_id, body.reason)

    @api.post("/projects/{project_id}/rules/zones/clear", tags=["rules"], dependencies=PROJECT,
              summary="Remove the rules' zone overrides (the source's zones show again)")
    def clear_rule_zones(project_id: int, body: RuleHashesBody, request: Request):
        hashes = _rule_hashes(body.rule_hashes)
        with m.get_engine().connect() as conn:
            _project_row(conn, project_id)
        res = m._rule_zones_clear(hashes, None, project_id=project_id)
        return _answer(res, request, f"zone overrides of {len(hashes)} rule(s) removed: " + _hashes_detail(hashes), project_id, body.reason)

    @api.put("/projects/{project_id}/rules/service", tags=["rules"], dependencies=PROJECT,
             summary="Set the rules' service override ('any', 'application-default', null clears)")
    def set_rule_service(project_id: int, body: RuleServiceBody, request: Request):
        hashes = _rule_hashes(body.rule_hashes)
        with m.get_engine().connect() as conn:
            _sid, _tid, plat = _pair_of(conn, project_id)
        service = (body.service or "").strip()
        if service and service not in ("any", "application-default"):
            raise HTTPException(400, "service must be 'any', 'application-default' or null")
        if service == "application-default" and plat == "checkpoint":
            raise HTTPException(400, "the checkpoint renderer does not read service.application-default (it reads any)")
        res = m._rule_service_apply(hashes, service, None, project_id=project_id)
        return _answer(res, request, f"service {service or 'cleared'} on {len(hashes)} rule(s): " + _hashes_detail(hashes), project_id, body.reason)

    @api.put("/projects/{project_id}/rules/applications", tags=["rules"], dependencies=PROJECT,
             summary="Set the rules' applications (['any'], names from the stored catalogue, [] clears to empty, null removes the override)")
    def set_rule_applications(project_id: int, body: RuleApplicationsBody, request: Request):
        hashes = _rule_hashes(body.rule_hashes)
        with m.get_engine().connect() as conn:
            _sid, tid, _plat = _pair_of(conn, project_id)
        apps = body.applications
        if apps is None:
            res = m._rule_applications_remove(hashes, project_id)
            what = "override removed"
        elif len(apps) == 0:
            res = m._rule_applications_clear(hashes, None, project_id=project_id)
            what = "cleared to empty"
        elif [a.strip().lower() for a in apps] == ["any"]:
            res = m._rule_applications_apply(hashes, "any", [], tid, None, project_id=project_id)
            what = "any"
        else:
            res = m._rule_applications_apply(hashes, "", [a for a in apps], tid, None, project_id=project_id)
            what = ", ".join(apps)[:200]
        return _answer(res, request, f"applications {what} on {len(hashes)} rule(s): " + _hashes_detail(hashes), project_id, body.reason)

    @api.put("/projects/{project_id}/rules/profiles", tags=["rules"], dependencies=PROJECT,
             summary="Set the rules' security profiles (PAN-OS group or slots, FortiGate UTM slots, neither clears the row)")
    def set_rule_profiles(project_id: int, body: RuleProfilesBody, request: Request):
        hashes = _rule_hashes(body.rule_hashes)
        with m.get_engine().connect() as conn:
            _sid, _tid, plat = _pair_of(conn, project_id)
        _field_platform_check(plat, "profiles")
        group = (body.profile_group or "").strip()
        slots = {k: (v.strip() if isinstance(v, str) and v.strip() else None) for k, v in (body.slots or {}).items()}
        if plat == "fortigate":
            if group:
                raise HTTPException(400, "the fortigate renderer reads profiles.slots, not a profile group")
            bad = [k for k in slots if k not in m._FORTI_UTM_SLOTS]
            if bad:
                raise HTTPException(400, f"not a FortiGate UTM slot: {', '.join(bad)} (the slots are {', '.join(m._FORTI_UTM_SLOTS)})")
            res = m._rule_utm_apply(hashes, slots, not slots, None, project_id=project_id)
        else:
            bad = [k for k in slots if k not in m._PA_INDIVIDUAL_SLOTS]
            if bad:
                raise HTTPException(400, f"not a PAN-OS profile slot: {', '.join(bad)} (the slots are {', '.join(m._PA_INDIVIDUAL_SLOTS)})")
            res = m._rule_profiles_apply(hashes, group, slots, None, project_id=project_id)
        what = group or (", ".join(f"{k}={v}" for k, v in slots.items()) if slots else "cleared")
        return _answer(res, request, f"profiles {what} on {len(hashes)} rule(s): " + _hashes_detail(hashes), project_id, body.reason)

    @api.put("/projects/{project_id}/rules/logging", tags=["rules"], dependencies=PROJECT,
             summary="Set the rules' logging (PAN-OS reads profile, log_start and log_end, FortiGate log_traffic, log_start and capture_packet, an empty body clears)")
    def set_rule_logging(project_id: int, body: RuleLoggingBody, request: Request):
        hashes = _rule_hashes(body.rule_hashes)
        with m.get_engine().connect() as conn:
            _sid, _tid, plat = _pair_of(conn, project_id)
        given = [f for f in ("profile", "log_start", "log_end", "log_traffic", "capture_packet") if getattr(body, f) is not None]
        _field_platform_check(plat, "logging", given)
        if plat == "fortigate":
            lt = (body.log_traffic or "").strip().lower()
            res = m._rule_forti_logging_apply(hashes, not lt, lt, 1 if body.log_start else 0, 1 if body.capture_packet else 0,
                                              None, project_id=project_id)
            what = lt or "cleared"
        else:
            profile = (body.profile or "").strip()
            res = m._rule_log_forwarding_apply(hashes, profile, 1 if body.log_start else 0,
                                               1 if (body.log_end is None or body.log_end) else 0, None, project_id=project_id)
            what = profile or "cleared"
        return _answer(res, request, f"logging {what} on {len(hashes)} rule(s): " + _hashes_detail(hashes), project_id, body.reason)

    @api.put("/projects/{project_id}/rules/track", tags=["rules"], dependencies=PROJECT,
             summary="Set the rules' track on a Check Point target (no track_type clears)")
    def set_rule_track(project_id: int, body: RuleTrackBody, request: Request):
        hashes = _rule_hashes(body.rule_hashes)
        with m.get_engine().connect() as conn:
            _sid, _tid, plat = _pair_of(conn, project_id)
        _field_platform_check(plat, "track")
        res = m._rule_track_apply(hashes, (body.track_type or "").strip(), 1 if body.accounting else 0,
                                  1 if body.per_session else 0, 1 if (body.per_connection is None or body.per_connection) else 0,
                                  None, project_id=project_id)
        return _answer(res, request, f"track {body.track_type or 'cleared'} on {len(hashes)} rule(s): " + _hashes_detail(hashes), project_id, body.reason)

    @api.put("/projects/{project_id}/rules/schedule", tags=["rules"], dependencies=PROJECT,
             summary="Set the rules' schedule (a name, 'none' for no schedule, null clears the override)")
    def set_rule_schedule(project_id: int, body: RuleScheduleBody, request: Request):
        hashes = _rule_hashes(body.rule_hashes)
        with m.get_engine().connect() as conn:
            _project_row(conn, project_id)
        sched = (body.schedule or "").strip()
        if body.schedule is None:
            res = m._rule_schedule_apply(hashes, True, "", None, project_id=project_id)
        else:
            res = m._rule_schedule_apply(hashes, False, "__none__" if sched.lower() == "none" else sched, None, project_id=project_id)
        return _answer(res, request, f"schedule {sched or 'cleared'} on {len(hashes)} rule(s): " + _hashes_detail(hashes), project_id, body.reason)

    @api.put("/projects/{project_id}/rules/negate", tags=["rules"], dependencies=PROJECT,
             summary="Set one negate flag of the rules (source, destination or service)")
    def set_rule_negate(project_id: int, body: RuleNegateBody, request: Request):
        hashes = _rule_hashes(body.rule_hashes)
        if body.aspect not in ("source", "destination", "service"):
            raise HTTPException(400, "aspect must be source, destination or service")
        with m.get_engine().connect() as conn:
            _project_row(conn, project_id)
        res = m._rule_negate_set(hashes, body.aspect, body.value, None, project_id=project_id)
        return _answer(res, request, f"negate {body.aspect}={body.value} on {len(hashes)} rule(s): " + _hashes_detail(hashes), project_id, body.reason)

    @api.put("/projects/{project_id}/rules/names", tags=["rules"], dependencies=PROJECT,
             summary="Set the rules' names in this project (rule hash to name, an empty name clears)")
    def set_rule_names(project_id: int, body: RuleNamesBody, request: Request):
        with m.get_engine().connect() as conn:
            sid, tid, plat = _pair_of(conn, project_id)
        res = m._rename_items(project_id, sid, tid, plat, {"kind": "rule", "mapping": body.names, "dry_run": False})
        return _answer(res, request, f"renamed {len(body.names)} rule name(s): " + _hashes_detail(body.names.keys()), project_id, body.reason)

    # ── the order (D5) ──

    @api.post("/projects/{project_id}/rules/move", tags=["rules"], dependencies=PROJECT,
              summary="Place one rule before or after another in this project")
    def move_rule(project_id: int, body: RuleMoveBody, request: Request):
        with m.get_engine().connect() as conn:
            sid, _tid, _plat = _pair_of(conn, project_id)
        res = m._rule_order_move(project_id, sid, body.rule_hash, body.before, body.after)
        where = f"before {body.before[:12]}" if body.before else f"after {(body.after or '')[:12]}"
        return _answer(res, request, f"rule {body.rule_hash[:12]} moved {where}", project_id, body.reason)

    @api.delete("/projects/{project_id}/rules/order", tags=["rules"], dependencies=PROJECT,
                summary="Reset the project's rule order (the named rules, or every override)")
    def reset_rule_order(project_id: int, request: Request, rule_hashes: str | None = Query(None, description="comma-separated, all when absent"),
                         reason: str | None = _REASON_Q):
        hashes = _rule_hashes([h for h in (rule_hashes or "").split(",") if h.strip()], cap=500) if rule_hashes else None
        with m.get_engine().connect() as conn:
            _project_row(conn, project_id)
        res = m._rule_order_reset(project_id, hashes)
        return _answer(res, request, f"rule order reset: {_json_of(res).get('removed')} override(s) removed", project_id, reason)

    # ── the catalogues and the assignment (D9) ──

    @api.get("/projects/{project_id}/catalog/{kind}", tags=["deploy"],
             summary="The target's stored catalogue of a kind (applications, security_profiles, log_forwarding, utm_profiles, threat_layers, threat_profiles) or the zone picker's catalogue")
    def get_catalog(project_id: int, kind: str):
        with m.get_engine().connect() as conn:
            sid, tid, plat = _pair_of(conn, project_id)
            if kind == "zones":
                project = _project_row(conn, project_id)
                _net, _layers, view, nm = _net_scope(conn, project)
                cat = m._zone_catalog_for_device(conn, sid, plat, name_map=nm, view=view)
                return {"project_id": project_id, "target_id": tid, "platform": plat, "kind": kind, "catalog": cat, "source": "project"}
            if kind not in m._CATALOG_KINDS:
                raise HTTPException(400, f"kind must be zones or one of {', '.join(m._CATALOG_KINDS)}")
            stored = m._catalog_stored(conn, tid, kind)
        if not stored:
            raise HTTPException(404, f"the target's {kind} catalogue is not stored yet: POST .../catalog/{kind}/refresh reads it from the Device")
        return {"project_id": project_id, "target_id": tid, "platform": plat, "kind": kind, **stored, "source": "stored"}

    @api.post("/projects/{project_id}/catalog/{kind}/refresh", tags=["deploy"], dependencies=PROJECT,
              summary="Read one catalogue from the target Device and store it")
    def refresh_catalog(project_id: int, kind: str, request: Request, reason: str | None = _REASON_Q):
        with m.get_engine().connect() as conn:
            _sid, tid, _plat = _pair_of(conn, project_id)
        res = m._catalog_refresh(tid, kind)
        return _answer(res, request, f"catalogue {kind} read from the target", project_id, reason, device_id=tid)

    @api.post("/projects/{project_id}/applications/assign", tags=["rules"], status_code=202, dependencies=PROJECT,
              summary="Assign the target's applications to the rules by port or by name, as a job")
    def assign_applications(project_id: int, body: AssignBody, request: Request):
        if body.mode not in ("ports", "names"):
            raise HTTPException(400, "mode must be ports or names")
        hashes = _rule_hashes(body.rule_hashes, cap=500) if body.rule_hashes else []
        with m.get_engine().connect() as conn:
            sid, tid, plat = _pair_of(conn, project_id)
        out = m._assign_start(project_id, sid, tid, plat, _client(request), body.mode, hashes)
        if not out.get("already"):
            _audit(request, f"applications assigned by {body.mode}" + (f" on {len(hashes)} rule(s)" if hashes else ""),
                   project_id=project_id, device_id=tid, reason=body.reason)
        return JSONResponse({"project_id": project_id, **out}, status_code=202)

    @api.get("/audit", tags=["audit"], summary="The writes made through the API, newest first")
    def get_audit(project_id: int | None = Query(None), device_id: int | None = Query(None),
                  limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
        with m.get_engine().connect() as conn:
            rows, total = apitokens.list_audit(conn, project_id, device_id, limit, offset, tenant_id=_token_tenant())
        for r in rows:
            r["created_at"] = str(r["created_at"])
        return {"writes": rows, "total": total, "limit": limit, "offset": offset}

    return api
