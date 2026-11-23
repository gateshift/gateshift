# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
"""The tools as plain functions over the API client: compact rows with fixed keys, strings capped and stripped of control
characters, lists paged, every answer scrubbed. No SDK here, so the unit tests
run on the host like the suite; `server` wires these into the MCP catalogue.

Every read names its project or Device outright. The rows carry a customer's
configuration text (rule names, descriptions, comments): data to read, never
instructions to follow."""
from __future__ import annotations

import time
from typing import Any, Callable

from .api import Api, ApiError, scrub, scrub_deep
from .kinds import KINDS

CAP = 200            # characters per string field
PAGE = 50            # rows per page
WAIT_CAP = 60.0      # seconds get_job waits at most (the client backgrounds a call after two minutes)
POLL = 3.0           # seconds between two reads of a job
EVENTS_TAIL = 40     # events a job answer carries

_CTRL = {c: None for c in range(32) if c not in (9, 10)}


def _s(v: Any, cap: int = CAP) -> Any:
    """A string field: stripped of control characters, capped, scrubbed. Other scalars unchanged."""
    if v is None or isinstance(v, (bool, int, float)):
        return v
    s = str(v).translate(_CTRL).strip()
    if len(s) > cap:
        s = s[:cap - 3] + "..."
    return scrub(s)


def _i(v: Any) -> int | None:
    try:
        return int(v) if v is not None and v != "" else None
    except (TypeError, ValueError):
        return None


def _names(v: Any, cap_items: int = 20) -> list:
    """A list of names, each capped, at most `cap_items` of them."""
    if not isinstance(v, list):
        return []
    out = [_s(x, 80) for x in v[:cap_items]]
    if len(v) > cap_items:
        out.append(f"... {len(v) - cap_items} more")
    return out


def _page(items: list, offset: int, limit: int) -> dict:
    offset = max(0, int(offset or 0))
    limit = max(1, min(int(limit or PAGE), 200))
    return {"items": items[offset:offset + limit], "offset": offset, "limit": limit, "total": len(items)}


# ── tenants, Devices, projects ───────────────────────────────────────

def list_tenants(api: Api) -> dict:
    r = api.get("/tenants")
    rows = [{"id": _i(t.get("id")), "name": _s(t.get("name")), "devices": _i(t.get("devices")),
             "projects": _i(t.get("projects"))} for t in (r.get("tenants") or [])]
    return {"tenants": rows, "total": len(rows)}


def _device_row(d: dict) -> dict:
    return {"id": _i(d.get("id")), "name": _s(d.get("name")), "platform": _s(d.get("platform")),
            "role": _s(d.get("role")), "kind": _s(d.get("device_kind")) or "firewall",
            "address": _s(d.get("mgmt_ip")), "has_api_key": bool(d.get("has_api_key")),
            "tenant_id": _i(d.get("tenant_id"))}


def list_devices(api: Api, tenant_id: int | None = None) -> dict:
    r = api.get("/devices", params={"tenant_id": tenant_id} if tenant_id else None)
    rows = [_device_row(d) for d in (r.get("devices") or [])]
    return {"tenant_id": _i(r.get("tenant_id")), "devices": rows, "total": len(rows)}


def get_device(api: Api, device_id: int) -> dict:
    d = api.get(f"/devices/{int(device_id)}")
    out = _device_row(d)      # the notes stay out (D5): free text where operators park what they should not
    out["scopes"] = [{"device_id": _i(s.get("device_id")), "name": _s(s.get("name")), "role": _s(s.get("role"))}
                     for s in (d.get("scopes") or [])]
    out["last_jobs"] = [{"job_id": _s(j.get("job_id")), "kind": _s(j.get("kind")), "status": _s(j.get("status")),
                         "success": j.get("success"), "created_at": _s(j.get("created_at"))}
                        for j in (d.get("last_jobs") or [])]
    return out


def _project_row(p: dict) -> dict:
    return {"id": _i(p.get("id")), "name": _s(p.get("name")), "status": _s(p.get("status")),
            "tenant_id": _i(p.get("tenant_id")), "tenant": _s(p.get("tenant_name")),
            "source_id": _i(p.get("source_ref_id")), "source": _s(p.get("source_name")),
            "target_id": _i(p.get("target_ref_id")), "target": _s(p.get("target_name")),
            "updated_at": _s(p.get("updated_at"))}


def list_projects(api: Api, tenant_id: int | None = None, name_contains: str | None = None) -> dict:
    r = api.get("/projects", params={"tenant_id": tenant_id} if tenant_id else None)
    rows = [_project_row(p) for p in (r.get("projects") or [])]
    if name_contains:
        needle = str(name_contains).lower()
        rows = [p for p in rows if needle in (p.get("name") or "").lower()]
    return {"tenant_id": _i(r.get("tenant_id")), "projects": rows, "total": len(rows)}


def get_project(api: Api, project_id: int) -> dict:
    p = api.get(f"/projects/{int(project_id)}")
    out = _project_row(p)
    prog = p.get("progress") or {}
    steps = []
    for st in (prog.get("steps") or []):
        if isinstance(st, dict):
            steps.append({k: _s(st.get(k)) for k in ("key", "label", "state", "hint") if st.get(k) is not None})
    # the hint of the step model is a dict (text, tab, step), the page reads its fields; the model gets the sentence
    hint = prog.get("hint")
    hint_text = hint.get("text") if isinstance(hint, dict) else hint
    nxt = prog.get("next")
    next_label = next((st.get("label") for st in steps if st.get("key") == nxt), None)
    out["progress"] = {"done": _i(prog.get("done")), "total": _i(prog.get("total")),
                       "complete": bool(prog.get("complete")), "next": _s(nxt, 64), "next_label": _s(next_label),
                       "hint": _s(hint_text, 400), "steps": steps}
    b = p.get("build") or {}
    summ = b.get("summary") or {}
    out["build"] = {"state": _s(b.get("state")), "build_id": _s(b.get("job_id")), "built_at": _s(b.get("built_at")),
                    "building": bool(b.get("building_job_id")), "stale": b.get("stale"),
                    "platform": _s(b.get("platform")),
                    "summary": {"entries": _i(summ.get("entries")), "blockers": _i(summ.get("blockers")),
                                "dropped_fields": _i(summ.get("dropped_fields")), "rules": summ.get("rules")}}
    return out


# ── the network of a project ─────────────────────────────────────────

def list_interfaces(api: Api, project_id: int) -> dict:
    r = api.get(f"/projects/{int(project_id)}/interfaces")
    rows = [{"id": _i(i.get("id")), "name": _s(i.get("name")), "source_name": _s(i.get("source_name")),
             "type": _s(i.get("type")), "parent": _s(i.get("parent")), "vlan_tag": _i(i.get("vlan_tag")),
             "ip_addresses": _names(i.get("ip_addresses")), "zone": _s(i.get("zone")), "vr": _s(i.get("vr")),
             "enabled": bool(i.get("enabled", True)), "dhcp": bool(i.get("dhcp")), "skip": bool(i.get("skip")),
             "description": _s(i.get("description"))} for i in (r.get("interfaces") or [])]
    return {"project_id": int(project_id), "network_device_id": _i(r.get("network_device_id")),
            "interfaces": rows, "total": len(rows)}


def list_zones(api: Api, project_id: int) -> dict:
    r = api.get(f"/projects/{int(project_id)}/zones")
    rows = [{"id": _i(z.get("id")), "name": _s(z.get("name")), "source_name": _s(z.get("source_name")),
             "members": _names(z.get("members")), "external": bool(z.get("is_external")),
             "description": _s(z.get("description")), "color": _s(z.get("color")), "own": bool(z.get("own")),
             "properties": ({str(k)[:64]: scrub(v) for k, v in z["properties"].items()}
                            if isinstance(z.get("properties"), dict) else {})} for z in (r.get("zones") or [])]
    return {"project_id": int(project_id), "zones": rows, "total": len(rows)}


# ── rules and findings ───────────────────────────────────────────────

def _rule_row(r: dict) -> dict:
    return {"rule_hash": _s(r.get("rule_hash"), 40), "name": _s(r.get("rule_name")),
            "action": _s(r.get("action")), "from_zones": _names(r.get("src_zones"), 8),
            "to_zones": _names(r.get("dst_zones"), 8),
            "sources": _i(r.get("src_count")) if r.get("src_count") is not None else len(r.get("sources") or []),
            "destinations": _i(r.get("dst_count")) if r.get("dst_count") is not None else len(r.get("destinations") or []),
            "service": _s(r.get("port_display") or r.get("application")),
            "applications": len(r.get("application_list") or []) if isinstance(r.get("application_list"), list) else None,
            "disabled": bool(r.get("disabled")), "disabled_by": _s(r.get("disabled_by")) or None,
            "position": _i(r.get("sequence"))}


def list_rules(api: Api, project_id: int, offset: int = 0, limit: int = PAGE,
               hashes: list[str] | None = None) -> dict:
    """The project's rules, compact, paged; `hashes` answers only those rows
    (excluded rules among them stay out, the exclusions list has them)."""
    offset = max(0, int(offset or 0))
    limit = max(1, min(int(limit or PAGE), 200))
    params: dict[str, Any] = {"limit": limit, "offset": offset}
    if hashes:
        params = {"hashes": ",".join(str(h).strip().lower() for h in hashes if str(h).strip())}
    r = api.get(f"/projects/{int(project_id)}/rules", params=params)
    rows = [_rule_row(x) for x in (r.get("rules") or [])]
    return {"project_id": int(project_id), "rules": rows, "offset": _i(r.get("offset")) or 0,
            "limit": _i(r.get("limit")) or limit, "total": _i(r.get("total")) or 0,
            "pipeline_pending": bool(r.get("needs_refresh")),
            "note": ("the ruleset pipeline has work pending for this installation: refresh_ruleset or a build "
                     "brings the rules up to date" if r.get("needs_refresh") else None)}


SECTIONS = ("issues", "dropped", "completeness", "import_drops", "skipped_interfaces")
# the server's own hint which tool resolves a finding kind;
# the kind's title and sentence stay the API's
RESOLVES_WITH = {
    "unresolved_reference": "list_objects with flags, then rename_items or delete_objects",
    "appdef_widened": "edit_rules with applications, or assign_applications",
    "no_zone": "edit_interface with zone, or create_zone",
    "no_interfaces": "edit_interface with skip=false, or fetch_target_inventory",
    "vr_orphan": "delete_vrf, or edit_interface with vr",
    "iface_subnet_overlap": "edit_interface, or mark_reviewed to accept",
    "pa_rescue_point_refused": "mark_reviewed to accept",
    "vpn_psk_rule": "the key is set on the page (the tools never carry a key)",
}


def get_findings(api: Api, project_id: int, section: str = "issues", kind: str | None = None,
                 offset: int = 0, limit: int = PAGE) -> dict:
    """The last build's findings with the meaning attached (D1): the summary
    counts always, the counts per kind, and one section's items paged:
    `issues` (the findings with the kind's title and sentence), `dropped`
    (fields the target cannot carry), `completeness` (dangling references),
    `import_drops`, `skipped_interfaces`."""
    f = api.get(f"/projects/{int(project_id)}/findings")
    report = f.get("report") or {}
    kinds = f.get("kinds") or {}
    summary = f.get("summary") or {}
    issues = [x for x in (report.get("validation_issues") or []) if isinstance(x, dict)]
    by_kind: dict[str, int] = {}
    for x in issues:
        k = str(x.get("kind") or "?")
        by_kind[k] = by_kind.get(k, 0) + 1
    section = (section or "issues").strip().lower()
    if section not in SECTIONS:
        raise ApiError(400, f"section must be one of {', '.join(SECTIONS)}")
    if section == "issues":
        items = []
        for x in issues:
            if kind and str(x.get("kind")) != kind:
                continue
            k = str(x.get("kind") or "?")
            meta = kinds.get(k) or {}
            row = {"kind": k, "title": _s(meta.get("title")), "sentence": _s(meta.get("sentence"), 600),
                   "tab": _s(meta.get("tab")), "subtab": _s(meta.get("subtab"))}
            if k in RESOLVES_WITH:
                row["resolve_with"] = RESOLVES_WITH[k]
            for key, val in x.items():
                if key == "kind":
                    continue
                if isinstance(val, (str, int, float, bool)) or val is None:
                    row[key] = _s(val, 300)
                elif isinstance(val, list):
                    row[key] = _names(val, 12)
            items.append(row)
    elif section == "dropped":
        items = [{k: _s(v, 300) for k, v in x.items() if isinstance(v, (str, int, float, bool)) or v is None}
                 for x in (report.get("dropped_fields") or []) if isinstance(x, dict)]
    elif section == "completeness":
        items = [{k: _s(v, 300) for k, v in x.items() if isinstance(v, (str, int, float, bool)) or v is None}
                 for x in (report.get("completeness") or []) if isinstance(x, dict)]
    elif section == "import_drops":
        raw = report.get("import_drops") or {}
        items = ([{"category": _s(k), "count": len(v) if isinstance(v, list) else _i(v), "names": _names(v, 12)}
                  for k, v in raw.items()] if isinstance(raw, dict) else [])
    else:
        items = [{"name": _s(x)} if not isinstance(x, dict) else {k: _s(v, 300) for k, v in x.items()}
                 for x in (report.get("skipped_interfaces") or [])]
    page = _page(items, offset, limit)
    return {"project_id": int(project_id), "state": _s(f.get("state")), "build_id": _s(f.get("job_id")),
            "built_at": _s(f.get("built_at")),
            "summary": {"blockers": _i(summary.get("blockers")), "leaks": _i(summary.get("leaks")),
                        "unresolved": _i(summary.get("unresolved")), "dropped_fields": _i(summary.get("dropped_fields")),
                        "entries": _i(summary.get("entries")), "rules": summary.get("rules"),
                        "issues": len(issues), "completeness": len(report.get("completeness") or [])},
            "issues_by_kind": {k: {"count": n, "title": _s((kinds.get(k) or {}).get("title"))} for k, n in sorted(by_kind.items())},
            "section": section, "kind": kind, **page}


def list_exclusions(api: Api, project_id: int) -> dict:
    r = api.get(f"/projects/{int(project_id)}/exclusions")
    rows = [{"device_id": _i(x.get("device_id")), "device": _s(x.get("device_name")), "kind": _s(x.get("kind")),
             "kind_label": _s(x.get("kind_label")), "item_key": _s(x.get("item_key"), 255), "label": _s(x.get("label")),
             "reason": _s(x.get("reason")), "created_at": _s(x.get("created_at"))} for x in (r.get("exclusions") or [])]
    return {"project_id": int(project_id), "exclusions": rows, "total": len(rows)}


def get_push_settings(api: Api, project_id: int) -> dict:
    r = api.get(f"/projects/{int(project_id)}/settings")
    rows = [{"key": _s(s.get("key")), "label": _s(s.get("label")), "type": _s(s.get("type")),
             "value": _s(s.get("value")), "default": _s(s.get("default")), "pinned": bool(s.get("pinned")),
             "options": _names(s.get("options"), 30)} for s in (r.get("settings") or []) if isinstance(s, dict)]
    return {"project_id": int(project_id), "platform": _s(r.get("platform")), "settings": rows,
            "note": _s(r.get("error"))}


def list_tunnels(api: Api, project_id: int) -> dict:
    r = api.get(f"/projects/{int(project_id)}/vpn")
    rows = [{"vpn_hash": _s(t.get("vpn_hash"), 40), "name": _s(t.get("name")), "disabled": bool(t.get("disabled")),
             "peer": _s(t.get("peer_address")), "peer_type": _s(t.get("peer_type")), "auth": _s(t.get("auth_type")),
             "ike": _s(t.get("ike_version")), "local_interface": _s(t.get("local_interface")),
             "tunnel_interface": _s(t.get("tunnel_interface")), "psk_set": bool(t.get("psk_set"))}
            for t in (r.get("tunnels") or [])]
    return {"project_id": int(project_id), "source_id": _i(r.get("source_id")), "tunnels": rows, "total": len(rows)}


# ── jobs and the audit ───────────────────────────────────────────────

def job_complete(job: dict) -> bool:
    """A job is complete when its status is done or failed. After a publish
    or discard (the push job stays done) when the event of that step is
    present or nothing is staged any more (D8)."""
    status = str(job.get("status") or "")
    if status not in ("done", "failed"):
        return False
    if job.get("push_id") and job.get("needs_commit"):
        steps = {str(e.get("step") or "") for e in (job.get("events") or [])}
        return bool(steps & {"publish", "discard"})
    return True


def _job_view(j: dict) -> dict:
    events = [e for e in (j.get("events") or []) if isinstance(e, dict)]
    tail = events[-EVENTS_TAIL:]
    return {"job_id": _s(j.get("job_id")), "kind": _s(j.get("kind")), "strand": _s(j.get("strand")),
            "status": _s(j.get("status")), "success": j.get("success"), "complete": job_complete(j),
            "staged": bool(j.get("push_id")) and bool(j.get("needs_commit")),
            "error": _s(j.get("error"), 600), "project_id": _i(j.get("project_id")),
            "source_id": _i(j.get("source_id")), "target_id": _i(j.get("target_id")),
            "created_at": _s(j.get("created_at")), "updated_at": _s(j.get("updated_at")),
            "events_total": len(events),
            "events": [{"seq": _i(e.get("seq")), "step": _s(e.get("step"), 120), "success": bool(e.get("success")),
                        "detail": _s(e.get("detail"), 600)} for e in tail]}


def get_job(api: Api, job_id: str, wait_seconds: int = 0,
            sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic) -> dict:
    """One job with the last events. With `wait_seconds` the call waits, up
    to WAIT_CAP, polling every POLL seconds, until the job is complete."""
    deadline = clock() + max(0.0, min(float(wait_seconds or 0), WAIT_CAP))
    while True:
        j = api.get(f"/jobs/{str(job_id).strip()}")
        if job_complete(j) or clock() >= deadline:
            return _job_view(j)
        sleep(POLL)


def get_audit(api: Api, project_id: int | None = None, device_id: int | None = None, limit: int = PAGE,
              offset: int = 0) -> dict:
    params: dict[str, Any] = {"limit": max(1, min(int(limit or PAGE), 200)), "offset": max(0, int(offset or 0))}
    if project_id:
        params["project_id"] = int(project_id)
    if device_id:
        params["device_id"] = int(device_id)
    r = api.get("/audit", params=params)
    rows = [{"when": _s(w.get("created_at")), "token": _s(w.get("token_name")), "token_id": _i(w.get("token_id")),
             "method": _s(w.get("method")),
             "path": _s(w.get("path"), 255), "project_id": _i(w.get("project_id")), "device_id": _i(w.get("device_id")),
             "what": _s(w.get("detail"), 400), "why": _s(w.get("reason"))} for w in (r.get("writes") or [])]
    return {"writes": rows, "total": _i(r.get("total")) or 0, "offset": params["offset"], "limit": params["limit"]}


# ── the documents (D2) ───────────────────────────────────────────────

DOCUMENTS = ("operating", "api", "known-limitations")


def document(api: Api, name: str) -> str:
    d = api.get(f"/documents/{name}")
    return scrub(str(d.get("text") or ""))


def answer(fn: Callable, api: Api, *args, **kwargs) -> dict | str:
    """A tool's answer: the function's result scrubbed, and the first-call
    notice of the version check added once (D10)."""
    notice = None
    if not api.probed:
        notice = api.probe()
    out = fn(api, *args, **kwargs)
    out = scrub_deep(out)
    if notice and isinstance(out, dict):
        out = {"notice": notice, **out}
    return out


# ── the writes of P2 (D3, D9): proposal first, then confirm ───────────

CAP_HASHES = 50          # rules per set_rules call
MIN_REASON = 3           # characters a reason needs
ACTIONS = ("disable", "enable", "exclude", "restore")
WRITE_SENTENCE = "no change was made: call again with confirm=true to apply this"


class RateLimiter:
    """What the server allows per minute (D9): a sliding window per tier,
    `middle` for the project-own writes and the derived jobs, `human` for
    the tier a human confirms (four a minute: a review stamp and a snapshot
    restore, each asked of the human). Clock injectable for the tests."""

    def __init__(self, middle_per_minute: int = 10, human_per_minute: int = 4,
                 clock: Callable[[], float] = time.monotonic):
        self.limits = {"middle": int(middle_per_minute), "human": int(human_per_minute)}
        self.clock = clock
        self._hits: dict[str, list[float]] = {"middle": [], "human": []}

    def take(self, tier: str) -> None:
        now = self.clock()
        hits = [t for t in self._hits.get(tier, []) if now - t < 60.0]
        if len(hits) >= self.limits.get(tier, 0):
            raise ApiError(429, f"the server allows {self.limits[tier]} {tier}-tier write(s) a minute, wait a moment")
        hits.append(now)
        self._hits[tier] = hits


LIMITER = RateLimiter()


def _hex40(h: Any) -> str | None:
    s = str(h or "").strip().lower()
    return s if len(s) == 40 and all(c in "0123456789abcdef" for c in s) else None


def _need_reason(reason: Any) -> str:
    r = str(reason or "").strip()
    if len(r) < MIN_REASON:
        raise ApiError(400, "a reason is required: one sentence on why this change is made")
    return r[:200]


def resolve_interface(api: Api, project_id: int, interface: Any) -> dict:
    """The interface a call names: its id, or its shown or source name among
    the project's interfaces; an ambiguous name (a multi-layer scope) asks
    for the id."""
    rows = list_interfaces(api, project_id)["interfaces"]
    key = str(interface or "").strip()
    if not key:
        raise ApiError(400, "name the interface: its shown name, its source name or its id")
    if key.isdigit():
        for r in rows:
            if r.get("id") == int(key):
                return r
        raise ApiError(404, f"no interface with id {key} in project {project_id}")
    hits = [r for r in rows if r.get("name") == key or r.get("source_name") == key]
    if not hits:
        raise ApiError(404, f"no interface named {key} in project {project_id}: list_interfaces shows the names")
    if len(hits) > 1:
        ids = ", ".join(str(r.get("id")) for r in hits)
        raise ApiError(409, f"the name {key} names {len(hits)} interfaces in this project's scope, use the id: {ids}")
    return hits[0]


def edit_interface(api: Api, project_id: int, interface: Any, reason: str, name: str | None = None,
                   zone: str | None = None, skip: bool | None = None, confirm: bool = False,
                   empty_zone_ok: bool = False, limiter: RateLimiter | None = None,
                   type: str | None = None, parent: str | None = None, vlan_tag: int | None = None,
                   ip_addresses: list | None = None) -> dict:
    """Rename, bind or skip one interface (D3): the proposal is composed from
    reads (the API has no dry run), the write happens with confirm=true, a
    zone that rules still use is emptied only with empty_zone_ok=true."""
    reason = _need_reason(reason)
    if (name is None and zone is None and skip is None and type is None and parent is None and vlan_tag is None
            and ip_addresses is None):
        raise ApiError(400, "nothing to change: give name, zone, skip, type, parent, vlan_tag or ip_addresses")
    row = resolve_interface(api, project_id, interface)
    changes: list[dict] = []
    warnings: list[str] = []
    body: dict[str, Any] = {"reason": reason}
    if name is not None:
        new = str(name).strip()
        if not new:
            raise ApiError(400, "the name cannot be empty")
        if new == row.get("name"):
            warnings.append(f"the interface is shown as {new} already, the name does not change")
        else:
            taken = [r for r in list_interfaces(api, project_id)["interfaces"] if r.get("name") == new and r.get("id") != row.get("id")]
            if taken:
                warnings.append(f"the name {new} is shown by interface {taken[0].get('id')} ({taken[0].get('source_name')}): the API will refuse it")
            changes.append({"field": "name", "from": row.get("name"), "to": new,
                            "note": "sub-interfaces named after the parent follow"})
            body["name"] = new
    if zone is not None:
        z = str(zone).strip()
        if not z or z.lower() in ("none", "null"):
            changes.append({"field": "zone", "from": row.get("zone"), "to": None, "note": "unbinds the zone"})
            body["zone"] = None
        else:
            zones = {x.get("name"): x for x in list_zones(api, project_id)["zones"]}
            note = "binds to the existing zone" if z in zones else "creates the project's own zone and binds it"
            if z == row.get("zone"):
                warnings.append(f"the interface is bound to {z} already")
            changes.append({"field": "zone", "from": row.get("zone"), "to": z, "note": note})
            body["zone"] = z
    if skip is not None:
        want = bool(skip)
        if want == bool(row.get("skip")):
            warnings.append("the interface is skipped already" if want else "the interface is in the push already")
        else:
            note = "leaves the interface out of the push" if want else "takes the interface back into the push"
            if want and row.get("zone"):
                members = next((x.get("members") or [] for x in list_zones(api, project_id)["zones"]
                                if x.get("name") == row.get("zone")), [])
                mine = {row.get("name"), row.get("source_name")}
                if members and all(m in mine for m in members):
                    warnings.append(f"the interface is the sole member of zone {row.get('zone')}: rules that use the zone "
                                    "go inactive until it has members again, empty_zone_ok=true confirms that")
            changes.append({"field": "skip", "from": bool(row.get("skip")), "to": want, "note": note})
            body["skip"] = want
    # the type, the parent and the tag: a consolidation onto VLANs of a port
    # needs them, the API had them already
    if type is not None:
        t = str(type).strip().lower()
        if t not in ("physical", "vlan", "loopback", "bond", "tunnel"):
            raise ApiError(400, "type is one of physical, vlan, loopback, bond, tunnel")
        if t == row.get("type"):
            warnings.append(f"the interface is of type {t} already")
        else:
            changes.append({"field": "type", "from": row.get("type"), "to": t,
                            "note": "a vlan needs parent and vlan_tag, a bond its members on the page"})
            body["type"] = t
    if parent is not None:
        pr = str(parent).strip() or None
        if pr == row.get("parent"):
            warnings.append(f"the parent is {pr} already")
        else:
            if pr and not any(pr in (x.get("name"), x.get("source_name")) for x in list_interfaces(api, project_id)["interfaces"]):
                warnings.append(f"no interface {pr} in the project: the API will refuse the parent")
            changes.append({"field": "parent", "from": row.get("parent"), "to": pr, "note": "the port the VLAN rides on"})
            body["parent"] = pr
    if vlan_tag is not None:
        try:
            vt = int(vlan_tag)
        except (TypeError, ValueError):
            raise ApiError(400, "vlan_tag is a number from 1 to 4094")
        if not 1 <= vt <= 4094:
            raise ApiError(400, "vlan_tag is a number from 1 to 4094")
        if vt == row.get("vlan_tag"):
            warnings.append(f"the tag is {vt} already")
        else:
            changes.append({"field": "vlan_tag", "from": row.get("vlan_tag"), "to": vt, "note": "the 802.1Q tag"})
            body["vlan_tag"] = vt
    # the addresses: a cloud subnet enters without one and the Review asks
    # for it, the API took them already
    if ip_addresses is not None:
        import ipaddress as _ipa
        ips = [str(x).strip() for x in (ip_addresses or []) if str(x).strip()]
        for ip in ips:
            try:
                _ipa.ip_interface(ip)
            except ValueError:
                raise ApiError(400, f"{ip} is no address with its length, like 10.1.2.1/24")
            if "/" not in ip:
                raise ApiError(400, f"{ip} needs its length, like 10.1.2.1/24")
        if ips == list(row.get("ip_addresses") or []):
            warnings.append("the interface carries these addresses already")
        else:
            changes.append({"field": "ip_addresses", "from": row.get("ip_addresses") or [], "to": ips,
                            "note": "an empty list removes the addresses"})
            body["ip_addresses"] = ips
    proposal = {"project_id": int(project_id), "interface": {k: row.get(k) for k in ("id", "name", "source_name", "zone", "skip", "type", "parent", "vlan_tag", "ip_addresses")},
                "changes": changes, "warnings": warnings, "reason": reason}
    if not changes:
        return {**proposal, "applied": False, "sentence": "nothing would change"}
    if not confirm:
        return {**proposal, "applied": False, "sentence": WRITE_SENTENCE}
    (limiter or LIMITER).take("middle")
    if empty_zone_ok:
        body["confirm_empty_zone"] = True
    try:
        api.patch(f"/projects/{int(project_id)}/interfaces/{row['id']}", body)
    except ApiError as exc:
        if exc.status == 409 and (exc.data or {}).get("confirmable"):
            return {**proposal, "applied": False, "needs": "empty_zone_ok", "sentence": exc.sentence()}
        raise
    after = resolve_interface(api, project_id, str(row["id"]))
    return {**proposal, "applied": True, "interface": {k: after.get(k) for k in ("id", "name", "source_name", "zone", "skip", "type")},
            "sentence": "applied, the audit carries the reason"}


def set_rules(api: Api, project_id: int, rule_hashes: list, action: str, reason: str, confirm: bool = False,
              limiter: RateLimiter | None = None) -> dict:
    """Disable, enable, exclude or restore rules by hash (D3), at most 50 a
    call: the proposal names the rules, the write happens with confirm=true."""
    reason = _need_reason(reason)
    action = str(action or "").strip().lower()
    if action not in ACTIONS:
        raise ApiError(400, f"action must be one of {', '.join(ACTIONS)}")
    wanted: list[str] = []
    bad: list[str] = []
    for h in rule_hashes or []:
        hx = _hex40(h)
        (wanted if hx else bad).append(hx or str(h)[:48])
    wanted = list(dict.fromkeys(wanted))
    if bad:
        raise ApiError(400, f"not a rule hash: {', '.join(bad[:3])}")
    if not wanted:
        raise ApiError(400, "name at least one rule by its rule_hash")
    if len(wanted) > CAP_HASHES:
        raise ApiError(400, f"at most {CAP_HASHES} rules per call ({len(wanted)} named): split the call")
    if action == "restore":
        excl = [x for x in list_exclusions(api, project_id)["exclusions"] if x.get("kind") == "rule"]
        known = {x.get("item_key"): x.get("label") for x in excl}
    else:
        rows = list_rules(api, project_id, hashes=wanted)["rules"]
        known = {r.get("rule_hash"): r.get("name") for r in rows}
    named = [{"rule_hash": h, "name": known.get(h)} for h in wanted if h in known]
    unknown = [h for h in wanted if h not in known]
    notes = {"disable": "the rules stay in the Device's facts and are pushed disabled",
             "enable": "the rules take their source state again",
             "exclude": "the rules leave this project's migration, the Device's facts keep them, restore brings them back",
             "restore": "the excluded rules come back into this project"}
    proposal = {"project_id": int(project_id), "action": action, "rules": named, "unknown": unknown,
                "note": notes[action], "reason": reason,
                "warnings": ([f"{len(unknown)} hash(es) name no rule of this project"
                              + (" (an excluded rule is restored, not disabled)" if action != "restore" else "")]
                             if unknown else [])}
    if not named:
        return {**proposal, "applied": False, "sentence": "nothing would change: none of the hashes names a rule here"}
    if not confirm:
        return {**proposal, "applied": False, "sentence": WRITE_SENTENCE}
    (limiter or LIMITER).take("middle")
    hashes = [r["rule_hash"] for r in named]
    if action in ("disable", "enable"):
        res = api.post(f"/projects/{int(project_id)}/rules/disable",
                       {"rule_hashes": hashes, "disabled": action == "disable", "reason": reason})
        changed = res.get("disabled") if action == "disable" else res.get("enabled")
    elif action == "exclude":
        res = api.post(f"/projects/{int(project_id)}/rules/exclude", {"rule_hashes": hashes, "reason": reason})
        changed = res.get("deleted")
    else:
        res = api.post(f"/projects/{int(project_id)}/rules/restore", {"rule_hashes": hashes, "reason": reason})
        changed = res.get("restored")
    return {**proposal, "applied": True, "changed": _i(changed), "sentence": "applied, the audit carries the reason"}


def set_push_settings(api: Api, project_id: int, settings: dict, reason: str, confirm: bool = False,
                      limiter: RateLimiter | None = None) -> dict:
    """The target's push settings for this project (D3): keys the target
    knows, no pinned key, a select within its options."""
    reason = _need_reason(reason)
    if not isinstance(settings, dict) or not settings:
        raise ApiError(400, "settings must name at least one key with its value")
    current = get_push_settings(api, project_id)
    by_key = {s.get("key"): s for s in current.get("settings") or []}
    changes: list[dict] = []
    for k, v in settings.items():
        k = str(k).strip()
        if k not in by_key:
            raise ApiError(400, f"the target knows no setting {k}: {', '.join(sorted(by_key)) or 'none'}")
        cur = by_key[k]
        if cur.get("pinned"):
            raise ApiError(400, f"the setting {k} is pinned on this Device and cannot be changed here")
        val = "" if v is None else str(v)
        if cur.get("options") and val not in cur["options"]:
            raise ApiError(400, f"the setting {k} takes one of: {', '.join(cur['options'])}")
        if val == (cur.get("value") or ""):
            continue
        changes.append({"key": k, "label": cur.get("label"), "from": cur.get("value"), "to": val})
    proposal = {"project_id": int(project_id), "platform": current.get("platform"), "changes": changes,
                "reason": reason, "note": "the target configuration is outdated afterwards and is rebuilt"}
    if not changes:
        return {**proposal, "applied": False, "sentence": "nothing would change"}
    if not confirm:
        return {**proposal, "applied": False, "sentence": WRITE_SENTENCE}
    (limiter or LIMITER).take("middle")
    api.put(f"/projects/{int(project_id)}/settings", {"settings": {c["key"]: c["to"] for c in changes}, "reason": reason})
    return {**proposal, "applied": True, "sentence": "applied, the audit carries the reason"}


def refresh_ruleset(api: Api, project_id: int, reason: str | None = None, limiter: RateLimiter | None = None) -> dict:
    """The ruleset pipeline as a job (nothing leaves the product)."""
    (limiter or LIMITER).take("middle")
    r = api.post(f"/projects/{int(project_id)}/refresh", params={"reason": reason} if reason else None)
    return {"project_id": int(project_id), "job_id": _s(r.get("job_id")), "already_running": bool(r.get("already")),
            "sentence": "the ruleset pipeline runs, get_job reads the job"}


def build_project(api: Api, project_id: int, reason: str | None = None, limiter: RateLimiter | None = None) -> dict:
    """The build of the target configuration as a job (nothing leaves the product)."""
    (limiter or LIMITER).take("middle")
    r = api.post(f"/projects/{int(project_id)}/build", {"reason": reason} if reason else {})
    return {"project_id": int(project_id), "job_id": _s(r.get("job_id")), "already_running": bool(r.get("already")),
            "sentence": "the build runs, get_job reads the job. Get_project shows the build_id the operator pushes on the Review & Deploy page"}


# ── the human-confirmed tier of P3 (D4, D9) ───────────────────────────

STRANDS = ("network", "policy")
HUMAN_PATHS = ("/push", "/publish", "/discard", "/reviewed")


def _q(v: Any, cap: int = 60) -> str:
    """A configuration-derived name inside a message: quoted and capped, so a
    name that reads like an instruction stays a name."""
    return "'" + str(_s(v, cap) or "").replace("'", "") + "'"


def _age(stamp: Any, now: Callable[[], float] = time.time) -> str | None:
    """A rough age of a server timestamp ('YYYY-MM-DD HH:MM:SS', UTC) in words."""
    s = str(stamp or "")[:19]
    try:
        import calendar
        t = calendar.timegm(time.strptime(s, "%Y-%m-%d %H:%M:%S"))
    except (ValueError, TypeError):
        return None
    d = max(0, int(now() - t))
    if d < 120:
        return "a moment ago"
    if d < 7200:
        return f"{d // 60} minutes ago"
    if d < 172800:
        return f"{d // 3600} hours ago"
    return f"{d // 86400} days ago"


def audit_tally(api: Api, project_id: int, token_name: str | None = None, token_id: int | None = None) -> dict:
    """What was written on the project since the last human-confirmed action
    (a push, publish, discard or review stamp): counts by kind, from the audit."""
    rows = []
    offset = 0
    while True:
        page = get_audit(api, project_id=project_id, limit=200, offset=offset)
        rows.extend(page["writes"])
        offset += 200
        if offset >= page["total"] or not page["writes"]:
            break
    since = None
    recent: list[dict] = []
    for w in rows:                       # newest first
        path = str(w.get("path") or "")
        if any(path.endswith(h) or f"{h}?" in path for h in HUMAN_PATHS):
            since = w
            break
        recent.append(w)
    tally = {"interfaces": 0, "rules_disabled": 0, "rules_enabled": 0, "rules_excluded": 0, "rules_restored": 0,
             "settings": 0, "builds": 0, "refreshes": 0, "renames": 0, "objects_deleted": 0, "objects_merged": 0,
             "rule_fields": 0, "moves": 0, "assigns": 0, "catalogues": 0,
             # stage 2
             "network_added": 0, "network_edited": 0, "network_deleted": 0,
             "nat_added": 0, "nat_edited": 0, "nat_deleted": 0, "snapshots": 0, "restores": 0,
             "other": 0, "writes": 0}
    for w in recent:
        if token_id is not None and w.get("token_id") != token_id:
            continue
        if token_id is None and token_name and w.get("token") != token_name:
            continue
        tally["writes"] += 1
        path, what = str(w.get("path") or ""), str(w.get("what") or "")
        n = 0
        try:
            n = int(what.split(" ")[1]) if what.split(" ")[1:2] and what.split(" ")[1].isdigit() else 0
        except (ValueError, IndexError):
            n = 0
        method = str(w.get("method") or "").upper()
        bare = path.split("?")[0].rstrip("/")
        # stage 2: the network strand's rows, the NAT rules and the snapshots
        # come before the /interfaces/ and /rules/ catch-alls (D13)
        if "/snapshots" in bare:
            tally["restores" if bare.endswith("/restore") else "snapshots"] += 1
        elif "/nat-rules" in bare:
            if method == "POST" and bare.endswith("/nat-rules"):
                tally["nat_added"] += 1
            elif method == "DELETE":
                tally["nat_deleted"] += 1
            else:
                tally["nat_edited"] += n or 1
        elif method == "POST" and bare.endswith(("/interfaces", "/routes", "/vrfs")):
            tally["network_added"] += 1
        elif method == "DELETE" and any(f"/{k}/" in bare for k in ("interfaces", "routes", "zones", "vrfs")):
            tally["network_deleted"] += 1
        elif (method == "PATCH" and ("/routes/" in bare or "/zones/" in bare)) or bare.endswith("/zones/properties"):
            tally["network_edited"] += n or 1
        elif "/interfaces/" in path:
            tally["interfaces"] += 1
        elif path.endswith("/rules/disable"):
            tally["rules_disabled" if what.startswith("disabled") else "rules_enabled"] += n or 1
        elif path.endswith("/rules/exclude"):
            tally["rules_excluded"] += n or 1
        elif path.endswith("/rules/restore"):
            tally["rules_restored"] += n or 1
        elif path.endswith("/settings"):
            tally["settings"] += 1
        elif path.endswith("/build"):
            tally["builds"] += 1
        elif path.endswith("/refresh") and "/catalog/" not in path:
            tally["refreshes"] += 1
        elif path.endswith("/rename") or path.endswith("/rules/names") or (path.split("?")[0].count("/objects/") and "PATCH" in str(w.get("method") or "")):
            tally["renames"] += n or 1
        elif "/objects/merge" in path:
            tally["objects_merged"] += n or 1
        elif "/objects" in path:
            tally["objects_deleted"] += n or 1
        elif path.endswith("/rules/move") or "/rules/order" in path:
            tally["moves"] += 1
        elif "/applications/assign" in path:
            tally["assigns"] += 1
        elif "/catalog/" in path:
            tally["catalogues"] += 1
        elif "/rules/" in path:
            tally["rule_fields"] += 1
        else:
            tally["other"] += 1
    tally["since"] = {"what": _s(since.get("what"), 80), "when": since.get("when"), "token": since.get("token")} if since else None
    return tally


def _tally_sentence(t: dict) -> str:
    if not t.get("writes"):
        return "no writes by this token since the last confirmed action"
    bits = []
    for key, label in (("interfaces", "interface edit(s)"), ("rules_disabled", "rule(s) disabled"),
                       ("rules_enabled", "rule(s) enabled"), ("rules_excluded", "rule(s) excluded"),
                       ("rules_restored", "rule(s) restored"), ("settings", "settings change(s)"), ("builds", "build(s)"),
                       ("refreshes", "ruleset refresh(es)"), ("renames", "name(s) set"), ("objects_deleted", "object(s) deleted"),
                       ("network_added", "network row(s) added"), ("network_edited", "network row(s) edited"),
                       ("network_deleted", "network row(s) deleted"), ("nat_added", "NAT rule(s) added"),
                       ("nat_edited", "NAT rule(s) edited"), ("nat_deleted", "NAT rule(s) deleted"),
                       ("snapshots", "snapshot(s) taken"), ("restores", "restore(s)"),
                       ("objects_merged", "object(s) merged"), ("rule_fields", "rule field edit(s)"), ("moves", "rule move(s)"),
                       ("assigns", "application assignment(s)"), ("catalogues", "catalogue refresh(es)"),
                       ("other", "other write(s)")):
        if t.get(key):
            bits.append(f"{t[key]} {label}")
    return f"{t['writes']} write(s) by this token since the last confirmed action: " + ", ".join(bits)


def _build_facts(api: Api, project_id: int) -> tuple[dict, dict, dict]:
    """The project, its target Device and the build state, read for a message."""
    p = get_project(api, project_id)
    raw = api.get(f"/projects/{int(project_id)}")
    build = raw.get("build") or {}
    target = get_device(api, p["target_id"]) if p.get("target_id") else {}
    return p, target, build


def review_preview(api: Api, project_id: int, build_id: str, token_name: str | None = None, token_id: int | None = None) -> dict:
    """What a human attests with mark_reviewed: the build and its summary."""
    p, target, build = _build_facts(api, project_id)
    bid = str(build_id or "").strip()
    if not bid:
        raise ApiError(400, "name the build_id, get_project shows it")
    summ = build.get("summary") or {}
    current = build.get("job_id") == bid
    reviewed = (build.get("reviewed") or {}).get("job_id") == bid
    lines = [f"Mark the findings of project {_q(p.get('name'))} (id {project_id}, tenant {_q(p.get('tenant'))}) as reviewed?",
             f"Build {bid[:12]} built {build.get('built_at')} ({_age(build.get('built_at')) or 'unknown age'}), "
             + ("the current build" if current else "NOT the current build any more"),
             f"Summary: {summ.get('blockers')} blocker(s), {summ.get('dropped_fields')} dropped field(s), "
             f"rules {((summ.get('rules') or {}).get('source'))} source to {((summ.get('rules') or {}).get('target'))} target",
             "This build is marked reviewed already." if reviewed else "This states that you read the findings (get_findings shows them).",
             _tally_sentence(audit_tally(api, project_id, token_name, token_id))]
    return {"message": "\n".join(lines), "accept": "mark reviewed", "current": current, "already": reviewed,
            "facts": {"project": p.get("name"), "target": target.get("name"), "build_id": bid, "summary": summ}}


def review_apply(api: Api, project_id: int, build_id: str, reason: str | None = None) -> dict:
    r = api.post(f"/projects/{int(project_id)}/reviewed", {"job_id": build_id, **({"reason": reason} if reason else {})})
    if not r.get("reviewed"):
        raise ApiError(409, "the build changed since, read the findings again (get_project shows the current build_id)")
    return {"confirmed": True, "reviewed": True, "build_id": build_id, "sentence": "the build is marked reviewed"}


# the human tier: the review stamp and
# the restore ask the human in the client. A push, a publish and a discard are no
# tools: an agent never writes to a Device, the operator does that on the page.
REFUSALS = {"review": "not confirmed, the build stays unreviewed",
            "restore": "not confirmed, nothing was restored"}
UNSUPPORTED = {"review": "confirm in an interactive client, or mark the build reviewed on the page",
               "restore": "confirm in an interactive client, or restore from the page"}


# ── the catalogue's second part: inventory, zones, rule zones, VRs ──

def fetch_target_inventory(api: Api, project_id: int, reason: str | None = None,
                           limiter: RateLimiter | None = None) -> dict:
    """The target's inventory read from the Device (interfaces, zones, VRs,
    routes and the platform's catalogues): nothing is written to the Device,
    the snapshot feeds the rename-to-target names. May take a minute or two."""
    (limiter or LIMITER).take("middle")
    r = api.call("POST", f"/projects/{int(project_id)}/target-inventory",
                 params={"reason": reason} if reason else None, timeout=600.0)
    return {"project_id": int(project_id), "target_id": _i(r.get("target_id")), "platform": _s(r.get("platform")),
            "fetched": _names(r.get("fetched"), 12), "not_on_this_platform": _names(r.get("not_on_this_platform"), 12),
            "failed": [{"kind": _s(f.get("kind")), "error": _s(f.get("error"), 300)} for f in (r.get("failed") or []) if isinstance(f, dict)],
            "warnings": _names(r.get("warnings"), 12),
            "sentence": ("the target's inventory is fetched, list_interfaces and list_zones show the names the target offers"
                         if r.get("fetched") else "nothing fetched")}


def list_vrfs(api: Api, project_id: int) -> dict:
    r = api.get(f"/projects/{int(project_id)}/vrfs")
    rows = [{"id": _i(v.get("id")), "name": _s(v.get("name")), "description": _s(v.get("description")),
             "project_own": bool(v.get("project_id"))} for v in (r.get("vrfs") or [])]
    return {"project_id": int(project_id), "vrfs": rows, "total": len(rows)}


# ── the reads of stage 2 ─────

def list_routes(api: Api, project_id: int) -> dict:
    r = api.get(f"/projects/{int(project_id)}/routes")
    rows = [{"id": _i(x.get("id")), "prefix": _s(x.get("prefix")), "interface": _s(x.get("interface")),
             "next_hop": _s(x.get("next_hop")), "vr": _s(x.get("vr")), "metric": _i(x.get("metric")),
             "route_type": _s(x.get("route_type")), "zone": _s(x.get("zone")),
             "edited": bool(x.get("edited")), "own": bool(x.get("own"))} for x in (r.get("routes") or [])]
    return {"project_id": int(project_id), "network_device_id": _i(r.get("network_device_id")),
            "routes": rows, "total": len(rows)}


_NAT_SCALARS = ("name", "nat_type", "interface", "trans_src", "trans_src_type", "trans_dst", "trans_dst_port",
                "description")
_NAT_LISTS = ("src_zones", "dst_zones", "orig_src", "orig_dst", "orig_service")
_NAT_FLAGS = ("disabled", "negate_source", "negate_destination", "negate_service", "own")
_NAT_MARKERS = ("disabled_override_source", "zone_override_source", "description_override_source",
                "properties_override_source", "negate_override_source")


def _nat_row(x: dict) -> dict:
    out: dict = {"nat_hash": _s(x.get("nat_hash"), 40), "id": _i(x.get("id")), "position": _i(x.get("position"))}
    for k in _NAT_SCALARS:
        out[k] = _s(x.get(k))
    for k in _NAT_LISTS:
        out[k] = _names(x.get(k))
    for k in _NAT_FLAGS:
        out[k] = bool(x.get(k))
    props = x.get("properties")
    out["properties"] = {str(k)[:64]: _s(v) for k, v in props.items()} if isinstance(props, dict) else {}
    out["overrides"] = sorted(k.replace("_override_source", "") for k in _NAT_MARKERS if x.get(k))
    return out


def list_nat_rules(api: Api, project_id: int, q: str | None = None, offset: int = 0, limit: int = 50) -> dict:
    r = api.get(f"/projects/{int(project_id)}/nat-rules")
    rows = [_nat_row(x) for x in (r.get("nat_rules") or [])]
    needle = str(q or "").strip().lower()
    if needle:
        rows = [x for x in rows if needle in str(x.get("name") or "").lower()
                or needle in str(x.get("description") or "").lower()]
    total = len(rows)
    off = max(0, int(offset or 0))
    page = rows[off:off + max(1, int(limit))]
    return {"project_id": int(project_id), "nat_device_id": _i(r.get("nat_device_id")),
            "nat_rules": page, "total": total, "offset": off, "next_offset": off + len(page) if off + len(page) < total else None}


def list_snapshots(api: Api, project_id: int) -> dict:
    r = api.get(f"/projects/{int(project_id)}/snapshots")
    rows = [{"id": _i(x.get("id")), "name": _s(x.get("name")), "kind": _s(x.get("kind")), "note": _s(x.get("note")),
             "created_at": _s(x.get("created_at")), "rows": _i(x.get("rows")),
             "source_changed": bool(x.get("source_changed"))} for x in (r.get("snapshots") or [])]
    return {"project_id": int(project_id), "snapshots": rows, "total": len(rows)}


def describe_kind(api: Api, project_id: int, kind: str) -> dict:
    r = api.get(f"/projects/{int(project_id)}/kinds/{str(kind).strip()}")
    out = {"project_id": int(project_id), "kind": _s(r.get("kind")), "key": _s(r.get("key")),
           "target_platform": _s(r.get("target_platform"))}
    for verb in ("add", "edit", "delete"):
        out[verb] = scrub_deep(r.get(verb)) if isinstance(r.get(verb), dict) else None
    if isinstance(r.get("property_keys"), list):
        out["property_keys"] = scrub_deep(r["property_keys"])
    return out


def create_zone(api: Api, project_id: int, name: str, reason: str, color: str | None = None, confirm: bool = False,
                limiter: RateLimiter | None = None) -> dict:
    """The project's own zone, proposed then created with confirm (D3)."""
    reason = _need_reason(reason)
    zname = str(name or "").strip()
    if not zname:
        raise ApiError(400, "the zone needs a name")
    zones = list_zones(api, project_id)["zones"]
    exists = any(z.get("name") == zname for z in zones)
    proposal = {"project_id": int(project_id), "zone": zname, "color": color or "blue", "reason": reason,
                "exists": exists, "note": "a zone of this project, bound to interfaces with edit_interface and used by rules"}
    if exists:
        return {**proposal, "applied": False, "sentence": f"a zone named {zname} exists already, nothing would change"}
    if not confirm:
        return {**proposal, "applied": False, "sentence": WRITE_SENTENCE}
    (limiter or LIMITER).take("middle")
    r = api.post(f"/projects/{int(project_id)}/zones", {"name": zname, "color": color or "blue", "reason": reason})
    return {**proposal, "applied": True, "id": _i(r.get("id")), "sentence": "applied, the audit carries the reason"}


def reset_rule_zones(api: Api, project_id: int, reason: str, confirm: bool = False,
                     limiter: RateLimiter | None = None) -> dict:
    """Every rule zone override of the project removed, derived and manual
    alike; derive_rule_zones brings the derived ones back."""
    reason = _need_reason(reason)
    proposal = {"project_id": int(project_id), "reason": reason,
                "note": "removes every rule's zone override of this project, the derived ones and the manual picks. "
                        "The rules show their source zones again until derive_rule_zones or a manual pick"}
    if not confirm:
        return {**proposal, "applied": False, "sentence": WRITE_SENTENCE}
    (limiter or LIMITER).take("middle")
    r = api.call("DELETE", f"/projects/{int(project_id)}/rule-zones", params={"reason": reason})
    return {**proposal, "applied": True, "removed": _i(r.get("deleted")), "sentence": "applied, the audit carries the reason"}


def derive_rule_zones(api: Api, project_id: int, reason: str, confirm: bool = False,
                      limiter: RateLimiter | None = None) -> dict:
    """The zones of every rule derived from the routes and the interfaces'
    zones; a rule with a manual pick keeps it."""
    reason = _need_reason(reason)
    proposal = {"project_id": int(project_id), "reason": reason,
                "note": "derives source and destination zones of every rule from the routes, writes them as derived "
                        "overrides. Manual picks stay. Rules without a route match stay empty"}
    if not confirm:
        return {**proposal, "applied": False, "sentence": WRITE_SENTENCE}
    (limiter or LIMITER).take("middle")
    r = api.post(f"/projects/{int(project_id)}/rule-zones/auto", params={"reason": reason})
    return {**proposal, "applied": True, "mapped": _i(r.get("mapped")), "manual_kept": _i(r.get("skipped_manual")),
            "no_match": _i(r.get("no_match")), "warning": _s(r.get("warning"), 400), "note_from_api": _s(r.get("note"), 400),
            "sentence": "applied, the audit carries the reason"}


def delete_vrf(api: Api, project_id: int, name: str, reason: str, confirm: bool = False,
               limiter: RateLimiter | None = None) -> dict:
    """A virtual router left out of this project: its interfaces and routes
    re-home to default; an imported VR becomes an exclusion the page can
    restore, the project's own VR is deleted."""
    reason = _need_reason(reason)
    vname = str(name or "").strip()
    rows = list_vrfs(api, project_id)["vrfs"]
    hit = next((v for v in rows if v.get("name") == vname), None)
    if hit is None:
        raise ApiError(404, f"no virtual router named {vname} in project {project_id}: " + ", ".join(v["name"] for v in rows))
    if vname == "default":
        raise ApiError(409, "the default virtual router is where deleted VRs' interfaces and routes go: it cannot be deleted")
    proposal = {"project_id": int(project_id), "vrf": vname, "project_own": hit.get("project_own"), "reason": reason,
                "note": ("the project's own VR is deleted and its members re-home to default" if hit.get("project_own")
                         else "an imported VR: becomes an exclusion of this project (restore brings it back), its interfaces and routes read under default")}
    if not confirm:
        return {**proposal, "applied": False, "sentence": WRITE_SENTENCE}
    (limiter or LIMITER).take("middle")
    api.call("DELETE", f"/projects/{int(project_id)}/vrfs/{vname}", params={"reason": reason})
    return {**proposal, "applied": True, "sentence": "applied, the audit carries the reason"}


def whoami(api: Api) -> dict:
    """The calling token (D13): id, name, scope, tenant, expiry."""
    return api.get("/whoami", timeout=5.0)


# ── the curation stage: objects, names, rule fields, order ──

OBJECT_KINDS = ("address", "service", "address_group", "service_group", "schedule")
RENAME_KINDS = ("object", "service", "interface", "zone", "vrf", "nat_rule", "rule")
CATALOG_KINDS = ("applications", "security_profiles", "log_forwarding", "utm_profiles", "threat_layers",
                 "threat_profiles", "zones")
RULE_FIELDS = ("zones", "service", "applications", "profiles", "logging", "track", "schedule", "negate")
CLEAR = "clear"          # the word that clears a scalar field through edit_rules
PROPOSAL_ROWS = 20       # rules a proposal names


def _object_row(o: dict) -> dict:
    row = {"id": _i(o.get("id")), "name": _s(o.get("name")), "source_name": _s(o.get("source_name"))}
    for key in ("type", "value", "protocol", "port", "source"):
        if o.get(key) not in (None, ""):
            row[key] = _s(o.get(key))
    if o.get("description"):
        row["description"] = _s(o.get("description"), 80)
    if isinstance(o.get("members"), list):
        row["members"] = _names(o.get("members"), 20)
        row["member_count"] = len(o.get("members"))
    if "flags" in o:
        row["flags"] = _names(o.get("flags"), 8)
    return row


def list_objects(api: Api, project_id: int, kind: str = "address", q: str | None = None, offset: int = 0,
                 limit: int = PAGE, flags: bool = False) -> dict:
    """The project's objects of one kind as the Objects tab shows them (D8),
    paged, with the lint flags on request."""
    if kind not in OBJECT_KINDS:
        raise ApiError(400, f"kind must be one of {', '.join(OBJECT_KINDS)}")
    offset = max(0, int(offset or 0))
    limit = max(1, min(int(limit or PAGE), 200))
    params: dict[str, Any] = {"kind": kind, "limit": limit, "offset": offset, "flags": 1 if flags else 0}
    if q:
        params["q"] = str(q)[:120]
    r = api.get(f"/projects/{int(project_id)}/objects", params=params)
    rows = [_object_row(o) for o in (r.get("objects") or []) if isinstance(o, dict)]
    return {"project_id": int(project_id), "kind": kind, "objects": rows, "offset": offset, "limit": limit,
            "total": _i(r.get("total")) or 0,
            "note": ("flags: unused (no rule, group or NAT of this project references it), dup_name, dup_value "
                     "(another object carries the same value), dup_member, member_value_dup" if flags else None)}


def list_names(api: Api, project_id: int, kind: str | None = None) -> dict:
    """The project's name map: what it shows under another name than the source's (D7)."""
    params = {"kind": kind} if kind else None
    r = api.get(f"/projects/{int(project_id)}/names", params=params)
    rows = [{"kind": _s(n.get("kind")), "source_name": _s(n.get("source_name")), "shown_as": _s(n.get("target_name")),
             "orphan": bool(n.get("orphan"))} for n in (r.get("names") or []) if isinstance(n, dict)]
    return {"project_id": int(project_id), "names": rows[:500], "total": _i(r.get("total")) or len(rows),
            "note": "an orphan row names a source entity the last import no longer carries"}


_RULE_FIELD_KEYS = ("service_override", "profile_group", "av_profile", "webfilter_profile", "dnsfilter_profile",
                    "ips_sensor", "application_list", "ssl_ssh_profile", "pa_spyware_profile", "pa_vulnerability_profile",
                    "pa_file_blocking_profile", "pa_wildfire_profile", "pa_data_filtering_profile", "log_forwarding",
                    "log_start", "log_end", "log_traffic", "capture_packet", "track_type", "accounting", "per_session",
                    "per_connection", "schedule", "negate_source", "negate_destination", "negate_service")


def _rule_full_row(r: dict) -> dict:
    pos = r.get("sequence")
    if isinstance(pos, float) and pos.is_integer():
        pos = int(pos)
    row = {"rule_hash": _s(r.get("rule_hash"), 40), "name": _s(r.get("rule_name")),
           "source_name": _s(r.get("source_rule_name")), "position": pos,
           "action": _s(r.get("action")), "disabled": bool(r.get("disabled")),
           "from_zones": _names(r.get("src_zones"), 8), "to_zones": _names(r.get("dst_zones"), 8),
           "sources": _names(r.get("sources"), 12), "destinations": _names(r.get("destinations"), 12),
           "service": _s(r.get("port_display") or r.get("application")),
           "applications": _s(r.get("application"), 300)}
    fields = {k: r.get(k) for k in _RULE_FIELD_KEYS if r.get(k) not in (None, "")}
    row["fields"] = {k: (_s(v, 120) if isinstance(v, str) else v) for k, v in fields.items()}
    return row


def get_rules(api: Api, project_id: int, rule_hashes: list) -> dict:
    """Up to fifty rules by hash with every effective field the page's row
    carries (D10): what edit_rules would change, as it is now."""
    hashes = [h for h in (_hex40(x) for x in (rule_hashes or [])) if h]
    if not hashes:
        raise ApiError(400, "name the rules by rule_hash (40 hex characters each)")
    if len(hashes) > CAP_HASHES:
        raise ApiError(400, f"at most {CAP_HASHES} rules a call")
    r = api.get(f"/projects/{int(project_id)}/rules", params={"hashes": ",".join(hashes)})
    rows = [_rule_full_row(x) for x in (r.get("rules") or []) if isinstance(x, dict)]
    found = {x["rule_hash"] for x in rows}
    return {"project_id": int(project_id), "rules": rows, "unknown": [h for h in hashes if h not in found],
            "note": "fields holds the project's overrides and the effective schedule and negates, position the effective order"}


def get_catalog(api: Api, project_id: int, kind: str, q: str | None = None, offset: int = 0, limit: int = PAGE) -> dict:
    """The target's stored catalogue of a kind, its names paged and filtered
    (D9), or the zone picker's catalogue; 404 names the refresh that reads it."""
    if kind not in CATALOG_KINDS:
        raise ApiError(400, f"kind must be one of {', '.join(CATALOG_KINDS)}")
    r = api.get(f"/projects/{int(project_id)}/catalog/{kind}")
    cat = r.get("catalog")
    out = {"project_id": int(project_id), "kind": kind, "platform": _s(r.get("platform")), "source": _s(r.get("source")),
           "read_at": _s(r.get("read_at"))}
    if kind == "zones":
        c = cat if isinstance(cat, dict) else {}

        def _entry_names(entries):
            return _names([(e.get("name") if isinstance(e, dict) else e) for e in (entries or [])], 200)
        out.update({"zones": _entry_names(c.get("zones")), "interfaces": _entry_names(c.get("interfaces")),
                    "any_allowed": c.get("any_allowed")})
        return out
    names: list[dict] = []
    if isinstance(cat, dict):
        for bucket, entries in cat.items():
            for e in (entries if isinstance(entries, list) else []):
                nm = e.get("name") if isinstance(e, dict) else e
                if nm:
                    names.append({"name": _s(nm), "bucket": _s(bucket)})
    elif isinstance(cat, list):
        for e in cat:
            nm = e.get("name") if isinstance(e, dict) else e
            if nm:
                names.append({"name": _s(nm)})
    if q:
        ql = str(q).lower()
        names = [n for n in names if ql in str(n.get("name") or "").lower()]
    out.update(_page(names, offset, limit))
    return out


def _proposal(kind: str, reason: str, body: dict, applied: bool, sentence: str, **extra) -> dict:
    return {"kind": kind, "reason": reason, "request": body, "applied": applied, "sentence": sentence, **extra}


def rename_items(api: Api, project_id: int, kind: str, reason: str, select: dict | None = None,
                 pattern: str | None = None, replace: list | None = None, case: str = "keep",
                 mapping: dict | None = None, confirm: bool = False, limiter: RateLimiter | None = None) -> dict:
    """The naming workbench (D7): the plan as the proposal, the write with
    confirm. A pattern over a selection, or an explicit mapping (source name
    or rule hash to the new name). The plan is a set: a collision refuses the
    whole batch, the answer names why."""
    reason = _need_reason(reason)
    if kind not in RENAME_KINDS:
        raise ApiError(400, f"kind must be one of {', '.join(RENAME_KINDS)}")
    if (pattern is None) == (mapping is None):
        raise ApiError(400, "give pattern with select, or mapping, one of the two")
    body: dict[str, Any] = {"kind": kind, "dry_run": True, "case": case or "keep", "reason": reason}
    if pattern is not None:
        body["pattern"] = str(pattern)
        body["select"] = select or {}
        if replace:
            body["replace"] = replace
    else:
        body["mapping"] = {str(k): str(v) for k, v in (mapping or {}).items()}
    plan = api.post(f"/projects/{int(project_id)}/rename", body)
    view = {k: plan.get(k) for k in ("selected", "changes", "changes_total", "refused", "refused_total", "unchanged_total",
                                     "over_limit_total", "inverse", "target_platform") if k in plan}
    if plan.get("refused_total"):
        return {"project_id": int(project_id), "applied": False, "sentence": plan.get("error") or "refused", **view}
    if not confirm:
        return {"project_id": int(project_id), "applied": False, "sentence": WRITE_SENTENCE, **view}
    (limiter or LIMITER).take("middle")
    body["dry_run"] = False
    done = api.post(f"/projects/{int(project_id)}/rename", body)
    return {"project_id": int(project_id), "applied": True, "written": _i(done.get("written")),
            "inverse": done.get("inverse"), "sentence": "applied, the audit carries the reason, mapping=inverse undoes it",
            "changes_total": _i(done.get("changes_total"))}


def delete_objects(api: Api, project_id: int, items: list, reason: str, confirm: bool = False,
                   limiter: RateLimiter | None = None) -> dict:
    """Leave objects out of the project (D8): the partition (deletable,
    blocked with the reasons, not found) is the proposal, confirm excludes
    the deletable ones."""
    reason = _need_reason(reason)
    clean = []
    for it in items or []:
        if not isinstance(it, dict) or it.get("kind") not in OBJECT_KINDS or it.get("id") is None:
            raise ApiError(400, "items are {kind, id} pairs, kind one of " + ", ".join(OBJECT_KINDS))
        clean.append({"kind": it["kind"], "id": int(it["id"])})
    if not clean:
        raise ApiError(400, "name at least one object")
    if len(clean) > 500:
        raise ApiError(400, "at most 500 objects a call")
    part = api.post(f"/projects/{int(project_id)}/objects/delete", {"items": clean, "dry_run": True, "reason": reason})
    view = {"deletable": [_s(x.get("name")) for x in (part.get("deletable") or [])][:PAGE],
            "deletable_total": len(part.get("deletable") or []),
            "blocked": [{"name": _s(x.get("name")), "reasons": _names(x.get("reasons"), 4)} for x in (part.get("blocked") or [])][:PAGE],
            "blocked_total": len(part.get("blocked") or []), "not_found": len(part.get("not_found") or [])}
    if not confirm:
        return {"project_id": int(project_id), "applied": False, "sentence": WRITE_SENTENCE, **view}
    if not part.get("deletable"):
        return {"project_id": int(project_id), "applied": False, "sentence": "nothing deletable: every object is blocked or unknown", **view}
    (limiter or LIMITER).take("middle")
    done = api.post(f"/projects/{int(project_id)}/objects/delete", {"items": clean, "dry_run": False, "reason": reason})
    return {"project_id": int(project_id), "applied": True, "deleted": len(done.get("deleted") or []),
            "blocked_total": len(done.get("blocked") or []), "sentence": "applied, the audit carries the reason, the page or the exclusions restore them"}


def merge_objects(api: Api, project_id: int, kind: str, buckets: list, reason: str, confirm: bool = False,
                  limiter: RateLimiter | None = None) -> dict:
    """Merge objects into canonicals (D8): the dry run with the references
    rewritten is the proposal, confirm applies."""
    reason = _need_reason(reason)
    if kind not in ("address", "service"):
        raise ApiError(400, "kind must be address or service")
    if not buckets or len(buckets) > 50:
        raise ApiError(400, "give 1 to 50 buckets of {canonical: {id}, losers: [{id}, ...]}")
    body = {"kind": kind, "buckets": buckets, "dry_run": True, "reason": reason}
    plan = api.post(f"/projects/{int(project_id)}/objects/merge", body)
    view = {"buckets": [{"canonical": _s(b.get("canonical_name")), "losers": len(b.get("loser_ids") or [])}
                        for b in (plan.get("buckets") or [])][:PAGE],
            "deleted": _i(plan.get("deleted")), "refs_rewritten": _i(plan.get("refs_rewritten"))}
    if not confirm:
        return {"project_id": int(project_id), "applied": False, "sentence": WRITE_SENTENCE, **view}
    (limiter or LIMITER).take("middle")
    body["dry_run"] = False
    done = api.post(f"/projects/{int(project_id)}/objects/merge", body)
    return {"project_id": int(project_id), "applied": True, "deleted": _i(done.get("deleted")),
            "refs_rewritten": _i(done.get("refs_rewritten")),
            "sentence": "applied, the audit carries the reason, the losers are exclusions and name-map rows on the page"}


def _edit_request(field: str, value: Any) -> tuple[str, str, dict]:
    """The route and body of one field edit (D6), from the tool's argument."""
    if field == "zones":
        v = value if isinstance(value, dict) else {}
        if v.get("src") is None and v.get("dst") is None:
            raise ApiError(400, "zones takes {src?, dst?}: a name adds it, 'any' resets the side, '__auto__' derives it, or {\"clear\": true}")
        if v.get("clear"):
            return "POST", "/rules/zones/clear", {}
        return "POST", "/rules/zones", {"src_zone": v.get("src"), "dst_zone": v.get("dst")}
    if field == "service":
        s = None if value in (None, CLEAR) else str(value)
        if s not in (None, "any", "application-default"):
            raise ApiError(400, "service is 'any', 'application-default' or 'clear'")
        return "PUT", "/rules/service", {"service": s}
    if field == "applications":
        if value == CLEAR or value == [CLEAR]:
            return "PUT", "/rules/applications", {"applications": None}
        if not isinstance(value, list):
            raise ApiError(400, "applications is a list of names, ['any'], [] (empty) or 'clear' (the source's again)")
        return "PUT", "/rules/applications", {"applications": [str(x) for x in value]}
    if field == "profiles":
        v = value if isinstance(value, dict) else {}
        return "PUT", "/rules/profiles", {"profile_group": v.get("group"), "slots": v.get("slots")}
    if field == "logging":
        v = value if isinstance(value, dict) else {}
        return "PUT", "/rules/logging", {k: v.get(k) for k in ("profile", "log_start", "log_end", "log_traffic", "capture_packet") if k in v}
    if field == "track":
        v = value if isinstance(value, dict) else {}
        return "PUT", "/rules/track", {k: v.get(k) for k in ("track_type", "accounting", "per_session", "per_connection") if k in v}
    if field == "schedule":
        return "PUT", "/rules/schedule", {"schedule": None if value in (None, CLEAR) else str(value)}
    if field == "negate":
        v = value if isinstance(value, dict) else {}
        if v.get("aspect") not in ("source", "destination", "service") or not isinstance(v.get("value"), bool):
            raise ApiError(400, "negate takes {aspect: source|destination|service, value: true|false}")
        return "PUT", "/rules/negate", {"aspect": v["aspect"], "value": v["value"]}
    raise ApiError(400, f"field must be one of {', '.join(RULE_FIELDS)}")


def edit_rules(api: Api, project_id: int, rule_hashes: list, reason: str, confirm: bool = False,
               limiter: RateLimiter | None = None, **fields) -> dict:
    """One field of a selection of rules (D6, D10): exactly one of zones,
    service, applications, profiles, logging, track, schedule, negate. The
    proposal names the rules with the field as it is now and echoes the write."""
    reason = _need_reason(reason)
    given = {k: v for k, v in fields.items() if v is not None}
    if len(given) != 1:
        raise ApiError(400, "give exactly one field: " + ", ".join(RULE_FIELDS))
    field, value = next(iter(given.items()))
    hashes = [h for h in (_hex40(x) for x in (rule_hashes or [])) if h]
    if not hashes:
        raise ApiError(400, "name the rules by rule_hash")
    if len(hashes) > CAP_HASHES:
        raise ApiError(400, f"at most {CAP_HASHES} rules a call")
    method, path, body = _edit_request(field, value)
    current = get_rules(api, project_id, hashes)
    rows = []
    for r in current["rules"][:PROPOSAL_ROWS]:
        now = {k: v for k, v in (r.get("fields") or {}).items() if _field_matches(field, k)}
        if field == "zones":
            now = {"from_zones": r.get("from_zones"), "to_zones": r.get("to_zones")}
        elif field == "applications":
            now = {"applications": r.get("applications")}
        rows.append({"rule_hash": r["rule_hash"], "name": r.get("name"), "now": now})
    proposal = {"project_id": int(project_id), "field": field, "write": body, "rules": rows,
                "rules_total": len(hashes), "unknown": current.get("unknown"), "reason": reason}
    if not confirm:
        return {**proposal, "applied": False, "sentence": WRITE_SENTENCE}
    (limiter or LIMITER).take("middle")
    full = {"rule_hashes": hashes, "reason": reason, **body}
    res = api.post(f"/projects/{int(project_id)}{path}", full) if method == "POST" else api.put(f"/projects/{int(project_id)}{path}", full)
    return {**proposal, "applied": True, "result": {k: v for k, v in (res or {}).items() if isinstance(v, (str, int, bool, float)) or v is None},
            "sentence": "applied, the audit carries the reason"}


_FIELD_PREFIXES = {"service": ("service_override",), "profiles": ("profile_group", "av_", "webfilter_", "dnsfilter_", "ips_", "application_list", "ssl_ssh", "pa_"),
                   "logging": ("log_", "capture_packet"), "track": ("track_", "accounting", "per_"), "schedule": ("schedule",),
                   "negate": ("negate_",)}


def _field_matches(field: str, key: str) -> bool:
    return any(key.startswith(p) for p in _FIELD_PREFIXES.get(field, ()))


def move_rule(api: Api, project_id: int, rule_hash: str, reason: str, before: str | None = None,
              after: str | None = None, confirm: bool = False, limiter: RateLimiter | None = None) -> dict:
    """Place one rule before or after another (D5): the proposal names both
    with their positions, confirm writes the project's order override."""
    reason = _need_reason(reason)
    h = _hex40(rule_hash)
    anchor = _hex40(before or after)
    if not h or not anchor or (before and after):
        raise ApiError(400, "name the rule and exactly one of before or after, by rule_hash")
    current = get_rules(api, project_id, [h, anchor])
    by = {r["rule_hash"]: r for r in current["rules"]}
    if h not in by or anchor not in by:
        raise ApiError(404, "unknown or excluded: " + ", ".join(x[:12] for x in (h, anchor) if x not in by))
    proposal = {"project_id": int(project_id), "rule": {k: by[h].get(k) for k in ("rule_hash", "name", "position")},
                "anchor": {k: by[anchor].get(k) for k in ("rule_hash", "name", "position")},
                "placement": "before" if before else "after", "reason": reason}
    if not confirm:
        return {**proposal, "applied": False, "sentence": WRITE_SENTENCE}
    (limiter or LIMITER).take("middle")
    res = api.post(f"/projects/{int(project_id)}/rules/move",
                   {"rule_hash": h, "before": anchor if before else None, "after": anchor if after else None, "reason": reason})
    return {**proposal, "applied": True, "rank": _i(res.get("rank")), "neighbours": res.get("neighbours"),
            "sentence": "applied, the audit carries the reason, reset_rule_order undoes it"}


def reset_rule_order(api: Api, project_id: int, reason: str, rule_hashes: list | None = None, confirm: bool = False,
                     limiter: RateLimiter | None = None) -> dict:
    """Remove the project's order overrides, the named rules' or all (D5)."""
    reason = _need_reason(reason)
    hashes = [h for h in (_hex40(x) for x in (rule_hashes or [])) if h]
    proposal = {"project_id": int(project_id), "scope": (f"{len(hashes)} rule(s)" if hashes else "every order override of the project"),
                "reason": reason}
    if not confirm:
        return {**proposal, "applied": False, "sentence": WRITE_SENTENCE}
    (limiter or LIMITER).take("middle")
    params: dict[str, Any] = {"reason": reason}
    if hashes:
        params["rule_hashes"] = ",".join(hashes)
    res = api.delete(f"/projects/{int(project_id)}/rules/order", params=params)
    return {**proposal, "applied": True, "removed": _i(res.get("removed")), "sentence": "applied, the source order shows again"}


def refresh_catalog(api: Api, project_id: int, kind: str, reason: str, confirm: bool = False,
                    limiter: RateLimiter | None = None) -> dict:
    """Read one catalogue from the target Device and store it (D9): the
    installation opens a session to the Device, so it is a proposal first."""
    reason = _need_reason(reason)
    if kind not in CATALOG_KINDS or kind == "zones":
        raise ApiError(400, "kind must be one of " + ", ".join(k for k in CATALOG_KINDS if k != "zones"))
    proposal = {"project_id": int(project_id), "kind": kind, "reason": reason,
                "note": "Gateshift will open a session to the target Device and read this catalogue"}
    if not confirm:
        return {**proposal, "applied": False, "sentence": WRITE_SENTENCE}
    (limiter or LIMITER).take("middle")
    res = api.post(f"/projects/{int(project_id)}/catalog/{kind}/refresh", None, params={"reason": reason})
    size = sum(len(v) for v in (res.get("catalog") or {}).values() if isinstance(v, list)) if isinstance(res.get("catalog"), dict) else None
    return {**proposal, "applied": True, "read_at": _s(res.get("read_at")), "entries": size, "sentence": "read and stored, get_catalog lists it"}


def assign_applications(api: Api, project_id: int, mode: str, reason: str, rule_hashes: list | None = None,
                        confirm: bool = False, limiter: RateLimiter | None = None) -> dict:
    """The automatic application assignment as a job (D9): by the rules' ports
    or by the source's application names; manual overrides are kept."""
    reason = _need_reason(reason)
    if mode not in ("ports", "names"):
        raise ApiError(400, "mode is ports (match the rules' ports to the catalogue) or names (match the source's application names)")
    hashes = [h for h in (_hex40(x) for x in (rule_hashes or [])) if h]
    proposal = {"project_id": int(project_id), "mode": mode, "scope": (f"{len(hashes)} rule(s)" if hashes else "every rule of the project"),
                "reason": reason, "note": "manual application picks are kept, the catalogue is read from the target Device"}
    if not confirm:
        return {**proposal, "applied": False, "sentence": WRITE_SENTENCE}
    (limiter or LIMITER).take("middle")
    res = api.post(f"/projects/{int(project_id)}/applications/assign",
                   {"mode": mode, "rule_hashes": hashes or None, "reason": reason})
    return {**proposal, "applied": True, "job_id": _s(res.get("job_id")), "already": bool(res.get("already")),
            "sentence": ("a job of this project was already running, its id is returned" if res.get("already")
                         else "started, get_job reads the counters in the last event's data")}


# ── the kinds of stage 2: add_item, edit_item, delete_item, the snapshots ──

_KIND_WORDS_2 = {"interface": "interface", "route": "route", "vrf": "virtual router", "zone": "zone", "nat_rule": "NAT rule"}
_KIND_PATH = {"interface": "interfaces", "route": "routes", "vrf": "vrfs", "zone": "zones", "nat_rule": "nat-rules"}
_ALTERNATIVE = {("interface", "edit"): "edit_interface carries the interface's edits",
                ("zone", "add"): "create_zone adds a zone",
                ("vrf", "edit"): "rename_items renames a virtual router"}


def _kind_rows(api: Api, project_id: int, kind: str) -> list[dict]:
    """The rows of one kind as the project sees them (the reads carry `own`)."""
    if kind == "interface":
        return list_interfaces(api, project_id)["interfaces"]
    if kind == "route":
        return list_routes(api, project_id)["routes"]
    if kind == "vrf":
        return list_vrfs(api, project_id)["vrfs"]
    if kind == "zone":
        return list_zones(api, project_id)["zones"]
    if kind == "nat_rule":
        rows: list[dict] = []
        offset = 0
        while True:
            page = list_nat_rules(api, project_id, None, offset, 50)
            rows.extend(page["nat_rules"])
            if page.get("next_offset") is None:
                return rows
            offset = page["next_offset"]
    raise ApiError(400, f"kind must be one of {', '.join(KINDS)}")


def _norm_prefix(s: Any) -> str | None:
    """A route prefix as the server stores it (the all-zeros address is the default route)."""
    try:
        import ipaddress
        net = ipaddress.ip_network(str(s or "").strip(), strict=False)
        if net.prefixlen == net.max_prefixlen and int(net.network_address) == 0:
            net = ipaddress.ip_network("::/0" if net.version == 6 else "0.0.0.0/0")
        return str(net)
    except ValueError:
        return None


def resolve_item(api: Api, project_id: int, kind: str, key: Any) -> dict:
    """The row a call names (D7): its id, or its shown or source name
    (interface, zone, virtual router), a NAT rule's hash or shown name, a
    route's `prefix|vr` or bare prefix (the default VR). An ambiguous key
    names the ids."""
    if kind not in KINDS:
        raise ApiError(400, f"kind must be one of {', '.join(KINDS)}")
    k = str(key or "").strip()
    if not k:
        raise ApiError(400, f"name the {_KIND_WORDS_2[kind]}: {KINDS[kind]['key']}")
    rows = _kind_rows(api, project_id, kind)
    word = _KIND_WORDS_2[kind]
    if k.isdigit() and kind != "nat_rule":
        for r in rows:
            if r.get("id") == int(k):
                return r
        raise ApiError(404, f"no {word} with id {k} in project {project_id}")
    if kind == "route":
        prefix, _, vr = k.partition("|")
        norm = _norm_prefix(prefix)
        if norm is None:
            raise ApiError(400, f"{prefix!r} is not a prefix: give the route's id, prefix|vr or a bare prefix")
        vr = (vr or "default").strip()
        hits = [r for r in rows if _norm_prefix(r.get("prefix")) == norm and (r.get("vr") or "default") == vr]
    elif kind == "nat_rule":
        h = _hex40(k)
        hits = [r for r in rows if r.get("nat_hash") == h] if h else [r for r in rows if r.get("name") == k]
    else:
        hits = [r for r in rows if r.get("name") == k or r.get("source_name") == k]
    if not hits:
        raise ApiError(404, f"no {word} {k!r} in project {project_id}: the list tool of the kind shows them")
    if len(hits) > 1:
        ids = ", ".join(str(r.get("id") or r.get("nat_hash")) for r in hits)
        raise ApiError(409, f"{k!r} names {len(hits)} {word}s in this project, use the id: {ids}")
    return hits[0]


def _check_fields(kind: str, verb: str, fields: Any) -> dict:
    """The fields of a call against the kind table (D7): unknown ones are
    refused with the list, enums checked, the required ones present for add."""
    table = KINDS.get(kind, {}).get(verb) if kind in KINDS else None
    if table is None:
        alt = _ALTERNATIVE.get((kind, verb))
        raise ApiError(400, f"{_KIND_WORDS_2.get(kind, kind)} has no {verb} here" + (f": {alt}" if alt else "")
                       if kind in KINDS else f"kind must be one of {', '.join(KINDS)}")
    given = dict(fields or {})
    unknown = sorted(k for k in given if k not in table)
    if unknown:
        raise ApiError(400, f"unknown field(s) for {kind} {verb}: {', '.join(unknown)}. The fields are "
                            f"{', '.join(table)}, describe_kind explains them")
    for fname, spec in table.items():
        if spec.get("required") and verb == "add" and not str(given.get(fname) or "").strip():
            raise ApiError(400, f"{fname} is required for a {_KIND_WORDS_2[kind]}")
        if "enum" in spec and given.get(fname) is not None and str(given[fname]) not in spec["enum"]:
            raise ApiError(400, f"{fname} must be one of {', '.join(spec['enum'])}")
    return given


def _object_known(api: Api, project_id: int, token: str, kinds_: tuple) -> bool:
    for kd in kinds_:
        try:
            rows = list_objects(api, project_id, kd, token, 0, 50, False)["objects"]
        except ApiError:
            continue
        if any(o.get("name") == token for o in rows):
            return True
    return False


def _add_proposal(api: Api, project_id: int, kind: str, fields: dict) -> tuple[list[str], list[str]]:
    """The checks of an addition composed from reads (the API has no dry
    run): what will happen and what the API will refuse."""
    notes: list[str] = []
    warnings: list[str] = []
    if kind == "interface":
        name = str(fields.get("name") or "").strip()
        rows = list_interfaces(api, project_id)["interfaces"]
        if any(r.get("name") == name or r.get("source_name") == name for r in rows):
            warnings.append(f"an interface named {_q(name)} exists in this project: the API will refuse it")
        if fields.get("parent") and not any(r.get("name") == fields["parent"] for r in rows):
            warnings.append(f"no interface named {_q(fields['parent'])} to be the parent")
        ips = [str(x) for x in (fields.get("ip_addresses") or [])]
        for ip in ips:
            if _norm_prefix(ip) is None:
                warnings.append(f"{_q(ip)} is not an address: the API will refuse it")
        if ips:
            import ipaddress
            for r in rows:
                for have in (r.get("ip_addresses") or []):
                    for ip in ips:
                        try:
                            a, b = ipaddress.ip_network(ip, strict=False), ipaddress.ip_network(have, strict=False)
                        except ValueError:
                            continue
                        if a.version == b.version and a.overlaps(b):
                            warnings.append(f"{ip} overlaps {have} on interface {_q(r.get('name'))}: the API will refuse it")
            notes.append(f"{len(ips)} connected route(s) are seeded")
        if fields.get("zone"):
            zones = {z.get("name") for z in list_zones(api, project_id)["zones"]}
            notes.append("bound to the existing zone" if fields["zone"] in zones else "the zone is created as the project's own and bound")
        if fields.get("dhcp") and ips:
            warnings.append("DHCP and a static address together: the API will refuse it")
    elif kind == "route":
        norm = _norm_prefix(fields.get("prefix"))
        if norm is None:
            warnings.append(f"{_q(fields.get('prefix'))} is not a prefix: the API will refuse it")
        vr = str(fields.get("vr") or "default").strip()
        notes.append(f"prefix {norm or fields.get('prefix')} in virtual router {vr}")
        if vr != "default" and not any(v.get("name") == vr for v in list_vrfs(api, project_id)["vrfs"]):
            warnings.append(f"no virtual router named {_q(vr)} in this project")
        if fields.get("interface") and not any(r.get("name") == fields["interface"] for r in list_interfaces(api, project_id)["interfaces"]):
            warnings.append(f"no interface named {_q(fields['interface'])} in this project")
        if (fields.get("route_type") or "static") == "static" and not fields.get("interface"):
            warnings.append("a static route needs an interface: the API will refuse it")
        for r in list_routes(api, project_id)["routes"]:
            if _norm_prefix(r.get("prefix")) == norm and (r.get("vr") or "default") == vr:
                warnings.append(f"a route to {norm} exists in {vr} already: the API will refuse it")
        for x in list_exclusions(api, project_id)["exclusions"]:
            if x.get("kind") == "route" and str(x.get("item_key") or "") == f"{norm}|{vr}":
                warnings.append("this prefix is excluded in this project: restore the exclusion instead")
    elif kind == "vrf":
        name = str(fields.get("name") or "").strip()
        if any(v.get("name") == name for v in list_vrfs(api, project_id)["vrfs"]):
            warnings.append(f"a virtual router named {_q(name)} exists in this project: the API will refuse it")
    elif kind == "nat_rule":
        name = str(fields.get("name") or "").strip()
        if any(n.get("name") == name for n in _kind_rows(api, project_id, "nat_rule")):
            warnings.append(f"a NAT rule named {_q(name)} exists in this project: the API will refuse it")
        zone_names = {z.get("name") for z in list_zones(api, project_id)["zones"]} | \
                     {i.get("name") for i in list_interfaces(api, project_id)["interfaces"]}
        for slot in ("src_zones", "dst_zones"):
            for z in (fields.get(slot) or []):
                if z not in zone_names:
                    warnings.append(f"{slot}: no zone or interface named {_q(z)} in this project")
        for slot, kinds_ in (("orig_src", ("address", "address_group")), ("orig_dst", ("address", "address_group")),
                             ("orig_service", ("service", "service_group"))):
            for tok in (fields.get(slot) or []):
                t = str(tok)
                if t.lower() in ("any", "application-default") or _norm_prefix(t) is not None or "/" in t:
                    continue
                if not _object_known(api, project_id, t, kinds_):
                    warnings.append(f"{slot}: no object named {_q(t)} in the project's source, it is stored as typed")
        notes.append(f"a {fields.get('nat_type')} rule, translated source type {fields.get('trans_src_type') or 'none'}")
    return notes, warnings


def add_item(api: Api, project_id: int, kind: str, fields: dict, reason: str, confirm: bool = False,
             limiter: RateLimiter | None = None) -> dict:
    """The project's own interface, route, virtual router or NAT rule (D7):
    the proposal composed from reads, the write with confirm=true."""
    reason = _need_reason(reason)
    given = _check_fields(kind, "add", fields)
    notes, warnings = _add_proposal(api, project_id, kind, given)
    proposal = {"project_id": int(project_id), "kind": kind, "fields": scrub_deep(given), "notes": notes,
                "warnings": warnings, "reason": reason,
                "undo": f"delete_item {kind} removes the project's own row again"}
    if not confirm:
        return {**proposal, "applied": False, "sentence": WRITE_SENTENCE}
    (limiter or LIMITER).take("middle")
    r = api.post(f"/projects/{int(project_id)}/{_KIND_PATH[kind]}", {**given, "reason": reason})
    out = {k: scrub(v) for k, v in (r or {}).items() if k in ("id", "nat_hash", "position", "prefix", "vr",
                                                              "zone_created", "connected_routes")}
    return {**proposal, "applied": True, **out, "sentence": "applied, the audit carries the reason"}


_EDIT_FROM = {
    "route": {"prefix": "prefix", "next_hop": "next_hop", "interface": "interface", "metric": "metric", "route_type": "route_type"},
    "zone": {"color": "color", "is_external": "external", "properties": "properties"},
    "nat_rule": {"name": "name", "description": "description", "disabled": "disabled", "properties": "properties",
                 "src_zone": "src_zones", "dst_zone": "dst_zones", "negate_source": "negate_source",
                 "negate_destination": "negate_destination", "negate_service": "negate_service"},
}


def edit_item(api: Api, project_id: int, kind: str, key: Any, fields: dict, reason: str, confirm: bool = False,
              limiter: RateLimiter | None = None) -> dict:
    """A route's, zone's or NAT rule's fields (D7): the row as it is now
    beside the parsed write, the PATCH with confirm=true. NAT rules go by
    hash or name, the negates ride in fields."""
    reason = _need_reason(reason)
    given = _check_fields(kind, "edit", fields)
    if not given:
        raise ApiError(400, "nothing to change: give at least one field")
    row = resolve_item(api, project_id, kind, key)
    changes = [{"field": f, "from": scrub(row.get(_EDIT_FROM[kind].get(f, f))), "to": scrub(v)} for f, v in given.items()]
    label = row.get("name") or row.get("prefix")
    proposal = {"project_id": int(project_id), "kind": kind, "item": {"id": row.get("id"), "nat_hash": row.get("nat_hash"),
                                                                       "name": label, "own": bool(row.get("own"))},
                "changes": changes, "reason": reason,
                "undo": ("the inverse edit" if row.get("own") else "the inverse edit removes the project's edit row")}
    if kind == "route" and "prefix" in given:
        proposal["note"] = "a new prefix: the old route leaves the view (an exclusion) and the project adds the new one"
    if not confirm:
        return {**proposal, "applied": False, "sentence": WRITE_SENTENCE}
    (limiter or LIMITER).take("middle")
    ident = row.get("nat_hash") if kind == "nat_rule" else row.get("id")
    r = api.patch(f"/projects/{int(project_id)}/{_KIND_PATH[kind]}/{ident}", {**given, "reason": reason})
    out = {"applied": True, "sentence": "applied, the audit carries the reason"}
    if isinstance(r, dict) and r.get("ignored_keys"):
        out["ignored_keys"] = _names(r.get("ignored_keys"))
    return {**proposal, **out}


def delete_item(api: Api, project_id: int, kind: str, key: Any, reason: str, confirm: bool = False,
                cascade: bool = False, empty_zone_ok: bool = False, limiter: RateLimiter | None = None) -> dict:
    """A row of the network strand or a NAT rule deleted in this project
    (D7): the project's own row is removed, an imported one becomes an
    exclusion the Overview restores. A zone with members and rules needs
    cascade=true (the rules move to the members' names after an
    auto-snapshot), an interface that empties a used zone empty_zone_ok=true."""
    reason = _need_reason(reason)
    if kind not in KINDS:
        raise ApiError(400, f"kind must be one of {', '.join(KINDS)}")
    row = resolve_item(api, project_id, kind, key)
    own = bool(row.get("own")) or bool(row.get("project_own"))
    label = row.get("name") or row.get("prefix")
    notes = ["the project's own row: removed for real" if own
             else "an imported row: it becomes an exclusion of this project, list_exclusions shows it and the Overview restores it"]
    if kind == "zone" and row.get("members"):
        notes.append(f"members: {', '.join(_q(m, 40) for m in row['members'][:12])}" + (
            ". Rules that use the zone are moved to the members' names first (cascade=true, after an auto-snapshot)"
            if cascade else ". With rules using the zone the API refuses unless cascade=true"))
    if kind == "interface" and row.get("zone"):
        notes.append(f"bound to zone {_q(row.get('zone'))}: as its sole member the delete needs empty_zone_ok=true")
    if kind == "vrf" and str(row.get("name")) == "default":
        raise ApiError(409, "the default virtual router cannot be deleted")
    proposal = {"project_id": int(project_id), "kind": kind,
                "item": {"id": row.get("id"), "nat_hash": row.get("nat_hash"), "name": label, "own": own},
                "notes": notes, "reason": reason,
                "undo": "add_item adds it again" if own else "the exclusion is restored on the Overview or through the API"}
    if not confirm:
        return {**proposal, "applied": False, "sentence": WRITE_SENTENCE}
    (limiter or LIMITER).take("middle")
    params: dict = {"reason": reason}
    if kind == "zone" and cascade:
        params["cascade"] = 1
    if kind == "interface" and empty_zone_ok:
        params["confirm_empty_zone"] = 1
    ident = row.get("nat_hash") if kind == "nat_rule" else (row.get("name") if kind == "vrf" else row.get("id"))
    try:
        r = api.delete(f"/projects/{int(project_id)}/{_KIND_PATH[kind]}/{ident}", params=params)
    except ApiError as exc:
        data = exc.data or {}
        if exc.status == 409 and (data.get("confirmable") or data.get("cascade_available") is not None):
            return {**proposal, "applied": False, "sentence": exc.sentence(),
                    "referrers": scrub_deep(data.get("referrers")), "member_interfaces": _names(data.get("member_interfaces")),
                    "hint": ("cascade=true moves the rules to the members' names" if data.get("cascade_available")
                             else "empty_zone_ok=true accepts the empty zone" if data.get("confirmable") else None)}
        raise
    out = {"applied": True, "sentence": "applied, the audit carries the reason"}
    if isinstance(r, dict):
        for k in ("removed", "excluded", "cascaded_rules", "auto_snapshot"):
            if k in r:
                out[k] = scrub(r[k])
    return {**proposal, **out}


def create_snapshot(api: Api, project_id: int, name: str, reason: str, note: str | None = None,
                    limiter: RateLimiter | None = None) -> dict:
    """A snapshot of the project's decisions (D6): a safety net that changes
    no decision, so it runs without a confirm, with a reason for the audit."""
    reason = _need_reason(reason)
    sname = str(name or "").strip()[:128]
    if not sname:
        raise ApiError(400, "the snapshot needs a name")
    (limiter or LIMITER).take("middle")
    r = api.post(f"/projects/{int(project_id)}/snapshots", {"name": sname, "note": (str(note or "").strip() or None), "reason": reason})
    return {"project_id": int(project_id), "applied": True, "id": _i(r.get("id")), "name": sname, "rows": _i(r.get("rows")),
            "sentence": "the snapshot is taken, restore_snapshot brings the project back to it"}


def restore_preview(api: Api, project_id: int, snapshot_id: int, token_name: str | None = None,
                    token_id: int | None = None) -> dict:
    """The message a human reads before a restore (D6): composed from reads."""
    p, _target, build = _build_facts(api, project_id)
    snaps = list_snapshots(api, project_id)["snapshots"]
    snap = next((s for s in snaps if s.get("id") == int(snapshot_id)), None)
    if not snap:
        raise ApiError(404, f"no snapshot with id {snapshot_id} in project {project_id}, list_snapshots shows them")
    lines = [f"Restore project {_q(p.get('name'))} (id {project_id}, tenant {_q(p.get('tenant'))}) to snapshot "
             f"{_q(snap.get('name'))} (id {snap.get('id')}, {snap.get('kind')}, {snap.get('rows')} row(s), taken "
             f"{snap.get('created_at')}, {_age(snap.get('created_at')) or 'unknown age'})?",
             "The source or target was imported again since the snapshot: rows for rules the source no longer has "
             "are restored as orphans" if snap.get("source_changed") else "The source and target are as they were at the snapshot",
             "Every decision made in this project since is discarded: renames, rule edits, exclusions, additions and order. "
             "An auto-snapshot of the state before the restore is taken first, so the restore itself can be undone",
             f"The artefact {'(state ' + str(build.get('state')) + ') ' if build.get('state') else ''}is marked outdated, "
             "a build is needed before a push",
             _tally_sentence(audit_tally(api, project_id, token_name, token_id))]
    return {"message": "\n".join(lines), "accept": "restore snapshot", "snapshot_id": int(snapshot_id),
            "facts": {"project": p.get("name"), "snapshot": snap.get("name"), "kind": snap.get("kind"),
                      "rows": snap.get("rows"), "source_changed": bool(snap.get("source_changed"))}}


def restore_apply(api: Api, project_id: int, snapshot_id: int, reason: str | None = None) -> dict:
    r = api.post(f"/projects/{int(project_id)}/snapshots/{int(snapshot_id)}/restore",
                 params={"reason": reason} if reason else None)
    out = {"confirmed": True, "snapshot_id": int(snapshot_id), "snapshot": _s(r.get("snapshot")),
           "restored": _i(r.get("restored")), "removed": _i(r.get("removed")), "orphans": _i(r.get("orphans")),
           "auto_snapshot": _i(r.get("auto_snapshot")), "source_changed": bool(r.get("source_changed")),
           "sentence": "restored, the artefact is outdated: build_project before a push"}
    if r.get("names_kept"):
        out["names_kept"] = True
        out["sentence"] += ". The snapshot predates the name map: the project's names stayed as they are"
    if _i(r.get("held")):
        out["held"] = _i(r.get("held"))
        out["sentence"] += (f". {out['held']} added row(s) stayed out: another project of the Device"
                            " holds that key (an interface, route, zone, virtual router or NAT rule name)")
    if isinstance(r.get("tables"), dict):
        out["tables"] = {str(k)[:40]: scrub_deep(v) for k, v in r["tables"].items()}
    return out
