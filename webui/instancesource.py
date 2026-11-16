# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
"""Virtual instances of a firewall as scopes under its Device row
(docs/VIRTUAL_INSTANCES_PLAN.md): FortiGate VDOMs, PAN-OS vsys, Check Point
virtual systems. A box that runs several instances is the container, each
instance a scope with a Device row of its own that carries the box's
address and credentials as a derived copy with one writer (D3), so every
path that reads a Device works for an instance unchanged. A box that runs
one instance gets no scopes and nothing changes for it (D2).

The recognition reads the vendor's instance list (`instances_of`), the
rails of the Management Center source give the scopes their rows and edges
(`sync_instance_rows`), the import and the collect of the box run the
vendor's handler once per instance row.
"""
from __future__ import annotations

import json

from deploy import _forti_common as _forti

# The database side imports lazily: the recognition runs in the tests on a host
# without SQLAlchemy, as the Management Center source does.

INSTANCE_ROLE = "instance"
KINDS = {"fortigate": "vdom", "panw": "vsys", "checkpoint": "vs"}


def has_instances(config) -> bool:
    """Whether a Device row is the container of instance scopes (its config
    records the recognition of the last import or collect)."""
    try:
        cfg = json.loads(config or "{}") if isinstance(config, str) else (config or {})
    except ValueError:
        return False
    return str(((cfg or {}).get("instances") or {}).get("mode") or "") == "multi"


def _fortigate_instances(device: dict, *, _get=None) -> dict | None:
    """The VDOMs of a FortiGate: None in no-vdom mode. In multi-VDOM mode
    every CMDB call carries the VDOM, `system global` names the management
    VDOM, `system settings` of a VDOM names its operation mode (lab 2026-11-04,
    section 3 of the plan). A VDOM the API user is not assigned to is listed
    as skipped: the prerequisites ask for the user's VDOM list."""
    base = _forti.base_url_for(device)
    token = _forti.token_for(device)

    def get(path: str, vdom: str) -> dict:
        if _get is not None:
            return _get(path, vdom)
        return _forti.api_get(base, token, path, vdom)

    g = (get("/api/v2/cmdb/system/global", "root").get("results") or {})
    if str(g.get("vdom-mode") or "no-vdom") == "no-vdom":
        return None
    mgmt = str(g.get("management-vdom") or "root")
    instances: list[dict] = []
    skipped: list[str] = []
    for v in get("/api/v2/cmdb/system/vdom", "root").get("results") or []:
        name = str(v.get("name") or "").strip()
        if not name:
            continue
        try:
            st = get("/api/v2/cmdb/system/settings", name).get("results") or {}
        except Exception as exc:                 # the API user is not assigned to this VDOM
            skipped.append(f"{name}: not readable by the API user ({exc.__class__.__name__})")
            continue
        opmode = str(st.get("opmode") or "nat").lower()
        if opmode != "nat":
            skipped.append(f"{name}: {opmode} mode, the plan covers NAT mode")
            continue
        instances.append({"type": "vdom", "name": name, "vendor_id": name, "management": name == mgmt})
    return {"kind": "vdom", "management": mgmt, "instances": instances, "skipped": skipped}


def _panw_instances(device: dict, *, _get=None) -> dict | None:
    """The vsys of a PAN-OS firewall: None with one vsys. Several vsys sit under
    `/config/devices/entry/vsys` (F-3 of the plan, built from the XML API
    reference: a VM-Series or a larger appliance, the lab PA-440 runs one).
    The shared objects of `/config/shared` become the root scope every vsys
    scope draws on (D4), vsys1 is marked as the default instance."""
    if _get is None:
        from main import _panw_get            # the import side's reader (running config)
        host = device.get("mgmt_ip") or device.get("host_name")
        base = f"https://{host}:{device.get('mgmt_port') or 443}"
        key = device.get("api_key") or ""
        _get = lambda xp: _panw_get(base, key, xp)   # noqa: E731
    root = _get("/config/devices/entry[@name='localhost.localdomain']/vsys")
    entries = root.findall(".//vsys/entry") if root is not None else []
    if len(entries) <= 1:
        return None
    instances = []
    for e in entries:
        name = str(e.attrib.get("name") or "").strip()
        if not name:
            continue
        instances.append({"type": "vsys", "name": name, "vendor_id": name, "management": name == "vsys1",
                          "display_name": (e.findtext("display-name") or "").strip() or None})
    return {"kind": "vsys", "management": "vsys1", "instances": instances, "skipped": [],
            "root": {"type": "shared", "name": "shared", "vendor_id": "shared"}}


def _checkpoint_instances(device: dict, *, _call=None, _call_top=None, _call_in=None) -> dict | None:
    """The virtual systems of a Check Point VSX gateway or cluster (F-4 of the
    plan, measured on the R81.20 MDS lab 2026-11-05): the registered gateway
    object must be a VSX class, found by uid in the box's own context. The
    candidates come from the listing at the management's top level, where an
    MDS answers the objects of every domain with their domain (under other
    uids than the domains do) and a SmartCenter its one context. A cluster's
    virtual systems are its own when their cluster member names are prefixed
    by the cluster's member names, a VSX gateway's virtual systems are taken
    as its own (one VSX gateway per management). Each is then read in its own
    domain for its uid there and becomes an instance with the policy
    installed on it, its domain and, from the VSX object's VSLS parameters,
    its VS id. A VS without an installed policy is listed as skipped. The
    objects are the domain's, so there is no root scope. A row pinned as a
    simple gateway or cluster asks the management nothing."""
    try:
        cfg = device.get("config")
        cfg = json.loads(cfg or "{}") if isinstance(cfg, str) else (cfg or {})
    except ValueError:
        cfg = {}
    from deploy.checkpoint import _VSX_GATEWAY_TYPES as _VSX_KINDS, _VS_TYPES      # the one list of the classes
    cp_cfg = (cfg or {}).get("cp") or {}
    gw_uid = str(cp_cfg.get("gateway_uid") or "").strip()
    if not gw_uid:
        return None
    pinned_type = str(cp_cfg.get("gateway_type") or "").strip()
    if pinned_type and pinned_type not in _VSX_KINDS:
        return None            # a simple gateway or cluster, pinned by the wizard: no listing needed
    box_domain = str(cp_cfg.get("domain") or "").strip() or None

    def _in_domain(domain: str | None):
        """A call bound to a session in `domain` (None: the top level)."""
        from deploy.checkpoint import _login, _call as _mgmt_call
        dcfg = dict(cfg)
        dcfg["cp"] = {k: v for k, v in cp_cfg.items() if k != "domain"}
        if domain:
            dcfg["cp"]["domain"] = domain
        sid, base = _login(dict(device, config=json.dumps(dcfg)))
        return lambda cmd, payload: _mgmt_call(base, sid, cmd, payload)

    if _call is None:
        _call = _in_domain(box_domain)
    if _call_top is None:
        _call_top = _in_domain(None) if box_domain else _call
    if _call_in is None:
        _call_in = _in_domain

    def _listing(call) -> list[dict]:
        objs: list[dict] = []
        offset = 0
        for _ in range(50):
            resp = call("show-gateways-and-servers", {"details-level": "full", "limit": 200, "offset": offset})
            items = resp.get("objects") or []
            if not isinstance(items, list) or not items:
                break
            objs.extend(o for o in items if isinstance(o, dict))
            offset += len(items)
            total = resp.get("total")
            if isinstance(total, int) and offset >= total:
                break
        return objs

    objs_box = _listing(_call)
    me = next((o for o in objs_box if str(o.get("uid") or "") == gw_uid), None)
    if not me or str(me.get("type") or "") not in _VSX_KINDS:
        return None
    is_cluster = "Cluster" in str(me.get("type") or "")
    my_members = [str(m) for m in (me.get("cluster-member-names") or []) if m]
    # the VS ids: the VSX object's VSLS parameters name each VS with its id
    vsid_of: dict[str, int] = {}
    try:
        gen = _call("show-generic-object", {"uid": gw_uid})
        gen = gen.get("object") if isinstance(gen.get("object"), dict) else gen
        for p in (gen.get("vslsParameters") or []) if isinstance(gen, dict) else []:
            if isinstance(p, dict) and p.get("ownedName") and p.get("vsid") is not None:
                vsid_of[str(p["ownedName"])] = int(p["vsid"])
    except Exception:
        vsid_of = {}
    objs_top = objs_box if _call_top is _call else _listing(_call_top)
    listings: dict[str | None, list[dict]] = {box_domain: objs_box, None: objs_top}
    instances, skipped = [], []
    for o in objs_top:
        otype = str(o.get("type") or "")
        if otype not in _VS_TYPES:
            continue
        name = str(o.get("name") or "").strip()
        if not name:
            continue
        members = [str(m) for m in (o.get("cluster-member-names") or []) if m]
        if is_cluster:
            if not members or not all(any(m.startswith(f"{mm}_") for mm in my_members) for m in members):
                continue                                   # a virtual system of another VSX cluster
        elif members:
            continue                                       # a cluster's virtual system, not this gateway's
        domain = str(((o.get("domain") or {}).get("name")) or "").strip() or None
        # the object as its own domain lists it: the uid the domain's reads answer to
        if domain == box_domain or domain is None:
            record = next((r for r in objs_box if r.get("name") == name and r.get("type") == otype), None)
        else:
            if domain not in listings:
                listings[domain] = _listing(_call_in(domain))
            record = next((r for r in listings[domain] if r.get("name") == name and r.get("type") == otype), None)
        if not record or not record.get("uid"):
            skipped.append(f"{name}: not listed in its domain {domain or ''}".rstrip())
            continue
        uid = str(record.get("uid"))
        pkg = str(((record.get("policy") or o.get("policy") or {}).get("access-policy-name")) or "").strip()
        if not pkg:
            skipped.append(f"{name}: no policy installed on it")
            continue
        vsid = vsid_of.get(name)
        slot = {"gateway_uid": uid, "gateway_type": otype, "policy_package": pkg, "vs": name}
        if vsid is not None:
            slot["vsid"] = vsid
        if domain:
            slot["domain"] = domain
        instances.append({"type": "vs", "name": name, "vendor_id": uid, "management": False,
                          "display_name": f"{name} ({domain})" if domain else None, "config_slot": slot})
    instances.sort(key=lambda i: (i["config_slot"].get("vsid", 10 ** 6), i["name"]))
    return {"kind": "vs", "management": None, "instances": instances, "skipped": skipped}


def instances_of(device: dict, *, _get=None, _call=None, _call_top=None, _call_in=None) -> dict | None:
    """The instance list of a firewall row, None when it runs one instance."""
    if device.get("device_kind"):
        return None
    platform = str(device.get("platform") or "")
    if platform == "fortigate":
        return _fortigate_instances(device, _get=_get)
    if platform == "panw":
        return _panw_instances(device, _get=_get)
    if platform == "checkpoint":
        return _checkpoint_instances(device, _call=_call, _call_top=_call_top, _call_in=_call_in)
    return None


def _instance_config(box_config: str | None, kind: str, inst: dict) -> str:
    """The instance row's config: the box's config with the instance named in
    the slot the vendor driver reads (`config.fortigate.vdom` today)."""
    try:
        cfg = json.loads(box_config or "{}")
    except ValueError:
        cfg = {}
    cfg.pop("instances", None)
    cfg["instance"] = {"kind": kind, "name": inst["name"], "management": bool(inst.get("management"))}
    if kind == "vdom":
        cfg.setdefault("fortigate", {})
        cfg["fortigate"]["vdom"] = inst["name"]
    elif kind == "vsys":
        cfg.setdefault("panw", {})
        cfg["panw"]["vsys"] = inst["name"]
    elif kind == "vs":
        cfg.setdefault("cp", {})
        cfg["cp"]["vs"] = inst["name"]
        cfg["cp"].update(inst.get("config_slot") or {})     # the VS object as the gateway, its package pinned
    return json.dumps(cfg)


def copy_box_fields(conn, box_id: int) -> int:
    """The derived copy (D3): every instance row takes the box's address,
    port, credentials, role and version. The one writer of those fields on
    an instance row. Returns the number of rows written."""
    from sqlalchemy import text
    import scopepersist
    rows = conn.execute(text(
        "SELECT s.scope_device_id FROM fw_scopes s WHERE s.manager_device_id = :m AND s.scope_role IN (:r, 'root')"),
        {"m": box_id, "r": INSTANCE_ROLE}).fetchall()
    if not rows:
        return 0
    # the shared root scope of a PAN-OS box reads /config/shared with the box's key too
    conn.execute(text(
        "UPDATE fw_devices i JOIN fw_devices b ON b.id = :m "
        "SET i.mgmt_ip = b.mgmt_ip, i.mgmt_port = b.mgmt_port, i.api_key = b.api_key, "
        "    i.gaia_user = b.gaia_user, i.gaia_password = b.gaia_password, i.role = b.role, "
        "    i.software_version = b.software_version, i.tenant_id = b.tenant_id "
        "WHERE i.id IN (SELECT scope_device_id FROM fw_scopes WHERE manager_device_id = :m AND scope_role IN (:r, 'root'))"),
        {"m": box_id, "r": INSTANCE_ROLE})
    return len(rows)


def sync_instance_rows(conn, box: dict, found: dict, *, clear_content: bool = True) -> list[dict]:
    """Give every instance its scope row under the box (the rails of the
    Management Center source), write the derived copy and mark the box as
    the container. Returns the instance rows as dicts for the import:
    {id, name, config, management}."""
    from sqlalchemy import text
    import scopepersist
    box_id = int(box["id"])
    kind = str(found.get("kind") or KINDS.get(str(box.get("platform") or ""), "vdom"))
    scopes = []
    root = found.get("root")
    if root:        # the shared objects as the root scope the instances draw on (D4)
        scopes.append({"type": str(root.get("type") or "shared"), "name": root["name"],
                       "vendor_id": str(root.get("vendor_id") or root["name"]),
                       "config": _instance_config(box.get("config"), kind, {"name": root["name"], "management": False}),
                       "_management": False, "_root": True})
    scopes += [{"type": kind, "name": i["name"], "vendor_id": str(i.get("vendor_id") or i["name"]),
                "config": _instance_config(box.get("config"), kind, i), "_management": bool(i.get("management")),
                "_root": False}
               for i in found.get("instances") or []]
    scopepersist.sync_scope_devices(conn, box_id, str(box.get("platform") or ""), scopes, clear_content=clear_content)
    root_sid = next((sc["_sdid"] for sc in scopes if sc["_root"]), None)
    for pos, sc in enumerate(scopes):
        scopepersist.write_scope_edge(conn, box_id, sc, "root" if sc["_root"] else INSTANCE_ROLE,
                                      None if sc["_root"] else root_sid, None)
        conn.execute(text("UPDATE fw_scopes SET position = :p WHERE manager_device_id = :m AND scope_device_id = :s"),
                     {"p": pos, "m": box_id, "s": sc["_sdid"]})
    copy_box_fields(conn, box_id)
    try:
        cfg = json.loads(box.get("config") or "{}")
    except ValueError:
        cfg = {}
    cfg["instances"] = {"mode": "multi", "kind": kind, "count": len(scopes),
                        "management": found.get("management"), "skipped": list(found.get("skipped") or [])}
    conn.execute(text("UPDATE fw_devices SET config = :c WHERE id = :id"), {"c": json.dumps(cfg), "id": box_id})
    box["config"] = json.dumps(cfg)
    return [{"id": int(sc["_sdid"]), "name": sc["name"], "config": sc["config"], "management": sc["_management"],
             "kind": sc["type"]}
            for sc in scopes]


def instance_device(box: dict, inst: dict) -> dict:
    """The device dict an import or collect handler gets for one instance:
    the box's dict (address, credentials, platform) with the instance row's
    id, names and config."""
    d = dict(box)
    d.update({"id": inst["id"], "host_name": f"mgr{box['id']}:{inst.get('kind', 'vdom')}:{inst['name']}",
              "display_name": inst["name"], "device_kind": "scope", "config": inst["config"]})
    return d


def clear_box_content(conn, box_id: int) -> None:
    """The box is the container: its own content tables empty, the instances
    carry the content (D2). Projects that point at the box row keep pointing
    at an empty row, the import log says so."""
    from sqlalchemy import text
    import scopepersist
    for tbl in scopepersist.SCOPE_CONTENT_TABLES:
        conn.execute(text(f"DELETE FROM {tbl} WHERE device_id = :d"), {"d": box_id})


def clear_box_network(conn, box_id: int) -> None:
    """The box's own network tables empty after a collect fanned into its
    instances (the import rows, a project's rows stay)."""
    from sqlalchemy import text
    import scopepersist
    for tbl in ("fw_interfaces", "fw_zones", "fw_routes", "fw_vrfs"):
        conn.execute(text(f"DELETE FROM {tbl} WHERE device_id = :d AND (project_id IS NULL OR project_id = 0)"), {"d": box_id})


def instance_rows(conn, box_id: int) -> list[dict]:
    """The instance rows of a box in position order: {id, name, config, management}."""
    from sqlalchemy import text
    import scopepersist
    out = []
    for r in conn.execute(text(
            "SELECT s.scope_device_id AS id, s.scope_name AS name, s.scope_type AS kind, d.config "
            "FROM fw_scopes s JOIN fw_devices d ON d.id = s.scope_device_id "
            "WHERE s.manager_device_id = :m AND s.scope_role = :r ORDER BY s.position, s.id"),
            {"m": box_id, "r": INSTANCE_ROLE}).mappings():
        try:
            mgmt = bool((json.loads(r["config"] or "{}").get("instance") or {}).get("management"))
        except ValueError:
            mgmt = False
        out.append({"id": int(r["id"]), "name": r["name"], "kind": r["kind"], "config": r["config"], "management": mgmt})
    return out
