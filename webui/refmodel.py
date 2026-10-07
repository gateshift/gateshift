# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""Central reference model - the single "who references whom" registry + engine.

Phase 0 of the referential-integrity refactor. Replaces the ≥9 scattered cascade/resolve/unused functions with ONE
declarative registry + a generic engine.

**Phase 0 is additive** - nothing in main.py imports this yet, zero behaviour change.
This increment ships the read side: `collect_references`, `collect_referent_names`,
`find_referrers`, `find_unused`, `find_dangling`. The write side (cascade_rename /
cascade_delete) and `resolve` land in later Phase-0 increments.

Registry shape (verified read-paths, see the doc's "Phase 0 blueprint"):
- table-backed referrers (route/interface/nat_rule/pbf_rule) are declared as data
  and read by a generic reader understanding three field shapes: `scalar`,
  `json_list` (JSON array of names), `json_dicts` (JSON array of {name,type}).
- the `access_rule` and `group` referrers are special readers (rule object names
  live at the effective stage via main._fetch_rules_and_devices; group members live
  in fw_imported_objects.value JSON, active-snapshot only).

A reference can be **polymorphic** - `targets` is a tuple of acceptable target
types (a rule/NAT "zone" is really zone-or-interface; PBF ingress resolves per item
to interface or zone). Names equal to "any"/""/None are not references.

Target/referent types: interface · zone · vrf · object (address|group) · service
(service|service-group). Plus non-validated ref targets: schedule.
"""
from __future__ import annotations

import dataclasses
import ipaddress
import json

from sqlalchemy import text

import projview


# ── declarations ─────────────────────────────────────────────────────────────

@dataclasses.dataclass(frozen=True)
class FieldRef:
    field: str                       # column name
    targets: tuple[str, ...]         # acceptable target types (polymorphic)
    shape: str = "scalar"            # scalar | json_list | json_dicts
    dict_name: str = "name"          # json_dicts: key holding the name
    dict_type: str | None = None     # json_dicts: key whose value picks the target
    type_map: dict | None = None     # json_dicts: {type_value: target_type}
    literal_ok: bool = False         # value may be a bare literal (e.g. NAT
                                     # trans_src can be an IP) → exact-match
                                     # rename/strip/find_referrers are correct,
                                     # but find_dangling must NOT flag it


@dataclasses.dataclass(frozen=True)
class TableReferrer:
    kind: str
    table: str
    id_col: str
    label_col: str
    device_col: str
    refs: tuple[FieldRef, ...]


# A rule/NAT "zone" can hold a zone OR (Forti, post auto-derive) an interface name.
ZONE_OR_IFACE = ("zone", "interface")

TABLE_REFERRERS: tuple[TableReferrer, ...] = (
    TableReferrer("route", "fw_routes", "id", "prefix", "device_id", (
        FieldRef("interface_name", ("interface",)),
        FieldRef("vr_name", ("vrf",)),
    )),
    TableReferrer("interface", "fw_interfaces", "id", "interface_name", "device_id", (
        FieldRef("vr_name", ("vrf",)),
        FieldRef("parent_iface_name", ("interface",)),
        FieldRef("member_iface_names", ("interface",), shape="json_list"),
        FieldRef("zone_name", ("zone",)),
    )),
    TableReferrer("nat_rule", "fw_nat_rules", "id", "name", "device_id", (
        FieldRef("src_zones", ZONE_OR_IFACE, shape="json_list"),
        FieldRef("dst_zones", ZONE_OR_IFACE, shape="json_list"),
        FieldRef("orig_src", ("object",), shape="json_list"),
        FieldRef("orig_dst", ("object",), shape="json_list"),
        FieldRef("orig_service", ("service",), shape="json_list"),
        FieldRef("interface_name", ("interface",)),
        # Translated source/dest - scalar object refs that may instead hold a bare
        # IP literal (exact-match rename/strip; never flagged dangling).
        # trans_src is additionally interface-typed: an interface-address
        # SNAT (PA dynamic-ip-and-port / Forti egress hide-NAT) stores the
        # egress INTERFACE name here - interface renames must cascade in.
        FieldRef("trans_src", ("object", "interface"), literal_ok=True),
        FieldRef("trans_dst", ("object",), literal_ok=True),
    )),
    TableReferrer("pbf_rule", "fw_pbf_rules", "id", "name", "device_id", (
        FieldRef("ingress", ZONE_OR_IFACE, shape="json_dicts", dict_type="type",
                 type_map={"interface": "interface", "zone": "zone"}),
        FieldRef("sources", ("object",), shape="json_list"),
        FieldRef("destinations", ("object",), shape="json_list"),
        FieldRef("services", ("service",), shape="json_list"),
        FieldRef("egress_interface", ("interface",)),
    )),
    # VPN tunnels reference interfaces by name (the local egress iface = Forti
    # local-if / PA tunnel local-interface, and the bound tunnel iface). Both are
    # vpn_hash inputs - under model A names are never rewritten here, so the
    # hash is stable; the migration re-keyed the overlay/secret/cert tables once.
    # SSL/TLS-inspection rules bind ZONES like access and NAT rules do (PA/CP
    # rulebase shape); without this entry a zone used only by a decryption
    # rule read as unreferenced and its delete guard stayed silent. Only the
    # zone fields live here: the rules' object/service names stay OUT of the
    # registry on purpose (vendor builtins such as 'HTTPS default services'
    # would false-positive in find_dangling) - see _ssl_used_names and
    # ssl_referrer_rules for that targeted layer.
    TableReferrer("ssl_rule", "fw_ssl_rules", "id", "name", "device_id", (
        FieldRef("src_zones", ZONE_OR_IFACE, shape="json_list"),
        FieldRef("dst_zones", ZONE_OR_IFACE, shape="json_list"),
    )),
    TableReferrer("vpn_tunnel", "fw_vpn_tunnels", "id", "name", "device_id", (
        FieldRef("local_interface", ("interface",)),
        FieldRef("tunnel_interface", ("interface",)),
        # Address objects a VPN references in its encryption domain / phase2 selectors
        # (CP enc-domain group, Forti phase2 src-name/dst-name). Captured at import so an
        # object used ONLY by a VPN counts as USED - see main._ensure_vpn_*_column.
        FieldRef("domain_objects", ("object",), shape="json_list"),
    )),
)

# Referents (targets) - type → list of (table, name_col, where|None). These are the
# canonical identities used for find_unused. "object"/"service" union plain objects
# with the matching group kind. NOTE: interface = SOURCE names only; the target
# bindings (port1, …) are NOT referents (they'd look like "unused interfaces") -
# they are accepted as valid *aliases* in find_dangling instead (see _valid_names).
_GRP_ACTIVE = ("source = 'synthetic' OR import_ts = "
               "(SELECT MAX(import_ts) FROM fw_imported_objects i2 "
               " WHERE i2.device_id = fw_imported_objects.device_id AND i2.source = 'import')")

REFERENT_SOURCES: dict[str, tuple[tuple[str, str, str | None], ...]] = {
    "interface": (("fw_interfaces", "interface_name", None),),
    "zone":      (("fw_zones", "name", None),),
    "vrf":       (("fw_vrfs", "name", None),),
    "object":    (("fw_address_objects", "name", None),
                  ("fw_imported_objects", "name", f"obj_type IN ('address', 'address_group') AND ({_GRP_ACTIVE})")),
    "service":   (("fw_service_objects", "name", None),
                  ("fw_imported_objects", "name", f"obj_type IN ('service', 'service_group') AND ({_GRP_ACTIVE})")),
    "schedule":  (("fw_imported_objects", "name", f"obj_type = 'schedule' AND ({_GRP_ACTIVE})"),),
}

VALIDATABLE = tuple(REFERENT_SOURCES.keys())

# Referent types that are tracked for find_unused / find_delete_blockers but
# NOT validated by find_dangling: a rule may reference a vendor BUILTIN schedule
# (Forti 'always', etc.) that is never imported as an object, so checking it for
# dangling would false-positive. (find_unused/blocker only ever match real
# imported names, so they're unaffected.)
DANGLING_SKIP_TYPES = frozenset({"schedule"})


# ── helpers ──────────────────────────────────────────────────────────────────

_SENTINELS = {"", "any", "all", "none"}


def _clean(name) -> str | None:
    if name is None:
        return None
    s = str(name).strip()
    return s if s and s.lower() not in _SENTINELS else None


def _is_ip_literal(name) -> bool:
    """True if `name` is a bare IP / CIDR / IP-range literal rather than an object
    name. Rule/NAT/PBF address+service refs can hold literals (esp. syslog-derived
    OPNsense rules carry raw IPs) - those aren't object references, so find_dangling
    must not flag them. Object NAMES (h-web, net-lan, s__inline_…) are not literals."""
    if not name:
        return False
    parts = (str(name).split("-")) if "-" in str(name) else [str(name)]
    for p in parts:
        p = p.strip()
        if not p:
            return False
        try:
            ipaddress.ip_network(p, strict=False)
        except ValueError:
            return False
    return True


def _jload(v):
    if isinstance(v, (list, dict)):
        return v
    if isinstance(v, str) and v.strip():
        try:
            return json.loads(v)
        except Exception:
            return None
    return None


def _extract(value, fr: FieldRef):
    """Yield (targets_tuple, name) for one field value per its declared shape."""
    if fr.shape == "scalar":
        n = _clean(value)
        if n:
            yield fr.targets, n
            # trans_src may hold an 'iface|ip' composite (interface-address
            # SNAT). The composite itself is literal_ok; additionally yield
            # the interface part so renames/deletes see the reference
            # (asa2pa finding 2026-09-01).
            if fr.field == "trans_src" and "interface" in fr.targets and "|" in n:
                part = _clean(n.split("|", 1)[0])
                if part:
                    yield ("interface",), part
    elif fr.shape == "json_list":
        arr = _jload(value)
        if isinstance(arr, list):
            for item in arr:
                n = _clean(item)
                if n:
                    yield fr.targets, n
    elif fr.shape == "json_dicts":
        arr = _jload(value)
        if isinstance(arr, list):
            for item in arr:
                if not isinstance(item, dict):
                    continue
                n = _clean(item.get(fr.dict_name))
                if not n:
                    continue
                if fr.dict_type and fr.type_map:
                    tgt = fr.type_map.get(str(item.get(fr.dict_type)))
                    yield (tgt,) if tgt else fr.targets, n
                else:
                    yield fr.targets, n


@dataclasses.dataclass(frozen=True)
class Reference:
    referrer_kind: str
    referrer_id: object
    referrer_label: str
    targets: tuple[str, ...]
    name: str
    literal_ok: bool = False         # carried from the FieldRef (see literal_ok)

    def label(self) -> str:
        return f"{self.referrer_kind} '{self.referrer_label}'"


# ── collectors ───────────────────────────────────────────────────────────────

def _excluded_tokens(excluded: dict | None, target_type: str) -> set:
    """Names a member list of `target_type` loses in the project view: the
    excluded objects and groups (or services and service groups)."""
    if not excluded:
        return set()
    kinds = ("object", "group") if target_type == "object" else (
        ("service", "service_group") if target_type == "service" else (target_type,))
    out: set = set()
    for k in kinds:
        out |= set(excluded.get(k) or ())
    return out


def collect_references(conn, device_id: int, *, device_host: str | None = None,
                       projects: list | None = None, excluded: dict | None = None,
                       view=None) -> list[Reference]:
    """All outgoing references for a device: table-backed referrers + groups +
    access rules. The override-shadowed parts (rules, NAT zones, PBF, VPN)
    are read from the effective view of `projects` - one project for a
    project-bound question such as generate - or, by default, of every
    project the device is the source of (the device-level question: is this
    still referenced anywhere?)."""
    out: list[Reference] = []
    # the project view (projview.ProjectView): its exclusions decide what
    # references nothing, its interface and route edits decide what a network
    # row references (a re-bound zone, a re-homed VR, a new parent / member,
    # a re-pointed egress)
    if view is not None:
        if excluded is None:
            excluded = view.excluded_dict(device_id)
        if projects is None and getattr(view, "project_id", None):
            projects = [view.project_id]

    for rr in TABLE_REFERRERS:
        # PBF is read from the EFFECTIVE view (override overlay applied) via
        # _pbf_references - the raw fw_pbf_rules row ignores a user's egress/
        # ingress remap or soft-delete. It stays in TABLE_REFERRERS for the
        # WRITE side (cascade_rename/delete rewrite the base row).
        if rr.kind == "pbf_rule":
            continue
        # VPN gets the SAME effective-view treatment via _vpn_references:
        # local_interface / tunnel_interface edits and the soft-delete live
        # in the fw_vpn_tunnel_overrides overlay, never in the raw columns -
        # scanning raw here left interfaces permanently undeletable after
        # the operator re-pointed or removed the tunnel (pa2fgt finding
        # 2026-08-31). Raw stays in TABLE_REFERRERS for the WRITE side.
        if rr.kind == "vpn_tunnel":
            continue
        # NAT zone slots are override-shadowed (fw_nat_rule_overrides.src_zones/
        # dst_zones, COALESCEd by _load_nat_rules - the deploy renders the
        # override, e.g. auto-derived interface-mode 'portN' instead of the
        # imported zone). Scanning the raw columns kept the imported zone
        # undeletable forever (pa2fgt finding 2026-08-31, same class as VPN/
        # PBF). Zone refs come from _nat_zone_references (effective view);
        # every other NAT field has no overlay and stays raw-scanned here.
        field_refs = rr.refs
        if rr.kind == "nat_rule":
            field_refs = tuple(fr for fr in rr.refs
                               if fr.field not in ("src_zones", "dst_zones"))
        cols = {rr.id_col, rr.label_col} | {fr.field for fr in field_refs}
        if view is not None and rr.kind == "interface":
            cols.add("import_interface_name")
        col_sql = ", ".join(sorted(cols))
        try:
            rows = conn.execute(
                text(f"SELECT {col_sql} FROM {rr.table} WHERE {rr.device_col} = :d"),
                {"d": device_id},
            ).mappings().all()
        except Exception:
            continue
        gone_if = set((excluded or {}).get("interface") or ())
        gone_routes = set((excluded or {}).get("route") or ())
        for row in rows:
            rid = row.get(rr.id_col)
            label = str(row.get(rr.label_col) or rid or "")
            if view is not None and rr.kind in ("interface", "route"):
                row = dict(row)
                if rr.kind == "interface":
                    e = view.interface_edits_for(device_id, row.get("import_interface_name"), label)
                    for k in ("zone_name", "vr_name", "parent_iface_name", "member_iface_names"):
                        if k in e:
                            row[k] = json.dumps(e[k]) if isinstance(e[k], list) else e[k]
                else:
                    e = view.route_edits_for(device_id, label, row.get("vr_name"))
                    for k in ("interface_name",):
                        if k in e:
                            row[k] = e[k]
            # the project view: a row deleted in the project references nothing -
            # an excluded interface, an excluded route, a route of an excluded interface
            if rr.kind == "interface" and label in gone_if:
                continue
            if rr.kind == "route" and (row.get("interface_name") in gone_if
                                       or projview.route_key(label, row.get("vr_name")) in gone_routes):
                continue
            for fr in field_refs:
                for targets, name in _extract(row.get(fr.field), fr):
                    # an interface's parent/member edge to its own name is not an
                    # external referrer
                    if rr.kind == "interface" and "interface" in targets and name == label:
                        continue
                    out.append(Reference(rr.kind, rid, label, targets, name, fr.literal_ok))

    out.extend(_group_references(conn, device_id, excluded))
    rule_refs, view_has_rules = _rule_references(conn, device_id, device_host, projects)
    out.extend(rule_refs)
    imported = _imported_rule_references(conn, device_id)
    if excluded:
        # the project view (docs/PROJECT_VIEW_DESIGN.md): a rule deleted in the
        # project references nothing, a deleted member is no reference
        gone_rules = set(excluded.get("rule") or ())
        gone_obj = _excluded_tokens(excluded, "object") | _excluded_tokens(excluded, "service")
        imported = [x for x in imported
                    if x.referrer_label not in gone_rules and x.name not in gone_obj]
    # The imported-rules fallback exists for the freshly-imported-but-not-
    # generated gap. Once the EFFECTIVE view carries this device's rules,
    # its zone/iface columns are authoritative for zone semantics (the
    # deploy renders overrides, not import values) - keeping the import-side
    # zone names as referrers made imported zones permanently undeletable
    # even after the operator set every rule to any (pa2fgt finding
    # 2026-08-31). Gate on "the view has RULES", not "the view produced
    # refs" - a device whose rules all collapsed to any/scalars yields
    # zero refs yet is fully covered by the effective view. Object/service
    # refs keep the safety-union unchanged.
    if view_has_rules:
        imported = [r for r in imported if r.targets != ZONE_OR_IFACE]
    out.extend(imported)
    out.extend(_pbf_references(conn, device_id, projects))
    out.extend(_vpn_references(conn, device_id, projects))
    out.extend(_nat_zone_references(conn, device_id, projects))
    return out


def _device_projects(conn, device_id: int) -> list:
    """The projects this device is the source of. Each holds its own
    decisions (overrides), so a device-level reference question - is this
    zone still referenced? - is the union over all of them. A device without
    a project reads its imported view only (project None)."""
    try:
        rows = conn.execute(text(
            "SELECT id FROM fw_projects WHERE source_ref_id = :d ORDER BY id"
        ), {"d": device_id}).fetchall()
    except Exception:
        rows = []
    return [int(r[0]) for r in rows] or [None]


def _effective_rows(conn, device_id: int, projects, loader) -> list[dict]:
    """One effective view per project (`projects`, or every project of the
    device), concatenated: a project's own rows stay exactly as its loader
    returns them, a row an earlier project already produced with the same
    content is skipped. A single project therefore reads as it always did.
    Rows are read in SOURCE space (no name map); each carries `_project_id`
    so override-owned values can be inverse-mapped per project."""
    out: list[dict] = []
    seen: set = set()
    for pid in (projects if projects is not None else _device_projects(conn, device_id)):
        for row in loader(conn, device_id, project_id=pid):
            key = json.dumps(row, sort_keys=True, default=str)
            if key in seen:
                continue
            seen.add(key)
            row["_project_id"] = pid
            out.append(row)
    return out


# Model A: override-owned values (a picked zone, an edited interface) are
# stored in PROJECT space; the reference engine compares names in SOURCE
# space. These helpers turn such a token into the source names it stands
# for - all pre-images of a merged name, the token itself when it is an
# unmapped source name or a target-side literal (which then simply fails to
# match any source entity, as it should).
def _inverse_maps(conn, cache: dict, project_id):
    if project_id not in cache:
        try:
            import namemap
            cache[project_id] = namemap.inverse_name_map(namemap.load_name_map(conn, project_id))
        except Exception:
            cache[project_id] = None
    return cache[project_id]


def _token_sources(inv, kinds, token) -> list:
    """Source names for a project-space token across the given kinds (a zone
    slot may hold a zone or an interface name)."""
    if not inv:
        return [token]
    out: list = []
    for kind in kinds:
        pre = (inv.get(kind) or {}).get(token)
        if pre:
            out.extend(pre)
    return _dedup_keep(out) if out else [token]


def _dedup_keep(seq):
    return list(dict.fromkeys(seq))


def _pbf_references(conn, device_id: int, projects=None) -> list[Reference]:
    """PBF references from the EFFECTIVE rule view (base + override edits, via
    main._load_pbf_rules) - so a user-remapped ingress/egress and soft-deleted
    rules reflect reality, not the raw fw_pbf_rules row. Mirrors why access rules
    read the effective stage. _load_pbf_rules(include_deleted=False) drops deleted
    rules → they reference nothing."""
    refs: list[Reference] = []
    try:
        from main import _load_pbf_rules  # lazy (avoids import cycle)
        rules = _effective_rows(conn, device_id, projects, _load_pbf_rules)
    except Exception:
        return refs
    _ING = {"interface": "interface", "zone": "zone"}
    inv_cache: dict = {}
    for p in rules:
        rid = p.get("id")
        label = str(p.get("name") or rid or "")
        edited = set(p.get("_edited_fields") or [])
        inv = _inverse_maps(conn, inv_cache, p.get("_project_id")) if edited else None
        for item in (p.get("ingress") or []):
            if not isinstance(item, dict):
                continue
            n = _clean(item.get("name"))
            if not n:
                continue
            tgt = _ING.get(str(item.get("type")))
            kinds = (tgt,) if tgt else ZONE_OR_IFACE
            names = _token_sources(inv, kinds, n) if "ingress" in edited else [n]
            for nn in names:
                refs.append(Reference("pbf_rule", rid, label, kinds, nn))
        eg = _clean(p.get("egress_interface"))
        if eg:
            names = _token_sources(inv, ("interface",), eg) if "egress_interface" in edited else [eg]
            for nn in names:
                refs.append(Reference("pbf_rule", rid, label, ("interface",), nn))
        for field, tgt in (("sources", "object"), ("destinations", "object"),
                           ("services", "service")):
            for item in (p.get(field) or []):
                n = _clean(item)
                if n:
                    refs.append(Reference("pbf_rule", rid, label, (tgt,), n))
    return refs


def _vpn_references(conn, device_id: int, projects=None) -> list[Reference]:
    """VPN interface references from the EFFECTIVE tunnel view (raw row +
    fw_vpn_tunnel_overrides edits, soft-deleted tunnels excluded) via
    main._load_vpn_tunnels - mirrors _pbf_references. The raw
    fw_vpn_tunnels columns ignore the operator's local-IF re-point and
    the tunnel soft-delete (both live in the overlay), which left
    interfaces permanently undeletable (pa2fgt finding 2026-08-31)."""
    refs: list[Reference] = []
    try:
        from main import _load_vpn_tunnels  # lazy (avoids import cycle)
        tunnels = _effective_rows(conn, device_id, projects, _load_vpn_tunnels)   # include_deleted=False
    except Exception:
        return refs
    inv_cache: dict = {}
    for v in tunnels:
        rid = v.get("id")
        label = str(v.get("name") or rid or "")
        edited = set(v.get("_edited_fields") or [])
        inv = _inverse_maps(conn, inv_cache, v.get("_project_id")) if edited else None
        for field in ("local_interface", "tunnel_interface"):
            n = _clean(v.get(field))
            if not n:
                continue
            names = _token_sources(inv, ("interface",), n) if field in edited else [n]
            for nn in names:
                refs.append(Reference("vpn_tunnel", rid, label, ("interface",), nn))
    return refs


def _nat_zone_references(conn, device_id: int, projects=None) -> list[Reference]:
    """NAT src/dst zone-or-iface references from the EFFECTIVE view
    (fw_nat_rule_overrides COALESCEd over raw, via main._load_nat_rules) -
    the raw columns keep the imported zone after the operator (or
    Auto-derive) re-pointed the slot, wrongly blocking that zone's delete.
    Unlike access rules there is no pipeline dependency: _load_nat_rules
    reads fw_nat_rules directly, so the effective view always exists.
    The remaining NAT fields (objects/services/interfaces) have no overlay
    and stay in the TABLE_REFERRERS raw scan."""
    refs: list[Reference] = []
    try:
        from main import _load_nat_rules  # lazy (avoids import cycle)
        rules = _effective_rows(conn, device_id, projects, _load_nat_rules)
    except Exception:
        return refs
    inv_cache: dict = {}
    for r in rules:
        rid = r.get("id")
        label = str(r.get("name") or rid or "")
        # Zone slots from the override row are project-space tokens.
        inv = (_inverse_maps(conn, inv_cache, r.get("_project_id"))
               if r.get("zone_override_source") else None)
        for field in ("src_zones", "dst_zones"):
            for item in (r.get(field) or []):
                n = _clean(item)
                if not n:
                    continue
                names = _token_sources(inv, ZONE_OR_IFACE, n) if r.get("zone_override_source") else [n]
                for nn in names:
                    refs.append(Reference("nat_rule", rid, label, ZONE_OR_IFACE, nn))
    return refs


def _group_references(conn, device_id: int, excluded: dict | None = None) -> list[Reference]:
    """Group memberships (fw_imported_objects.value JSON), active snapshot only:
    address_group members → object, service_group members → service. With
    `excluded` (the project view) a deleted group references nothing and a
    deleted member is no reference."""
    refs: list[Reference] = []
    gone_groups = set((excluded or {}).get("group") or ()) | set((excluded or {}).get("service_group") or ())
    try:
        rows = conn.execute(text(
            "SELECT name, obj_type, value FROM fw_imported_objects "
            "WHERE device_id = :d AND obj_type IN ('address_group','service_group') "
            f"AND ({_GRP_ACTIVE})"
        ), {"d": device_id}).fetchall()
    except Exception:
        return refs
    for name, obj_type, val in rows:
        if excluded and _clean(name) in gone_groups:
            continue
        tgt = "object" if obj_type == "address_group" else "service"
        gone = _excluded_tokens(excluded, tgt)
        data = _jload(val) or {}
        members = data.get("members") if isinstance(data, dict) else None
        for m in (members or []):
            n = _clean(m)
            if n and n not in gone:
                refs.append(Reference("group", name, str(name or ""), (tgt,), n))
    return refs


def _rule_references(conn, device_id: int,
                     device_host: str | None, projects=None) -> tuple[list[Reference], bool]:
    """Access-rule references from the effective, name-bearing rules view
    (main._fetch_rules_and_devices) - NOT raw consolidated columns. Lazy import
    avoids a circular import. Returns (refs, view_has_rules): the second slot
    says whether the effective view carried ANY rules for this device - the
    caller gates the imported-rules zone fallback on it (zero refs does not
    mean zero coverage; an all-any device yields rules but no refs)."""
    refs: list[Reference] = []
    try:
        from main import _fetch_rules_and_devices, load_display  # lazy
        if device_host is None:
            device_host = conn.execute(text(
                "SELECT COALESCE(display_name, host_name) FROM fw_devices WHERE id = :id"
            ), {"id": device_id}).scalar()
        if not device_host:
            return refs, False
        disp = load_display(conn)
        # One effective view per project (`projects`, else every project of
        # the device) - each holds its own decisions; the references are
        # their union, a project's own list kept as it is.
        views = [(pid, _fetch_rules_and_devices(conn, page=1, page_size=100000,
                                                device=device_host, display=disp,
                                                project_id=pid))
                 for pid in (projects if projects is not None
                             else _device_projects(conn, device_id))]
    except Exception:
        return refs, False

    list_fields = (("src_zones", ZONE_OR_IFACE), ("dst_zones", ZONE_OR_IFACE),
                   ("sources", ("object",)), ("destinations", ("object",)),
                   ("services", ("service",)))
    # Source-imported named refs survive in import_* even when consolidation
    # collapses the effective field (e.g. a named service → scalar
    # proto/port). They are what the deploy renders AND what find_delete_blockers
    # reads (fw_imported_rules), so they must count as 'used' here too - else a
    # still-referenced service/object is wrongly listed unused yet blocks the
    # delete (the contradiction the unused filter showed). Stored as JSON
    # strings; 'any'/'application-default' are sentinels, not referents.
    import_fields = (("import_src_zones", ZONE_OR_IFACE),
                     ("import_dst_zones", ZONE_OR_IFACE),
                     ("import_sources", ("object",)),
                     ("import_destinations", ("object",)),
                     ("import_services", ("service",)))
    scalar_fields = (("schedule", ("schedule",)),)
    # Zone overrides are the effective truth for a rule's zone slots (the
    # deploy renders them, not the import values). An overridden side's
    # IMPORT zone names must therefore not count as references - otherwise
    # a zone stays undeletable forever after the operator re-zoned or
    # any'd every rule (pa2fgt finding 2026-08-31). Presence map per side:
    view_has_rules = False
    seen: set = set()
    inv_cache: dict = {}
    for pid, data in views:
        # Override-owned zone slots hold project-space tokens (model A).
        inv = _inverse_maps(conn, inv_cache, pid)
        zone_ovr: dict[str, tuple[bool, bool]] = {}
        try:
            for h, s, d in conn.execute(text(
                    "SELECT LOWER(HEX(rule_hash)), src_zone, dst_zone "
                    "FROM fw_rule_zone_overrides WHERE project_id = :p"),
                    {"p": pid if pid else -1}).fetchall():
                zone_ovr[h] = (s is not None, d is not None)
        except Exception:
            pass
        proj_refs: list[Reference] = []
        for grp in (data.get("devices") or {}).values():
            for rule in grp:
                view_has_rules = True
                label = str(rule.get("rule_name") or rule.get("rhash") or "")
                rid = rule.get("rhash")
                ovr_src, ovr_dst = zone_ovr.get(str(rid or "").lower(), (False, False))
                overridden = bool(rule.get("zone_override_source"))
                for key, targets in list_fields:
                    for item in (rule.get(key) or []):
                        n = _clean(item)
                        if not n:
                            continue
                        if overridden and key in ("src_zones", "dst_zones"):
                            for nn in _token_sources(inv, ZONE_OR_IFACE, n):
                                proj_refs.append(Reference("access_rule", rid, label, targets, nn))
                        else:
                            proj_refs.append(Reference("access_rule", rid, label, targets, n))
                for key, targets in import_fields:
                    if key == "import_src_zones" and ovr_src:
                        continue
                    if key == "import_dst_zones" and ovr_dst:
                        continue
                    arr = _jload(rule.get(key))
                    if not isinstance(arr, list):
                        continue
                    for item in arr:
                        n = _clean(item)
                        if n and n.lower() not in ("any", "application-default"):
                            proj_refs.append(Reference("access_rule", rid, label, targets, n))
                for key, targets in scalar_fields:
                    n = _clean(rule.get(key))
                    if n:
                        proj_refs.append(Reference("access_rule", rid, label, targets, n))
        # What an earlier project already contributed is not repeated.
        refs.extend(r for r in proj_refs if r not in seen)
        seen.update(proj_refs)
    return refs, view_has_rules


def _imported_rule_references(conn, device_id: int) -> list[Reference]:
    """Access-rule references straight from the IMPORT landing (fw_imported_rules) -
    the pipeline-INDEPENDENT source of truth. _rule_references above reads the
    consolidated view, which is EMPTY on a freshly-imported-but-not-generated device,
    so a rule's object/service refs would be MISSED → find_unused would over-report →
    an unsafe delete (diagnosed: srv-grp + used services wrongly flagged unused).
    Unioned with the view refs - the used-set only GROWS, so find_unused only SHRINKS
    (strictly safer, never lists a still-referenced object as unused). JSON lists;
    'any'/'application-default' are sentinels; IP-literals are filtered downstream by
    find_dangling (_is_ip_literal), same as the view path."""
    refs: list[Reference] = []
    fields = (("src_zones", ZONE_OR_IFACE), ("dst_zones", ZONE_OR_IFACE),
              ("sources", ("object",)), ("destinations", ("object",)),
              ("services", ("service",)))
    try:
        rows = conn.execute(text(
            "SELECT rule_name, src_zones, dst_zones, sources, destinations, "
            "services, schedule "
            "FROM fw_imported_rules WHERE device_id = :d"), {"d": device_id}).mappings().all()
    except Exception:
        return refs
    for row in rows:
        label = str(row.get("rule_name") or "")
        for key, targets in fields:
            arr = _jload(row.get(key))
            if not isinstance(arr, list):
                continue
            for item in arr:
                n = _clean(item)
                if n and n.lower() not in ("any", "application-default"):
                    refs.append(Reference("access_rule", label, label, targets, n))
        # Scalar schedule ref - the consolidated view carries it, but this
        # fallback missed it, so a freshly-imported-not-generated device
        # flagged every referenced schedule as unused (matrix finding M-2).
        sched = _clean(row.get("schedule"))
        if sched:
            refs.append(Reference("access_rule", label, label,
                                  ("schedule",), sched))
    return refs


def _ssl_used_names(conn, device_id: int) -> dict[str, set[str]]:
    """Object/service names used by SSL/TLS-inspection rules (fw_ssl_rules) - a
    SEPARATE policy layer the reference collectors above do NOT cover. Deliberately
    kept OUT of collect_references (and thus find_dangling): SSL rules routinely name
    vendor BUILTINS (e.g. 'HTTPS default services', predefined URL categories) that are
    never imported, which find_dangling would then false-positive as dangling. But for
    find_unused the rule is simple - a name a decryption rule references is USED, so
    folding it into the used-set only SHRINKS the unused set (strictly safer, never
    lists a still-referenced object as unused). Returns {'object': {…}, 'service': {…}}."""
    out: dict[str, set[str]] = {"object": set(), "service": set()}
    try:
        rows = conn.execute(text(
            "SELECT sources, destinations, services FROM fw_ssl_rules "
            "WHERE device_id = :d"), {"d": device_id}).mappings().all()
    except Exception:
        return out
    for row in rows:
        for key, tt in (("sources", "object"), ("destinations", "object"),
                        ("services", "service")):
            arr = _jload(row.get(key))
            if isinstance(arr, list):
                for item in arr:
                    n = _clean(item)
                    if n:
                        out[tt].add(n)
    return out


def ssl_referrer_rules(conn, device_id: int, target_type: str, name: str) -> list[str]:
    """Decryption-rule NAMES in this scope that reference (target_type, name) - source/destination
    for an object, service for a service. SSL is a SEPARATE reference layer (deliberately kept OUT
    of collect_references so find_dangling doesn't false-positive on SSL's vendor-builtin names, see
    _ssl_used_names) - this TARGETED scan lets replace/delete SEE decryption refs without that side
    effect. Ordered by rule position, de-duped."""
    want = _clean(name)
    fields = ("sources", "destinations") if target_type == "object" else ("services",)
    out: list[str] = []
    try:
        rows = conn.execute(text(
            "SELECT name, sources, destinations, services FROM fw_ssl_rules "
            "WHERE device_id = :d ORDER BY position, id"), {"d": device_id}).mappings().all()
    except Exception:
        return out
    for row in rows:
        for f in fields:
            arr = _jload(row.get(f))
            if isinstance(arr, list) and any(_clean(x) == want for x in arr):
                nm = row.get("name")
                if nm and nm not in out:
                    out.append(nm)
                break
    return out


def collect_referent_names(conn, device_id: int) -> dict[str, set[str]]:
    """Existing referent names per validatable target type."""
    out: dict[str, set[str]] = {}
    for ttype, sources in REFERENT_SOURCES.items():
        names: set[str] = set()
        for table, name_col, where in sources:
            sql = f"SELECT {name_col} FROM {table} WHERE device_id = :d"
            if where:
                sql += f" AND {where}"
            try:
                for (nm,) in conn.execute(text(sql), {"d": device_id}):
                    n = _clean(nm)
                    if n:
                        names.add(n)
            except Exception:
                continue
        out[ttype] = names
    return out


# ── engine ops (read side) ───────────────────────────────────────────────────

def find_referrers(conn, device_id: int, target_type: str, name: str,
                   *, device_host: str | None = None, projects: list | None = None,
                   excluded: dict | None = None, view=None) -> list[Reference]:
    """Everything that references (target_type, name)."""
    want = _clean(name)
    return [r for r in collect_references(conn, device_id, device_host=device_host,
                                          projects=projects, excluded=excluded, view=view)
            if target_type in r.targets and r.name == want]


def find_unused(conn, device_id: int, target_type: str,
                *, device_host: str | None = None, projects: list | None = None,
                excluded: dict | None = None) -> set[str]:
    """Referents of target_type that nothing references. The used-set folds in
    SSL/TLS-inspection rule refs (a separate policy layer, see _ssl_used_names) so an
    object used only in a decryption rule is never wrongly listed unused. With
    `projects` / `excluded` (the project view) the question is the project's:
    what it deleted is neither a referent nor a referrer."""
    referents = collect_referent_names(conn, device_id).get(target_type, set())
    if excluded:
        referents = referents - _excluded_tokens(excluded, target_type)
    used = {r.name for r in collect_references(conn, device_id, device_host=device_host,
                                               projects=projects, excluded=excluded)
            if target_type in r.targets}
    used |= _ssl_used_names(conn, device_id).get(target_type, set())
    return referents - used


def _valid_names(conn, device_id: int) -> dict[str, set[str]]:
    """Referent names PLUS valid aliases - the acceptance set for find_dangling.
    Interface accepts its canonical name AND nameif aliases (ASA routes carry the
    nameif, which equals the interface's zone_name - see
    project_asa_route_interface_naming)."""
    valid = {t: set(s) for t, s in collect_referent_names(conn, device_id).items()}
    aliases: set[str] = set()
    try:
        aliases |= {n for (z,) in conn.execute(text(
            "SELECT DISTINCT zone_name FROM fw_interfaces WHERE device_id = :d "
            "AND zone_name IS NOT NULL AND zone_name <> ''"
        ), {"d": device_id}) for n in (_clean(z),) if n}
    except Exception:
        pass
    valid["interface"] = valid.get("interface", set()) | aliases
    return valid


def find_dangling(conn, device_id: int,
                  *, device_host: str | None = None,
                  projects: list | None = None) -> list[Reference]:
    """References whose name exists under NONE of their validatable target types
    (interface accepts source names + target bindings). `projects` as in
    collect_references - generate passes its own project."""
    valid = _valid_names(conn, device_id)
    dangling: list[Reference] = []
    for r in collect_references(conn, device_id, device_host=device_host,
                                projects=projects):
        if r.literal_ok:
            continue  # value may legitimately be a bare literal (e.g. NAT trans IP)
        # object/service refs can hold bare IP/CIDR/range literals (syslog-derived
        # rules) - those aren't object references.
        if _is_ip_literal(r.name) and any(t in ("object", "service") for t in r.targets):
            continue
        checkable = [t for t in r.targets if t in valid and t not in DANGLING_SKIP_TYPES]
        if not checkable:
            continue  # only non-validatable targets (e.g. schedule builtin) → skip
        if not any(r.name in valid[t] for t in checkable):
            dangling.append(r)
    return dangling


# ── engine ops (write side - Phase 0 part 2a) ────────────────────────────────
# Rules are READ via the effective view but WRITTEN to fw_imported_rules (mirroring
# _rewrite_refs_in_rules - parity). Zone's consolidated/flows mirror is part 2b.

_IMPORTED_RULES_NEWEST = (
    "import_ts = (SELECT MAX(import_ts) FROM fw_imported_rules ir2 "
    "WHERE ir2.device_id = fw_imported_rules.device_id)")

_RULE_WRITE = TableReferrer("access_rule", "fw_imported_rules", "id", "rule_name", "device_id", (
    FieldRef("sources", ("object",), shape="json_list"),
    FieldRef("destinations", ("object",), shape="json_list"),
    FieldRef("services", ("service",), shape="json_list"),
    FieldRef("src_zones", ZONE_OR_IFACE, shape="json_list"),
    FieldRef("dst_zones", ZONE_OR_IFACE, shape="json_list"),
))


def _rewrite_field(conn, table, device_col, id_col, fr: FieldRef, device_id,
                   target_type, old, new, where=None) -> int:
    if fr.shape == "scalar":
        sql = f"UPDATE {table} SET {fr.field} = :new WHERE {device_col} = :d AND {fr.field} = :old"
        if where:
            sql += f" AND ({where})"
        return conn.execute(text(sql), {"new": new, "old": old, "d": device_id}).rowcount
    sel = f"SELECT {id_col} AS _id, {fr.field} AS _v FROM {table} WHERE {device_col} = :d"
    if where:
        sel += f" AND ({where})"
    touched = 0
    for row in conn.execute(text(sel), {"d": device_id}).mappings().all():
        arr = _jload(row["_v"])
        if not isinstance(arr, list):
            continue
        changed = False
        out = []
        for item in arr:
            if fr.shape == "json_list":
                if item == old:
                    out.append(new); changed = True
                else:
                    out.append(item)
            elif fr.shape == "json_dicts" and isinstance(item, dict) and item.get(fr.dict_name) == old:
                itgt = (fr.type_map or {}).get(str(item.get(fr.dict_type))) if fr.dict_type else None
                if itgt is None or itgt == target_type:
                    out.append({**item, fr.dict_name: new}); changed = True
                else:
                    out.append(item)
            else:
                out.append(item)
        if changed:
            # Dedup json_list after a rename (preserve order): old→new may collide
            # with an existing new (the merge case A,B→A), and a list-ref must not
            # carry duplicates. Mirrors _rewrite_array_with_dedup.
            if fr.shape == "json_list":
                seen: set = set()
                deduped = []
                for x in out:
                    if x in seen:
                        continue
                    seen.add(x)
                    deduped.append(x)
                out = deduped
            conn.execute(text(f"UPDATE {table} SET {fr.field} = :v WHERE {id_col} = :id"),
                         {"v": json.dumps(out), "id": row["_id"]})
            touched += 1
    return touched


def _rename_in_groups(conn, device_id, target_type, old, new) -> int:
    grp_type = "address_group" if target_type == "object" else "service_group"
    rows = conn.execute(text(
        "SELECT id, value FROM fw_imported_objects WHERE device_id = :d AND obj_type = :t "
        f"AND ({_GRP_ACTIVE})"
    ), {"d": device_id, "t": grp_type}).fetchall()
    n = 0
    for rid, val in rows:
        data = _jload(val) or {}
        members = data.get("members") if isinstance(data, dict) else None
        if not isinstance(members, list) or old not in members:
            continue
        # Rename + dedup preserving order (old→new may collide with an existing
        # new - the merge case A,B→A → just A).
        seen: set = set()
        deduped = []
        for m in members:
            nm = new if m == old else m
            if nm in seen:
                continue
            seen.add(nm)
            deduped.append(nm)
        data["members"] = deduped
        conn.execute(text("UPDATE fw_imported_objects SET value = :v WHERE id = :id"),
                     {"v": json.dumps(data), "id": rid})
        n += 1
    return n


def _rewrite_nat_trans_src_composite(conn, device_id: int, old: str, new: str) -> int:
    """Rewrite the interface part of 'iface|ip' composites in
    fw_nat_rules.trans_src (interface-address SNAT)."""
    return conn.execute(text(
        "UPDATE fw_nat_rules "
        "SET trans_src = CONCAT(:new, '|', SUBSTRING_INDEX(trans_src, '|', -1)) "
        "WHERE device_id = :d AND trans_src LIKE '%|%' "
        "AND SUBSTRING_INDEX(trans_src, '|', 1) = :old"
    ), {"new": new, "old": old, "d": device_id}).rowcount or 0


def _rehash_nat_rekey_overrides(conn, device_id: int) -> None:
    """Recompute nat_hash AND re-key fw_nat_rule_overrides to the new
    hashes - a bare recompute orphans the operator's NAT enrichment
    (zone slots, negate flags), which keys on nat_hash."""
    before = {r[0]: r[1] for r in conn.execute(text(
        "SELECT id, nat_hash FROM fw_nat_rules WHERE device_id = :d"),
        {"d": device_id}).fetchall()}
    _recompute_nat_hash(conn, device_id)
    after = {r[0]: r[1] for r in conn.execute(text(
        "SELECT id, nat_hash FROM fw_nat_rules WHERE device_id = :d"),
        {"d": device_id}).fetchall()}
    for rid, old_h in before.items():
        new_h = after.get(rid)
        if old_h and new_h and old_h != new_h:
            conn.execute(text(
                "UPDATE IGNORE fw_nat_rule_overrides "
                "SET nat_hash = :n WHERE nat_hash = :o"),
                {"n": new_h, "o": old_h})


def _recompute_nat_hash(conn, device_id: int) -> None:
    """Recompute nat_hash for the device - object/service/zone names are hash
    inputs, so a rename/strip touching NAT must re-hash (mirrors the old
    _rewrite_refs_in_nat / _strip_name_from_nat per-row recompute)."""
    try:
        from main import _write_nat_hash  # lazy (avoids import cycle)
        _write_nat_hash(conn, "n.device_id = :did", {"did": device_id})
    except Exception:
        pass


def _rewrite_zone_mirrors(conn, device_id: int, old: str, new: str) -> int:
    """A zone name also lives in fw_flows and the consolidated rule tables
    (keyed by device_host) - the mirror the old zone cascade rewrote. Used
    by reverse_rename (migration) only; model A never rewrites it again."""
    touched = 0
    host = conn.execute(text(
        "SELECT COALESCE(display_name, host_name) FROM fw_devices WHERE id = :id"
    ), {"id": device_id}).scalar()
    if host:
        from main import _CONSOLIDATED_ZONE_TABLES  # lazy (single source of the list)
        for tbl in ("fw_flows",) + tuple(_CONSOLIDATED_ZONE_TABLES):
            for col in ("src_zone", "dst_zone"):
                try:
                    touched += conn.execute(text(
                        f"UPDATE {tbl} SET {col} = :new WHERE device_host = :h AND {col} = :old"
                    ), {"new": new, "old": old, "h": host}).rowcount
                except Exception:
                    pass
    return touched


def _rewrite_json_edits(conn, table: str, where: str, params: dict,
                        fn) -> int:
    """Apply fn(edits_dict) -> changed? to the JSON `edits` column of the
    rows `where` selects (the device-level edit tables and the project
    overlays both keep operator edits as a JSON dict)."""
    n = 0
    try:
        rows = conn.execute(text(
            f"SELECT {where['key']} AS _k, edits FROM {table} WHERE {where['cond']}"
        ), params).fetchall()
    except Exception:
        return 0
    for k, raw in rows:
        edits = _jload(raw)
        if not isinstance(edits, dict) or not edits:
            continue
        if fn(edits):
            conn.execute(text(
                f"UPDATE {table} SET edits = :e WHERE {where['key']} = :k AND {where['cond']}"
            ), {**params, "e": json.dumps(edits), "k": k})
            n += 1
    return n


def _rewrite_device_edit_tokens(conn, device_id: int, kind: str, old: str, new: str) -> int:
    """Device-level edit tables (model A: source space) that carry names the
    old cascade never rewrote: an interface's zone binding / parent in
    fw_interface_overrides.edits, a route's egress interface in
    fw_route_overrides.edits and the VR in fw_route_overrides' key."""
    n = 0
    if kind in ("zone", "interface"):
        field = "zone_name" if kind == "zone" else "parent_iface_name"

        def _iface(edits):
            if edits.get(field) == old:
                edits[field] = new
                return True
            return False
        n += _rewrite_json_edits(conn, "fw_interface_overrides",
                                 {"key": "import_interface_name", "cond": "device_id = :d"},
                                 {"d": device_id}, _iface)
    if kind == "interface":
        def _route(edits):
            if edits.get("interface_name") == old:
                edits["interface_name"] = new
                return True
            return False
        n += _rewrite_json_edits(conn, "fw_route_overrides",
                                 {"key": "CONCAT(prefix, '/', prefix_len, '@', vr_name)",
                                  "cond": "device_id = :d"},
                                 {"d": device_id}, _route)
    if kind == "vrf":
        try:
            n += conn.execute(text(
                "UPDATE IGNORE fw_route_overrides SET vr_name = :new "
                "WHERE device_id = :d AND vr_name = :old"
            ), {"new": new, "old": old, "d": device_id}).rowcount or 0
        except Exception:
            pass
    return n


def _rewrite_registry(conn, device_id: int, target_type: str, old: str, new: str) -> int:
    """old -> new through every registered referrer column of the device's
    imported data (rules at the newest import, NAT, PBF, VPN, interfaces,
    routes) plus group members for objects/services."""
    touched = 0
    for rr in (_RULE_WRITE,) + TABLE_REFERRERS:
        where = _IMPORTED_RULES_NEWEST if rr.table == "fw_imported_rules" else None
        for fr in rr.refs:
            if target_type in fr.targets:
                touched += _rewrite_field(conn, rr.table, rr.device_col, rr.id_col,
                                          fr, device_id, target_type, old, new, where)
    if target_type in ("object", "service"):
        touched += _rename_in_groups(conn, device_id, target_type, old, new)
    return touched


def cascade_rename(conn, device_id: int, target_type: str, old: str, new: str) -> int:
    """Model A: the one remaining MUTATING rename - an object/service MERGE
    (object_merge): the loser's references are rewritten to the canonical
    name in the imported data (rules, NAT, PBF, VPN, groups) and NAT is
    re-hashed (orig_*/trans_* are nat_hash inputs; the overrides follow by
    re-key). Interfaces, zones and VRFs are never renamed in place any more
    - a rename is a project name-map row (main._name_map_set)."""
    if target_type not in ("object", "service"):
        raise ValueError(f"cascade_rename is for object/service merges, not {target_type!r}")
    old = _clean(old)
    new = str(new).strip() if new else None
    if not old or not new or old == new:
        return 0
    touched = _rewrite_registry(conn, device_id, target_type, old, new)
    _rehash_nat_rekey_overrides(conn, device_id)
    return touched


def reverse_rename(conn, device_id: int, kind: str, old: str, new: str) -> int:
    """Migration projects_names_v1 only: put a device's data back into
    SOURCE space by undoing one in-place rename (old = the chosen name, new
    = the collector's name). Mirrors exactly what the old cascade touched
    (registry, group members, the zone mirror in flows + consolidated
    tables, the 'iface|ip' NAT composite) plus the device-level edit tables
    it never touched. Project-space tokens (rule/NAT zone overrides, PBF/VPN
    edits) are NOT touched - they keep the chosen name, which the map now
    says. No hash is recomputed here: the caller re-hashes + re-keys once
    per device (rehash_and_rekey) after every rename of the device."""
    old = _clean(old)
    new = str(new).strip() if new else None
    if not old or not new or old == new:
        return 0
    touched = _rewrite_registry(conn, device_id, kind, old, new)
    if kind == "zone":
        touched += _rewrite_zone_mirrors(conn, device_id, old, new)
    if kind == "interface":
        touched += _rewrite_nat_trans_src_composite(conn, device_id, old, new)
    touched += _rewrite_device_edit_tokens(conn, device_id, kind, old, new)
    return touched


def rehash_and_rekey(conn, device_id: int) -> dict:
    """Recompute nat/pbf/vpn hashes of a device and re-key every table that
    keys on them (project overlays, VPN secrets + certs) old -> new per row.
    Migration projects_names_v1 runs this once per device after the reverse
    renames - the last time a hash of imported data ever changes."""
    from main import _write_nat_hash, _write_pbf_hash, _write_vpn_hash  # lazy
    out = {}
    for name, table, col, writer, keyed in (
            ("nat", "fw_nat_rules", "nat_hash", _write_nat_hash, ("fw_nat_rule_overrides",)),
            ("pbf", "fw_pbf_rules", "pbf_hash", _write_pbf_hash, ("fw_pbf_rule_overrides",)),
            ("vpn", "fw_vpn_tunnels", "vpn_hash", _write_vpn_hash,
             ("fw_vpn_tunnel_overrides", "fw_vpn_tunnel_secrets", "fw_vpn_tunnel_certs"))):
        try:
            before = {r[0]: r[1] for r in conn.execute(text(
                f"SELECT id, HEX({col}) FROM {table} WHERE device_id = :d"),
                {"d": device_id}).fetchall()}
            alias = {"fw_nat_rules": "n", "fw_pbf_rules": "p", "fw_vpn_tunnels": "v"}[table]
            writer(conn, f"{alias}.device_id = :did", {"did": device_id})
            after = {r[0]: r[1] for r in conn.execute(text(
                f"SELECT id, HEX({col}) FROM {table} WHERE device_id = :d"),
                {"d": device_id}).fetchall()}
        except Exception:
            continue
        n = 0
        for rid, old_h in before.items():
            new_h = after.get(rid)
            if not old_h or not new_h or old_h == new_h:
                continue
            for t in keyed:
                try:
                    conn.execute(text(
                        f"UPDATE IGNORE {t} SET {col} = UNHEX(:n) WHERE {col} = UNHEX(:o)"
                    ), {"n": new_h, "o": old_h})
                except Exception:
                    pass
            n += 1
        out[name] = n
    return out


def rewrite_project_tokens(conn, project_id: int, kind: str, old: str, new: str) -> int:
    """A project's name map changed (old -> new is what the operator now
    sees for one source entity): the project-space tokens that spelled the
    old name follow - rule and NAT zone overrides (zone-or-interface
    slots), PBF ingress/egress and VPN interface edits. Imported data is
    not touched. Returns rows rewritten."""
    old = _clean(old)
    new = str(new).strip() if new else None
    if not old or not new or old == new or kind not in ("zone", "interface"):
        return 0
    n = _rewrite_zone_override_values(conn, project_id, old, new)
    n += _rewrite_nat_override_zone_values(conn, project_id, old, new)

    def _pbf(edits):
        changed = False
        ing = edits.get("ingress")
        if isinstance(ing, list):
            for item in ing:
                if isinstance(item, dict) and item.get("name") == old \
                        and str(item.get("type") or "") in ("", kind):
                    item["name"] = new
                    changed = True
        if kind == "interface" and edits.get("egress_interface") == old:
            edits["egress_interface"] = new
            changed = True
        return changed
    n += _rewrite_json_edits(conn, "fw_pbf_rule_overrides",
                             {"key": "HEX(pbf_hash)", "cond": "project_id = :p"},
                             {"p": project_id}, _pbf)
    if kind == "interface":
        def _vpn(edits):
            changed = False
            for f in ("local_interface", "tunnel_interface"):
                if edits.get(f) == old:
                    edits[f] = new
                    changed = True
            return changed
        n += _rewrite_json_edits(conn, "fw_vpn_tunnel_overrides",
                                 {"key": "HEX(vpn_hash)", "cond": "project_id = :p"},
                                 {"p": project_id}, _vpn)
    return n


def _rewrite_nat_override_zone_values(conn, project_id: int, old: str, new: str) -> int:
    """Rewrite zone-or-iface tokens inside ONE project's
    fw_nat_rule_overrides.src_zones/dst_zones (JSON lists)."""
    try:
        rows = conn.execute(text(
            "SELECT nat_hash, src_zones, dst_zones FROM fw_nat_rule_overrides "
            "WHERE project_id = :p AND (src_zones LIKE :pat OR dst_zones LIKE :pat)"),
            {"p": project_id, "pat": f"%{old}%"}).fetchall()
    except Exception:
        return 0
    n = 0
    for nh, src, dst in rows:
        def _sub(v):
            if not v:
                return v
            try:
                arr = json.loads(v)
            except Exception:
                return v
            if not isinstance(arr, list):
                return v
            out = [new if str(tok) == old else tok for tok in arr]
            return json.dumps(list(dict.fromkeys(out))) if out != arr else v
        ns, nd = _sub(src), _sub(dst)
        if ns == src and nd == dst:
            continue
        conn.execute(text(
            "UPDATE fw_nat_rule_overrides SET src_zones = :s, dst_zones = :d "
            "WHERE project_id = :p AND nat_hash = :nh"),
            {"s": ns, "d": nd, "p": project_id, "nh": nh})
        n += 1
    return n


def _rewrite_zone_override_values(conn, project_id: int, old: str, new: str) -> int:
    """Rewrite zone-or-iface tokens (newline-joined multi-values) inside ONE
    project's fw_rule_zone_overrides."""
    try:
        rows = conn.execute(text(
            "SELECT rule_hash, src_zone, dst_zone FROM fw_rule_zone_overrides "
            "WHERE project_id = :p AND (src_zone LIKE :pat OR dst_zone LIKE :pat)"),
            {"p": project_id, "pat": f"%{old}%"}).fetchall()
    except Exception:
        return 0
    n = 0
    for rh, src, dst in rows:
        def _sub(v):
            if not v:
                return v
            toks = [new if tok == old else tok for tok in v.split("\n")]
            return "\n".join(dict.fromkeys(toks))
        ns, nd = _sub(src), _sub(dst)
        if ns == src and nd == dst:
            continue
        conn.execute(text(
            "UPDATE fw_rule_zone_overrides SET src_zone = :s, dst_zone = :d "
            "WHERE project_id = :p AND rule_hash = :rh"),
            {"s": ns, "d": nd, "p": project_id, "rh": rh})
        n += 1
    return n


def deletability(conn, device_id: int, target_type: str, name: str,
                 *, device_host: str | None = None, projects: list | None = None,
                 excluded: dict | None = None, view=None) -> dict:
    """Whether a referent can be removed. Interface: routes cascade with it
    (interface_delete clears routes by name), so they don't block; everything else
    blocks, plus 'sole member of a referenced zone' (would empty a used zone)."""
    name = _clean(name)
    if view is not None:
        if excluded is None:
            excluded = view.excluded_dict(device_id)
        if projects is None and getattr(view, "project_id", None):
            projects = [view.project_id]
    refs = find_referrers(conn, device_id, target_type, name, device_host=device_host,
                          projects=projects, excluded=excluded, view=view)
    if target_type != "interface":
        return {"removable": not refs, "referrers": refs}
    blockers = [r for r in refs if r.referrer_kind != "route"]
    cascading_routes = [r for r in refs if r.referrer_kind == "route"]
    sole_used_zone = None
    _zrow = conn.execute(text(
        "SELECT zone_name, import_interface_name FROM fw_interfaces "
        "WHERE device_id = :d AND interface_name = :n"
    ), {"d": device_id, "n": name}).fetchone()
    z = _clean(_zrow[0]) if _zrow else None
    if view is not None and _zrow:
        # the project's zone binding of this interface, when it edited it
        e = view.interface_edits_for(device_id, _zrow[1], name)
        if "zone_name" in e:
            z = _clean(e.get("zone_name"))
    # 'default' is the NO-ZONE sentinel on fw_interfaces.zone_name - an
    # unzoned interface is not "the sole member of a zone" (5th sentinel
    # site, missed by the afc22ca sweep; it blocked skip/delete on every
    # freshly imported unzoned interface, e.g. a CP member's eth0).
    if z == "default":
        z = None
    if z:
        # the project view: interfaces deleted in the project are no members
        gone_if = set((excluded or {}).get("interface") or ())
        others = []
        for n, imp, zn in conn.execute(text(
                "SELECT interface_name, import_interface_name, zone_name FROM fw_interfaces "
                "WHERE device_id = :d AND interface_name <> :n"
        ), {"d": device_id, "n": name}).fetchall():
            if n in gone_if:
                continue
            if view is not None:
                zn = view.interface_edits_for(device_id, imp, n).get("zone_name", zn)
            if _clean(zn) == z:
                others.append(n)
        # Who else would still use the zone - the interface's OWN zone
        # reference does not count (it leaves with the interface). Without
        # this the sole member of an otherwise unreferenced zone always
        # needed the empty-zone confirm, and the message counted the
        # interface itself as a rule reference.
        zrefs = [r for r in find_referrers(conn, device_id, "zone", z, device_host=device_host,
                                           projects=projects, excluded=excluded, view=view)
                 if not (r.referrer_kind == "interface" and r.referrer_label == name)]
        if not others and zrefs:
            sole_used_zone = z
    return {"removable": not blockers and not sole_used_zone, "referrers": refs,
            "blockers": blockers, "cascading_routes": cascading_routes,
            "sole_used_zone": sole_used_zone}


def _object_list_targets(target_type: str):
    """(table, id_col, device_col, field, where) for the json_list referrers of an
    object/service - the strippable fields. Mirrors _strip_name_from_*."""
    out = []
    for rr in (_RULE_WRITE,) + TABLE_REFERRERS:
        where = _IMPORTED_RULES_NEWEST if rr.table == "fw_imported_rules" else None
        for fr in rr.refs:
            if target_type in fr.targets and fr.shape == "json_list":
                out.append((rr.table, rr.id_col, rr.device_col, fr.field, where))
    return out


def _object_scalar_targets(target_type: str):
    """Scalar referrers of an object/service (e.g. NAT trans_src/trans_dst).
    A scalar ref holding the name is a sole-member container → it blocks delete
    (nulling it would corrupt the rule), and force-strip nulls it. Mirrors
    _strip_name_from_nat's trans_* handling + _object_references' trans blockers."""
    out = []
    for rr in (_RULE_WRITE,) + TABLE_REFERRERS:
        where = _IMPORTED_RULES_NEWEST if rr.table == "fw_imported_rules" else None
        for fr in rr.refs:
            if target_type in fr.targets and fr.shape == "scalar":
                out.append((rr.table, rr.id_col, rr.device_col, fr.field, where))
    return out


def find_delete_blockers(conn, device_id: int, target_type: str, names,
                         *, excluded: dict | None = None) -> dict:
    """Selection-aware last-member guard. A name is blocked when removing the WHOLE
    `names` selection would EMPTY a container - a rule field, a NAT field (list or
    scalar trans_*), or a group - that is NOT itself in the selection (deleting an
    object together with the group it solely populates is allowed). Returns
    {name: [human reasons]}. Mirrors _object_references + _object_delete_blockers,
    plus PBF (which the old pair missed)."""
    names = {n for n in (_clean(x) for x in names) if n}
    blocked: dict[str, list] = {}
    if not names or target_type not in ("object", "service", "schedule"):
        return blocked

    # Schedule blocks off the EFFECTIVE rule schedule (override-applied) - the
    # same source find_unused reads - so 'blocked' and 'unused' can never
    # contradict (raw fw_imported_rules.schedule would ignore a schedule
    # override and falsely block a no-longer-used schedule). The schedule slot
    # is scalar: any referencing rule empties it on delete → blocks.
    gone_rules = set((excluded or {}).get("rule") or ())
    gone_members = _excluded_tokens(excluded, target_type)
    if target_type == "schedule":
        for r in collect_references(conn, device_id, excluded=excluded):
            if "schedule" in r.targets and r.name in names:
                blocked.setdefault(r.name, []).append(
                    f"schedule of {r.referrer_kind} {r.referrer_label!r}")
        return blocked

    def _check(members, reason, owner=None):
        if owner is not None and owner in names:
            return  # the container itself is being deleted → not a blocker
        # the project view: members the project already deleted are no survivors
        ms = {m for m in (_clean(x) for x in members) if m} - gone_members
        removed = ms & names
        if not removed or (ms - names):
            return  # nothing of ours, or survivors remain → not emptied
        for nm in removed:
            r = blocked.setdefault(nm, [])
            if reason not in r:
                r.append(reason)

    for rr in (_RULE_WRITE,) + TABLE_REFERRERS:
        frs = [fr for fr in rr.refs
               if target_type in fr.targets and fr.shape in ("json_list", "scalar")]
        if not frs:
            continue
        where = _IMPORTED_RULES_NEWEST if rr.table == "fw_imported_rules" else None
        cols = {rr.id_col, rr.label_col} | {fr.field for fr in frs}
        sel = f"SELECT {', '.join(sorted(cols))} FROM {rr.table} WHERE {rr.device_col} = :d"
        if where:
            sel += f" AND ({where})"
        for row in conn.execute(text(sel), {"d": device_id}).mappings().all():
            label = str(row.get(rr.label_col) or row.get(rr.id_col) or "")
            if rr.kind == "access_rule" and label in gone_rules:
                continue   # a rule deleted in the project holds nothing
            for fr in frs:
                if fr.shape == "json_list":
                    arr = _jload(row.get(fr.field))
                    members = arr if isinstance(arr, list) else []
                else:  # scalar - a held name is a sole-member container
                    v = _clean(row.get(fr.field))
                    members = [v] if v else []
                if members:
                    _check(members, f"sole {fr.field} of {rr.kind} {label!r}")

    # Group last-member guard applies to address/service groups only; schedules
    # have no analogous member-group referrer in scope.
    if target_type in ("object", "service"):
        grp_type = "address_group" if target_type == "object" else "service_group"
        for gid, gname, val in conn.execute(text(
                "SELECT id, name, value FROM fw_imported_objects WHERE device_id = :d "
                f"AND obj_type = :t AND ({_GRP_ACTIVE})"), {"d": device_id, "t": grp_type}):
            if excluded and _clean(gname) in (set(excluded.get("group") or ()) | set(excluded.get("service_group") or ())):
                continue   # a group deleted in the project holds nothing
            data = _jload(val) or {}
            members = data.get("members") if isinstance(data, dict) else None
            if isinstance(members, list):
                _check(members, f"sole member of group {gname!r}", owner=_clean(gname))
    return blocked


def cascade_delete(conn, device_id: int, target_type: str, name: str,
                   *, force: bool = False) -> dict:
    """Strip `name` from its referrers (rules/NAT/groups/PBF) for object/service,
    including scalar NAT trans_*. Last-member guard via find_delete_blockers
    (returns {stripped:0, blocked:[reasons]}) unless force; nat_hash is recomputed.
    Interface/zone don't strip - use deletability + the row delete."""
    name = _clean(name)
    if not name or target_type not in ("object", "service"):
        return {"stripped": 0, "blocked": [],
                "note": "object/service only, interface/zone via deletability"}
    if not force:
        blk = find_delete_blockers(conn, device_id, target_type, {name})
        if name in blk:
            return {"stripped": 0, "blocked": blk[name]}

    stripped = 0
    for table, _id_col, dev_col, field, where in _object_scalar_targets(target_type):
        sql = f"UPDATE {table} SET {field} = NULL WHERE {dev_col} = :d AND {field} = :n"
        if where:
            sql += f" AND ({where})"
        stripped += conn.execute(text(sql), {"d": device_id, "n": name}).rowcount
    for table, id_col, dev_col, field, where in _object_list_targets(target_type):
        sel = f"SELECT {id_col} AS _id, {field} AS _v FROM {table} WHERE {dev_col} = :d"
        if where:
            sel += f" AND ({where})"
        for row in conn.execute(text(sel), {"d": device_id}).mappings().all():
            arr = _jload(row["_v"])
            if not isinstance(arr, list) or name not in arr:
                continue
            conn.execute(text(f"UPDATE {table} SET {field} = :v WHERE {id_col} = :id"),
                         {"v": json.dumps([x for x in arr if x != name]), "id": row["_id"]})
            stripped += 1
    grp_type = "address_group" if target_type == "object" else "service_group"
    for rid, val in conn.execute(text(
            "SELECT id, value FROM fw_imported_objects WHERE device_id = :d "
            f"AND obj_type = :t AND ({_GRP_ACTIVE})"), {"d": device_id, "t": grp_type}):
        data = _jload(val) or {}
        members = data.get("members") if isinstance(data, dict) else None
        if isinstance(members, list) and name in members:
            data["members"] = [m for m in members if m != name]
            conn.execute(text("UPDATE fw_imported_objects SET value = :v WHERE id = :id"),
                         {"v": json.dumps(data), "id": rid})
            stripped += 1
    _recompute_nat_hash(conn, device_id)  # orig_*/trans_* are nat_hash inputs
    return {"stripped": stripped, "blocked": []}
