# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
"""Project name map (rename model A): the imported data keeps its source
names, a project owns a map source -> target name per kind, and the map is
applied to the loaded dicts at read time - once per loader, never written
back into a table.

Kinds: interface, zone, vrf, object, service. A rule's zone slot may hold a
zone OR an interface name (FortiGate interface mode, log-derived rules);
such slots try the zone map first, then the interface map - the one rename
that happened is the one that applies, which is what the old cascade did.

Overrides are stored in project space (what the operator picked, which may
be a target-side literal) and are never mapped: the loaders map imported
values only where no override is in force. Everything here is pure: dicts
in, dicts out (mutated in place and returned). An empty map is the
identity, byte for byte."""
import json
import re

KINDS = ("interface", "zone", "vrf", "object", "service")


# ── map object ───────────────────────────────────────────────────────────────

def empty_map() -> dict:
    return {k: {} for k in KINDS}


def load_name_map(conn, project_id) -> dict:
    """{kind: {source_name: target_name}} for a project; empty without one."""
    nm = empty_map()
    if not project_id:
        return nm
    from sqlalchemy import text
    for kind, src, tgt in conn.execute(text(
            "SELECT kind, source_name, target_name FROM fw_project_name_map "
            "WHERE project_id = :p"), {"p": int(project_id)}).fetchall():
        if kind in nm and src and tgt and src != tgt:
            nm[kind][src] = tgt
    return nm


def is_empty(nm) -> bool:
    return not nm or not any(nm.get(k) for k in KINDS)


def inverse_name_map(nm: dict) -> dict:
    """{kind: {target_name: [source_names]}} - several sources may share a
    target (a merge); each list is sorted."""
    inv = {k: {} for k in KINDS}
    for kind in KINDS:
        for src, tgt in (nm.get(kind) or {}).items():
            inv[kind].setdefault(tgt, []).append(src)
    for kind in KINDS:
        for tgt in inv[kind]:
            inv[kind][tgt].sort()
    return inv


def sources_of(inv: dict, kind: str, token) -> list:
    """The source names a project-space token stands for: its pre-images,
    else the token itself (an unmapped source name, or a target-side
    literal - the caller knows which entities exist)."""
    if token is None:
        return []
    pre = (inv.get(kind) or {}).get(token)
    return list(pre) if pre else [token]


def to_source(inv: dict, kind: str, token, current=None):
    """A project-space token picked for a DEVICE FACT (an interface's zone
    binding, parent or bond members, a route's egress or VR) back to the one
    source name it stands for: the token itself when it is no mapped name,
    its pre-image otherwise - `current` (the fact's present value) when the
    name merges several sources, else the first of them."""
    if not token or not isinstance(token, str):
        return token
    pre = (inv.get(kind) or {}).get(token)
    if not pre:
        return token
    if current in pre:
        return current
    return pre[0]


def to_source_list(inv: dict, kind: str, values, current=None):
    """`to_source` over a list (bond members), duplicates collapsed."""
    if not isinstance(values, list):
        return values
    cur = set(current or [])
    out = []
    for v in values:
        pre = (inv.get(kind) or {}).get(v) if isinstance(v, str) else None
        if not pre:
            out.append(v)
            continue
        hit = [p for p in pre if p in cur]
        out.append(hit[0] if hit else pre[0])
    return _dedup(out)


def to_source_zone_or_iface(inv: dict, token, current=None):
    """Zone-slot token back to source space: the zone map first, then the
    interface map (the inverse of map_zone_or_iface)."""
    if not token or not isinstance(token, str):
        return token
    if token in (inv.get("zone") or {}):
        return to_source(inv, "zone", token, current)
    return to_source(inv, "interface", token, current)


def is_mapped_name(inv: dict, kind: str, token) -> bool:
    """True when some source name of the kind is shown as `token` - a new
    entity may not take that name, it would collide in project space."""
    return bool(token) and isinstance(token, str) and token in (inv.get(kind) or {})


def name_map_conflict(nm: dict, kind: str, source_name: str, target_name: str,
                      source_names=None):
    """Why source_name -> target_name must be refused, or None. A target may
    not be the mapped name of ANOTHER source, nor the (unmapped) name of
    another source entity of the kind - either would merge two entities by
    accident; deliberate merges go through object_merge."""
    if not target_name or target_name == source_name:
        return None
    kind_map = nm.get(kind) or {}
    for src, tgt in kind_map.items():
        if tgt == target_name and src != source_name:
            return f"{target_name!r} is already the name {src!r} is mapped to"
    if source_names and target_name in source_names \
            and kind_map.get(target_name, target_name) == target_name:
        return f"a {kind} named {target_name!r} already exists in the source"
    return None


# ── primitives ───────────────────────────────────────────────────────────────

def map_name(nm: dict, kind: str, name):
    if not name or not isinstance(name, str):
        return name
    return (nm.get(kind) or {}).get(name, name)


def map_zone_or_iface(nm: dict, token):
    """Zone-slot token: the zone map first, then the interface map."""
    if not token or not isinstance(token, str):
        return token
    z = (nm.get("zone") or {}).get(token)
    if z is not None:
        return z
    return (nm.get("interface") or {}).get(token, token)


def map_iface_or_object(nm: dict, value):
    """A slot that holds an interface name or an object name (NAT trans_src
    without an address half): the interface map first, then objects."""
    if not value or not isinstance(value, str):
        return value
    i = (nm.get("interface") or {}).get(value)
    if i is not None:
        return i
    return (nm.get("object") or {}).get(value, value)


def _dedup(seq):
    return list(dict.fromkeys(seq))


def _collate(name) -> tuple:
    """Sort key close to the columns' utf8mb4_unicode_ci collation (case
    folded, punctuation and digits before letters as in code-point order),
    so a list re-sorted here orders like the SQL it came from."""
    s = str(name or "")
    return (s.lower(), s)


def sort_shown(nm: dict, rows: list, key: str = "name") -> list:
    """Rows came from SQL ordered by their SOURCE name; with a map in force
    the operator sees the mapped names, so order them by what is shown.
    Identity (no re-sort) when the map is empty."""
    if is_empty(nm) or not isinstance(rows, list):
        return rows
    rows.sort(key=lambda r: _collate(r.get(key) if isinstance(r, dict) else r))
    return rows


def sort_names(nm: dict, names: list) -> list:
    """A plain list of shown names, ordered like sort_shown."""
    if is_empty(nm) or not isinstance(names, list):
        return names
    return sorted(names, key=_collate)


def fold_merged(rows: list, member_keys=(), key=None) -> list:
    """After mapping: source rows that now share one name are ONE row in
    project space (a merge, `B -> A`). The row whose own source name is the
    name - the merge winner, unmapped - is kept, otherwise the first; the
    others fold away, their member lists unioned into the kept row. `key`
    picks the fold key per row (default: the name); rows whose key is None
    pass through."""
    if not rows:
        return rows
    keyf = key or (lambda o: o.get("name") if isinstance(o.get("name"), str) else None)
    winners: dict = {}
    keyed = 0
    for o in rows:
        k = keyf(o)
        if k is None:
            continue
        keyed += 1
        w = winners.get(k)
        n = o.get("name")
        if w is None or (o.get("source_name") == n and w.get("source_name") != n):
            winners[k] = o
    if len(winners) == keyed:
        return rows
    out = []
    for o in rows:
        k = keyf(o)
        if k is None:
            out.append(o)
            continue
        w = winners[k]
        if w is o:
            out.append(o)
            continue
        for mk in member_keys:
            if isinstance(o.get(mk), list):
                w[mk] = _dedup((w.get(mk) if isinstance(w.get(mk), list) else []) + o[mk])
    return out


def _mapper(nm: dict, kind: str):
    if kind == "zone_or_iface":
        return lambda v: map_zone_or_iface(nm, v)
    return lambda v: map_name(nm, kind, v)


def map_list(nm: dict, kind: str, values):
    """A list of names, order kept, duplicates collapsed (a merge may fold
    two members into one). Non-lists pass through untouched."""
    if not isinstance(values, list):
        return values
    return _dedup(map(_mapper(nm, kind), values))


def map_json_list(nm: dict, kind: str, raw):
    """A JSON-encoded list (import_* mirrors, group members) - re-encoded
    only when something changed, so untouched strings stay byte-identical."""
    if not raw or not isinstance(raw, str):
        return raw
    try:
        arr = json.loads(raw)
    except Exception:
        return raw
    if not isinstance(arr, list):
        return raw
    out = map_list(nm, kind, arr)
    return raw if out == arr else json.dumps(out)


def map_newline_list(nm: dict, kind: str, raw):
    """Newline-joined multi-values (the rules view's zone slots)."""
    if not raw or not isinstance(raw, str):
        return raw
    if "\n" not in raw:
        return _mapper(nm, kind)(raw)
    return "\n".join(map_list(nm, kind, raw.split("\n")))


def map_composite_iface(nm: dict, value):
    """'iface|ip' composite (interface-address SNAT): the interface half."""
    if not value or not isinstance(value, str) or "|" not in value:
        return value
    iface, _, rest = value.partition("|")
    return map_name(nm, "interface", iface) + "|" + rest


def map_dict_keys_values(nm: dict, key_kind: str, val_kind: str, d):
    """{object: zone} maps (the rules view's per-object zone resolution)."""
    if not isinstance(d, dict):
        return d
    km, vm = _mapper(nm, key_kind), _mapper(nm, val_kind)
    return {km(k): vm(v) for k, v in d.items()}


# ── per loaded dict shape ────────────────────────────────────────────────────

RULE_IMPORT_FIELDS = (("import_sources", "object"), ("import_destinations", "object"),
                      ("import_services", "service"),
                      ("import_src_zones", "zone_or_iface"), ("import_dst_zones", "zone_or_iface"))


def map_rules(nm: dict, rules: list) -> list:
    """Effective rules (_fetch_rules_and_devices). Imported zone slots map
    only when no zone override is in force - an override is already a
    project-space value and wins untouched. Objects and services have no
    override layer and always map; the import_* mirrors map alongside."""
    if is_empty(nm):
        return rules
    for r in rules:
        for f in ("sources", "destinations"):
            if isinstance(r.get(f), list):
                r[f] = map_list(nm, "object", r[f])
        if isinstance(r.get("services"), list):
            r["services"] = map_list(nm, "service", r["services"])
        if not r.get("zone_override_source"):
            # The pipeline hands these lists sorted by (source) name; keep
            # them sorted by the shown name.
            for f in ("src_zones", "dst_zones"):
                if isinstance(r.get(f), list):
                    r[f] = sort_names(nm, map_list(nm, "zone_or_iface", r[f]))
                elif isinstance(r.get(f), str) and r[f]:
                    r[f] = "\n".join(sort_names(nm, map_list(nm, "zone_or_iface", r[f].split("\n"))))
        # {object: zone}: keys are object names (always mapped), values are
        # zone tokens (mapped unless an override owns the zone slots).
        for f in ("src_ip_zones", "dst_ip_zones"):
            d = r.get(f)
            if isinstance(d, dict):
                if r.get("zone_override_source"):
                    r[f] = {map_name(nm, "object", k): v for k, v in d.items()}
                else:
                    r[f] = map_dict_keys_values(nm, "object", "zone_or_iface", d)
        for f, kind in RULE_IMPORT_FIELDS:
            if f in r:
                r[f] = map_json_list(nm, kind, r[f])
        for f in ("iface_in", "iface_out"):
            if isinstance(r.get(f), str):
                r[f] = map_name(nm, "interface", r[f])
    return rules


def map_nat_rules(nm: dict, rows: list) -> list:
    """NAT rows (_load_nat_rules). Zone slots map unless the row carries a
    zone override; orig_* are objects/services, trans_src is an interface
    (plain or 'iface|ip') or an object, trans_dst an object."""
    if is_empty(nm):
        return rows
    for n in rows:
        if not n.get("zone_override_source"):
            for f in ("src_zones", "dst_zones"):
                if isinstance(n.get(f), list):
                    n[f] = map_list(nm, "zone_or_iface", n[f])
        for f in ("orig_src", "orig_dst"):
            if isinstance(n.get(f), list):
                n[f] = map_list(nm, "object", n[f])
        if isinstance(n.get("orig_service"), list):
            n["orig_service"] = map_list(nm, "service", n["orig_service"])
        if isinstance(n.get("interface_name"), str):
            n["interface_name"] = map_name(nm, "interface", n["interface_name"])
        ts = n.get("trans_src")
        if isinstance(ts, str) and ts:
            n["trans_src"] = map_composite_iface(nm, ts) if "|" in ts else map_iface_or_object(nm, ts)
        if isinstance(n.get("trans_dst"), str):
            n["trans_dst"] = map_name(nm, "object", n["trans_dst"])
        if isinstance(n.get("trans_service"), str):
            n["trans_service"] = map_name(nm, "service", n["trans_service"])
    return rows


def map_pbf_rules(nm: dict, rows: list) -> list:
    if is_empty(nm):
        return rows
    for p in rows:
        ing = p.get("ingress")
        if isinstance(ing, list):
            for item in ing:
                if not (isinstance(item, dict) and item.get("name")):
                    continue
                t = str(item.get("type") or "")
                if t == "zone":
                    item["name"] = map_name(nm, "zone", item["name"])
                elif t == "interface":
                    item["name"] = map_name(nm, "interface", item["name"])
                else:
                    item["name"] = map_zone_or_iface(nm, item["name"])
        if isinstance(p.get("egress_interface"), str):
            p["egress_interface"] = map_name(nm, "interface", p["egress_interface"])
        for f in ("sources", "destinations"):
            if isinstance(p.get(f), list):
                p[f] = map_list(nm, "object", p[f])
        if isinstance(p.get("services"), list):
            p["services"] = map_list(nm, "service", p["services"])
    return rows


def map_ssl_rules(nm: dict, rows: list) -> list:
    if is_empty(nm):
        return rows
    for s in rows:
        for f in ("src_zones", "dst_zones"):
            if isinstance(s.get(f), list):
                s[f] = map_list(nm, "zone_or_iface", s[f])
        for f in ("sources", "destinations"):
            if isinstance(s.get(f), list):
                s[f] = map_list(nm, "object", s[f])
        if isinstance(s.get("services"), list):
            s["services"] = map_list(nm, "service", s["services"])
    return rows


def map_vpn_tunnels(nm: dict, rows: list) -> list:
    if is_empty(nm):
        return rows
    for v in rows:
        for f in ("local_interface", "tunnel_interface"):
            if isinstance(v.get(f), str):
                v[f] = map_name(nm, "interface", v[f])
        if isinstance(v.get("domain_objects"), list):
            v["domain_objects"] = map_list(nm, "object", v["domain_objects"])
    return rows


def map_interfaces(nm: dict, rows: list) -> list:
    """Network rows: the interface's own name, its parent and bond members,
    its zone binding and VRF. The import_* mirrors stay source names, and
    `source_name` carries the row's own source name for pickers (value =
    source, label = mapped)."""
    for i in rows:
        if "source_name" not in i and isinstance(i.get("interface_name"), str):
            i["source_name"] = i["interface_name"]
    if is_empty(nm):
        return rows
    for i in rows:
        if isinstance(i.get("interface_name"), str):
            i["interface_name"] = map_name(nm, "interface", i["interface_name"])
        if isinstance(i.get("parent_iface_name"), str):
            i["parent_iface_name"] = map_name(nm, "interface", i["parent_iface_name"])
        m = i.get("member_iface_names")
        if isinstance(m, list):
            i["member_iface_names"] = map_list(nm, "interface", m)
        elif isinstance(m, str) and m:
            i["member_iface_names"] = map_json_list(nm, "interface", m)
        if isinstance(i.get("zone_name"), str):
            i["zone_name"] = map_name(nm, "zone", i["zone_name"])
        if isinstance(i.get("vr_name"), str):
            i["vr_name"] = map_name(nm, "vrf", i["vr_name"])
    return sort_shown(nm, rows, "interface_name")


def map_routes(nm: dict, rows: list) -> list:
    """Route rows: egress interface (stored, connected or derived) and VRF."""
    if is_empty(nm):
        return rows
    for r in rows:
        for f in ("interface_name", "connected_iface", "derived_iface"):
            if isinstance(r.get(f), str):
                r[f] = map_name(nm, "interface", r[f])
        if isinstance(r.get("vr_name"), str):
            r["vr_name"] = map_name(nm, "vrf", r["vr_name"])
    return rows


def map_route_groups(nm: dict, groups: dict) -> dict:
    """The Network tab's routes grouped by VRF name: keys and rows."""
    if is_empty(nm) or not isinstance(groups, dict):
        return groups
    out = {}
    for vr, rows in groups.items():
        out.setdefault(map_name(nm, "vrf", vr), []).extend(map_routes(nm, rows))
    return out


def map_zones(nm: dict, rows: list) -> list:
    for z in rows:
        if "source_name" not in z and isinstance(z.get("name"), str):
            z["source_name"] = z["name"]
    if is_empty(nm):
        return rows
    for z in rows:
        if isinstance(z.get("name"), str):
            z["name"] = map_name(nm, "zone", z["name"])
        for f in ("members", "interfaces"):
            if isinstance(z.get(f), list):
                z[f] = sort_names(nm, map_list(nm, "interface", z[f]))
    return sort_shown(nm, fold_merged(rows, ("members", "interfaces")))


def map_vrfs(nm: dict, rows: list) -> list:
    for v in rows:
        if "source_name" not in v and isinstance(v.get("name"), str):
            v["source_name"] = v["name"]
    if is_empty(nm):
        return rows
    for v in rows:
        if isinstance(v.get("name"), str):
            v["name"] = map_name(nm, "vrf", v["name"])
        if isinstance(v.get("members"), list):
            v["members"] = sort_names(nm, map_list(nm, "interface", v["members"]))
    return sort_shown(nm, fold_merged(rows, ("members",)))


def map_named(nm: dict, kind: str, rows: list) -> list:
    """Rows of one known kind with a `name` and, for groups, members either
    at the top level or inside a `value` dict (generate's object lists, the
    Objects tab rows). Rows a merge folds into one are dropped - use the
    returned list."""
    for o in rows:
        if "source_name" not in o and isinstance(o.get("name"), str):
            o["source_name"] = o["name"]
    if is_empty(nm):
        return rows
    for o in rows:
        if isinstance(o.get("name"), str):
            o["name"] = map_name(nm, kind, o["name"])
        if isinstance(o.get("members"), list):
            o["members"] = map_list(nm, kind, o["members"])
        val = o.get("value")
        if isinstance(val, dict) and isinstance(val.get("members"), list):
            new = map_list(nm, kind, val["members"])
            if new != val["members"]:
                val = dict(val)
                val["members"] = new
                o["value"] = val
    return fold_merged(rows)


def map_name_dict_keys(nm: dict, kind: str, d: dict) -> dict:
    """{name: anything} maps keyed by a source name (zone colours, bond
    membership); on a merge the later key wins."""
    if is_empty(nm) or not isinstance(d, dict):
        return d
    return {map_name(nm, kind, k): v for k, v in d.items()}


_OBJECT_KIND = {"address": "object", "address_group": "object",
                "service": "service", "service_group": "service"}


def map_objects(nm: dict, rows: list) -> list:
    """Imported objects: the name by obj_type, and group members inside the
    value JSON (a dict with 'members' or a bare list). A value kept as a
    string is re-encoded only when a member changed."""
    for o in rows:
        if "source_name" not in o and isinstance(o.get("name"), str) \
                and _OBJECT_KIND.get(str(o.get("obj_type") or o.get("type") or "")):
            o["source_name"] = o["name"]
    if is_empty(nm):
        return rows
    for o in rows:
        otype = str(o.get("obj_type") or o.get("type") or "")
        kind = _OBJECT_KIND.get(otype)
        if kind is None:
            continue
        if isinstance(o.get("name"), str):
            o["name"] = map_name(nm, kind, o["name"])
        if not otype.endswith("_group"):
            continue
        val = o.get("value")
        as_str = isinstance(val, str)
        data = None
        if as_str:
            try:
                data = json.loads(val)
            except Exception:
                data = None
        else:
            data = val
        if isinstance(data, dict) and isinstance(data.get("members"), list):
            new = map_list(nm, kind, data["members"])
            if new != data["members"]:
                data = dict(data)
                data["members"] = new
                o["value"] = json.dumps(data) if as_str else data
        elif isinstance(data, list):
            new = map_list(nm, kind, data)
            if new != data:
                o["value"] = json.dumps(new) if as_str else new

    def _key(o):
        k = _OBJECT_KIND.get(str(o.get("obj_type") or o.get("type") or ""))
        n = o.get("name")
        return (k, n) if (k and isinstance(n, str)) else None
    return fold_merged(rows, key=_key)
