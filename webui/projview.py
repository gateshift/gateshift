# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
"""The project view (docs/PROJECT_VIEW_DESIGN.md).

Imported facts are immutable; everything the user does in a workspace is
an edit of the project, applied when the project's view of its devices is
read. Model A (namemap) does this for names. This module carries the
other edit classes, starting with exclusions - "deleted in this project":
a fact row the project hides, never pushes and never counts, while the
device keeps it and every other project still sees it.

    view = projview.load(conn, project_id)
    rows = view.filter(device_id, "interface", rows, key="interface_name")

Keys are stable across re-imports: the content hash for rules and NAT
rules, the source name for everything else, ``prefix|vr`` for routes. The
label is what the item was called when it was excluded - the Overview
lists it, and the integrity net checks a render against it.
"""
from __future__ import annotations

import json

from sqlalchemy import bindparam, text

import namemap

KINDS = ("rule", "nat_rule", "object", "service", "group", "service_group", "schedule",
         "interface", "zone", "route", "vrf", "tag")
KIND_LABELS = {
    "rule": "firewall rule", "nat_rule": "NAT rule", "object": "address object",
    "service": "service", "group": "address group", "service_group": "service group",
    "schedule": "schedule", "interface": "interface", "zone": "zone", "route": "route",
    "vrf": "virtual router", "tag": "tag",
}
_NETWORK_KINDS = frozenset({"interface", "zone", "route", "vrf"})
# the Objects tab's kinds -> exclusion kinds
UI_KIND = {"address": "object", "service": "service", "address_group": "group",
           "service_group": "service_group", "schedule": "schedule"}
# a member token of an address list names an object or a group; of a service list a service or a service group
MEMBER_KINDS = {"object": ("object", "group"), "service": ("service", "service_group")}


def strand_of(kind: str) -> str:
    return "network" if kind in _NETWORK_KINDS else "policy"


def route_key(prefix, vr_name) -> str:
    """A route's exclusion key: the fact row's prefix (CIDR) and VR - the
    pair fw_routes keeps unique per device (uq_dev_prefix_vr)."""
    return f"{prefix}|{vr_name or 'default'}"


def route_label(prefix, next_hop=None, vr_name=None) -> str:
    out = str(prefix)
    if next_hop:
        out += f" via {next_hop}"
    if vr_name and vr_name != "default":
        out += f" [{vr_name}]"
    return out


def _ids(device_ids) -> list:
    """One device id or an iterable of layer ids -> list of ints."""
    if device_ids is None:
        return []
    if isinstance(device_ids, (int, str)):
        return [int(device_ids)]
    return [int(d) for d in device_ids if d is not None]


class ProjectView:
    """What one project sees. ``exclusions`` maps (device_id, kind) to the
    set of excluded keys; ``labels`` maps kind to {key: label}."""

    __slots__ = ("project_id", "name_map", "exclusions", "labels", "host_device",
                 "iface_edits", "route_edits", "zone_edits")

    def __init__(self, project_id, name_map: dict, exclusions: dict, labels: dict,
                 host_device: dict | None = None, iface_edits: dict | None = None,
                 route_edits: dict | None = None, zone_edits: dict | None = None):
        self.project_id = project_id
        self.name_map = name_map
        self.exclusions = exclusions
        self.labels = labels
        self.host_device = host_device or {}      # device host / display name -> device id
        # the project's field edits (P3b): (device_id, import name) -> {field: value},
        # (device_id, prefix, vr) -> {...}, (device_id, zone name) -> {...}
        self.iface_edits = iface_edits or {}
        self.route_edits = route_edits or {}
        self.zone_edits = zone_edits or {}

    def excluded_keys(self, device_id, kind: str) -> set:
        return self.exclusions.get((int(device_id), kind), set()) if device_id is not None else set()

    def is_excluded(self, device_id, kind: str, key) -> bool:
        return str(key) in self.excluded_keys(device_id, kind)

    def filter(self, device_id, kind: str, rows, key="name") -> list:
        """The rows of one kind without the project's exclusions. ``key`` is
        a column name or a callable; rows without a key value pass."""
        gone = self.excluded_keys(device_id, kind)
        if not gone:
            return list(rows)
        getter = key if callable(key) else (lambda r: r.get(key))
        out = []
        for r in rows:
            k = getter(r)
            if k is None or str(k) not in gone:
                out.append(r)
        return out

    def excluded_names(self) -> dict:
        """kind -> set of labels (the integrity net's input)."""
        return {kind: {lbl for lbl in m.values() if lbl} for kind, m in self.labels.items()}

    def excluded_dict(self, device_id) -> dict:
        """kind -> set of names excluded on one device (the reference model's
        input): keys for name-keyed kinds, labels for the hash-keyed ones."""
        out: dict = {}
        for (did, kind), keys in self.exclusions.items():
            if did != int(device_id):
                continue
            if kind in ("rule", "nat_rule"):
                out[kind] = {self.labels.get(kind, {}).get(k, k) for k in keys}
            else:
                # a merged loser is renamed, not gone: its references stand (as the canonical)
                mk = "object" if kind in ("object", "group") else ("service" if kind in ("service", "service_group") else None)
                mapped = ((self.name_map or {}).get(mk) or {}) if mk else {}
                out[kind] = {k for k in keys if k not in mapped}
        return out

    def excluded_tokens(self, device_id, token_kind: str) -> set:
        """Names that must leave a member list of ``token_kind`` (object or
        service): the excluded objects and the excluded groups of that side -
        except a merged loser, which the name map turns into its canonical
        (the reference stays, the loser's own row is what leaves)."""
        gone: set = set()
        for k in MEMBER_KINDS.get(token_kind, (token_kind,)):
            gone |= self.excluded_keys(device_id, k)
        mapped = (self.name_map or {}).get(token_kind) or {}
        return {n for n in gone if n not in mapped}

    def filter_tokens(self, device_id, token_kind: str, tokens):
        if not isinstance(tokens, list):
            return tokens
        gone = self.excluded_tokens(device_id, token_kind)
        return [x for x in tokens if not (isinstance(x, str) and x in gone)] if gone else tokens

    def filter_json_list(self, device_id, token_kind: str, raw):
        """A JSON-encoded member list (the import_* mirrors); re-encoded only
        when something left."""
        if not raw or not isinstance(raw, str):
            return raw
        try:
            arr = json.loads(raw)
        except Exception:
            return raw
        if not isinstance(arr, list):
            return raw
        out = self.filter_tokens(device_id, token_kind, arr)
        return raw if out == arr else json.dumps(out)

    def device_id_for_host(self, host):
        return self.host_device.get(host) if host else None

    def filter_rules(self, rules: list) -> list:
        """Effective rules (main._fetch_rules_and_devices, source names, before
        the name map): excluded objects, groups, services and service groups
        leave the member lists and their import_* mirrors. The rules
        themselves are excluded in SQL (P1)."""
        if self.empty:
            return rules
        for r in rules:
            did = self.device_id_for_host(r.get("device_host"))
            if did is None:
                continue
            for f in ("sources", "destinations"):
                r[f] = self.filter_tokens(did, "object", r.get(f))
            r["services"] = self.filter_tokens(did, "service", r.get("services"))
            r["import_sources"] = self.filter_json_list(did, "object", r.get("import_sources"))
            r["import_destinations"] = self.filter_json_list(did, "object", r.get("import_destinations"))
            r["import_services"] = self.filter_json_list(did, "service", r.get("import_services"))
        return rules

    def filter_groups(self, device_id, kind: str, rows: list) -> list:
        """Groups of one kind (group / service_group) without the excluded
        ones; the members of the rest without excluded tokens. Members sit
        at row['members'] (the Objects tab) or row['value']['members'] (the
        generate)."""
        token_kind = "object" if kind == "group" else "service"
        kept = self.filter(device_id, kind, rows)
        gone = self.excluded_tokens(device_id, token_kind)
        if not gone:
            return kept
        for g in kept:
            if isinstance(g.get("members"), list):
                g["members"] = self.filter_tokens(device_id, token_kind, g["members"])
            v = g.get("value")
            if isinstance(v, dict) and isinstance(v.get("members"), list):
                v["members"] = self.filter_tokens(device_id, token_kind, v["members"])
        return kept

    def filter_nat_rules(self, device_id, rows: list) -> list:
        """NAT rules without the ones deleted in this project (keyed on the
        NAT hash) and without excluded members in their original slots."""
        gone = self.excluded_keys(device_id, "nat_rule")
        out = [n for n in rows if not (n.get("nat_hash") and str(n["nat_hash"]) in gone)]
        for n in out:
            for f in ("orig_src", "orig_dst"):
                n[f] = self.filter_tokens(device_id, "object", n.get(f))
            n["orig_service"] = self.filter_tokens(device_id, "service", n.get("orig_service"))
        return out

    def filter_tags(self, device_id, rows: list, key="name") -> list:
        """The tag catalog without the tags deleted in this project."""
        return self.filter(device_id, "tag", rows, key=key)

    def filter_policy_rows(self, device_id, rows: list) -> list:
        """PBF and decryption rows: sources / destinations / services lists."""
        for r in rows:
            for f in ("sources", "destinations"):
                r[f] = self.filter_tokens(device_id, "object", r.get(f))
            r["services"] = self.filter_tokens(device_id, "service", r.get("services"))
        return rows

    # ── the network strand ──────────────────────────────────────────────
    # Interfaces, zones, routes and VRs are read per device or per stack of
    # template layers (the effective network of a Panorama stack). A row's
    # own device decides whether the row is excluded; the fallbacks (an
    # excluded VR re-homes to 'default', an excluded zone unbinds) look at
    # every layer, because a stack's VRs and zones are shared across them.

    def excluded_any(self, device_ids, kind: str) -> set:
        gone: set = set()
        for d in _ids(device_ids):
            gone |= self.exclusions.get((d, kind), set())
        return gone

    def has_network_exclusions(self, device_ids) -> bool:
        return any(self.exclusions.get((d, k)) for d in _ids(device_ids) for k in _NETWORK_KINDS)

    def vr_name(self, device_ids, vr):
        """The VR a row shows in this project: 'default' when its VR is
        deleted here (today's re-homing, as a rule of the view)."""
        if vr and vr in self.excluded_any(device_ids, "vrf"):
            return "default"
        return vr

    def _row_gone(self, device_ids, kind: str, row: dict, name, device_key):
        if name is None:
            return False
        did = row.get(device_key) if device_key else None
        if did is not None:
            return str(name) in self.exclusions.get((int(did), kind), set())
        return str(name) in self.excluded_any(device_ids, kind)

    # ── field edits (P3b) ────────────────────────────────────────────────
    # An edit is stored as {field: value} and laid over the fact row when the
    # loaders read it; the fact itself is never changed. Lists (ip_addresses,
    # member_iface_names) and the properties dict arrive decoded.

    def _dev_of(self, row: dict, device_ids, device_key):
        did = row.get(device_key) if device_key else None
        if did is None:
            ids = _ids(device_ids)
            did = ids[0] if len(ids) == 1 else row.get("device_id")
        return int(did) if did is not None else None

    def interface_edits_for(self, device_id, import_name, name=None) -> dict:
        if device_id is None:
            return {}
        e = self.iface_edits.get((int(device_id), import_name)) if import_name else None
        if e is None and name:
            e = self.iface_edits.get((int(device_id), name))
        return e or {}

    def apply_interface_edits(self, device_ids, rows: list, *, device_key=None) -> list:
        if not self.iface_edits:
            return rows
        for r in rows:
            did = self._dev_of(r, device_ids, device_key)
            e = self.interface_edits_for(did, r.get("import_interface_name"), r.get("interface_name"))
            if not e:
                continue
            for k, v in e.items():
                if k == "properties" and isinstance(v, dict):
                    cur = dict(r.get("properties") or {}) if isinstance(r.get("properties"), dict) else {}
                    for pk, pv in v.items():
                        if pv is None:
                            cur.pop(pk, None)
                        else:
                            cur[pk] = pv
                    r["properties"] = cur
                else:
                    r[k] = v
            r["edited"] = True
        return rows

    def route_edits_for(self, device_id, prefix, vr_name) -> dict:
        if device_id is None:
            return {}
        return self.route_edits.get((int(device_id), str(prefix), vr_name or "default")) or {}

    def apply_route_edits(self, device_ids, rows: list, *, device_key=None) -> list:
        if not self.route_edits:
            return rows
        for r in rows:
            did = self._dev_of(r, device_ids, device_key)
            e = self.route_edits_for(did, r.get("prefix"), r.get("vr_name"))
            if not e:
                continue
            for k, v in e.items():
                r[k] = v
            r["edited"] = True
        return rows

    def zone_edits_for(self, device_id, zone_name) -> dict:
        if device_id is None or not zone_name:
            return {}
        return self.zone_edits.get((int(device_id), str(zone_name))) or {}

    def apply_zone_edits(self, device_ids, rows: list) -> list:
        if not self.zone_edits:
            return rows
        for z in rows:
            e = self.zone_edits_for(z.get("device_id") if z.get("device_id") is not None
                                    else self._dev_of(z, device_ids, None), z.get("name"))
            if not e:
                continue
            for k, v in e.items():
                z[k] = v
            z["edited"] = True
        return rows

    @property
    def has_edits(self) -> bool:
        return bool(self.iface_edits or self.route_edits or self.zone_edits)

    def filter_interfaces(self, device_ids, rows: list, *, device_key=None) -> list:
        """Interface dicts without the excluded ones, with the project's
        edits laid over; an excluded VR reads as 'default', an excluded zone
        as no zone. ``device_key`` names the column holding the row's own
        device (stack loaders); without it the rows belong to ``device_ids``."""
        if not self.has_network_exclusions(device_ids) and not self.iface_edits:
            return list(rows)
        gone_zones = self.excluded_any(device_ids, "zone")
        out = []
        for r in rows:
            if self._row_gone(device_ids, "interface", r, r.get("interface_name"), device_key):
                continue
            out.append(r)
        self.apply_interface_edits(device_ids, out, device_key=device_key)
        for r in out:
            if "vr_name" in r:
                r["vr_name"] = self.vr_name(device_ids, r.get("vr_name"))
            if gone_zones and r.get("zone_name") in gone_zones:
                r["zone_name"] = None
        return out

    def filter_routes(self, device_ids, rows: list, *, device_key=None) -> list:
        """Route dicts (prefix, vr_name, interface_name, next_hop) without
        the excluded ones and without the routes of excluded interfaces (a
        route leaves with its interface, as the delete always did), with the
        project's edits laid over. Routes of an excluded VR re-home to
        'default'; one whose prefix 'default' already carries is dropped,
        the default copy wins."""
        if not self.has_network_exclusions(device_ids) and not self.route_edits:
            return list(rows)
        gone_ifaces = self.excluded_any(device_ids, "interface")
        kept = []
        for r in rows:
            vr = r.get("vr_name") or "default"
            if self._row_gone(device_ids, "route", r, route_key(r.get("prefix"), vr), device_key):
                continue
            kept.append(r)
        self.apply_route_edits(device_ids, kept, device_key=device_key)
        if gone_ifaces:
            kept = [r for r in kept
                    if not (r.get("interface_name") and r.get("interface_name") in gone_ifaces)]
        gone_vrs = self.excluded_any(device_ids, "vrf")
        if not gone_vrs:
            return kept
        taken = {(r.get(device_key) if device_key else None, r.get("prefix"))
                 for r in kept if (r.get("vr_name") or "default") == "default"}
        out = []
        for r in kept:
            vr = r.get("vr_name") or "default"
            if vr in gone_vrs:
                k = (r.get(device_key) if device_key else None, r.get("prefix"))
                if k in taken:
                    continue
                taken.add(k)
                r["vr_name"] = "default"
            out.append(r)
        return out

    def filter_zones(self, device_ids, rows: list) -> list:
        """Zone dicts (name, device_id, members) without the excluded ones,
        with the project's edits (colour, external flag, properties) laid
        over; the members of the rest without excluded interfaces."""
        if not self.has_network_exclusions(device_ids) and not self.zone_edits:
            return list(rows)
        gone_ifaces = self.excluded_any(device_ids, "interface")
        out = []
        for z in rows:
            if self._row_gone(device_ids, "zone", z, z.get("name"), "device_id"):
                continue
            if gone_ifaces and isinstance(z.get("members"), list):
                z["members"] = [m for m in z["members"] if m not in gone_ifaces]
            out.append(z)
        return self.apply_zone_edits(device_ids, out)

    def filter_vrfs(self, device_ids, rows: list, *, device_key=None, ensure_default=False) -> list:
        """VR dicts without the excluded ones. With ``ensure_default`` a
        'default' entry is synthesized when a VR was excluded and no default
        row exists - the re-homed interfaces and routes need their VR (the
        old cascade inserted that row)."""
        gone = self.excluded_any(device_ids, "vrf")
        if not gone:
            return list(rows)
        out = [v for v in rows if not self._row_gone(device_ids, "vrf", v, v.get("name"), device_key)]
        if ensure_default and not any((v.get("name") or "default") == "default" for v in out):
            synth = {"name": "default", "properties": None}
            if rows and "raw_name" in rows[0]:
                synth["raw_name"] = "default"
            if rows and "id" in rows[0]:
                synth["id"] = 0
                synth["device_id"] = rows[0].get("device_id")
                synth["import_vr_name"] = "default"
            out.append(synth)
        return out

    @property
    def empty(self) -> bool:
        return not self.exclusions and not self.has_edits


def empty_view(project_id=None) -> ProjectView:
    return ProjectView(project_id, namemap.empty_map(), {}, {})


def _jload(raw):
    if isinstance(raw, dict):
        return raw
    try:
        v = json.loads(raw) if raw else {}
    except Exception:
        return {}
    return v if isinstance(v, dict) else {}


# the fact tables that carry project-owned additions (D5): table, exclusion kind,
# and the SQL expression that yields the row's exclusion key
ADDITION_TABLES = (("fw_interfaces", "interface", "interface_name"),
                   ("fw_zones", "zone", "name"),
                   ("fw_vrfs", "vrf", "name"),
                   ("fw_nat_rules", "nat_rule", "LOWER(HEX(nat_hash))"),
                   ("fw_tags", "tag", "name"))


def load(conn, project_id) -> ProjectView:
    """The project's view: its name map, its exclusions, its field edits,
    and the other projects' additions hidden like exclusions. No project
    (None / 0) gives the plain facts."""
    if not project_id:
        return empty_view(project_id)
    pid = int(project_id)
    nm = namemap.load_name_map(conn, pid)
    exclusions: dict = {}
    labels: dict = {}
    for did, kind, key, label in conn.execute(text(
            "SELECT device_id, kind, item_key, label FROM fw_project_exclusions WHERE project_id = :p"),
            {"p": pid}).fetchall():
        exclusions.setdefault((int(did), kind), set()).add(str(key))
        labels.setdefault(kind, {})[str(key)] = label or str(key)
    # another project's additions are not this project's facts (D5): they
    # leave the view like exclusions and may not come out of its build
    try:
        for table, kind, col in ADDITION_TABLES:
            for did, name in conn.execute(text(
                    f"SELECT device_id, {col} FROM {table} "
                    "WHERE project_id IS NOT NULL AND project_id <> :p"), {"p": pid}).fetchall():
                if name:
                    exclusions.setdefault((int(did), kind), set()).add(str(name))
                    labels.setdefault(kind, {}).setdefault(str(name), str(name))
        for did, prefix, vr in conn.execute(text(
                "SELECT device_id, prefix, vr_name FROM fw_routes "
                "WHERE project_id IS NOT NULL AND project_id <> :p"), {"p": pid}).fetchall():
            exclusions.setdefault((int(did), "route"), set()).add(route_key(prefix, vr))
    except Exception:
        pass        # before the P3b schema exists there are no additions
    iface_edits: dict = {}
    route_edits: dict = {}
    zone_edits: dict = {}
    try:
        for did, imp, raw in conn.execute(text(
                "SELECT device_id, import_interface_name, edits FROM fw_interface_overrides "
                "WHERE project_id = :p AND edits IS NOT NULL"), {"p": pid}).fetchall():
            e = _jload(raw)
            if e:
                iface_edits[(int(did), imp)] = e
        for did, prefix, vr, raw in conn.execute(text(
                "SELECT device_id, prefix, vr_name, edits FROM fw_route_overrides "
                "WHERE project_id = :p AND edits IS NOT NULL"), {"p": pid}).fetchall():
            e = _jload(raw)
            if e:
                route_edits[(int(did), str(prefix), vr or "default")] = e
        for did, zname, raw in conn.execute(text(
                "SELECT device_id, zone_name, edits FROM fw_zone_overrides "
                "WHERE project_id = :p AND edits IS NOT NULL"), {"p": pid}).fetchall():
            e = _jload(raw)
            if e:
                zone_edits[(int(did), str(zname))] = e
    except Exception:
        pass        # before the P3b schema exists there are no project edits
    host_device: dict = {}
    if exclusions:
        ids = sorted({did for did, _k in exclusions})
        for did, host, shown in conn.execute(text(
                "SELECT id, host_name, display_name FROM fw_devices WHERE id IN :ids"
        ).bindparams(bindparam("ids", expanding=True)), {"ids": ids}).fetchall():
            for h in (host, shown):
                if h:
                    host_device[h] = int(did)
    return ProjectView(pid, nm, exclusions, labels, host_device,
                       iface_edits=iface_edits, route_edits=route_edits, zone_edits=zone_edits)


def set_edits(conn, table: str, project_id: int, device_id: int, key: dict, patch: dict) -> dict:
    """Merge ``patch`` into the project's edit row of one network item and
    return the merged edits. ``table`` is fw_interface_overrides (key
    import_interface_name), fw_route_overrides (key prefix, prefix_len,
    vr_name) or fw_zone_overrides (key zone_name)."""
    where = " AND ".join(f"{k} = :{k}" for k in key)
    params = {"p": int(project_id), "d": int(device_id), **key}
    cur = conn.execute(text(
        f"SELECT edits FROM {table} WHERE project_id = :p AND device_id = :d AND {where}"), params).fetchone()
    edits = _jload(cur[0]) if cur and cur[0] else {}
    edits.update(patch)
    cols = ", ".join(["project_id", "device_id", *key.keys(), "edits"])
    vals = ", ".join([":p", ":d", *(f":{k}" for k in key), ":ed"])
    conn.execute(text(
        f"INSERT INTO {table} ({cols}) VALUES ({vals}) ON DUPLICATE KEY UPDATE edits = VALUES(edits)"),
        {**params, "ed": json.dumps(edits)})
    return edits


def exclude(conn, project_id: int, device_id: int, kind: str, key, label=None,
            reason: str = "manual") -> None:
    """Record one exclusion (idempotent; a second call refreshes the label)."""
    if kind not in KINDS:
        raise ValueError(f"unknown exclusion kind {kind!r}")
    conn.execute(text(
        "INSERT INTO fw_project_exclusions (project_id, device_id, kind, item_key, label, reason) "
        "VALUES (:p, :d, :k, :key, :l, :r) "
        "ON DUPLICATE KEY UPDATE label = VALUES(label), reason = VALUES(reason)"
    ), {"p": int(project_id), "d": int(device_id), "k": kind, "key": str(key)[:255],
        "l": (str(label)[:255] if label else None), "r": reason[:32]})


def restore(conn, project_id: int, device_id: int, kind: str, key) -> int:
    """Drop one exclusion; returns the number of rows removed (0 or 1)."""
    return conn.execute(text(
        "DELETE FROM fw_project_exclusions "
        "WHERE project_id = :p AND device_id = :d AND kind = :k AND item_key = :key"
    ), {"p": int(project_id), "d": int(device_id), "k": kind, "key": str(key)}).rowcount or 0


def list_rows(conn, project_id: int) -> list[dict]:
    """The project's exclusions for the Overview, newest first."""
    rows = conn.execute(text(
        "SELECT x.device_id, COALESCE(d.display_name, d.host_name) AS device_name, "
        "       x.kind, x.item_key, x.label, x.reason, x.created_at "
        "FROM fw_project_exclusions x LEFT JOIN fw_devices d ON d.id = x.device_id "
        "WHERE x.project_id = :p ORDER BY x.created_at DESC, x.kind, x.item_key"
    ), {"p": int(project_id)}).mappings().all()
    return [{"device_id": r["device_id"], "device_name": r["device_name"] or "?",
             "kind": r["kind"], "kind_label": KIND_LABELS.get(r["kind"], r["kind"]),
             "item_key": r["item_key"], "label": r["label"] or r["item_key"],
             "reason": r["reason"], "created_at": str(r["created_at"] or "")[:16]}
            for r in rows]
