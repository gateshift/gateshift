# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""Gateshift Enterprise - the shared persistence of a manager's scope-devices.

A manager import (Panorama, FortiManager, Check Point MDS, Strata Cloud
Manager) fans the manager into scope-devices: fw_devices rows of
device_kind 'scope' that hold one scope's raw local configuration. What a
POLICY scope holds (objects, security rules, NAT, policy routing,
decryption, tags) and what a NETWORK scope holds (interfaces, zones,
routes, VRFs, VPN tunnels) is written here with the same statements the
firewall imports use, so a scope-device is first-class in /rules. The
parsers hand in the row shapes the CE parsers produce (see
main._parse_panw_* for the vocabulary), this module only writes.
"""
from __future__ import annotations

import json as _json

from sqlalchemy import text

import hitcounts as _hits   # the box's own rule counters on the scope rows (docs/HIT_COUNTS_PLAN.md)
from scopeidentity import host_name_for, plan_scope_sync, vendor_id_of


def persist_policy_scope(conn, sdid: int, ts, objs: list, rules: list, nats: list,
                         pbfs: list, ssls: list, tags: list) -> None:
    """Write a policy scope's content to the scope-device `sdid`. Objects land
    in fw_imported_objects and, for addresses and services, in the unified
    object tables; rules, NAT, policy routing and decryption rules in their
    tables with their hashes; tags in fw_tags."""
    from main import (_upsert_object_tables, _write_nat_hash, _write_pbf_hash,
                      _write_ssl_hash)
    if objs:
        conn.execute(text(
            "INSERT INTO fw_imported_objects "
            "(device_id, import_ts, obj_type, name, value, source_vendor_id) "
            "VALUES (:did,:ts,:type,:name,:val,:svid)"),
            [{"did": sdid, "ts": ts, "type": o["obj_type"], "name": o["name"],
              "val": _json.dumps(o["value"]),
              "svid": o.get("source_vendor_id") or o["name"]} for o in objs])
        _upsert_object_tables(conn, sdid, objs)
    if rules:
        conn.execute(text("""
            INSERT INTO fw_imported_rules
                (device_id, import_ts, rule_name, seq_num, action, src_zones, dst_zones,
                 sources, destinations, services, applications, description, disabled, tags,
                 negate_source, negate_destination, negate_service, schedule,
                 source_identities, raw_extras, source_vendor_id,
                 box_hits, box_first_hit, box_last_hit, box_hits_since, box_hits_read_at)
            VALUES
                (:did,:ts,:name,:seq,:action,:sz,:dz,:src,:dst,:svc,:app,:desc,:dis,:tags,
                 :nsrc,:ndst,:nsvc,:sched,:idents,:extras,:svid,
                 :bhits, :bfirst, :blast, :bsince, :bread)
        """), [
            {"did": sdid, "ts": ts, "name": r["rule_name"], "seq": r["seq_num"],
             "action": r["action"], "sz": _json.dumps(r["src_zones"]),
             "dz": _json.dumps(r["dst_zones"]), "src": _json.dumps(r["sources"]),
             "dst": _json.dumps(r["destinations"]), "svc": _json.dumps(r["services"]),
             "app": _json.dumps(r["applications"]), "desc": r["description"],
             "dis": r["disabled"], "tags": _json.dumps(r["tags"]),
             "nsrc": int(r.get("negate_source") or 0),
             "ndst": int(r.get("negate_destination") or 0),
             "nsvc": int(r.get("negate_service") or 0), "sched": r.get("schedule") or None,
             "idents": _json.dumps(r["source_identities"]) if r.get("source_identities") else None,
             "extras": _json.dumps(r["raw_extras"]) if r.get("raw_extras") else None,
             "svid": r.get("source_vendor_id") or r["rule_name"],
             **_hits.params(r)} for r in rules])
    if nats:
        conn.execute(text("""
            INSERT INTO fw_nat_rules
                (device_id, position, name, nat_type, disabled,
                 src_zones, dst_zones, interface_name,
                 orig_src, orig_dst, orig_service,
                 trans_src, trans_src_type, trans_dst, trans_dst_port,
                 description, properties,
                 negate_source, negate_destination, negate_service,
                 box_hits, box_first_hit, box_last_hit, box_hits_since, box_hits_read_at)
            VALUES
                (:did,:pos,:name,:type,:dis,:sz,:dz,:iface,
                 :osrc,:odst,:osvc,:tsrc,:tstype,:tdst,:tdport,
                 :desc,:props,:nsrc,:ndst,:nsvc,
                 :bhits, :bfirst, :blast, :bsince, :bread)
        """), [
            {"did": sdid, "pos": n["position"], "name": n["name"],
             "type": n["nat_type"], "dis": n["disabled"],
             "sz": _json.dumps(sorted(n["src_zones"] or [])),
             "dz": _json.dumps(sorted(n["dst_zones"] or [])),
             "iface": n.get("interface_name"),
             "osrc": _json.dumps(sorted(n["orig_src"] or [])),
             "odst": _json.dumps(sorted(n["orig_dst"] or [])),
             "osvc": _json.dumps(sorted(n["orig_service"] or [])),
             "tsrc": n.get("trans_src"), "tstype": n.get("trans_src_type") or "none",
             "tdst": n.get("trans_dst"), "tdport": n.get("trans_dst_port"),
             "desc": n.get("description") or "",
             "props": (_json.dumps(n["properties"]) if n.get("properties") else None),
             "nsrc": int(n.get("negate_source") or 0),
             "ndst": int(n.get("negate_destination") or 0),
             "nsvc": int(n.get("negate_service") or 0),
             **_hits.params(n)}
            for n in nats])
        _write_nat_hash(conn, "n.device_id = :did", {"did": sdid})
    if pbfs:
        conn.execute(text("""
            INSERT INTO fw_pbf_rules
                (device_id, position, name, disabled,
                 ingress, sources, destinations, services,
                 action, egress_interface, next_hop,
                 description, raw_extras)
            VALUES
                (:did,:pos,:name,:dis,:ing,:src,:dst,:svc,
                 :act,:egress,:nh,:desc,:extras)
        """), [
            {"did": sdid, "pos": p["position"], "name": p["name"], "dis": p["disabled"],
             "ing": _json.dumps(sorted(p.get("ingress") or [], key=lambda x: x.get("name", ""))),
             "src": _json.dumps(sorted(p.get("sources") or [])),
             "dst": _json.dumps(sorted(p.get("destinations") or [])),
             "svc": _json.dumps(sorted(p.get("services") or [])),
             "act": p.get("action") or "forward",
             "egress": p.get("egress_interface"), "nh": p.get("next_hop"),
             "desc": p.get("description") or "",
             "extras": (_json.dumps(p["raw_extras"]) if p.get("raw_extras") else None)}
            for p in pbfs])
        _write_pbf_hash(conn, "p.device_id = :did", {"did": sdid})
    if ssls:
        conn.execute(text("""
            INSERT INTO fw_ssl_rules
                (device_id, position, name, disabled,
                 src_zones, dst_zones, sources, destinations, services,
                 url_categories, source_identities,
                 action, ssl_type, cert_ref, profile_props, description, raw_extras)
            VALUES
                (:did,:pos,:name,:dis,:sz,:dz,:src,:dst,:svc,
                 :uc,:si,:act,:typ,:cert,:props,:desc,:extras)
        """), [
            {"did": sdid, "pos": s["position"], "name": s["name"],
             "dis": int(bool(s.get("disabled"))),
             "sz": _json.dumps(sorted(s.get("src_zones") or [])),
             "dz": _json.dumps(sorted(s.get("dst_zones") or [])),
             "src": _json.dumps(sorted(s.get("sources") or [])),
             "dst": _json.dumps(sorted(s.get("destinations") or [])),
             "svc": _json.dumps(sorted(s.get("services") or [])),
             "uc": _json.dumps(sorted(s.get("url_categories") or [])),
             "si": _json.dumps(sorted(s.get("source_identities") or [],
                                      key=lambda x: x.get("name", ""))),
             "act": s.get("action") or "decrypt",
             "typ": s.get("ssl_type") or "forward-proxy",
             "cert": s.get("cert_ref"),
             "props": (_json.dumps(s["profile_props"]) if s.get("profile_props") else None),
             "desc": s.get("description") or "",
             "extras": (_json.dumps(s["raw_extras"]) if s.get("raw_extras") else None)}
            for s in ssls])
        _write_ssl_hash(conn, "s.device_id = :did", {"did": sdid})
    if tags:
        conn.execute(text(
            "INSERT INTO fw_tags (device_id, name, properties, source) "
            "VALUES (:did,:name,:props,'import') "
            "ON DUPLICATE KEY UPDATE properties=IF(source='manual',properties,VALUES(properties)), "
            "source=IF(source='manual',source,'import')"),
            [{"did": sdid, "name": t["name"], "props": _json.dumps(t.get("properties") or {})}
             for t in tags])


def persist_vpn_tunnels(conn, sdid: int, vpns: list) -> None:
    """Write the route-based IPsec tunnels of a network scope (the shape of
    main._parse_panw_vpn_tunnels). The PSK is never part of it."""
    from main import _write_vpn_hash
    if not vpns:
        return
    conn.execute(text("""
        INSERT INTO fw_vpn_tunnels
            (device_id, position, name, disabled,
             gateway_name, peer_address, peer_type,
             local_interface, local_address,
             auth_type, cert_ref, local_id, peer_id,
             ike_version, ike_crypto_profile, ipsec_crypto_profile,
             tunnel_interface, traffic_selectors, domain_objects, raw_extras)
        VALUES
            (:did,:pos,:name,:dis,:gw,:peer,:ptype,:liface,:laddr,
             :auth,:cert,:lid,:pid,:ikev,:ikec,:ipsecc,:tiface,:tsel,:dobj,:extras)
    """), [
        {"did": sdid, "pos": v.get("position", i), "name": v["name"],
         "dis": int(bool(v.get("disabled"))),
         "gw": v.get("gateway_name"), "peer": v.get("peer_address") or "",
         "ptype": v.get("peer_type") or "ip",
         "liface": v.get("local_interface"), "laddr": v.get("local_address"),
         "auth": v.get("auth_type") or "psk", "cert": v.get("cert_ref"),
         "lid": v.get("local_id"), "pid": v.get("peer_id"),
         "ikev": v.get("ike_version") or "ikev2",
         "ikec": v.get("ike_crypto_profile"), "ipsecc": v.get("ipsec_crypto_profile"),
         "tiface": v.get("tunnel_interface"),
         "tsel": (_json.dumps(v["traffic_selectors"]) if v.get("traffic_selectors") else None),
         "dobj": (_json.dumps(v["domain_objects"]) if v.get("domain_objects") else None),
         "extras": (_json.dumps(v["raw_extras"]) if v.get("raw_extras") else None)}
        for i, v in enumerate(vpns)])
    _write_vpn_hash(conn, "v.device_id = :did", {"did": sdid})


def persist_network(conn, sdid: int, cres: dict) -> None:
    """Write a network scope's collect result (interfaces, zones, routes,
    VRFs) with the shared persist the firewall collectors use."""
    from main import _write_collect_result
    cres.setdefault("interfaces", [])
    cres.setdefault("routes", [])
    cres.setdefault("vrfs", [])
    cres.setdefault("zones", [])
    _write_collect_result(conn, sdid, cres)


# What one import rewrites for a scope Device it keeps: the tables the
# firewall import clears before it writes (main.device_import_run), plus the
# import-sourced tags below. Keyed by device_id only, never by name. What is
# NOT here survives the import on purpose: the curation keyed on the Device
# (manual tags, the VPN secrets and certificates, the deploy settings, the
# project exclusions), the hash-keyed overrides, and the network tables,
# whose writer replaces per kind itself (_write_collect_result).
SCOPE_CONTENT_TABLES = (
    "fw_imported_rules", "fw_imported_objects", "fw_nat_rules", "fw_pbf_rules",
    "fw_ssl_rules", "fw_imported_tp_rules", "fw_vpn_tunnels", "fw_active_routes",
    "fw_import_drops", "fw_raw_objects",
)


def retire_scope_device(conn, sid: int) -> None:
    """A scope the manager no longer has: its curation through the rule
    tables, then everything keyed on its id, then the Device row (the
    fw_scopes edge cascades)."""
    from main import _delete_hash_keyed_overrides, _purge_device_data
    if not conn.execute(text("SELECT 1 FROM fw_devices WHERE id = :id"), {"id": sid}).scalar():
        return
    _delete_hash_keyed_overrides(conn, sid)
    _purge_device_data(conn, [sid])
    conn.execute(text("DELETE FROM fw_target_configs WHERE source_id = :d OR target_id = :d"),
                 {"d": sid})
    conn.execute(text("DELETE FROM fw_devices WHERE id = :id"), {"id": sid})


def sync_scope_devices(conn, manager_id: int, platform: str, scopes: list, *, clear_content: bool = True) -> dict:
    """Give every discovered scope its Device row and set sc['_sdid']: the row
    of a prior import when the vendor id (or, for a row that never learned
    its id, the name) matches, a new row otherwise. Scopes the manager no
    longer has are retired. A kept Device's content tables are cleared so the
    caller writes the scope fresh; its curation stays (scopeidentity,
    docs/DEVICE_IDENTITY_PLAN.md phase 3). Returns the counts."""
    existing = [tuple(r) for r in conn.execute(text(
        "SELECT scope_device_id, scope_type, scope_name, vendor_id FROM fw_scopes "
        "WHERE manager_device_id = :m"), {"m": manager_id}).fetchall()]
    plan = plan_scope_sync(existing, scopes)
    # Retired scopes first: a kept scope may have taken a retired one's name.
    for sid, _sname in plan.retire:
        retire_scope_device(conn, sid)
    # Kept scopes. scope_name is a unique key per manager and two scopes can
    # swap names in one import, so the renamed rows step aside first.
    renamed = [(sc, sid) for sc, sid, old, _l in plan.keep if old != sc["name"]]
    for sc, sid in renamed:
        conn.execute(text(
            "UPDATE fw_scopes SET scope_name = :n WHERE manager_device_id = :m AND scope_device_id = :s"),
            {"n": f":renaming:{sid}", "m": manager_id, "s": sid})
    for sc, sid, old, learned in plan.keep:
        conn.execute(text(
            "UPDATE fw_devices SET host_name = :hn, display_name = :dn, platform = :pl, "
            "role = 'source', device_kind = 'scope' WHERE id = :id"),
            {"hn": host_name_for(manager_id, sc), "dn": sc["name"], "pl": platform, "id": sid})
        if sc.get("config") is not None:
            conn.execute(text("UPDATE fw_devices SET config = :c WHERE id = :id"),
                         {"c": sc["config"], "id": sid})
        conn.execute(text(
            "UPDATE fw_scopes SET scope_name = :n" + (", vendor_id = :v" if learned else "") +
            " WHERE manager_device_id = :m AND scope_device_id = :s"),
            {"n": sc["name"], "v": learned, "m": manager_id, "s": sid})
        if clear_content:        # a collect keeps the instance's imported content (instancesource)
            for tbl in SCOPE_CONTENT_TABLES:
                conn.execute(text(f"DELETE FROM {tbl} WHERE device_id = :id"), {"id": sid})
            conn.execute(text("DELETE FROM fw_tags WHERE device_id = :id AND source = 'import'"),
                         {"id": sid})
        sc["_sdid"] = sid
    for sc in plan.new:
        sc["_sdid"] = conn.execute(text(
            "INSERT INTO fw_devices (host_name, display_name, platform, role, device_kind, config) "
            "VALUES (:hn, :dn, :pl, 'source', 'scope', :cfg)"),
            {"hn": host_name_for(manager_id, sc), "dn": sc["name"], "pl": platform,
             "cfg": sc.get("config")}).lastrowid
    counts = {"kept": len(plan.keep), "learned": sum(1 for k in plan.keep if k[3]),
              "renamed": len(renamed), "new": len(plan.new), "retired": len(plan.retire)}
    print(f"[scopes] manager #{manager_id}: {counts}", flush=True)
    return counts


def write_scope_edge(conn, manager_id: int, sc: dict, role, parent_sid, members) -> None:
    """The scope's fw_scopes row: type, role, name, vendor id, the parent
    edge and the members list. Updated in place for a kept scope, inserted
    for a new one. `members` is a list (a template-stack's templates, a
    package's install targets) or None."""
    params = {"m": manager_id, "s": sc["_sdid"], "t": sc["type"], "r": role,
              "n": sc["name"], "v": vendor_id_of(sc), "p": parent_sid,
              "mem": _json.dumps(members) if members else None}
    rid = conn.execute(text(
        "SELECT id FROM fw_scopes WHERE manager_device_id = :m AND scope_device_id = :s"),
        {"m": manager_id, "s": sc["_sdid"]}).scalar()
    if rid:
        params["id"] = rid
        conn.execute(text(
            "UPDATE fw_scopes SET scope_type = :t, scope_role = :r, scope_name = :n, "
            "vendor_id = :v, parent_scope_device_id = :p, members = :mem WHERE id = :id"), params)
    else:
        conn.execute(text(
            "INSERT INTO fw_scopes (manager_device_id, scope_device_id, scope_type, scope_role, "
            "scope_name, vendor_id, parent_scope_device_id, members) "
            "VALUES (:m, :s, :t, :r, :n, :v, :p, :mem)"), params)
