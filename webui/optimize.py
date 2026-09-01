# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""Gateshift in-place OPTIMIZATION engine (O-3).

Same-vendor config hygiene: find objects that NOTHING references → operator curates
→ delete on the CANDIDATE (reversible) via the vendor API. Built on O-0 (raw snapshot
/ identity), O-2 (candidate writes), and the shared refmodel reference engine.

SAFETY - a delete is safe only if the reference view is COMPLETE. Reference
completeness is refmodel's job: it collects object/service references from access
rules, groups, NAT and PBF. Refmodel's rule-ref source now UNIONS the import landing
(refmodel._imported_rule_references), so it is complete on a freshly-imported-but-not-
generated device too - before that fix find_unused over-reported on a fresh import
(the consolidated view was empty → used services / a referenced group were wrongly
listed unused), which would have made a delete UNSAFE. Using refmodel keeps this
single-source with the rest of Gateshift's integrity checks (incl. NAT/PBF coverage,
so no more "unchecked rule types" warning).
"""
import json

from sqlalchemy import text

import refmodel
from deploy.panw import _api_url, _api_delete

_VSYS = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"
_PA_SECTION = {
    "address": "address", "service": "service",
    "address_group": "address-group", "service_group": "service-group",
}

# fortigate CMDB resource paths per object type (for the live delete + read-back).
_FORTI_CMDB_PATH = {
    "address": "firewall/address", "address_group": "firewall/addrgrp",
    "service": "firewall.service/custom", "service_group": "firewall.service/group",
}

# Well-known CheckPoint PREDEFINED/system objects that get imported as ordinary
# address objects (they pass the read-only import filter) yet are referenced by CP
# subsystems Gateshift does NOT model (Office Mode, Remote Access, system rules) - and
# CP does not reliably block deleting them (the Office-Mode pool deletes with only a
# consequence-warning). Never offer them for deletion. Coarse-but-SAFE: this is an
# EXCLUSION list, so over-listing only protects more and under-listing merely falls
# back to today's behaviour + operator review + CP delete-time integrity. Principled
# follow-up: capture CP's predefined flag at import (needs live meta-info + re-import).
_CP_PREDEFINED = {
    "All_Internet", "LocalMachine_Loopback", "CP_default_Office_Mode_addresses_pool",
    "InternalNet", "DMZNet", "LocalMachine", "NAT-hide-services",
}

# FortiOS FACTORY-DEFAULT objects (addresses / groups / services). Every FortiGate ships
# these; the import stores them like any object because FortiOS exposes NO reliable
# per-object "predefined" flag (verified live: predefined vs user objects have identical
# CMDB field-sets - only a heuristic `category` differs). So on a box with few policies
# find_unused flags dozens of them → NEVER offer them for deletion. Captured (UNIONED)
# from pristine FortiOS 7.6 + 7.2 VMs = the authoritative default set; over-listing only
# protects more (a user object can't collide - FortiOS reserves these names). Refresh per
# major FortiOS version by capturing another pristine box's object lists + unioning.
_FORTI_PREDEFINED = frozenset({
    # addresses + address-groups
    "all", "none", "FABRIC_DEVICE", "FIREWALL_AUTH_PORTAL_ADDRESS", "SSLVPN_TUNNEL_ADDR1",
    "metadata-server", "gmail.com", "wildcard.google.com", "wildcard.dropbox.com",
    "login.microsoft.com", "login.microsoftonline.com", "login.windows.net",
    "EMS_ALL_UNKNOWN_CLIENTS", "EMS_ALL_UNMANAGEABLE_CLIENTS", "FCTEMS_ALL_FORTICLOUD_SERVERS",
    "G Suite", "Microsoft Office 365",
    # service-groups
    "Email Access", "Exchange Server", "Web Access", "Windows AD",
    # services
    "ALL", "ALL_TCP", "ALL_UDP", "ALL_ICMP", "ALL_ICMP6", "NONE", "AFS3", "AH", "AOL",
    "BGP", "CVSPSERVER", "DCE-RPC", "DHCP", "DHCP6", "DNS", "ESP", "FINGER", "FTP",
    "FTP_GET", "FTP_PUT", "GOPHER", "GRE", "GTP", "H323", "HTTP", "HTTPS", "IKE", "IMAP",
    "IMAPS", "INFO_ADDRESS", "INFO_REQUEST", "Internet-Locator-Service", "IRC", "KERBEROS",
    "L2TP", "LDAP", "LDAP_UDP", "MGCP", "MMS", "MS-SQL", "MYSQL", "NetMeeting", "NFS",
    "NNTP", "NTP", "ONC-RPC", "OSPF", "PC-Anywhere", "PING", "PING6", "POP3", "POP3S",
    "PPTP", "QUAKE", "RADIUS", "RADIUS-OLD", "RAUDIO", "RDP", "REXEC", "RIP", "RLOGIN",
    "RSH", "RTSP", "SAMBA", "SCCP", "SIP", "SIP-MSNmessenger", "SMB", "SMTP", "SMTPS",
    "SNMP", "SOCKS", "SQUID", "SSH", "SYSLOG", "TALK", "TELNET", "TFTP", "TIMESTAMP",
    "TRACEROUTE", "UUCP", "VDOLIVE", "VNC", "WAIS", "WINFRAME", "WINS", "X-WINDOWS",
    "webproxy",
})

# platform → predefined/system name-set withheld from deletion candidacy.
_PREDEFINED = {"checkpoint": _CP_PREDEFINED, "fortigate": _FORTI_PREDEFINED}


def find_unused_objects(conn, device_id):
    """{"unused": [{name, obj_type}], "warnings": [str]}. Objects (address / service /
    address-group / service-group) that NOTHING references - safe to delete - via the
    shared refmodel engine (complete incl. NAT/PBF + SSL-inspection rules on a fresh
    import). find_unused returns cleaned names; map each back to the box's real entry
    name + type. Two safety filters close audited reference-model gaps (CP-A0):
      - CP predefined/system objects are withheld (referenced by un-modeled CP
        subsystems; CP may not block the delete) - see _CP_PREDEFINED.
      - if the device has VPN encryption domains, ADDRESS-type candidates are withheld:
        traffic_selectors persist CIDRs, the enc-domain object NAME is lost at import,
        so refmodel can't see an object used only in a VPN domain. Services unaffected."""
    platform = conn.execute(text(
        "SELECT platform FROM fw_devices WHERE id = :d"), {"d": device_id}).scalar()
    unused_names = (refmodel.find_unused(conn, device_id, "object")
                    | refmodel.find_unused(conn, device_id, "service"))
    by_clean = {}
    for name, obj_type in conn.execute(text(
            "SELECT name, obj_type FROM fw_imported_objects WHERE device_id = :d "
            "AND obj_type IN ('address', 'service', 'address_group', 'service_group')"),
            {"d": device_id}):
        by_clean[refmodel._clean(name)] = (name, obj_type)
    unused = []
    for cname in sorted(unused_names):
        entry = by_clean.get(cname)
        if entry:
            unused.append({"name": entry[0], "obj_type": entry[1]})

    warnings = []

    # Vendor predefined/system objects → never deletable: they're referenced by
    # un-modeled vendor subsystems and/or the vendor won't reliably block their delete,
    # and they're not user migration content. (CP: defaults that slip the read-only
    # filter; FortiOS: factory-default addresses/services/groups, ~100 of them.)
    predefined = _PREDEFINED.get(platform)
    if predefined:
        before = len(unused)
        unused = [u for u in unused if u["name"] not in predefined]
        if len(unused) < before:
            label = "CheckPoint" if platform == "checkpoint" else "FortiOS"
            warnings.append(f"{before - len(unused)} {label} predefined/system "
                            "object(s) withheld from deletion.")

    # VPN object-reference gate (audited): refmodel can't see address objects referenced
    # from INSIDE a VPN tunnel unless they're visible in the model. A vendor skips this
    # blunt gate (is in _vpn_precise) when EITHER its collector captures the VPN object names
    # into fw_vpn_tunnels.domain_objects (→ refmodel FieldRef) - fortigate (phase2
    # named-selectors) + checkpoint (enc-domain group), follow-up 1 - OR its VPN references
    # NO address objects at all - panw (proxy-id local/remote are literal subnets, never
    # object refs; verified in the PA VPN collector). Any vendor NOT listed still withholds
    # ALL address-type candidates when the device has a VPN tunnel (services are never
    # VPN-referenced). All CE vendors are now precise, so the gate is effectively a backstop
    # for a hypothetical future/un-audited vendor.
    _vpn_precise = ("fortigate", "checkpoint", "panw")
    has_vpn = conn.execute(text(
        "SELECT COUNT(*) FROM fw_vpn_tunnels WHERE device_id = :d"), {"d": device_id}).scalar()
    if has_vpn and platform not in _vpn_precise:
        held = [u for u in unused if u["obj_type"] in ("address", "address_group")]
        if held:
            unused = [u for u in unused if u["obj_type"] not in ("address", "address_group")]
            warnings.append(f"{len(held)} address object(s) withheld: this device has VPN "
                            "tunnels whose object references aren't audited yet "
                            "(deleting an address used only in a VPN could break it).")

    return {"unused": unused, "warnings": warnings}


def apply_object_deletes(device, deletions):
    """Apply the curated object deletes, vendor-dispatched. Both paths are REVERSIBLE and
    Gateshift commits NOTHING on its own:
      - panw → delete on the CANDIDATE config (operator commits/reverts in PAN-OS).
      - checkpoint → STAGE the deletes on a DEDICATED Mgmt session WITHOUT publishing and
        return its handle; the caller persists it (save_pending) so the operator can
        publish (commit) or discard (revert) that exact session via Gateshift.
    deletions = [{name, obj_type}]. Returns a mode-tagged dict."""
    plat = device.get("platform")
    if plat == "checkpoint":
        return _stage_cp_deletes(device, deletions)
    if plat == "fortigate":
        return _forti_delete(device, deletions)
    return _apply_panw_deletes(device, deletions)


def _apply_panw_deletes(device, deletions):
    """panw: action=delete each object on the CANDIDATE at its vsys xpath."""
    base_url = _api_url(device)
    api_key = device.get("api_key") or ""
    applied, errors = [], []
    for d in deletions:
        section = _PA_SECTION.get(d.get("obj_type"))
        if not section:
            continue
        xp = f"{_VSYS}/{section}/entry[@name='{d['name']}']"
        try:
            _api_delete(base_url, api_key, xp)
            applied.append({"obj_type": d["obj_type"], "name": d["name"]})
        except Exception as e:
            errors.append({"name": d.get("name"), "error": str(e)})
    return {"mode": "candidate", "applied": applied, "errors": errors}


def _cp_resolve(base_url, sid, name):
    """Resolve a CP object NAME → (type, uid). CP's show-object needs a uid, so we search
    via show-objects (fuzzy filter) and take the EXACT-name match. The CP type (host /
    network / address-range / group / service-tcp / …) is what picks the delete verb.
    Returns (None, None) if absent."""
    from deploy.checkpoint import _call
    r = _call(base_url, sid, "show-objects",
              {"filter": name, "limit": 50, "details-level": "full"})
    for o in (r.get("objects") or []):
        if o.get("name") == name:
            return o.get("type"), o.get("uid")
    return None, None


def _stage_cp_deletes(device, deletions):
    """checkpoint: stage deletes on a DEDICATED (un-cached) session, no publish. Delete
    verb = 'delete-' + the object's CP type (resolved via _cp_resolve), by uid, with NO
    ignore-warnings → CP itself refuses to delete an in-use object (a second safety layer
    beneath refmodel). Returns {mode, staged, errors, handle}; handle={sid,base_url} when
    anything was staged (else the empty session is discarded here)."""
    from deploy.checkpoint import _login, _call, _logout
    sid, base_url = _login(device, fresh=True)
    staged, errors = [], []
    for d in deletions:
        name = d.get("name")
        try:
            typ, uid = _cp_resolve(base_url, sid, name)
            if not typ or not uid:
                errors.append({"name": name, "error": "not found on device"})
                continue
            _call(base_url, sid, "delete-" + typ, {"uid": uid})   # NO ignore-warnings
            staged.append({"obj_type": d.get("obj_type"), "name": name})
        except Exception as e:
            errors.append({"name": name, "error": str(e)})
    if not staged:
        try:
            _call(base_url, sid, "discard", {})
        except Exception:
            pass
        _logout(base_url, sid)
    return {"mode": "session", "staged": staged, "errors": errors,
            "handle": {"sid": sid, "base_url": base_url} if staged else None}


def _forti_conn(device):
    from deploy import _forti_common as fc
    from deploy.fortinet import _verify_tls
    return (fc.base_url_for(device), device.get("api_key") or "",
            fc.vdom_for(device), _verify_tls(device))


def _forti_backup(device):
    """Full-config backup = the pre-delete restore point (FortiOS has no candidate/undo).
    FortiOS 7.x: POST monitor/system/config/backup {scope:global} → the config text (GET 405s)."""
    import requests
    base, token, vdom, verify = _forti_conn(device)
    r = requests.post(f"{base}/api/v2/monitor/system/config/backup",
                      headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                      data='{"scope":"global"}', verify=verify, timeout=(5, 60))
    r.raise_for_status()
    return r.text


def _forti_delete(device, deletions):
    """fortigate: Forti has NO candidate/session - a delete is LIVE and irreversible. Safety
    model: take a full-config BACKUP first (the restore point); DELETE each object with NO
    override → FortiOS itself rejects an in-use delete (a backstop beneath refmodel); then
    READ-BACK to confirm it's gone. Returns {mode:"live", deleted, errors, backup}; the
    caller stores `backup` so the operator can download it (the undo). If the backup fails,
    NOTHING is deleted."""
    import requests
    from urllib.parse import quote
    from deploy.fortinet import _delete, _cmdb_base
    base, token, vdom, verify = _forti_conn(device)
    cmdb = _cmdb_base(device)
    hdr = {"Authorization": f"Bearer {token}"}
    try:
        backup = _forti_backup(device)
    except Exception as e:
        return {"mode": "live", "deleted": [], "backup": None,
                "errors": [{"error": f"pre-delete backup failed - nothing deleted: {e}"}]}
    deleted, errors = [], []
    for d in deletions:
        name = d.get("name")
        path = _FORTI_CMDB_PATH.get(d.get("obj_type"))
        if not path:
            continue
        rid = f"/{path}/{quote(name, safe='')}"
        try:
            _delete(cmdb, token, rid, vdom, verify)   # no override → in-use delete rejected
            gone = False
            try:
                requests.get(f"{cmdb}{rid}?vdom={vdom}", headers=hdr, verify=verify,
                             timeout=(5, 20)).raise_for_status()
            except Exception:
                gone = True   # read-back GET 404 → object is gone
            if gone:
                deleted.append({"obj_type": d.get("obj_type"), "name": name})
            else:
                errors.append({"name": name, "error": "still present after delete"})
        except Exception as e:
            errors.append({"name": name, "error": str(e)})
    return {"mode": "live", "deleted": deleted, "errors": errors, "backup": backup}


# ── CP staged-session store (device_id -> held session handle) ─────────────────
# A CP delete is session-local until published. We stage on a dedicated session and
# persist its handle so the operator can publish/discard via Gateshift across requests.
# DB-backed (survives a worker reload within CP's ~10-min session TTL); on loss the
# orphaned CP session simply times out and auto-discards (safe - nothing was published).

def save_pending(conn, device_id, handle, deleted):
    conn.execute(text(
        "REPLACE INTO fw_optimize_pending (device_id, session_handle, deleted) "
        "VALUES (:d, :h, :x)"),
        {"d": device_id, "h": json.dumps(handle), "x": json.dumps(deleted)})


def load_pending(conn, device_id, ttl=540):
    """The held CP session handle for a device, or None if absent/expired (> ttl s)."""
    row = conn.execute(text(
        "SELECT session_handle, deleted, TIMESTAMPDIFF(SECOND, created_at, NOW()) "
        "FROM fw_optimize_pending WHERE device_id = :d"), {"d": device_id}).fetchone()
    if not row:
        return None
    handle_json, deleted_json, age = row
    if age is not None and age > ttl:
        return None
    def _j(v):
        return json.loads(v) if isinstance(v, str) else v
    return {"handle": _j(handle_json), "deleted": _j(deleted_json)}


def clear_pending(conn, device_id):
    conn.execute(text("DELETE FROM fw_optimize_pending WHERE device_id = :d"), {"d": device_id})


# ── Forti pre-delete config backup store (the restore point for a LIVE delete) ──

def save_backup(conn, device_id, backup, deleted):
    conn.execute(text(
        "REPLACE INTO fw_optimize_backups (device_id, backup, deleted) VALUES (:d, :b, :x)"),
        {"d": device_id, "b": backup, "x": json.dumps(deleted)})


def load_backup(conn, device_id):
    row = conn.execute(text(
        "SELECT backup, deleted, created_at FROM fw_optimize_backups WHERE device_id = :d"),
        {"d": device_id}).fetchone()
    if not row:
        return None
    return {"backup": row[0],
            "deleted": (json.loads(row[1]) if isinstance(row[1], str) else row[1]),
            "created_at": str(row[2])}
