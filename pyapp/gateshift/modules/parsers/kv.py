# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

import re
import hashlib
import ipaddress


KV_RE = re.compile(r'(\w+)=(".*?"|\S+)')


def _pack_ip(ip: str):
    try:
        return ipaddress.ip_address(ip).packed
    except Exception:
        return None


def _port(x):
    try:
        v = int(x)
        return v if 0 <= v <= 65535 else None
    except Exception:
        return None


def _direction_norm(x: str):
    x = (x or "").lower()
    if x in {"in", "out", "forward"}:
        return x
    return "unknown"


def _sha256(b: bytes):
    return hashlib.sha256(b).digest()


def _detect_vendor(d: dict) -> str | None:
    """Detect vendor from characteristic KV field names."""
    # Fortinet: devid starts with FG/FGT, or has logid+vd fields
    devid = d.get("devid", "")
    if devid.startswith(("fg", "fgt")):
        return "fortinet"
    if "logid" in d and "vd" in d:
        return "fortinet"
    # Checkpoint: product field or origin_sic_name
    if "product" in d or "origin_sic_name" in d:
        return "checkpoint"
    return None


# Fortinet-specific action mapping (FortiOS uses accept/close/timeout/etc.)
_FORTI_ACTION = {
    "accept": "allow", "close": "allow", "timeout": "allow",
    "server-rst": "allow", "client-rst": "allow",
    "deny": "deny",
    "drop": "drop", "ip-conn": "drop",
    "reject": "reject",
}


def _forti_enrich(d: dict, result: dict):
    """Extract Fortinet-specific fields into the normalised result."""
    # Re-map action using Fortinet vocabulary
    action_raw = (d.get("action") or "").lower()
    if action_raw in _FORTI_ACTION:
        result["action"] = _FORTI_ACTION[action_raw]

    # Fortinet direction: subtype=forward/local
    subtype = (d.get("subtype") or "").lower()
    if subtype in {"forward", "local"}:
        result["direction"] = "forward"

    # NAT fields (tranip/tranport = translated source; transip/transport = translated dest)
    result["nat_src_ip"]   = _pack_ip(d["tranip"])   if d.get("tranip")   else None
    result["nat_src_port"] = _port(d.get("tranport"))
    result["nat_dst_ip"]   = _pack_ip(d["transip"])  if d.get("transip")  else None
    result["nat_dst_port"] = _port(d.get("transport"))

    # Zones: Fortinet often has srcintfrole/dstintfrole (lan/wan/dmz/undefined)
    # Use explicit zone fields first, fall back to interface roles
    if not result.get("src_zone"):
        role = (d.get("srcintfrole") or "").lower()
        if role and role != "undefined":
            result["src_zone"] = role
    if not result.get("dst_zone"):
        role = (d.get("dstintfrole") or "").lower()
        if role and role != "undefined":
            result["dst_zone"] = role

    # Application category
    if not result.get("application"):
        result["application"] = d.get("appcat")


def _checkpoint_enrich(d: dict, result: dict):
    """Extract Checkpoint-specific fields into the normalised result."""
    # Checkpoint uses src/dst instead of srcip/dstip
    if not result.get("src_ip") and d.get("src"):
        result["src_ip"] = _pack_ip(d["src"])
    if not result.get("dst_ip") and d.get("dst"):
        result["dst_ip"] = _pack_ip(d["dst"])
    # Checkpoint port field: s_port/service
    if result.get("dst_port") is None and d.get("service"):
        result["dst_port"] = _port(d["service"])
    if result.get("src_port") is None and d.get("s_port"):
        result["src_port"] = _port(d["s_port"])
    # Checkpoint interface direction
    if d.get("ifdir"):
        result["direction"] = "in" if d["ifdir"].lower() == "inbound" else "out"
    # Checkpoint rule number
    if not result.get("rule_id") and d.get("rule"):
        result["rule_id"] = d["rule"]
    if not result.get("rule_name") and d.get("rule_name"):
        result["rule_name"] = d["rule_name"]


def parse(payload: str):
    d = {}
    for k, v in KV_RE.findall(payload or ""):
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        d[k.lower()] = v

    if not d:
        return None

    vendor = _detect_vendor(d)

    action_raw = (d.get("action") or "").lower()
    if action_raw in {"allow", "accept", "pass", "permit"}:
        action = "allow"
    elif action_raw in {"deny"}:
        action = "deny"
    elif action_raw in {"drop", "block"}:
        action = "drop"
    elif action_raw in {"reject"}:
        action = "reject"
    else:
        action = "unknown"

    rule_name = d.get("policyname") or d.get("rulename")
    rule_hash = _sha256(rule_name.encode("utf-8")) if rule_name else None

    result = {
        "vendor": vendor,
        "program": None,
        "action": action,
        "direction": _direction_norm(d.get("direction")),
        "iface_in": d.get("srcintf"),
        "iface_out": d.get("dstintf"),
        "proto": d.get("proto"),
        "src_ip": _pack_ip(d.get("srcip")) if d.get("srcip") else None,
        "src_port": _port(d.get("srcport")),
        "dst_ip": _pack_ip(d.get("dstip")) if d.get("dstip") else None,
        "dst_port": _port(d.get("dstport")),
        "nat_src_ip": None,
        "nat_src_port": None,
        "nat_dst_ip": None,
        "nat_dst_port": None,
        "rule_hash": rule_hash,
        "rule_id": d.get("policyid"),
        "rule_name": rule_name,
        "rule_text": None,
        "src_zone": d.get("srczone") or d.get("src_zone"),
        "dst_zone": d.get("dstzone") or d.get("dst_zone"),
        "application": d.get("app") or d.get("application"),
        "security_profile": d.get("profile"),
        "security_profile_group": d.get("profile-group") or d.get("profilegroup"),
        "url_category": d.get("catdesc") or d.get("cat"),
        "extra": d,
    }

    # Vendor-specific enrichment
    if vendor == "fortinet":
        _forti_enrich(d, result)
    elif vendor == "checkpoint":
        _checkpoint_enrich(d, result)

    return result
