# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

import hashlib
import ipaddress


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


def _safe_get(parts, idx):
    try:
        v = parts[idx].strip()
        return v if v != "" else None
    except Exception:
        return None


def _sha256(b: bytes):
    return hashlib.sha256(b).digest()


def parse(payload: str):
    parts = [p.strip() for p in (payload or "").split(",")]
    if len(parts) < 20:
        return None

    rule_id = _safe_get(parts, 0)
    iface = _safe_get(parts, 4)
    pf_action = (_safe_get(parts, 6) or "").lower() or None
    direction = _direction_norm(_safe_get(parts, 7))
    ipver = _safe_get(parts, 8)

    proto_name = _safe_get(parts, 16)
    proto_num = _safe_get(parts, 15)

    src_ip = _safe_get(parts, 18)
    dst_ip = _safe_get(parts, 19)
    src_port = _safe_get(parts, 20)
    dst_port = _safe_get(parts, 21)

    if pf_action == "pass":
        action = "allow"
    elif pf_action in {"block", "drop"}:
        action = "drop"
    elif pf_action == "reject":
        action = "reject"
    elif pf_action in {"rdr", "nat"}:
        action = "allow"
    else:
        action = "unknown"

    rh_material = f"opnsense|rule_id={rule_id}|iface={iface}|pf_action={pf_action}|dir={direction}|ipver={ipver}|proto={proto_name or proto_num}"
    rule_hash = _sha256(rh_material.encode("utf-8", "ignore")) if rule_id else None

    return {
        "vendor": "opnsense",
        "program": "filterlog",
        "action": action,
        "direction": direction,
        "iface_in": iface,
        "iface_out": None,
        "proto": (proto_name or proto_num),
        "src_ip": _pack_ip(src_ip) if src_ip else None,
        "src_port": _port(src_port),
        "dst_ip": _pack_ip(dst_ip) if dst_ip else None,
        "dst_port": _port(dst_port),
        "nat_src_ip": None,
        "nat_src_port": None,
        "nat_dst_ip": None,
        "nat_dst_port": None,
        "rule_hash": rule_hash,
        "rule_id": rule_id,
        "rule_name": None,
        "rule_text": None,
        "extra": {"opnsense_parts": parts, "pf_action": pf_action, "iface": iface, "direction": direction},
    }