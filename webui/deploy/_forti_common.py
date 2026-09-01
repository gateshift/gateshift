# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""
Shared FortiOS REST API helpers + parsers.

Used by both the collector (main.py: import + network strand) and the
deploy driver (deploy/fortinet.py: list_target_* methods). Lives under
deploy/ so the driver doesn't import from main.py - the collector imports
from here.

V1 scope: IPv4, single VDOM (from device.config.fortigate.vdom, default
'root'). Bearer-token auth. SSL-verify off (lab self-signed certs).
"""

from __future__ import annotations

import ipaddress
import json

import requests


# Cap the TCP-connect phase so an unreachable/blackholed device fails in
# seconds instead of blocking the full read-timeout per call. This is the
# read path for import + discover + enrichment catalogs. Mirrors the
# _CONNECT_TIMEOUT in checkpoint.py / panw.py / fortinet.py.
_CONNECT_TIMEOUT = 5


# ── REST API ─────────────────────────────────────────────────────

def base_url_for(device: dict) -> str:
    host = device.get("mgmt_ip") or device.get("host_name")
    port = device.get("mgmt_port") or 443
    return f"https://{host}:{port}"


def vdom_for(device: dict) -> str:
    """Read VDOM from device.config.fortigate.vdom (default 'root')."""
    try:
        cfg = json.loads(device.get("config") or "{}")
        return (cfg.get("fortigate") or {}).get("vdom") or "root"
    except Exception:
        return "root"


def api_get(base_url: str, token: str, path: str, vdom: str = "root") -> dict:
    """GET FortiOS REST endpoint. count=2000 is Forti's max - defers true
    pagination to a later slice."""
    sep = "&" if "?" in path else "?"
    url = f"{base_url}{path}{sep}vdom={vdom}&count=2000"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    resp = requests.get(url, headers=headers, verify=False,
                        timeout=(_CONNECT_TIMEOUT, 30))
    resp.raise_for_status()
    return resp.json()


def fetch_hostname(base_url: str, token: str, vdom: str = "root") -> str | None:
    """Hostname comes from /api/v2/monitor/system/status results.hostname
    (verified: results is a dict, not a list, for this monitor endpoint)."""
    try:
        payload = api_get(base_url, token, "/api/v2/monitor/system/status", vdom=vdom)
        results = payload.get("results") or {}
        if isinstance(results, dict):
            return results.get("hostname") or None
    except Exception:
        return None
    return None


# ── Conversions ──────────────────────────────────────────────────

def subnet_to_cidr(subnet_str: str | None) -> str | None:
    """FortiOS 'ipmask' subnet is space-separated 'addr mask' (e.g.
    '10.0.0.0 255.255.255.0'). Convert to CIDR; return None on parse failure."""
    if not subnet_str:
        return None
    parts = subnet_str.strip().split()
    if len(parts) != 2:
        return None
    try:
        return ipaddress.IPv4Network(f"{parts[0]}/{parts[1]}", strict=False).with_prefixlen
    except Exception:
        return None


def iface_ip_to_cidr(ip_str: str | None) -> str | None:
    """Convert FortiOS iface ip-field 'addr mask' → 'addr/prefix' preserving
    host bits. Differs from subnet_to_cidr (which normalizes to the network
    address for address-objects). Returns None for unassigned IPs
    ('0.0.0.0 0.0.0.0') or parse failures."""
    if not ip_str:
        return None
    parts = ip_str.strip().split()
    if len(parts) != 2:
        return None
    addr, mask = parts
    if addr in ("0.0.0.0", "::"):
        return None
    try:
        prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
        ipaddress.IPv4Address(addr)
        return f"{addr}/{prefix}"
    except Exception:
        return None


def cidr_to_subnet(cidr: str | None) -> str | None:
    """Inverse of subnet_to_cidr - render 'a.b.c.d/N' as 'a.b.c.d MASK' for
    Forti API payloads (firewall.address subnet, router.static dst). Returns
    None on parse failure."""
    if not cidr:
        return None
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
        return f"{net.network_address} {net.netmask}"
    except Exception:
        return None


def iface_cidr_to_payload(cidr: str | None) -> str | None:
    """Render a host-preserving CIDR (e.g. '10.0.0.5/24') as Forti's iface
    'ip' payload 'addr mask' WITHOUT normalizing host→network. Used for
    pushing iface IPs, where host bits matter."""
    if not cidr:
        return None
    try:
        iface = ipaddress.IPv4Interface(cidr)
        return f"{iface.ip} {iface.network.netmask}"
    except Exception:
        return None


def ref_names(items) -> list[str]:
    """Extract 'name' from a FortiOS ref-list like srcaddr=[{name:'foo',...},...]."""
    if not items:
        return []
    return [x.get("name", "") for x in items if isinstance(x, dict) and x.get("name")]


def any_names(items) -> list[str]:
    """ref_names + FortiOS any-normalization: the factory objects 'all' (address) and
    'ALL' (service) ARE Forti's spelling of any - they're skipped as factory objects at
    import, so passing the literal name through would leave a DANGLING reference on any
    cross-vendor render (CP 404s [all], PAN-OS rejects 'all'). A list containing the
    any-object collapses to ['any'] (the any makes siblings redundant)."""
    names = ref_names(items)
    if not names:
        return ["any"]
    if any(n in ("all", "ALL") for n in names):
        return ["any"]
    return names


# ── Parsers (used by collector + driver list_target_*) ───────────

def parse_rules(payload: dict) -> list[dict]:
    """Parse FortiOS firewall policy entries into agnostic rule dicts."""
    rules: list[dict] = []
    for i, e in enumerate(payload.get("results") or []):
        raw_extras: dict = {}
        dropped: list[str] = []

        # Phase 2 (User/Groups) Option C: Forti splits identity refs into
        # two policy fields - users[] and groups[] - so kind is trivially
        # exact. Map to agnostic source_identities [{name, kind}].
        identities: list[dict] = []
        for u in (ref_names(e.get("users")) or []):
            if u:
                identities.append({"name": u, "kind": "user"})
        for g in (ref_names(e.get("groups")) or []):
            if g:
                identities.append({"name": g, "kind": "group"})
        rule_dict_identities = identities or None

        # Phase 1b: the Forti schedule ref on the rule moves into its own
        # column. Forti's "always" is the semantic default and NULL means
        # the same - store NULL for "always" so rules_query COALESCE
        # matches NULL = "always". raw_extras["schedule"] stays in
        # addition for the Phase-B promoter (lifting old imports).
        schedule = (e.get("schedule") or "").strip()
        forti_rule_schedule = None
        if schedule and schedule.lower() != "always":
            raw_extras["schedule"] = schedule
            forti_rule_schedule = schedule

        apps = ref_names(e.get("application-list"))
        if apps:
            raw_extras["application_ctrl"] = apps
            dropped.append("security_profile_individual")
        for prof_field in ("av-profile", "webfilter-profile", "ips-sensor",
                           "dnsfilter-profile", "ssl-ssh-profile"):
            v = (e.get(prof_field) or "").strip()
            if v:
                raw_extras.setdefault("security_profile_individual", {})[prof_field] = v
                if "security_profile_individual" not in dropped:
                    dropped.append("security_profile_individual")

        logtraffic = (e.get("logtraffic") or "").strip().lower()
        if logtraffic and logtraffic != "disable":
            raw_extras["log_setting"] = logtraffic
            dropped.append("log_setting")

        # Phase-B roundtrip slots - FortiOS reports these as "enable"/"disable"
        # strings. Stored separately from log_setting so the promoter can map
        # them 1:1 onto fw_rule_log_overrides.{log_start, capture_packet}.
        logtraffic_start = (e.get("logtraffic-start") or "").strip().lower()
        if logtraffic_start == "enable":
            raw_extras["logtraffic_start"] = True
            if "log_setting" not in dropped:
                dropped.append("log_setting")
        capture_packet = (e.get("capture-packet") or "").strip().lower()
        if capture_packet == "enable":
            raw_extras["capture_packet"] = True
            if "log_setting" not in dropped:
                dropped.append("log_setting")

        if (e.get("nat") or "").strip().lower() == "enable":
            raw_extras["policy_nat"] = True
            dropped.append("policy_nat")
            # Pool-based SNAT enriches the boolean with pool refs. When
            # ippool=disable (default), Forti hides src behind the outbound
            # iface IP - consumed by the Phase-B promoter to choose
            # trans_src_type=interface-address vs dynamic-ip-and-port.
            if (e.get("ippool") or "").strip().lower() == "enable":
                pool_refs = ref_names(e.get("poolname"))
                if pool_refs:
                    raw_extras["policy_nat_ippool"] = pool_refs
            # Phase-E policy-NAT flags - pass through to the synth-SNAT
            # marker so the renderer can re-emit them on push and the
            # Enrichment > NAT UI surfaces the source-intent.
            if (e.get("fixedport") or "").strip().lower() == "enable":
                raw_extras["policy_nat_fixedport"] = True
            if (e.get("natoutbound") or "").strip().lower() == "enable":
                raw_extras["policy_nat_outbound"] = True

        action_raw = (e.get("action") or "").strip().lower()
        if action_raw == "ipsec":
            raw_extras["vpn_action"] = "ipsec"
            dropped.append("vpn_action")
            action_raw = "deny"

        # FortiOS exposes srcaddr-negate / dstaddr-negate / service-negate as
        # "enable"/"disable" strings (V0 lab-probe). First-class on the rule-dict
        # so fw_imported_rules.negate_* columns capture them; downstream
        # COALESCEs against fw_rule_negate_overrides per project_rule_negation_plan.
        negate_src_flag = 1 if (e.get("srcaddr-negate") or "").strip().lower() == "enable" else 0
        negate_dst_flag = 1 if (e.get("dstaddr-negate") or "").strip().lower() == "enable" else 0
        negate_svc_flag = 1 if (e.get("service-negate") or "").strip().lower() == "enable" else 0

        rules.append({
            "rule_name":      e.get("name") or f"policy-{e.get('policyid', i)}",
            "seq_num":        i,
            "action":         action_raw,
            "src_zones":      ref_names(e.get("srcintf")) or ["any"],
            "dst_zones":      ref_names(e.get("dstintf")) or ["any"],
            "sources":        any_names(e.get("srcaddr")),
            "destinations":   any_names(e.get("dstaddr")),
            "services":       any_names(e.get("service")),
            "applications":   [],
            "description":    e.get("comments") or "",
            "disabled":       1 if (e.get("status") or "").lower() == "disable" else 0,
            "tags":           [],
            "negate_source":      negate_src_flag,
            "negate_destination": negate_dst_flag,
            "negate_service":     negate_svc_flag,
            "schedule":       forti_rule_schedule,
            "source_identities": rule_dict_identities,
            "raw_extras":     raw_extras or None,
            "dropped_inputs": dropped,
        })
    return rules


# ── Schedule cross-vendor LCD intervals helpers (Phase 2) ────────────
# Mirrored locally to keep _forti_common.py import-light (webui/main.py
# imports from here, not the other way around). Kept lockstep with
# webui/main.py:_derive_schedule_intervals semantics.

_FORTI_WEEKDAY_CANON = {
    "sunday": "Sun", "monday": "Mon", "tuesday": "Tue", "wednesday": "Wed",
    "thursday": "Thu", "friday": "Fri", "saturday": "Sat",
}


def _forti_to_iso_dt(s: str) -> str:
    """FortiOS onetime-schedule datetime → ISO 'YYYY-MM-DD HH:MM'.

    FortiOS formats onetime start/end as 'HH:MM YYYY/MM/DD' - TIME first. We
    normalize to date-first ISO (sortable; what CP add-time / PA expect). The
    old impl only swapped '/'→'-' and kept FortiOS's order, yielding
    'HH:MM YYYY-MM-DD' → CP add-time rejected it as malformed. Tolerates
    already-date-first input, a single token, or empty. Single source of the
    FortiOS datetime-order normalization (main._sched_forti_dt_to_iso delegates
    here)."""
    s = (s or "").strip().replace("/", "-")
    if not s:
        return ""
    parts = s.split()
    if len(parts) == 2 and ":" in parts[0] and "-" in parts[1]:
        # time-first (FortiOS native) → swap to date-first
        return f"{parts[1]} {parts[0]}"
    return s


def parse_schedules_recurring(payload: dict) -> list[dict]:
    """Parse FortiOS firewall.schedule.recurring → schedule objects.

    Recurring schedule: list of days + start/end time (HH:MM).
    value: {forti_recurring: {day: […], start_time, end_time},
            intervals: [{kind:'weekly', weekdays, start_time, end_time}],
            forti_description?}
    """
    out = []
    for e in payload.get("results") or []:
        name = (e.get("name") or "").strip()
        if not name:
            continue
        day = e.get("day") or ""
        start = (e.get("start") or "").strip()
        end = (e.get("end") or "").strip()
        if not start and not end:
            continue
        days = [d.strip() for d in str(day).split() if d.strip()] if day else []
        val = {"forti_recurring": {
            "day":        days,
            "start_time": start,
            "end_time":   end,
        }}
        # Phase 2: LCD intervals slot for cross-vendor renderers.
        val["intervals"] = [{
            "kind": "weekly",
            "weekdays": [_FORTI_WEEKDAY_CANON.get(d.lower(), d) for d in days],
            "start_time": start,
            "end_time":   end,
        }]
        desc = (e.get("comment") or "").strip()
        if desc:
            val["forti_description"] = desc
        out.append({"obj_type": "schedule", "name": name, "value": val})
    return out


def parse_schedules_onetime(payload: dict) -> list[dict]:
    """Parse FortiOS firewall.schedule.onetime → schedule objects.

    Onetime schedule: single start/end datetime (YYYY/MM/DD HH:MM).
    value: {forti_onetime: {start, end},
            intervals: [{kind:'onetime', start_datetime, end_datetime}],
            forti_description?}
    """
    out = []
    for e in payload.get("results") or []:
        name = (e.get("name") or "").strip()
        if not name:
            continue
        start = (e.get("start") or "").strip()
        end = (e.get("end") or "").strip()
        if not start and not end:
            continue
        val = {"forti_onetime": {"start": start, "end": end}}
        # Phase 2: LCD intervals slot for cross-vendor renderers.
        val["intervals"] = [{
            "kind": "onetime",
            "start_datetime": _forti_to_iso_dt(start),
            "end_datetime":   _forti_to_iso_dt(end),
        }]
        desc = (e.get("comment") or "").strip()
        if desc:
            val["forti_description"] = desc
        out.append({"obj_type": "schedule", "name": name, "value": val})
    return out


def parse_schedules_group(payload: dict) -> list[dict]:
    """Parse FortiOS firewall.schedule.group → schedule objects (group).
    value: {forti_group: [member_names],
            intervals: [{kind:'group', members}],
            forti_description?}
    """
    out = []
    for e in payload.get("results") or []:
        name = (e.get("name") or "").strip()
        if not name:
            continue
        members = ref_names(e.get("member"))
        if not members:
            continue
        val = {"forti_group": members}
        # Phase 2: LCD intervals slot for cross-vendor renderers.
        val["intervals"] = [{
            "kind": "group",
            "members": list(members),
        }]
        desc = (e.get("comment") or "").strip()
        if desc:
            val["forti_description"] = desc
        out.append({"obj_type": "schedule", "name": name, "value": val})
    return out


def parse_url_categories(payload: dict) -> list[dict]:
    """Parse FortiOS webfilter/urlfilter → fw_imported_objects.

    Forti's URL Filter table is the closest semantic match to PA's
    Custom URL Category - a list of URL patterns with type + action.
    Structurally richer (per-entry action) than PA, but the core
    pattern-list semantics are the same.

    Value slots (forti_-prefixed per
    feedback_vendor_properties_schema_driven):
      forti_entries  list[{url, type, action}] - type: simple/regex/wildcard
                     action: exempt/block/allow/monitor (default: block)
      forti_description  str (from 'comment')

    Plan: project_phase_1_schedule_urlcustom_active_plan (Phase 1a).
    """
    objects: list[dict] = []
    for e in payload.get("results") or []:
        name = e.get("name") or ""
        if not name:
            continue
        entries = []
        for ent in e.get("entries") or []:
            url = (ent.get("url") or "").strip()
            if not url:
                continue
            entries.append({
                "url":    url,
                "type":   (ent.get("type") or "simple").lower(),
                "action": (ent.get("action") or "block").lower(),
            })
        if not entries:
            # Empty URL-filter - skip
            continue
        val: dict = {"forti_entries": entries}
        desc = (e.get("comment") or "").strip()
        if desc:
            val["forti_description"] = desc
        objects.append({"obj_type": "url_category", "name": name, "value": val})
    return objects


def parse_addresses(payload: dict) -> tuple[list[dict], dict]:
    """Parse FortiOS firewall/address entries → fw_imported_objects.

    Supported: ipmask, iprange, fqdn. Others → drops['address_unsupported'].
    """
    objects: list[dict] = []
    drops: list[str] = []
    for e in payload.get("results") or []:
        name = e.get("name") or ""
        if not name:
            continue
        atype = (e.get("type") or "ipmask").lower()
        desc = e.get("comment") or ""
        if atype == "ipmask":
            cidr = subnet_to_cidr(e.get("subnet"))
            if not cidr:
                drops.append(name)
                continue
            val = {"type": "ip-netmask", "value": cidr, "description": desc}
        elif atype == "iprange":
            start = (e.get("start-ip") or "").strip()
            end = (e.get("end-ip") or "").strip()
            if not start or not end:
                drops.append(name)
                continue
            val = {"type": "ip-range", "value": f"{start}-{end}", "description": desc}
        elif atype == "fqdn":
            fqdn = (e.get("fqdn") or "").strip()
            if not fqdn:
                drops.append(name)
                continue
            val = {"type": "fqdn", "value": fqdn, "description": desc}
        else:
            drops.append(name)
            continue
        objects.append({"obj_type": "address", "name": name, "value": val})
    return objects, {"address_unsupported": drops} if drops else {}


def parse_address_groups(payload: dict) -> list[dict]:
    """Parse FortiOS firewall/addrgrp → fw_imported_objects (address_group).
    All members retained verbatim (renderer-side normalization rule)."""
    objects: list[dict] = []
    for e in payload.get("results") or []:
        name = e.get("name") or ""
        if not name:
            continue
        members = ref_names(e.get("member"))
        val = {
            "type": "static",
            "members": members,
            "description": e.get("comment") or "",
        }
        objects.append({"obj_type": "address_group", "name": name, "value": val})
    return objects


# ── FortiGuard factory address objects ────────────────────────────────────
# FortiOS ships a set of default "factory" address objects and groups (wildcard
# FQDNs for well-known SaaS, the 'all'/'none' sentinels, a few named defaults).
# They are Fortinet's, not the customer's policy - and the wildcard FQDNs can't
# even be represented on other vendors (PAN-OS rejects a '*' in an FQDN object).
# An import drops them from the migration set (reported), so the target gets the
# customer's config, not the vendor's shipped cruft. Detection is best-effort by
# VALUE (reliable: wildcard FQDN) + NAME, because /firewall/address exposes no
# read-only flag (q_origin_key just mirrors the name). Extend the name list as
# real-world cases surface - the wildcard-value rule already catches the bulk.
_FORTI_FACTORY_ADDR_NAMES = frozenset({
    "swscan.apple.com", "firmware.apple.com", "autoupdate.opera.com",
    "google-play", "Gotomeeting", "adobe", "Adobe Login",
})


def is_factory_address(name: str, value: dict | None) -> bool:
    """True for a FortiGuard-shipped factory address object (see note above)."""
    n = (name or "").strip()
    if n.lower() in ("all", "none"):
        return True
    v = value or {}
    if v.get("type") == "fqdn" and "*" in (v.get("value") or ""):
        return True
    return n in _FORTI_FACTORY_ADDR_NAMES


def filter_factory_objects(objects: list[dict], drops: dict) -> tuple[int, int]:
    """Drop FortiGuard factory address objects from `objects`, prune them from
    every address-group's member list, and drop groups left with no members
    (iterated, so a group made only of factory groups also goes). Mutates
    `objects`/`drops` in place; records dropped names under 'address_factory'
    and 'group_factory'. Returns (n_addresses, n_groups) dropped.

    Rule references left dangling by a dropped object are pruned render-side by
    the integrity layer (prune_refs) and reported there - this only trims the
    object catalog, so nothing depends on import order."""
    factory_addr = {o["name"] for o in objects
                    if o.get("obj_type") == "address"
                    and is_factory_address(o.get("name"), o.get("value"))}
    result = [o for o in objects if not (
        o.get("obj_type") == "address" and o.get("name") in factory_addr)]

    removed = set(factory_addr)          # names no longer available as members
    dropped_groups: set[str] = set()
    while True:                          # fixpoint - handles nested factory groups
        again = False
        for o in result:
            if o.get("obj_type") != "address_group":
                continue
            val = o.get("value") or {}
            mem = val.get("members") or []
            new_mem = [m for m in mem if m not in removed]
            if len(new_mem) != len(mem):
                val["members"] = new_mem
            if not new_mem and o.get("name") not in dropped_groups:
                dropped_groups.add(o["name"])
                removed.add(o["name"])
                again = True
        if not again:
            break
    result = [o for o in result if not (
        o.get("obj_type") == "address_group" and o.get("name") in dropped_groups)]
    objects[:] = result

    if factory_addr:
        drops.setdefault("address_factory", []).extend(sorted(factory_addr))
    if dropped_groups:
        drops.setdefault("group_factory", []).extend(sorted(dropped_groups))
    return len(factory_addr), len(dropped_groups)


def parse_services(payload: dict, predefined: bool = False) -> tuple[list[dict], dict]:
    """Parse FortiOS firewall.service/custom (or /predefined) → service objects.

    A Forti service can carry multiple proto-portrange families at once
    (TCP/UDP/SCTP combined). Raw structure kept in value-JSON; driver fans
    out at push time. Single-family → collapse to (proto, port) for the
    fw_service_objects upsert.
    """
    objects: list[dict] = []
    drops: list[str] = []
    for e in payload.get("results") or []:
        name = e.get("name") or ""
        if not name:
            continue
        proto_raw = (e.get("protocol") or "").upper()
        val: dict = {"description": e.get("comment") or ""}
        if predefined:
            val["predefined"] = True

        # FortiOS port ranges may carry a SOURCE-port suffix:
        # 'dst:src' (e.g. RLOGIN '513:512-1023'). Every other vendor models
        # source-ports separately, so split here rather than leaking the
        # colon syntax into the agnostic value (QA finding: PAN-OS rejected
        # '<port>513:512-1023</port>' outright).
        def _split_src(spec: str) -> tuple[str, str]:
            dst_parts, src_parts = [], []
            for tok in (spec or "").split():
                d, sep, sp = tok.partition(":")
                dst_parts.append(d)
                if sep and sp:
                    src_parts.append(sp)
            return " ".join(dst_parts), " ".join(src_parts)

        tcp_ports, tcp_src = _split_src((e.get("tcp-portrange") or "").strip())
        udp_ports, udp_src = _split_src((e.get("udp-portrange") or "").strip())
        sctp_ports, sctp_src = _split_src((e.get("sctp-portrange") or "").strip())
        _src_ports = " ".join(x for x in (tcp_src, udp_src, sctp_src) if x)

        if "TCP" in proto_raw or "UDP" in proto_raw or "SCTP" in proto_raw:
            if tcp_ports:
                val["tcp_portrange"] = tcp_ports
            if udp_ports:
                val["udp_portrange"] = udp_ports
            if sctp_ports:
                val["sctp_portrange"] = sctp_ports
            if "tcp_portrange" not in val and "udp_portrange" not in val and "sctp_portrange" not in val:
                drops.append(name)
                continue
            if _src_ports:
                val["source_port"] = _src_ports
            keys_present = [k for k in ("tcp_portrange", "udp_portrange", "sctp_portrange") if k in val]
            if len(keys_present) == 1:
                k = keys_present[0]
                val["protocol"] = k.split("_", 1)[0]
                val["port"] = val[k]
        elif proto_raw == "ICMP":
            val["protocol"] = "icmp"
            t = e.get("icmptype")
            c = e.get("icmpcode")
            if t is not None:
                val["icmp_type"] = t
            if c is not None:
                val["icmp_code"] = c
        elif proto_raw == "ICMP6":
            val["protocol"] = "icmpv6"
            t = e.get("icmptype")
            if t is not None:
                val["icmp_type"] = t
        elif proto_raw == "IP":
            val["protocol"] = "ip"
            pn = e.get("protocol-number")
            if pn is not None:
                val["ip_protocol"] = pn
        else:
            drops.append(name)
            continue
        objects.append({"obj_type": "service", "name": name, "value": val})
    return objects, ({"service_unsupported": drops} if drops else {})


def parse_service_groups(payload: dict) -> list[dict]:
    """Parse FortiOS firewall.service/group → service_group objects."""
    objects: list[dict] = []
    for e in payload.get("results") or []:
        name = e.get("name") or ""
        if not name:
            continue
        members = ref_names(e.get("member"))
        val = {
            "members": members,
            "description": e.get("comment") or "",
        }
        objects.append({"obj_type": "service_group", "name": name, "value": val})
    return objects


def parse_nat_vips(payload: dict) -> tuple[list[dict], dict[str, list[str]]]:
    """Parse FortiOS firewall/vip → fw_imported_objects obj_type='nat_vip'.

    V1 scope: type='static-nat' only. Other types (dns-translation, fqdn,
    load-balance, server-load-balance, …) land in drops['vip_unsupported'].

    Returns ([{"obj_type": "nat_vip", "name", "value": {...}}, ...], drops).
    `value` mirrors the Forti shape compactly so the renderer (Phase B4) can
    rebuild the push payload without re-querying the source.
    """
    objects: list[dict] = []
    drops: dict[str, list[str]] = {}
    for e in payload.get("results") or []:
        name = e.get("name") or ""
        if not name:
            continue
        vip_type = (e.get("type") or "static-nat").strip().lower()
        if vip_type != "static-nat":
            drops.setdefault("vip_unsupported", []).append(f"{name}({vip_type})")
            continue
        mapped = e.get("mappedip") or []
        # Forti returns mappedip as a list of {"range": "1.2.3.4"} entries.
        # V1 uses the first entry verbatim; >1 entries fold into a range.
        mapped_ips = [m.get("range") for m in mapped if m.get("range")]
        val = {
            "ext_ip":       (e.get("extip") or "").strip() or None,
            "mapped_ips":   mapped_ips,
            "ext_intf":     (e.get("extintf") or "").strip() or None,
            "portforward":  (e.get("portforward") or "").strip().lower() == "enable",
            "protocol":     (e.get("protocol") or "").strip().lower() or None,
            "ext_port":     (e.get("extport") or "").strip() or None,
            "mapped_port":  (e.get("mappedport") or "").strip() or None,
            "description":  (e.get("comment") or "").strip() or None,
        }
        objects.append({"obj_type": "nat_vip", "name": name, "value": val})
    return objects, drops


def parse_nat_ippools(payload: dict) -> tuple[list[dict], dict[str, list[str]]]:
    """Parse FortiOS firewall/ippool → fw_imported_objects obj_type='nat_ippool'.

    V1 scope: type='overload' (PAT/many-to-one, the FortiOS default). Other
    types (one-to-one, fixed-port-range, port-block-allocation) land in
    drops['ippool_unsupported'].
    """
    objects: list[dict] = []
    drops: dict[str, list[str]] = {}
    for e in payload.get("results") or []:
        name = e.get("name") or ""
        if not name:
            continue
        pool_type = (e.get("type") or "overload").strip().lower()
        if pool_type != "overload":
            drops.setdefault("ippool_unsupported", []).append(f"{name}({pool_type})")
            continue
        val = {
            "pool_type":    pool_type,
            "start_ip":     (e.get("startip") or "").strip() or None,
            "end_ip":       (e.get("endip") or "").strip() or None,
            "description":  (e.get("comments") or "").strip() or None,
        }
        objects.append({"obj_type": "nat_ippool", "name": name, "value": val})
    return objects, drops


def parse_central_snat_rules(payload: dict) -> list[dict]:
    """Parse FortiOS firewall/central-snat-map → fw_nat_rules list.

    Returns nat-rule dicts in the same shape as _parse_panw_nat_rules /
    _parse_cp_nat_rules - all SNAT type. Each rule references an
    ippool-name (string) in trans_src when nat-ippool is set; otherwise
    trans_src is NULL and trans_src_type=interface-address (PAT to
    outbound iface IP).
    """
    rules: list[dict] = []
    for i, e in enumerate(payload.get("results") or []):
        # Forti emits 'disable' as the nat-flag for explicit no-NAT rows;
        # we still capture them so the user sees source intent - they're
        # marked disabled instead of dropped.
        nat_state = (e.get("nat") or "").strip().lower()
        pool_refs = ref_names(e.get("nat-ippool"))
        if pool_refs:
            trans_src = pool_refs[0]
            trans_type = "dynamic-ip-and-port"
        else:
            trans_src = None
            trans_type = "interface-address"
        # central-snat-map carries no negate fields (schema-verified
        # 2026-06-03). Negate flags stay 0 on import.
        rules.append({
            "position":        e.get("policyid", i),
            "name":            f"central-snat-{e.get('policyid', i)}",
            "nat_type":        "snat",
            "disabled":        1 if nat_state == "disable" else 0,
            "src_zones":       ref_names(e.get("srcintf")) or ["any"],
            "dst_zones":       ref_names(e.get("dstintf")) or ["any"],
            "interface_name":  None,
            "orig_src":        any_names(e.get("orig-addr")),
            "orig_dst":        any_names(e.get("dst-addr")),
            "orig_service":    ["any"],  # central-snat doesn't carry service refs
            "trans_src":       trans_src,
            "trans_src_type":  trans_type,
            "trans_dst":       None,
            "trans_dst_port":  None,
            "description":     e.get("comments") or "",
            "negate_source":      0,
            "negate_destination": 0,
            "negate_service":     0,
        })
    return rules


# FortiOS router/policy protocol is an IP protocol NUMBER, not a name
# (audit fund 3). Map the common ones; 0 / missing = any.
_FORTI_PROTO_NUM = {0: "any", 1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6"}


def _forti_subnet_to_cidr(s: str) -> str:
    """'10.0.0.0 255.255.255.0' → '10.0.0.0/24'. Returns input unchanged
    if it doesn't parse (e.g. already CIDR or a single host).

    FortiOS also emits a MIXED form in router/policy: 'addr/255.255.255.0'
    (slash + dotted mask), which every target rejects as a prefix - normalize
    it to a real prefix length too (QA finding, Forti→PA PBF push)."""
    s = (s or "").strip()
    if "/" in s:
        head, _, tail = s.partition("/")
        if "." in tail:                      # dotted mask after the slash
            try:
                import ipaddress as _ip
                return str(_ip.ip_network(f"{head}/{tail}", strict=False))
            except ValueError:
                return s
        return s
    if not s:
        return s
    parts = s.split()
    if len(parts) == 2:
        try:
            import ipaddress
            net = ipaddress.ip_network(f"{parts[0]}/{parts[1]}", strict=False)
            return str(net)
        except Exception:
            return s
    return s


def _cidr_to_forti_subnet(cidr: str) -> str:
    """'192.0.2.0/24' → '192.0.2.0 255.255.255.0' (FortiOS ip-netmask form).
    Returns input unchanged if it doesn't parse (e.g. already 'ip mask')."""
    s = (cidr or "").strip()
    if not s:
        return ""
    try:
        net = ipaddress.ip_network(s, strict=False)
        return f"{net.network_address} {net.netmask}"
    except ValueError:
        return s


def parse_policy_routes(payload: dict) -> list[dict]:
    """Parse FortiOS router/policy → agnostic PBF-rule dicts (Phase 3).

    Forti policy-routes match on input-device (interface, no zones),
    src/dst as inline-subnet OR srcaddr/dstaddr object-refs, protocol as
    an IP number + start/end-port (range). action=permit → forward via
    output-device+gateway; action=deny → no-pbf (stop policy routing).
    """
    rules: list[dict] = []
    for i, e in enumerate(payload.get("results") or []):
        seq = e.get("seq-num", i)
        # ── Ingress: input-device (interface) ──
        ingress = [{"name": n, "type": "interface"}
                   for n in ref_names(e.get("input-device")) if n]

        # ── Source/Dest: prefer object-refs, fall back to inline subnet ──
        def _addr(obj_key, inline_key):
            objs = ref_names(e.get(obj_key))
            if objs:
                return objs
            inline = []
            for m in (e.get(inline_key) or []):
                sub = m.get("subnet") if isinstance(m, dict) else None
                if sub:
                    inline.append(_forti_subnet_to_cidr(sub))
            return inline or ["any"]
        sources      = _addr("srcaddr", "src")
        destinations = _addr("dstaddr", "dst")

        # ── Service: protocol number → name, + port-range (fund J) ──
        proto_num = e.get("protocol")
        proto = _FORTI_PROTO_NUM.get(proto_num if isinstance(proto_num, int) else 0, str(proto_num))
        sp, ep = e.get("start-port"), e.get("end-port")
        if proto in ("any", None) or sp in (None, 0):
            services = ["any"]
        elif ep and ep != sp:
            services = [f"{proto}/{sp}-{ep}"]
        else:
            services = [f"{proto}/{sp}"]

        # ── Action ──
        act = (e.get("action") or "permit").strip().lower()
        if act == "deny":
            action, egress, gw = "no-pbf", None, None
        else:
            action = "forward"
            egress = (e.get("output-device") or "").strip() or None
            gw = (e.get("gateway") or "").strip() or None
            if gw in ("0.0.0.0", ""):
                gw = None

        raw_extras: dict = {}
        dropped: list[str] = []
        isvc = e.get("internet-service")
        if isvc in ("enable", 1, True):
            raw_extras["forti_internet_service"] = True
            dropped.append("pbf_internet_service")  # SaaS-match, out of scope

        rules.append({
            "name":             f"policy-route-{seq}",
            "position":         seq,
            "ingress":          ingress,
            "sources":          sources,
            "destinations":     destinations,
            "services":         services,
            "action":           action,
            "egress_interface": egress,
            "next_hop":         gw,
            "disabled":         1 if (e.get("status") or "").lower() == "disable" else 0,
            "raw_extras":       raw_extras or None,
            "dropped_inputs":   dropped,
        })
    return rules


_FORTI_PROTO_NAME = {"any": 0, "icmp": 1, "tcp": 6, "udp": 17, "icmpv6": 58}


def parse_ssl_profiles(payload: dict) -> tuple[list[dict], dict[str, list[str]]]:
    """Parse FortiOS firewall/ssl-ssh-profile → fw_imported_objects
    obj_type='ssl_profile' (Phase 5). A Forti decryption "profile" is a reusable
    object referenced per security policy - NOT a per-traffic rule - so it lands
    as an object (like nat_vip/nat_ippool), not in fw_ssl_rules.

    V1 captures the HTTPS block + CA/server-cert REFERENCES (names only - certs
    are ref-only, never keys) + the ssl-exempt list. Non-HTTPS protocol blocks
    (ftps/imaps/pop3s/smtps/ssh/…) are kept compactly in value['other_protocols']
    for a faithful same-vendor round-trip; V1 push focuses on https.

    Returns ([{"obj_type": "ssl_profile", "name", "value": {...}}, ...], drops).
    """
    objects: list[dict] = []
    drops: dict[str, list[str]] = {}
    _PROTOS = ("ftps", "imaps", "pop3s", "smtps", "ssh", "ssl", "dot",
               "mapi-over-https", "rpc-over-https")
    for e in payload.get("results") or []:
        name = e.get("name") or ""
        if not name:
            continue
        https = e.get("https") or {}
        other = {p: e[p] for p in _PROTOS
                 if isinstance(e.get(p), dict)
                 and (e[p].get("status") not in (None, "disable"))}
        val = {
            "caname":           e.get("caname"),
            "untrusted_caname": e.get("untrusted-caname"),
            "server_cert":      e.get("server-cert"),
            "server_cert_mode": e.get("server-cert-mode"),
            "use_ssl_server":   e.get("use-ssl-server"),
            "comment":          (e.get("comment") or "").strip() or None,
            "https": {
                "status":                  https.get("status"),
                "ports":                   https.get("ports"),
                "min_allowed_ssl_version": https.get("min-allowed-ssl-version"),
                "expired_server_cert":     https.get("expired-server-cert"),
                "revoked_server_cert":     https.get("revoked-server-cert"),
                "untrusted_server_cert":   https.get("untrusted-server-cert"),
                "unsupported_ssl":         (https.get("unsupported-ssl-version")
                                            or https.get("unsupported-ssl")),
                "sni_server_cert_check":   https.get("sni-server-cert-check"),
            },
            "ssl_exempt": [
                {k: x.get(k) for k in
                 ("type", "address", "address6", "fortiguard-category",
                  "regex", "wildcard-fqdn") if x.get(k)}
                for x in (e.get("ssl-exempt") or [])
            ],
        }
        if other:
            val["other_protocols"] = sorted(other.keys())
            drops.setdefault("ssl_profile_nonhttps", []).extend(
                f"{name}:{p}" for p in sorted(other.keys()))
        objects.append({"obj_type": "ssl_profile", "name": name, "value": val})
    return objects, drops


def render_policy_routes(pbf_rules: list, dropped, resolve_subnets=None,
                         iface_map=None) -> str:
    """Render agnostic PBF-routes → FortiOS router/policy JSON (Phase 3).

    ingress must be an interface (Forti has no zones) - zone-ingress is
    dropped with a warn (audit fund G, no cross-vendor zone→iface infra).
    src/dst → the inline ``src``/``dst`` **subnet** tables (``[{"subnet":
    "a.b.c.d/N"}]``), so PBF is self-contained and carries no cross-strand
    dependency on the policy-strand address objects. (Live schema-probe
    2026-06-11: router/policy accepts the CIDR subnet form here; the earlier
    -45 "value parse error" was the space-mask shape, not the concept.)
    ``resolve_subnets(ref, rule_id) -> list[str]`` maps an agnostic address ref
    to its CIDR subnet(s) - object value, group members (flattened), range
    (CIDR-decomposed); fqdn/unresolvable yield [] (the resolver warns). A side
    whose refs ALL fail to resolve would silently widen to 'any', so the rule
    is dropped instead. service 'proto/port[-port]' → protocol number +
    start/end-port (fund 3+J). action forward → permit + output-device +
    gateway; discard/no-pbf → deny.
    """
    from .base import DroppedField

    def _subnet_table(items, rule_id):
        """(subnet_dicts, had_refs) - had_refs True when non-'any' refs existed,
        so the caller can drop a rule whose refs all resolved to nothing rather
        than emit an empty (= match-any) side."""
        had = False
        seen: set[str] = set()
        res: list[dict] = []
        for s in (items or []):
            if not s or s == "any":
                continue
            had = True
            for cidr in (resolve_subnets(s, rule_id) if resolve_subnets else []):
                if cidr and cidr not in seen:
                    seen.add(cidr)
                    res.append({"subnet": cidr})
        return res, had

    out = []
    _imap = (lambda n: (iface_map or {}).get(n, n))
    for i, p in enumerate(pbf_rules or []):
        name = p.get("name") or f"policy-route-{i+1}"
        entry: dict = {"seq-num": p.get("position", i) + 1}

        # ── Ingress: interface only ── (iface names normalized for Forti, F7/F8)
        ifaces = [_imap(ing["name"]) for ing in (p.get("ingress") or [])
                  if ing.get("type") == "interface" and ing.get("name")]
        zones = [ing["name"] for ing in (p.get("ingress") or [])
                 if ing.get("type") == "zone"]
        if zones:
            dropped.append(DroppedField(
                rule_id=name, field="pbf_ingress_zone",
                reason=f"zone-ingress {zones} can't map to a Forti interface",
                fallback="ingress narrowed to interfaces only",
            ))
        if ifaces:
            entry["input-device"] = [{"name": n} for n in ifaces]

        # ── Source/Dest as inline subnet tables (src/dst) ──
        src, src_had = _subnet_table(p.get("sources"), name)
        dst, dst_had = _subnet_table(p.get("destinations"), name)
        # A side that had refs but resolved to zero subnets (all fqdn /
        # unresolvable) would otherwise be omitted → match ANY source/dest.
        # Drop the rule instead of silently widening it.
        if (src_had and not src) or (dst_had and not dst):
            dropped.append(DroppedField(
                rule_id=name, field="policy_route",
                reason="src/dst address refs can't be represented as router/"
                       "policy subnets (fqdn/unresolvable) - rule dropped to "
                       "avoid matching all traffic",
            ))
            continue
        if src:
            entry["src"] = src
        if dst:
            entry["dst"] = dst

        # ── Service: 'proto/port[-port]' → protocol num + ports ──
        svcs = [s for s in (p.get("services") or []) if s and s != "any"]
        if svcs:
            first = svcs[0]  # Forti policy-route carries one protocol
            if "/" in first:
                proto, port = first.split("/", 1)
                entry["protocol"] = _FORTI_PROTO_NAME.get(proto.lower(), 0)
                if "-" in port:
                    sp, ep = port.split("-", 1)
                    entry["start-port"] = int(sp) if sp.isdigit() else 0
                    entry["end-port"] = int(ep) if ep.isdigit() else 0
                elif port.isdigit():
                    entry["start-port"] = int(port)
                    entry["end-port"] = int(port)
            if len(svcs) > 1:
                dropped.append(DroppedField(
                    rule_id=name, field="pbf_service",
                    reason="Forti policy-route carries one protocol; extra "
                           f"services dropped ({svcs[1:]})",
                    fallback=f"using {first}",
                ))

        # ── Action ──
        action = (p.get("action") or "forward").lower()
        if action in ("discard", "no-pbf"):
            entry["action"] = "deny"
        else:
            entry["action"] = "permit"
            egress = _imap((p.get("egress_interface") or "").strip())
            gw = (p.get("next_hop") or "").strip()
            if egress:
                entry["output-device"] = egress
            if gw:
                entry["gateway"] = gw
        entry["status"] = "disable" if p.get("disabled") else "enable"
        out.append(entry)
    return json.dumps(out)


def parse_zones_map(payload: dict) -> dict[str, str]:
    """Build reverse iface→zone-name map. FortiOS zone-entry member key is
    'interface-name', NOT 'name' - generic ref_names returns empty."""
    iface_to_zone: dict[str, str] = {}
    for z in payload.get("results") or []:
        zname = z.get("name") or ""
        if not zname:
            continue
        for m in z.get("interface") or []:
            iname = m.get("interface-name") or ""
            if iname:
                iface_to_zone[iname] = zname
    return iface_to_zone


def parse_zones_full(payload: dict) -> list[dict]:
    """Parse FortiGate system/zone payload into agnostic zone-object dicts.

    Returns [{"name", "properties": {forti_*}, "members": [iface_names]}].
    Properties carry vendor-prefixed keys so cross-vendor migrations keep
    PA-slots untouched.
    """
    zones: list[dict] = []
    for z in payload.get("results") or []:
        name = z.get("name") or ""
        if not name:
            continue
        members: list[str] = []
        for m in z.get("interface") or []:
            iname = m.get("interface-name") or ""
            if iname:
                members.append(iname)
        intrazone = (z.get("intrazone") or "").strip().lower()
        properties = {
            "forti_intrazone_block": intrazone == "deny",
            "forti_description":     (z.get("description") or "").strip() or None,
        }
        zones.append({"name": name, "properties": properties, "members": members})
    return zones


# FortiOS iface-type → Gateshift iface_type. Types not listed (vap-switch,
# hard-switch, wl-mesh, redundant, …) are skipped + drop-logged.
IFACE_TYPE_MAP = {
    "physical":  "physical",
    "vlan":      "vlan",
    "aggregate": "bond",
    "loopback":  "loopback",
    "tunnel":    "tunnel",
}


# FortiOS auto-generated / system interfaces - present on a FortiGate because
# a feature exists, NOT because an admin configured a data-plane port. They
# carry no migratable config (the feature's real config lives in its own block,
# e.g. vpn.ssl.settings) and have no equivalent on other vendors, so they're
# skipped at import (logged to the 'interface_system' drop channel → surfaced
# in the import warning). Matched by NAME, not type: ssl./l2t./naf.* are
# type=tunnel exactly like real IPSec S2S tunnels (tun-psk-*), which we keep.
#   fortilink  - Security-Fabric / FortiSwitch-FortiAP management link
#   ssl.<vdom> - SSL-VPN termination       l2t.<vdom> - L2TP termination
#   naf.<vdom> - ZTNA (Network Access)     vsys_*     - HA / inter-VDOM system
#   port_ha    - HA heartbeat
# Deliberately NOT filtered: mgmt / mgmt1 / modem - those can be real
# admin-configured OOB / dialup ports (over-filtering a real interface is worse
# than leaving a system one in). Reversible: if remote-access VPN ever enters
# scope, drop the relevant entry here.
_FORTI_SYSTEM_IFACES = {"fortilink", "port_ha"}
_FORTI_SYSTEM_IFACE_PREFIXES = ("ssl.", "l2t.", "naf.", "vsys_")


def is_forti_system_iface(name: str) -> bool:
    """True if `name` is a FortiOS auto-generated/system interface (see
    _FORTI_SYSTEM_IFACES)."""
    n = (name or "").strip().lower()
    return n in _FORTI_SYSTEM_IFACES or n.startswith(_FORTI_SYSTEM_IFACE_PREFIXES)


def parse_interfaces(payload: dict, zone_map: dict[str, str]) -> tuple[list[dict], dict[str, list[str]]]:
    """Parse system/interface entries into collector-shaped iface dicts.
    Tunnel-IFs retained as iface_type='tunnel' (they appear in policy
    srcintf/dstintf refs); unsupported types skipped + logged. FortiOS
    system/auto-generated interfaces (fortilink, ssl./l2t./naf.*, vsys_*) are
    skipped at import - see is_forti_system_iface."""
    interfaces: list[dict] = []
    drops: dict[str, list[str]] = {}
    for e in payload.get("results") or []:
        name = e.get("name") or ""
        if not name:
            continue
        # FortiOS system/auto-generated interface - skip at import (logged,
        # not silent). Checked before type-mapping: ssl./l2t./naf.* are tunnels
        # and would otherwise be kept by the "tunnels are retained" rule.
        if is_forti_system_iface(name):
            drops.setdefault("interface_system", []).append(name)
            continue
        raw_type = (e.get("type") or "").strip().lower()
        mapped = IFACE_TYPE_MAP.get(raw_type)
        if not mapped:
            drops.setdefault("interface_unsupported", []).append(name)
            continue

        ips: list[str] = []
        primary = iface_ip_to_cidr(e.get("ip"))
        if primary:
            ips.append(primary)
        for sec in e.get("secondaryip") or []:
            cidr = iface_ip_to_cidr(sec.get("ip"))
            if cidr:
                ips.append(cidr)

        members: list[str] = []
        if mapped == "bond":
            members = [m.get("interface-name") or "" for m in e.get("member") or []]
            members = [m for m in members if m]

        parent = None
        vlan_tag = None
        if mapped == "vlan":
            parent = (e.get("interface") or "").strip() or None
            try:
                vid = int(e.get("vlanid") or 0)
                if vid > 0:
                    vlan_tag = vid
            except (TypeError, ValueError):
                pass

        vrf_id = 0
        try:
            vrf_id = int(e.get("vrf") or 0)
        except (TypeError, ValueError):
            pass
        vr_name = "default" if vrf_id == 0 else f"vrf-{vrf_id}"

        role_raw = (e.get("role") or "").strip().lower()
        role = role_raw if role_raw in {"lan", "wan", "dmz", "undefined"} else None

        # FortiOS encodes DHCP-client mode as `mode: "dhcp"` on the iface.
        # Other modes (static, pppoe, etc.) leave dhcp_enabled at False;
        # the renderer treats anything but `dhcp` as static.
        dhcp_on = (e.get("mode") or "").strip().lower() == "dhcp"

        # `status` is `up` / `down` for admin state; default to `up` so an
        # imported iface without an explicit status field doesn't get
        # silently disabled.
        status = (e.get("status") or "up").strip().lower()
        enabled = status != "down"

        iface: dict = {
            "name":         name,
            "zone":         zone_map.get(name),
            "description":  (e.get("description") or "").strip() or None,
            "ips":          ips,
            "type":         mapped,
            "vr_name":      vr_name,
            "role":         role,
            "dhcp_enabled": dhcp_on,
            "enabled":      enabled,
        }
        if mapped == "bond" and members:
            iface["members"] = members
        if mapped == "vlan":
            if parent:
                iface["parent"] = parent
            if vlan_tag is not None:
                iface["vlan_tag"] = vlan_tag
        # Tunnel-IFs are intentionally kept (rules may reference them via
        # srcintf/dstintf). No "drop" log - the import warning channel is
        # reserved for things actually missing from the output.
        interfaces.append(iface)
    return interfaces, drops


def parse_routes(payload: dict, iface_names: set[str],
                 iface_vrf: dict[str, int] | None = None) -> list[dict]:
    """Parse router/static entries. dst-field is 'addr mask' or CIDR.
    Skips disabled routes; drops routes whose device-iface didn't survive
    interface parsing."""
    routes: list[dict] = []
    for e in payload.get("results") or []:
        status = (e.get("status") or "enable").lower()
        if status != "enable":
            continue
        dst_raw = (e.get("dst") or "").strip()
        if not dst_raw:
            continue
        try:
            if " " in dst_raw:
                addr, mask = dst_raw.split()
                net = ipaddress.IPv4Network(f"{addr}/{mask}", strict=False)
            else:
                net = ipaddress.IPv4Network(dst_raw, strict=False)
        except Exception:
            continue
        ip_from = int(net.network_address)
        ip_to = int(net.broadcast_address)

        iface_name = (e.get("device") or "").strip() or None
        if iface_name and iface_names and iface_name not in iface_names:
            iface_name = None
        next_hop = (e.get("gateway") or "").strip() or None
        if next_hop in ("0.0.0.0", ""):
            next_hop = None

        vrf_id = 0
        try:
            vrf_id = int(e.get("vrf") or 0)
        except (TypeError, ValueError):
            pass
        # FortiOS may report vrf 0/'unspecified' on a route whose egress
        # DEVICE sits in a VRF - the route then lives in the device's table.
        # Without this fallback two defaults (main + guest VRF) collapse
        # onto vr 'default' and the collect INSERT dies on uq_dev_prefix_vr
        # (found on the CE run of the FGT->PA leg).
        if vrf_id == 0 and iface_vrf and iface_name:
            vrf_id = int(iface_vrf.get(iface_name) or 0)
        vr_name = "default" if vrf_id == 0 else f"vrf-{vrf_id}"

        routes.append({
            "prefix":   str(net.network_address),
            "plen":     net.prefixlen,
            "ip_from":  ip_from,
            "ip_to":    ip_to,
            "iface":    iface_name,
            "next_hop": next_hop,
            "vr":       vr_name,
        })
    return routes


# ── IPSec VPN render (CE plan P3b) ───────────────────────────────────
# Canonical (PA-style) crypto tokens → FortiOS tokens. Inverse of the parse-side
# maps in main.py (_FORTI_ENC_MAP/_FORTI_HASH_MAP); defined here to avoid a
# circular import (the driver is imported by main).
_CANON_ENC_TO_FORTI = {
    "des": "des", "3des": "3des",
    "aes-128-cbc": "aes128", "aes-192-cbc": "aes192", "aes-256-cbc": "aes256",
    "aes-128-gcm": "aes128gcm", "aes-256-gcm": "aes256gcm",
    "aria-128-cbc": "aria128", "aria-192-cbc": "aria192", "aria-256-cbc": "aria256",
    "seed": "seed", "null": "null", "chacha20-poly1305": "chacha20poly1305",
}
_CANON_HASH_TO_FORTI = {
    "md5": "md5", "sha1": "sha1", "sha256": "sha256",
    "sha384": "sha384", "sha512": "sha512",
}
_FORTI_GCM_ENC = {"aes128gcm", "aes256gcm", "chacha20poly1305"}

VPN_PSK_PLACEHOLDER = "GATESHIFT-PLACEHOLDER-PSK-CHANGE-ME"


def _canon_to_forti_proposal(encs: list, hashes: list) -> str:
    """canonical encryption[] + hash[] → FortiOS proposal string. Forti lists
    explicit enc-hash pairs (cartesian product); AEAD/GCM enc carry no separate
    hash. Unknown tokens pass through verbatim."""
    fe = [_CANON_ENC_TO_FORTI.get(e, e) for e in (encs or [])]
    fh = [_CANON_HASH_TO_FORTI.get(h, h) for h in (hashes or [])]
    pairs: list[str] = []
    for e in fe:
        if e in _FORTI_GCM_ENC or not fh:
            if e not in pairs:
                pairs.append(e)
        else:
            for h in fh:
                p = f"{e}-{h}"
                if p not in pairs:
                    pairs.append(p)
    return " ".join(pairs)


def _canon_dhgrp_to_forti(groups: list) -> str:
    """['group14','group5'] → '14 5' (FortiOS dhgrp = space-separated numbers)."""
    out: list[str] = []
    for g in groups or []:
        s = str(g)
        n = s[5:] if s.lower().startswith("group") else s
        if n and n not in out:
            out.append(n)
    return " ".join(out)


def _lifetime_seconds(lifetime: dict | None) -> int | None:
    """{unit,value} → seconds (FortiOS keylife is always seconds)."""
    if not lifetime:
        return None
    unit, val = lifetime.get("unit"), lifetime.get("value")
    try:
        val = int(val)
    except (TypeError, ValueError):
        return None
    return {"seconds": 1, "minutes": 60, "hours": 3600, "days": 86400}.get(unit, 1) * val


def _forti_phase1_name(name: str, seen: set) -> str:
    """One tunnel's Forti phase1-interface name: the tunnel name truncated to the
    15-char interface-name limit, deduped against `seen` (mutated)."""
    p1 = name[:15]
    if p1 in seen:
        base = p1[:13]
        i = 1
        while f"{base}{i}"[:15] in seen and i < 100:
            i += 1
        p1 = f"{base}{i}"[:15]
    seen.add(p1)
    return p1


def forti_safe_iface(name: str, itype: str | None) -> str:
    """FortiOS treats a '.' in a NON-VLAN interface name as a VLAN sub-reference
    in its zone/route datasource lookups - so e.g. a loopback 'loopback.1'
    creates fine but fails as a zone member / route device with -3 'entry not
    found'. VLANs keep their meaningful .tag; strip the dot from other types (F7)."""
    if not name or (itype or "").lower() == "vlan":
        return name
    return name.replace(".", "")


def tunnel_iface_names(vpn_tunnels: list) -> dict[str, str]:
    """Map source tunnel-interface (e.g. 'tunnel.1') → the Forti tunnel-iface name
    (= the phase1-interface name render_vpn creates). Lets zone/rule renders that
    reference a tunnel interface follow the VPN render's renaming (F8). Uses the
    SAME seen-sequence/truncation as render_vpn so the names match exactly."""
    seen: set[str] = set()
    out: dict[str, str] = {}
    for v in vpn_tunnels or []:
        if v.get("deleted"):
            continue
        name = v.get("name")
        if not name:
            continue
        p1 = _forti_phase1_name(name, seen)
        ti = v.get("tunnel_interface")
        if ti:
            out[ti] = p1
    return out


def render_vpn(vpn_tunnels: list, ike_cryptos: dict, ipsec_cryptos: dict,
               dropped) -> tuple[list[dict], list[dict]]:
    """Agnostic vpn tunnels → FortiOS (phase1-interface, phase2-interface) entry
    lists (CE plan P3b). The referenced crypto profiles are INLINED into the
    phase1/phase2 proposal (Forti has no separate crypto objects). Route-based
    (phase2 selectors = 0.0.0.0/0). The PSK is a PLACEHOLDER (operator sets the
    real secret); cert auth → authmethod=signature + certificate ref.

    ike_cryptos / ipsec_cryptos: {name: value-dict} lookups from the source."""
    from .base import DroppedField
    p1_entries: list[dict] = []
    p2_entries: list[dict] = []
    seen: set[str] = set()
    for v in vpn_tunnels or []:
        if v.get("deleted"):
            continue
        name = v.get("name")
        if not name:
            continue
        # FortiOS names the tunnel-iface after the phase1-interface → 15-char
        # interface-name limit. Truncate (+ dedup) and thread the result through
        # phase2.phase1name so the link still resolves. Shared with
        # tunnel_iface_names() so zone/rule renders translate consistently (F8).
        p1name = _forti_phase1_name(name, seen)
        if p1name != name:
            dropped.append(DroppedField(
                rule_id=name, field="name",
                reason=f"phase1-interface renamed to '{p1name}' "
                       "(FortiOS 15-char interface-name limit)"))
        ike = ike_cryptos.get(v.get("ike_crypto_profile") or "") or {}
        p1: dict = {
            "name": p1name,
            "ike-version": "2" if (v.get("ike_version") or "ikev2") != "ikev1" else "1",
            "net-device": "enable",
        }
        if v.get("local_interface"):
            p1["interface"] = v["local_interface"]
        else:
            # FortiOS phase1-interface REQUIRES a local egress interface
            # (errcode -651 "Attribute 'interface' MUST be set"). A CheckPoint
            # source is community-based and carries none, so skip the tunnel
            # with a clear, actionable warning instead of pushing an invalid
            # phase1 - the operator sets it per tunnel in the VPN tab.
            dropped.append(DroppedField(
                rule_id=name, field="interface",
                reason="FortiGate phase1 needs a local egress interface; the "
                       "source carries none (e.g. CheckPoint communities)",
                fallback="set the Local IF for this tunnel in the VPN tab"))
            continue
        ptype = v.get("peer_type") or "ip"
        peer = (v.get("peer_address") or "").strip()
        if ptype == "fqdn" and peer:
            p1["type"] = "ddns"
            p1["remotegw-ddns"] = peer
        elif ptype == "dynamic" or not peer:
            p1["type"] = "dynamic"
        else:
            p1["type"] = "static"
            p1["remote-gw"] = peer
        if (v.get("auth_type") or "psk") == "cert":
            cert_name = v.get("cert_name")
            # cert-auth needs an uploaded identity cert (CR-3) - its name is the
            # on-target ref, imported server-side before this phase1 lands.
            # Without one, signature auth can't resolve → skip phase1 + phase2.
            if not cert_name:
                dropped.append(DroppedField(
                    rule_id=name, field="certificate",
                    reason="cert-auth: upload the local identity cert (PEM + key) "
                           "in the VPN tab to migrate this tunnel"))
                continue
            p1["authmethod"] = "signature"
            p1["certificate"] = [{"name": cert_name}]
        else:
            p1["authmethod"] = "psk"
            # Per-tunnel token (vpn_hash, no secret) → injected server-side at
            # push if a PSK was set in Gateshift, else resolves to the placeholder.
            vh = v.get("vpn_hash")
            p1["psksecret"] = f"__GATESHIFT_PSK_{vh}__" if vh else VPN_PSK_PLACEHOLDER
            dropped.append(DroppedField(
                rule_id=name, field="psksecret",
                reason="PSK: a placeholder is pushed unless one is set in Gateshift "
                       "(then injected, encrypted, at push-time) - source secrets "
                       "are never migrated"))
        prop = _canon_to_forti_proposal(ike.get("encryption"), ike.get("hash"))
        if prop:
            p1["proposal"] = prop
        dh = _canon_dhgrp_to_forti(ike.get("dh_group"))
        if dh:
            p1["dhgrp"] = dh
        kl = _lifetime_seconds(ike.get("lifetime"))
        if kl:
            p1["keylife"] = kl
        if v.get("local_id"):
            p1["localid"] = v["local_id"]
        if v.get("peer_id"):
            p1["peerid"] = v["peer_id"]
        p1_entries.append(p1)

        ipsec = ipsec_cryptos.get(v.get("ipsec_crypto_profile") or "") or {}
        prop2 = _canon_to_forti_proposal(ipsec.get("encryption"), ipsec.get("auth"))
        dh2 = _canon_dhgrp_to_forti(ipsec.get("pfs_group"))
        kl2 = _lifetime_seconds(ipsec.get("lifetime"))

        # Policy-based target: one phase2-interface per traffic-selector
        # (src/dst subnet) linked to the same phase1. Route-based (no
        # selectors) → the single 0.0.0.0/0 phase2 (the prior behaviour).
        sels = v.get("traffic_selectors") or []
        pairs = [(_cidr_to_forti_subnet(s.get("local")),
                  _cidr_to_forti_subnet(s.get("remote"))) for s in sels]
        if not pairs:
            pairs = [("0.0.0.0 0.0.0.0", "0.0.0.0 0.0.0.0")]
        if any(s.get("protocol") for s in sels):
            dropped.append(DroppedField(
                rule_id=name, field="proxy-id-protocol",
                reason="phase2 selectors carry subnets only - "
                       "protocol/port narrowing dropped"))
        for idx, (src, dst) in enumerate(pairs):
            p2name = (f"{p1name}-p2-{idx + 1}" if len(pairs) > 1
                      else f"{p1name}-p2")[:35]
            p2: dict = {
                "name": p2name,
                "phase1name": p1name,
                "src-subnet": src or "0.0.0.0 0.0.0.0",
                "dst-subnet": dst or "0.0.0.0 0.0.0.0",
            }
            if prop2:
                p2["proposal"] = prop2
            if dh2:
                p2["dhgrp"] = dh2
            if kl2:
                p2["keylifeseconds"] = kl2
            p2_entries.append(p2)
    return p1_entries, p2_entries
