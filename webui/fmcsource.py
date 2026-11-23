# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
"""Cisco Secure Firewall Management Center as a migration source. The Community Edition reads the whole manager
and fans it into scope Devices through the scope rails (scopepersist):

- a `domain` scope per domain (role root for Global, policy below) holding
  the domain's object dictionary,
- an `access-policy` scope per access policy (role rulebase) holding the
  policy's rulebase as the FTD evaluates it: the prefilter's FASTPATH and
  BLOCK rules at the head (D7), the base policies' Mandatory rules, its own
  rules, the base policies' Default rules (D5, composed at import because
  generate reads a scope's own rules), the default action as the final
  rule, plus every object those rules reference,
- a `device` scope per standalone FTD, HA pair or cluster (role network)
  holding interfaces, zones, virtual routers and routes, and the NAT rules
  of the NAT policy assigned to it (D8: NAT follows the device), plus the
  objects the NAT references.

The access-policy scope's members are the devices it is assigned to, so
the composite pairs it with a device scope the way a Panorama device-group
pairs with its template stack. Literal addresses and ports in rules become
synthetic objects named like the ASA parser's (`_inline_H_`, `_inline_N_`,
`_inline_R_`, `_inline_S_`). Predefined objects are imported only when
something references them (D10). What is left out is declared: MONITOR
rules, ANALYZE and tunnel prefilter rules, VLAN tags, security group tags,
dynamic objects, URL conditions, application filters, the inspection
policies, bridge groups, redundant and switch-port interfaces, overrides.
"""
from __future__ import annotations

import ipaddress
import json
import re

from deploy import _fmc_common as _fmc
from deploy import _ftd_common as _ftd

SPEC_DATE = "2026-11-04"            # the vendor documentation the reader follows
SCOPE_ROLE = {"domain": "policy", "access-policy": "rulebase", "device": "network"}
_ANY_NAMES = {"any", "any-ipv4", "any-ipv6"}
_ACTIONS = {"ALLOW": "allow", "TRUST": "allow", "BLOCK": "deny", "BLOCK_INTERACTIVE": "deny",
            "BLOCK_RESET": "reject", "BLOCK_RESET_INTERACTIVE": "reject"}
_DEFAULT_ACTIONS = {"BLOCK": "deny", "TRUST": "allow", "PERMIT": "allow", "NETWORK_DISCOVERY": "allow"}
_WEEKDAY = {"SUN": "sunday", "MON": "monday", "TUE": "tuesday", "WED": "wednesday", "THU": "thursday",
            "FRI": "friday", "SAT": "saturday"}
_OVERRIDE_PATH = {"Host": "hosts", "Network": "networks", "Range": "ranges", "FQDN": "fqdns",
                  "NetworkGroup": "networkgroups", "ProtocolPortObject": "protocolportobjects",
                  "ICMPV4Object": "icmpv4objects", "ICMPV6Object": "icmpv6objects",
                  "PortObjectGroup": "portobjectgroups", "Url": "urls", "UrlGroup": "urlgroups"}


class FmcImportError(RuntimeError):
    """The sentence the import shows. Never carries a credential."""


def fmc_cfg(device: dict) -> dict | None:
    """The row's `config.fmc` block, None for a row that is not a Management
    Center (the FDM path handles a plain firepower row)."""
    try:
        cfg = json.loads(device.get("config") or "{}").get("fmc")
    except Exception:
        return None
    return cfg if isinstance(cfg, dict) else None


# ── small helpers ─────────────────────────────────────────────────────────

def _name(ref) -> str | None:
    return ref.get("name") if isinstance(ref, dict) and ref.get("name") else None


def _objects(container, key: str = "objects") -> list[dict]:
    if not isinstance(container, dict):
        return []
    return [x for x in (container.get(key) or []) if isinstance(x, dict)]


def _domain_of(item: dict, default: str) -> str:
    return str(((item.get("metadata") or {}).get("domain") or {}).get("id") or default)


def _predefined(item: dict) -> bool:
    return bool(((item.get("metadata") or {}).get("readOnly") or {}).get("state"))


def _host_cidr(value: str) -> str | None:
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return None


class Drops:
    """The declared drops of one scope: channel -> names (the import log
    shows the count and a sample)."""

    def __init__(self):
        self.by_channel: dict[str, list[str]] = {}

    def add(self, channel: str, name: str) -> None:
        self.by_channel.setdefault(channel, []).append(str(name))

    def merge(self, other: "Drops") -> None:
        for k, v in other.by_channel.items():
            self.by_channel.setdefault(k, []).extend(v)

    def counts(self) -> dict:
        return {k: len(v) for k, v in self.by_channel.items()}


# ── the object dictionary of a domain ─────────────────────────────────────

class Dictionary:
    """A domain's objects in row shape, keyed by name, with what the import
    needs beside them: which are predefined, which are overridable, the
    interface groups, the zones, and the synthetic objects literals turn
    into."""

    def __init__(self):
        self.objects: dict[str, dict] = {}        # name -> {obj_type, name, value}
        self.predefined: set[str] = set()
        self.overrides: dict[str, list] = {}      # name -> [{target, value}]
        self.ifgroups: dict[str, list[dict]] = {}  # name -> interface refs
        self.zones: list[dict] = []                # the domain's security zones (raw)
        self.zone_of_iface_id: dict[str, str] = {}
        self.value_of: dict[str, str] = {}         # address name -> literal value (routes)
        self.literals: int = 0
        self.unsupported: Drops = Drops()

    def add(self, obj: dict, *, predefined: bool = False, raw_value: str | None = None) -> None:
        self.objects[obj["name"]] = obj
        if predefined:
            self.predefined.add(obj["name"])
        if raw_value is not None:
            self.value_of[obj["name"]] = raw_value

    # literals of rules, groups and NAT become objects every renderer resolves
    def literal_address(self, typ: str, value: str) -> str | None:
        value = (value or "").strip()
        if not value:
            return None
        net = _host_cidr(value)
        if net is None:
            if typ == "FQDN" or re.match(r"^[A-Za-z0-9.-]+$", value):
                name = f"_inline_F_{value}"
                if name not in self.objects:
                    self.add({"obj_type": "address", "name": name,
                              "value": {"type": "fqdn", "value": value, "description": "literal of the FMC rule"}})
                    self.literals += 1
                return name
            return None
        n = ipaddress.ip_network(net)
        single = n.prefixlen == n.max_prefixlen
        name = f"_inline_H_{n.network_address}" if single else f"_inline_N_{n.network_address}_{n.prefixlen}"
        if name not in self.objects:
            self.add({"obj_type": "address", "name": name,
                      "value": {"type": "ip-netmask", "value": str(n.network_address) if single else net,
                                "description": "literal of the FMC rule"}}, raw_value=net)
            self.literals += 1
        return name

    def port_number(self, name: str) -> str | None:
        """The one tcp/udp port a service object names, for the NAT port fields."""
        val = (self.objects.get(name) or {}).get("value")
        port = str(val.get("port") or "").strip() if isinstance(val, dict) else ""
        return port if port.isdigit() and str(val.get("protocol") or "") in ("tcp", "udp") else None

    def literal_port(self, lit: dict) -> str | None:
        t = str(lit.get("type") or "")
        if t == "PortLiteral":
            proto = _proto_name(lit.get("protocol"))
            port = str(lit.get("port") or "").strip()
            if proto in ("tcp", "udp") and port:
                name = f"_inline_S_{proto}_{port}"
                val = {"protocol": proto, "port": port, "description": "literal of the FMC rule"}
            elif proto and not port:
                name = f"_inline_S_{proto}"
                val = {"protocol": proto, "description": "literal of the FMC rule"}
            else:
                return None
        elif t in ("ICMPv4PortLiteral", "ICMPv6PortLiteral"):
            proto = "icmp" if t == "ICMPv4PortLiteral" else "icmp6"
            it = str(lit.get("icmpType") or "").strip()
            code = str(lit.get("code") or "").strip()
            name = f"_inline_S_{proto}_{it or 'any'}" + (f"_{code}" if code else "")
            val = {"protocol": proto, "description": "literal of the FMC rule"}
            if it.isdigit():
                val["icmp_type"] = int(it)
            if code.isdigit():
                val["icmp_code"] = int(code)
        else:
            return None
        if name not in self.objects:
            self.add({"obj_type": "service", "name": name, "value": val})
            self.literals += 1
        return name

    def closure(self, names) -> set[str]:
        """The names plus everything the groups among them contain."""
        out: set[str] = set()
        todo = [n for n in names if n and n not in _ANY_NAMES]
        while todo:
            n = todo.pop()
            if n in out:
                continue
            o = self.objects.get(n)
            if not o:
                continue
            out.add(n)
            if o["obj_type"] in ("address_group", "service_group"):
                todo.extend(o["value"].get("members") or [])
        return out

    def rows(self, referenced: set[str] | None = None) -> list[dict]:
        """The object rows of a scope: every custom object, and the
        predefined ones something references (D10)."""
        out = []
        for name, o in self.objects.items():
            if referenced is not None and name not in referenced:
                continue
            if referenced is None and name in self.predefined:
                continue
            row = {"obj_type": o["obj_type"], "name": name, "value": dict(o["value"]), "source_vendor_id": o.get("source_vendor_id") or name}
            if name in self.predefined:
                # information only: the renderers' `predefined` flag means "the
                # target ships this object, reference it, do not create it",
                # which holds for FortiOS factory services but not for the
                # FMC's built-ins (HTTP, HTTPS, SSH ...), whose names no other
                # vendor ships. They are materialised like custom objects.
                row["value"]["fmc_predefined"] = True
            if name in self.overrides:
                row["value"]["fmc_overrides"] = self.overrides[name]
            out.append(row)
        return out


def _proto_name(p) -> str:
    s = str(p or "").strip().upper()
    if s in ("TCP", "6"):
        return "tcp"
    if s in ("UDP", "17"):
        return "udp"
    if s in ("ICMP", "1"):
        return "icmp"
    if s in ("ICMPV6", "58"):
        return "icmp6"
    return s.lower() if s.isdigit() else s.lower()


def read_dictionary(client, uid: str, *, read_overrides: bool = True) -> Dictionary:
    d = Dictionary()
    cfg = client.cfg
    for a in client.get_all(cfg(uid, "/object/networkaddresses")):
        name, typ, val = a.get("name"), str(a.get("type") or ""), str(a.get("value") or "").strip()
        if not name:
            continue
        if name in _ANY_NAMES:
            d.predefined.add(name)
            continue
        desc = a.get("description") or ""
        if typ in ("Host", "Network"):
            obj = {"type": "ip-netmask", "value": val, "description": desc}
        elif typ == "Range":
            obj = {"type": "ip-range", "value": val, "description": desc}
        elif typ == "FQDN":
            obj = {"type": "fqdn", "value": val, "description": desc}
            if a.get("dnsResolution"):
                obj["fmc_dns_resolution"] = a["dnsResolution"]
        else:
            d.unsupported.add("address_unsupported", f"{name}({typ})")
            continue
        d.add({"obj_type": "address", "name": name, "value": obj, "source_vendor_id": a.get("id")},
              predefined=_predefined(a), raw_value=val)
        if read_overrides and a.get("overridable") and a.get("id") and typ in _OVERRIDE_PATH:
            _read_overrides(client, uid, d, name, typ, a["id"])
    for g in client.get_all(cfg(uid, "/object/networkgroups")):
        name = g.get("name")
        if not name:
            continue
        members = [n for n in (_name(o) for o in _objects(g)) if n]
        for lit in _objects(g, "literals"):
            ln = d.literal_address(str(lit.get("type") or ""), str(lit.get("value") or ""))
            if ln:
                members.append(ln)
            else:
                d.unsupported.add("group_literal_unsupported", f"{name}:{lit.get('value')}")
        d.add({"obj_type": "address_group", "name": name, "source_vendor_id": g.get("id"),
               "value": {"type": "static", "members": members, "description": g.get("description") or ""}},
              predefined=_predefined(g))
        if read_overrides and g.get("overridable") and g.get("id"):
            _read_overrides(client, uid, d, name, "NetworkGroup", g["id"])
    for p in client.get_all(cfg(uid, "/object/ports")):
        name, typ = p.get("name"), str(p.get("type") or "")
        if not name:
            continue
        desc = p.get("description") or ""
        if typ == "ProtocolPortObject":
            proto = _proto_name(p.get("protocol"))
            val = {"protocol": proto, "description": desc}
            port = str(p.get("port") or "").strip()
            if port:
                val["port"] = port
        elif typ in ("ICMPV4Object", "ICMPV6Object"):
            val = {"protocol": "icmp" if typ == "ICMPV4Object" else "icmp6", "description": desc}
            it = str(p.get("icmpType") or "").strip()
            if it.isdigit():
                val["icmp_type"] = int(it)
            elif it:
                num = _ftd._ICMP4_TYPE_NUM.get(it.upper())
                if num is not None:
                    val["icmp_type"] = num
            code = str(p.get("code") or "").strip()
            if code.isdigit():
                val["icmp_code"] = int(code)
        else:
            d.unsupported.add("service_unsupported", f"{name}({typ})")
            continue
        d.add({"obj_type": "service", "name": name, "value": val, "source_vendor_id": p.get("id")},
              predefined=_predefined(p))
        if read_overrides and p.get("overridable") and p.get("id") and typ in _OVERRIDE_PATH:
            _read_overrides(client, uid, d, name, typ, p["id"])
    for g in client.get_all(cfg(uid, "/object/portobjectgroups")):
        name = g.get("name")
        if not name:
            continue
        d.add({"obj_type": "service_group", "name": name, "source_vendor_id": g.get("id"),
               "value": {"members": [n for n in (_name(o) for o in _objects(g)) if n],
                         "description": g.get("description") or ""}}, predefined=_predefined(g))
    for t in client.get_all(cfg(uid, "/object/timeranges"), tolerate=(404,)):
        sched = _norm_timerange(t)
        if sched:
            d.add(sched, predefined=_predefined(t))
    url_of: dict[str, str] = {}
    for u in client.get_all(cfg(uid, "/object/urls"), tolerate=(404,)):
        if u.get("name") and u.get("url"):
            url_of[u["name"]] = str(u["url"])
            d.add({"obj_type": "url_category", "name": u["name"], "source_vendor_id": u.get("id"),
                   "value": {"pa_list": [str(u["url"])], "fmc_type": "url"}}, predefined=_predefined(u))
    for g in client.get_all(cfg(uid, "/object/urlgroups"), tolerate=(404,)):
        if not g.get("name"):
            continue
        urls = [url_of[n] for n in (_name(o) for o in _objects(g)) if n in url_of]
        urls += [str(x.get("url")) for x in _objects(g, "literals") if x.get("url")]
        d.add({"obj_type": "url_category", "name": g["name"], "source_vendor_id": g.get("id"),
               "value": {"pa_list": urls, "fmc_type": "url-group"}}, predefined=_predefined(g))
    for ig in client.get_all(cfg(uid, "/object/interfacegroups"), tolerate=(404,)):
        if ig.get("name"):
            d.ifgroups[ig["name"]] = [x for x in (ig.get("interfaces") or []) if isinstance(x, dict)]
    d.zones = client.get_all(cfg(uid, "/object/securityzones"), tolerate=(404,))
    for z in d.zones:
        for ref in (z.get("interfaces") or []):
            if isinstance(ref, dict) and ref.get("id") and z.get("name"):
                d.zone_of_iface_id[ref["id"]] = z["name"]
    for channel, path in (("vlan_tag_objects", "/object/vlantags"), ("dynamic_objects", "/object/dynamicobjects"),
                          ("geolocation_objects", "/object/geolocations")):
        for x in client.get_all(cfg(uid, path), tolerate=(404,)):
            if x.get("name"):
                d.unsupported.add(channel, x["name"])
    return d


def _read_overrides(client, uid: str, d: Dictionary, name: str, typ: str, oid: str) -> None:
    body = client.get_all(client.cfg(uid, f"/object/{_OVERRIDE_PATH[typ]}/{oid}/overrides"), tolerate=(404, 400))
    vals = []
    for o in body:
        ov = o.get("overrides") or {}
        tgt = _name(ov.get("target")) if isinstance(ov, dict) else None
        vals.append({"target": tgt or "?", "value": o.get("value") if o.get("value") is not None
                     else [n for n in (_name(x) for x in _objects(o)) if n]})
    if vals:
        d.overrides[name] = vals


def _norm_timerange(t: dict) -> dict | None:
    name = t.get("name")
    if not name:
        return None
    value: dict = {"fmc_effective": [t.get("effectiveStartDateTime"), t.get("effectiveEndDateTime")]}
    weekly: dict[str, list[str]] = {}
    for rec in (t.get("recurrenceList") or []):
        if not isinstance(rec, dict):
            continue
        rtype = str(rec.get("recurrenceType") or "").upper()
        start, end = rec.get("dailyStartTime") or rec.get("rangeStartTime"), rec.get("dailyEndTime") or rec.get("rangeEndTime")
        if not (start and end):
            continue
        days = [_WEEKDAY.get(str(x).upper()[:3]) for x in (rec.get("days") or [])]
        days = [x for x in days if x]
        if rtype == "DAILY_INTERVAL" and days:
            for dname in days:
                weekly.setdefault(dname, []).append(f"{start}-{end}")
        elif rtype == "DAILY_INTERVAL":
            value.setdefault("pa_recurring_daily", []).append(f"{start}-{end}")
        else:
            value.setdefault("fmc_range_recurrences", []).append(rec)
    if weekly:
        value["pa_recurring_weekly"] = weekly
    if not weekly and not value.get("pa_recurring_daily"):
        s, e = t.get("effectiveStartDateTime"), t.get("effectiveEndDateTime")
        if s and e:
            value["pa_non_recurring"] = [f"{str(s).replace('-', '/').replace('T', '@')}-{str(e).replace('-', '/').replace('T', '@')}"]
    derive = _schedule_deriver()
    if derive is not None:
        try:
            iv = derive(value)
            if iv:
                value["intervals"] = iv
        except Exception:
            pass
    return {"obj_type": "schedule", "name": name, "value": value, "source_vendor_id": t.get("id")}


_DERIVER: list = []     # [callable] once main answered, [None] when it cannot (the tests on the host)


def _schedule_deriver():
    """main._derive_schedule_intervals, looked up once: the app's module is
    heavy and absent in a bare test environment."""
    if not _DERIVER:
        try:
            from main import _derive_schedule_intervals
            _DERIVER.append(_derive_schedule_intervals)
        except Exception:
            _DERIVER.append(None)
    return _DERIVER[0]


# ── zones for the policy and NAT readers ──────────────────────────────────

class ZoneResolver:
    """Interface objects of a rule or a NAT rule to zone names: a security
    zone by its name, an interface group by the zones of its member
    interfaces (the domain's zone bindings), else the group's name with a
    declared drop."""

    def __init__(self, d: Dictionary):
        self.d = d

    def zones(self, refs: list[dict], drops: Drops, where: str) -> list[str]:
        out: list[str] = []
        for r in refs:
            n, t = _name(r), str(r.get("type") or "")
            if not n:
                continue
            if t == "InterfaceGroup" or n in self.d.ifgroups:
                members = self.d.ifgroups.get(n) or []
                zs = sorted({self.d.zone_of_iface_id.get(m.get("id"), "") for m in members if m.get("id")} - {""})
                if zs:
                    out.extend(zs)
                else:
                    drops.add("interface_group_unresolved", f"{where}:{n}")
                    out.append(n)
            else:
                out.append(n)
        seen: set = set()
        return [z for z in out if not (z in seen or seen.add(z))]


# ── access rules ──────────────────────────────────────────────────────────

def norm_rule(e: dict, seq: int, d: Dictionary, zr: ZoneResolver, drops: Drops, *,
              inherited_from: str | None = None, section_hint: str | None = None) -> dict | None:
    """One FMC access rule in row shape, None for a MONITOR rule (no match
    outcome, declared)."""
    name = e.get("name") or f"rule-{seq}"
    action_raw = str(e.get("action") or "").upper()
    if action_raw == "MONITOR":
        drops.add("monitor_rule", name)
        return None
    act = _ACTIONS.get(action_raw, "deny")
    raw: dict = {}
    dropped: list[str] = []
    if action_raw == "TRUST":
        raw["ftd_trust"] = True
        dropped.append("ftd_trust_action")

    def nets(container, where):
        names = [n for n in (_name(o) for o in _objects(container)) if n]
        for lit in _objects(container, "literals"):
            ln = d.literal_address(str(lit.get("type") or ""), str(lit.get("value") or ""))
            if ln:
                names.append(ln)
            else:
                drops.add("network_literal_unsupported", f"{name}:{lit.get('value')}")
        return _ftd.any_net_names([{"name": n} for n in names]) if names else ["any"]

    sources = nets(e.get("sourceNetworks"), "src")
    destinations = nets(e.get("destinationNetworks"), "dst")
    services = [n for n in (_name(o) for o in _objects(e.get("destinationPorts"))) if n]
    for lit in _objects(e.get("destinationPorts"), "literals"):
        ln = d.literal_port(lit)
        if ln:
            services.append(ln)
        else:
            drops.add("port_literal_unsupported", f"{name}:{lit.get('type')}")
    src_ports = [n for n in (_name(o) for o in _objects(e.get("sourcePorts"))) if n]
    src_ports += [str(x.get("port")) for x in _objects(e.get("sourcePorts"), "literals") if x.get("port")]
    if src_ports:
        raw["ftd_source_ports"] = src_ports
        dropped.append("source_ports")
    apps = [n for n in (_name(a) for a in _objects(e.get("applications"), "applications")) if n]
    if _objects(e.get("applications"), "inlineApplicationFilters"):
        raw["ftd_app_filter"] = True
        dropped.append("application_filter")
    urls = e.get("urls") or {}
    if isinstance(urls, dict) and (urls.get("objects") or urls.get("literals") or urls.get("urlCategoriesWithReputation")):
        raw["urls"] = {"objects": [n for n in (_name(o) for o in _objects(urls)) if n],
                       "literals": [x.get("url") for x in _objects(urls, "literals") if x.get("url")],
                       "categories": [{"name": _name(c.get("category")), "reputation": c.get("reputation")}
                                      for c in _objects(urls, "urlCategoriesWithReputation") if _name(c.get("category"))]}
        dropped.append("url_filter")
    identities = []
    for u in _objects(e.get("users")):
        n = _name(u)
        if n:
            identities.append({"name": n, "kind": "group" if "Group" in str(u.get("type") or "") else "user",
                               "realm": _name(u.get("realm"))})
    trs = [n for n in (_name(t) for t in (e.get("timeRangeObjects") or []) if isinstance(t, dict)) if n]
    schedule = trs[0] if trs else None
    if len(trs) > 1:
        raw["fmc_time_ranges"] = trs
        dropped.append("schedule_multiple")
    if e.get("vlanTags") and (_objects(e.get("vlanTags")) or _objects(e.get("vlanTags"), "literals")):
        raw["vlan_tags"] = e.get("vlanTags")
        dropped.append("vlan_tags")
    for fld, ch in (("sourceSecurityGroupTags", "security_group_tags"), ("destinationSecurityGroupTags", "security_group_tags"),
                    ("sourceDynamicObjects", "dynamic_objects"), ("destinationDynamicObjects", "dynamic_objects")):
        if _objects(e.get(fld)):
            raw.setdefault(ch, []).extend(n for n in (_name(o) for o in _objects(e.get(fld))) if n)
            if ch not in dropped:
                dropped.append(ch)
    for fld, key in (("ipsPolicy", "intrusion_policy"), ("filePolicy", "file_policy"), ("variableSet", "variable_set")):
        n = _name(e.get(fld))
        if n:
            raw.setdefault("security_profile_individual", {})[key] = n
            if "security_profile_individual" not in dropped:
                dropped.append("security_profile_individual")
    log = {k: bool(e.get(k)) for k in ("logBegin", "logEnd", "sendEventsToFMC", "logFiles", "enableSyslog") if e.get(k)}
    if log:
        raw["log_setting"] = log
        dropped.append("log_setting")
    comments = [str(c.get("comment")) for c in (e.get("commentHistoryList") or []) if isinstance(c, dict) and c.get("comment")]
    meta = e.get("metadata") or {}
    if meta.get("section"):
        raw["fmc_section"] = meta["section"]
    if meta.get("category") and meta["category"] != "--Undefined--":
        raw["fmc_category"] = meta["category"]
    if inherited_from:
        raw["fmc_inherited_from"] = inherited_from
    if section_hint:
        raw["fmc_prefilter"] = section_hint
    return {
        "rule_name": name, "seq_num": seq, "action": act,
        "src_zones": zr.zones(_objects(e.get("sourceZones")), drops, name) or ["any"],
        "dst_zones": zr.zones(_objects(e.get("destinationZones")), drops, name) or ["any"],
        "sources": sources, "destinations": destinations,
        "services": services or ["any"], "applications": apps,
        "description": " | ".join(comments) if comments else (e.get("description") or ""),
        "disabled": 0 if e.get("enabled", True) else 1, "tags": [],
        "negate_source": 0, "negate_destination": 0, "negate_service": 0,
        "schedule": schedule, "source_identities": identities or None,
        "raw_extras": raw or None, "dropped_inputs": dropped,
        "source_vendor_id": e.get("id") or name,
    }


def norm_prefilter_rule(e: dict, seq: int, policy_name: str, d: Dictionary, zr: ZoneResolver, drops: Drops) -> dict | None:
    """A prefilter rule at the head of the rulebase (D7): FASTPATH is an
    allow, BLOCK a deny, ANALYZE and tunnel rules are declared and left
    out."""
    name = e.get("name") or f"prefilter-{seq}"
    rtype, action = str(e.get("ruleType") or "PREFILTER").upper(), str(e.get("action") or "").upper()
    if rtype == "TUNNEL":
        drops.add("prefilter_tunnel", name)
        return None
    if action == "ANALYZE":
        drops.add("prefilter_analyze", name)
        return None
    act = "allow" if action == "FASTPATH" else "deny"
    shaped = dict(e)
    shaped["action"] = "ALLOW" if act == "allow" else "BLOCK"
    shaped["sourceZones"] = e.get("sourceInterfaces") or {}
    shaped["destinationZones"] = e.get("destinationInterfaces") or {}
    r = norm_rule(shaped, seq, d, zr, drops, section_hint=f"{policy_name}:{action.lower()}")
    if r is None:
        return None
    r["raw_extras"] = {**(r["raw_extras"] or {}), "ftd_prefilter": {"policy": policy_name, "action": action.lower(),
                                                                     "rule_type": rtype.lower(),
                                                                     "bidirectional": bool(e.get("bidirectional"))}}
    if "ftd_trust_action" in r["dropped_inputs"]:
        r["dropped_inputs"].remove("ftd_trust_action")
    r["dropped_inputs"].append("prefilter_rule")
    return r


def default_action_rule(pol: dict, seq: int) -> dict:
    """The access policy's default action as the final rule, marked as the
    vendor default like a FortiOS implicit deny."""
    da = pol.get("defaultAction") or {}
    action_raw = str(da.get("action") or "BLOCK").upper()
    raw = {"vendor_default": True, "fmc_default_action": action_raw}
    if da.get("logBegin") or da.get("logEnd") or da.get("sendEventsToFMC"):
        raw["log_setting"] = {k: True for k in ("logBegin", "logEnd", "sendEventsToFMC") if da.get(k)}
    return {"rule_name": f"{pol.get('name')} default action", "seq_num": seq,
            "action": _DEFAULT_ACTIONS.get(action_raw, "deny"),
            "src_zones": ["any"], "dst_zones": ["any"], "sources": ["any"], "destinations": ["any"],
            "services": ["any"], "applications": [], "description": "the access policy's default action",
            "disabled": 0, "tags": [], "negate_source": 0, "negate_destination": 0, "negate_service": 0,
            "schedule": None, "source_identities": None, "raw_extras": raw,
            "dropped_inputs": ["vendor_default"], "source_vendor_id": f"{pol.get('id')}:default"}


class PolicyReader:
    """Reads access policies of one domain: the rulebase as the Management
    Center lists it (the base chain's rules included), the chain for the
    scope's record."""

    def __init__(self, client, uid: str, d: Dictionary, policies: list[dict]):
        self.client, self.uid, self.d = client, uid, d
        self.zr = ZoneResolver(d)
        self.by_id = {p["id"]: p for p in policies if p.get("id")}
        self._rules: dict[str, list[dict]] = {}
        self._base: dict[str, str | None] = {}
        self._prefilter: dict[str, list[dict]] = {}

    def raw_rules(self, pid: str) -> list[dict]:
        if pid not in self._rules:
            self._rules[pid] = self.client.get_all(self.client.cfg(self.uid, f"/policy/accesspolicies/{pid}/accessrules"))
        return self._rules[pid]

    def base_of(self, pol: dict) -> str | None:
        pid = pol.get("id")
        if pid in self._base:
            return self._base[pid]
        meta = pol.get("metadata") or {}
        base = _name(meta.get("parentPolicy")) and (meta.get("parentPolicy") or {}).get("id")
        if not base and meta.get("inherit", True):
            for s in self.client.get_all(self.client.cfg(self.uid, f"/policy/accesspolicies/{pid}/inheritancesettings"),
                                         tolerate=(404, 400)):
                bp = s.get("basePolicy") if isinstance(s, dict) else None
                if not (isinstance(bp, dict) and bp.get("id")) and isinstance(s, dict) and s.get("id"):
                    # the list carries only ids, the item names the base
                    item = self.client.get(self.client.cfg(self.uid, f"/policy/accesspolicies/{pid}/inheritancesettings/{s['id']}"),
                                           tolerate=(404, 400)) or {}
                    bp = item.get("basePolicy")
                if isinstance(bp, dict) and bp.get("id"):
                    base = bp["id"]
                    break
        self._base[pid] = base if base and base in self.by_id and base != pid else None
        return self._base[pid]

    def chain(self, pol: dict) -> list[dict]:
        """The base policies, nearest first."""
        out, seen, cur = [], {pol.get("id")}, pol
        while True:
            b = self.base_of(cur)
            if not b or b in seen:
                break
            seen.add(b)
            cur = self.by_id[b]
            out.append(cur)
        return out

    def prefilter_rules(self, pol: dict) -> list[dict]:
        pf = pol.get("prefilterPolicySetting") or {}
        pfid = pf.get("id")
        if not pfid:
            return []
        if pfid not in self._prefilter:
            self._prefilter[pfid] = self.client.get_all(
                self.client.cfg(self.uid, f"/policy/prefilterpolicies/{pfid}/prefilterrules"), tolerate=(404,))
        return self._prefilter[pfid]

    def rulebase(self, pol: dict, drops: Drops) -> list[dict]:
        rules: list[dict] = []
        seq = 0
        pf = pol.get("prefilterPolicySetting") or {}
        for e in self.prefilter_rules(pol):
            r = norm_prefilter_rule(e, seq, _name(pf) or "prefilter", self.d, self.zr, drops)
            if r:
                rules.append(r)
                seq += 1
        # The policy's own list IS the effective rulebase: the base chain's
        # rules sit in it in evaluation order (base Mandatory, own Mandatory, own Default,
        # base Default, over every level), each rule naming its owner in metadata.accessPolicy.
        own = str(pol.get("id") or "")
        for e in self.raw_rules(own):
            owner = (e.get("metadata") or {}).get("accessPolicy")
            owner = owner if isinstance(owner, dict) else {}
            inherited = _name(owner) if str(owner.get("id") or "") not in ("", own) else None
            r = norm_rule(e, seq, self.d, self.zr, drops, inherited_from=inherited)
            if r:
                rules.append(r)
                seq += 1
        rules.append(default_action_rule(pol, seq))
        return rules


# ── NAT ───────────────────────────────────────────────────────────────────

def read_nat_rules(client, uid: str, nat_pol: dict, d: Dictionary, drops: Drops) -> list[dict]:
    """The NAT policy's rules in effective order (manual before, auto,
    manual after), interface references resolved to zones, the policy
    named in the properties."""
    zr = ZoneResolver(d)
    items = client.get_all(client.cfg(uid, f"/policy/ftdnatpolicies/{nat_pol['id']}/natrules"), tolerate=(404,))
    order = {"BEFORE_AUTO": 0, "AUTO": 1, "AFTER_AUTO": 2}
    items = sorted(items, key=lambda e: (order.get(str((e.get("metadata") or {}).get("section") or "AUTO").upper(), 1),
                                         int((e.get("metadata") or {}).get("index") or 0)))
    out: list[dict] = []
    for i, e in enumerate(items):
        shaped = dict(e)
        src_refs = [e["sourceInterface"]] if isinstance(e.get("sourceInterface"), dict) else []
        dst_refs = [e["destinationInterface"]] if isinstance(e.get("destinationInterface"), dict) else []
        nm = e.get("name") or f"nat-{i}"
        src_z, dst_z = zr.zones(src_refs, drops, nm), zr.zones(dst_refs, drops, nm)
        # the FDM parsers read the interface field's name: hand them the first zone
        shaped["sourceInterface"] = {"name": src_z[0]} if src_z else None
        shaped["destinationInterface"] = {"name": dst_z[0]} if dst_z else None
        for fld in ("originalSource", "originalDestination", "translatedSource", "translatedDestination",
                    "originalNetwork", "translatedNetwork"):
            ref = e.get(fld)
            if isinstance(ref, dict) and _name(ref) in _ANY_NAMES:
                shaped[fld] = None
        if str(e.get("type") or "") == "FTDAutoNatRule":
            r = _ftd.parse_object_nat_rules([shaped], position_base=i)[0]
        else:
            r = _ftd.parse_manual_nat_rules([shaped], position_base=i, port_of=d.port_number)[0]
        if src_z:
            r["src_zones"] = src_z
        if dst_z:
            r["dst_zones"] = dst_z
        meta = e.get("metadata") or {}
        props = {"fmc_nat_policy": nat_pol.get("name"), "fmc_section": meta.get("section"),
                 "fmc_rule_type": e.get("type")}
        for k in ("dns", "noProxyArp", "routeLookup", "netToNet", "unidirectional", "interfaceIpv6", "fallThrough"):
            if e.get(k):
                props[k] = True
        if isinstance(e.get("patOptions"), dict):
            props["patOptions"] = e["patOptions"]
        for fld in ("originalSourcePort", "translatedSourcePort", "originalDestinationPort", "translatedDestinationPort"):
            if _name(e.get(fld)):
                props[fld] = _name(e.get(fld))
        r["properties"] = props
        r["source_vendor_id"] = e.get("id")
        out.append(r)
    return out


# ── the device network ────────────────────────────────────────────────────

def _prefix_of(mask: str) -> int | None:
    mask = str(mask or "").strip()
    if mask.isdigit():
        return int(mask)
    return _ftd._netmask_to_prefix(mask) if mask else None


def _iface_ips(e: dict) -> tuple[list[str], bool]:
    ips: list[str] = []
    v4 = e.get("ipv4") or {}
    dhcp = bool(v4.get("dhcp"))
    st = v4.get("static") or {}
    if st.get("address"):
        plen = _prefix_of(st.get("netmask"))
        ips.append(f"{st['address']}/{plen if plen is not None else 32}")
    v6 = e.get("ipv6") or {}
    for a in (v6.get("addresses") or []):
        if isinstance(a, dict) and a.get("address"):
            try:
                ips.append(str(ipaddress.ip_interface(f"{a['address']}/{a.get('prefix') or 128}")))
            except ValueError:
                continue
    return ips, dhcp


def fill_interface_nat(nats: list[dict], net: dict | None) -> None:
    """An interface-address NAT (PAT behind the egress interface) names that
    interface's IPv4 as the `iface|ip` literal the PAN-OS and FortiOS imports
    write, when the destination zone holds exactly one addressed interface of
    the device. The Check Point renderer materialises the address from it,
    PAN-OS and FortiOS keep the interface form."""
    by_zone: dict[str, list[tuple[str, str]]] = {}
    for i in (net or {}).get("interfaces") or []:
        v4 = [ip for ip in (i.get("ips") or []) if ":" not in ip]
        if i.get("zone") and v4:
            by_zone.setdefault(i["zone"], []).append((i["name"], v4[0].split("/")[0]))
    for n in nats:
        if n.get("trans_src_type") != "interface-address" or n.get("trans_src"):
            continue
        zones = [z for z in (n.get("dst_zones") or []) if z and z != "any"]
        cands = by_zone.get(zones[0], []) if len(zones) == 1 else []
        if len(cands) == 1:
            n["trans_src"] = f"{cands[0][0]}|{cands[0][1]}"


def read_device_network(client, uid: str, dev: dict, d: Dictionary, drops: Drops) -> dict:
    """Interfaces, zones, virtual routers and routes of one device record,
    in the collect result shape the firewall collectors produce."""
    did = dev["id"]
    cfg = client.cfg
    base = f"/devices/devicerecords/{did}"
    interfaces: list[dict] = []
    ifname_of_id: dict[str, str] = {}
    hw_ifname: dict[str, str] = {}
    zone_by_id = {str(z.get("id")): z["name"] for z in d.zones if isinstance(z, dict) and z.get("id") and z.get("name")}

    def _zone_of(e: dict) -> str | None:
        """The interface's zone: the record's securityZone carries only id and type
        while the zone's interfaces[] list the record ids."""
        sz = e.get("securityZone") if isinstance(e.get("securityZone"), dict) else {}
        return (_name(sz) or zone_by_id.get(str(sz.get("id") or ""))
                or d.zone_of_iface_id.get(str(e.get("id") or "")) or None)

    def _one(e: dict, itype: str, parent: str | None = None, members: list | None = None) -> None:
        ifname = (e.get("ifname") or "").strip()
        hw = (e.get("name") or "").strip()
        if e.get("managementOnly"):
            drops.add("interface_system", ifname or hw)
            return
        if not ifname:
            drops.add("interface_unnamed", hw or "?")
            return
        ips, dhcp = _iface_ips(e)
        desc = (e.get("description") or "").strip()
        if hw and hw != ifname:
            desc = f"{desc} [{hw}]".strip()
        iface: dict = {"name": ifname, "zone": _zone_of(e), "description": desc or None,
                       "ips": ips, "type": itype, "vr_name": "default", "role": None,
                       "dhcp_enabled": dhcp, "enabled": bool(e.get("enabled", True))}
        if parent:
            iface["parent"] = parent
            try:
                vid = int(e.get("vlanId") or 0)
                if vid > 0:
                    iface["vlan_tag"] = vid
            except (TypeError, ValueError):
                pass
        if members:
            iface["members"] = members
        interfaces.append(iface)
        if e.get("id"):
            ifname_of_id[e["id"]] = ifname
        if hw and itype in ("physical", "bond"):     # a VLAN child's record name is its parent's hardware name
            hw_ifname[hw] = ifname

    phys = client.get_all(cfg(uid, f"{base}/physicalinterfaces"), tolerate=(404,))
    for e in phys:
        _one(e, "physical")
    for e in client.get_all(cfg(uid, f"{base}/etherchannelinterfaces"), tolerate=(404, 405)):
        members = [n for n in (_name(m) for m in (e.get("selectedInterfaces") or []) if isinstance(m, dict)) if n]
        _one(e, "bond", members=[hw_ifname.get(m, m) for m in members])
    for e in client.get_all(cfg(uid, f"{base}/subinterfaces"), tolerate=(404, 405)):
        hw = (e.get("name") or "").strip()
        _one(e, "vlan", parent=hw_ifname.get(hw) or hw or None)
    for e in client.get_all(cfg(uid, f"{base}/virtualtunnelinterfaces"), tolerate=(404, 405)):
        _one(e, "tunnel")
    for e in client.get_all(cfg(uid, f"{base}/loopbackinterfaces"), tolerate=(404, 405)):
        _one(e, "loopback")
    for channel, sub in (("bridge_group_interfaces", "bridgegroupinterfaces"), ("redundant_interfaces", "redundantinterfaces"),
                         ("switch_port_vlan_interfaces", "vlaninterfaces")):
        for e in client.get_all(cfg(uid, f"{base}/{sub}"), tolerate=(404, 405)):
            drops.add(channel, e.get("ifname") or e.get("name") or "?")
    names = {i["name"] for i in interfaces}
    zones = []
    for z in d.zones:
        members = sorted(i["name"] for i in interfaces if i.get("zone") == z.get("name"))
        zones.append({"name": z.get("name"), "members": members,
                      "properties": {"ftd_mode": str(z.get("interfaceMode") or "").lower() or None}})
    vrfs: list[dict] = []
    routes: list[dict] = []

    def _routes(items: list[dict], vr: str) -> None:
        for e in items:
            gw = e.get("gateway") or {}
            next_hop = None
            if isinstance(gw, dict):
                if isinstance(gw.get("object"), dict):
                    nm = _name(gw["object"])
                    val = d.value_of.get(nm) or nm or ""
                    next_hop = val.split("/")[0] if val else None
                elif isinstance(gw.get("literal"), dict):
                    next_hop = str(gw["literal"].get("value") or "") or None
            iface = e.get("interfaceName") if e.get("interfaceName") in names else None
            for ref in (e.get("selectedNetworks") or []):
                nm = _name(ref)
                val = d.value_of.get(nm) if nm else None
                if nm in ("any-ipv4", "any"):
                    val = "0.0.0.0/0"
                elif nm == "any-ipv6":
                    val = "::/0"
                try:
                    net = ipaddress.ip_network(val, strict=False)
                except Exception:
                    drops.add("route_unresolved", f"{e.get('name') or '?'}:{nm}")
                    continue
                routes.append({"prefix": str(net.network_address), "plen": net.prefixlen, "iface": iface,
                               "next_hop": next_hop, "vr": vr, "metric": e.get("metricValue")})

    vrs = client.get_all(cfg(uid, f"{base}/routing/virtualrouters"), tolerate=(404,))
    if vrs:
        for vr in vrs:
            raw = str(vr.get("name") or "")
            vname = "default" if raw.lower() in ("global", "default", "") else raw
            members = [ifname_of_id.get(x.get("id")) or hw_ifname.get(_name(x) or "") for x in (vr.get("interfaces") or []) if isinstance(x, dict)]
            members = [m for m in members if m]
            for i in interfaces:
                if i["name"] in members:
                    i["vr_name"] = vname
            vrfs.append({"name": vname, "interface_members": members, "properties": {"interface_members": members, "fmc_router": raw}})
            if vname == "default":
                _routes(client.get_all(cfg(uid, f"{base}/routing/ipv4staticroutes"), tolerate=(404,)), vname)
                _routes(client.get_all(cfg(uid, f"{base}/routing/ipv6staticroutes"), tolerate=(404,)), vname)
            else:
                _routes(client.get_all(cfg(uid, f"{base}/routing/virtualrouters/{vr.get('id')}/ipv4staticroutes"), tolerate=(404,)), vname)
                _routes(client.get_all(cfg(uid, f"{base}/routing/virtualrouters/{vr.get('id')}/ipv6staticroutes"), tolerate=(404,)), vname)
    else:
        _routes(client.get_all(cfg(uid, f"{base}/routing/ipv4staticroutes"), tolerate=(404,)), "default")
        _routes(client.get_all(cfg(uid, f"{base}/routing/ipv6staticroutes"), tolerate=(404,)), "default")
    return {"interfaces": interfaces, "routes": routes, "vrfs": vrfs, "zones": zones, "errors": [], "warnings": []}


# ── the structure and the scopes ──────────────────────────────────────────

def read_hit_counts(client, uid: str, policy_id: str, device_id: str, prefilter_id: str | None = None):
    """The Center's hit counts of one access policy, and of its prefilter
    policy, for one device: hitCount, firstHitTimeStamp, lastHitTimeStamp and
    lastFetchTimeStamp per rule reference. The first GET for a device fetches
    from the device by the Center's own rule, later GETs answer the stored
    values; nothing here orders a fetch (PUT) or a reset (DELETE), D9."""
    import hitcounts
    found: dict = {}
    fetched = None
    paths = [f"/policy/accesspolicies/{policy_id}/operational/hitcounts"]
    if prefilter_id:
        paths.append(f"/policy/prefilterpolicies/{prefilter_id}/operational/hitcounts")
    for p in paths:
        for it in client.get_all(client.cfg(uid, p), params={"filter": f"deviceId:{device_id}"}, tolerate=(404,)):
            rule = it.get("rule") if isinstance(it.get("rule"), dict) else {}
            rid = rule.get("id")
            if not rid:
                continue
            found[str(rid)] = hitcounts.entry(it.get("hitCount"),
                                              first=hitcounts.from_iso(it.get("firstHitTimeStamp")),
                                              last=hitcounts.from_iso(it.get("lastHitTimeStamp")))
            f = hitcounts.from_iso(it.get("lastFetchTimeStamp"))
            if f and (fetched is None or f > fetched):
                fetched = f
    return hitcounts.Reading(rules=found, read_at=fetched or hitcounts.utcnow())


def hits_device_of(targets: list, pair_primary: dict | None = None) -> tuple:
    """The one device a policy's counters are read for (D5): (device id, None)
    for a policy assigned to one device or one HA pair (its primary), else
    (None, the reason): counters are per device and never summed."""
    devs = [t for t in (targets or []) if isinstance(t, dict) and t.get("id")]
    if not devs:
        return None, "the policy is assigned to no device"
    if len(devs) > 1:
        return None, f"the policy is assigned to {len(devs)} devices, counters are per device"
    t = devs[0]
    if str(t.get("type") or "") == "DeviceHAPair":
        prim = (pair_primary or {}).get(t["id"])
        if not prim:
            return None, f"the policy is assigned to the HA pair {t.get('name') or t['id']} whose primary is unknown"
        return prim, None
    return t["id"], None


def discover_fmc_scopes(client) -> dict:
    """Every scope of the Management Center with its content, ready for the
    rails: {"scopes": [...], "skipped": [...], "version": str}."""
    domains = client.auth.domain_list()
    version = client.server_version()
    scopes: list[dict] = []
    skipped: list[str] = []
    seen_devices: set[str] = set()
    cfg = client.cfg
    # An assignment is listed in the domain of its POLICY, not of its device (a
    # Global policy assigned to a child-domain device shows in Global's list
    # only), so the map is built once over every domain.
    assignments: dict = {}
    for dom in domains:
        for a in client.get_all(cfg(dom["uuid"], "/assignment/policyassignments"), tolerate=(404,)):
            pol = a.get("policy") or {}
            key = (pol.get("type"), pol.get("id"))
            targets = [t for t in (a.get("targets") or []) if isinstance(t, dict)]
            if key not in assignments or len(targets) > len(assignments[key]):
                assignments[key] = targets
    for dom in sorted(domains, key=lambda x: str(x.get("name") or "")):
        dname, uid = str(dom.get("name") or "Global"), dom["uuid"]
        parent = dname.rsplit("/", 1)[0] if "/" in dname else None
        d = read_dictionary(client, uid)
        policies = [p for p in client.get_all(cfg(uid, "/policy/accesspolicies")) if _domain_of(p, uid) == uid and p.get("id")]
        all_policies = [p for p in client.get_all(cfg(uid, "/policy/accesspolicies")) if p.get("id")]
        nat_policies = [n for n in client.get_all(cfg(uid, "/policy/ftdnatpolicies"), tolerate=(404,)) if _domain_of(n, uid) == uid and n.get("id")]
        devices = [x for x in client.get_all(cfg(uid, "/devices/devicerecords"), tolerate=(404,))
                   if _domain_of(x, uid) == uid and x.get("id") and x["id"] not in seen_devices]
        seen_devices.update(x["id"] for x in devices)
        pairs = client.get_all(cfg(uid, "/devicehapairs/ftddevicehapairs"), tolerate=(404,))
        clusters = client.get_all(cfg(uid, "/deviceclusters/ftddevicecluster"), tolerate=(404,))
        dom_drops = Drops()
        dom_drops.merge(d.unsupported)
        scopes.append({"type": "domain", "name": dname, "vendor_id": uid, "role": "root" if parent is None else "policy",
                       "parent": parent, "members": None, "config": None, "_dict": d,
                       "objs": None, "rules": [], "nats": [], "net": None, "drops": dom_drops,
                       "_referenced": set()})
        dom_scope = scopes[-1]
        reader = PolicyReader(client, uid, d, all_policies)
        target_names: dict[str, str] = {}      # device id -> the scope name it belongs to (pair folds members)
        pair_of: dict[str, dict] = {}
        pair_primary: dict[str, str] = {}
        for p in pairs:
            for role in ("primary", "secondary"):
                m = p.get(role) or {}
                if m.get("id"):
                    pair_of[m["id"]] = p
            if p.get("id") and isinstance(p.get("primary"), dict) and (p["primary"] or {}).get("id"):
                pair_primary[p["id"]] = p["primary"]["id"]
        for p in policies:
            drops = Drops()
            rules = reader.rulebase(p, drops)
            refs: set[str] = set()
            for r in rules:
                refs |= d.closure(r["sources"] + r["destinations"] + r["services"] + ([r["schedule"]] if r.get("schedule") else []))
            members = [t.get("name") for t in assignments.get(("AccessPolicy", p["id"]), []) if t.get("name")]
            dom_scope["_referenced"] |= refs
            # Hit counts from the box: the policy's
            # counters for its one device; several devices or none declare, a failed read too
            import hitcounts as _hits
            _dev_id, _why = hits_device_of(assignments.get(("AccessPolicy", p["id"]), []), pair_primary)
            if _dev_id:
                try:
                    _reading = read_hit_counts(client, uid, p["id"], _dev_id,
                                               prefilter_id=(p.get("prefilterPolicySetting") or {}).get("id"))
                except _fmc.FmcAuthError:
                    raise
                except Exception as exc:
                    _reading = _hits.declared(f"hitcounts failed: {str(exc)[:200]}")
            else:
                _reading = _hits.declared(_why)
            _hits.attach(rules, _reading)
            scopes.append({"type": "access-policy", "name": f"{dname}/{p['name']}", "vendor_id": p["id"], "role": "rulebase",
                           "parent": dname, "members": members, "objs": d.rows(refs), "rules": rules, "nats": [],
                           "net": None, "drops": drops, "box_declared": _reading.declared,
                           "config": json.dumps({"fmc": {"policy_id": p["id"], "domain": dname,
                                                         "base_policy": [a.get("name") for a in reader.chain(p)],
                                                         "prefilter": _name(p.get("prefilterPolicySetting"))}})})
        nat_of_target: dict[str, list[dict]] = {}
        for n in nat_policies:
            for t in assignments.get(("FTDNatPolicy", n["id"]), []):
                if t.get("id"):
                    nat_of_target.setdefault(t["id"], []).append(n)
        acp_of_target: dict[str, str] = {}
        for p in policies:
            for t in assignments.get(("AccessPolicy", p["id"]), []):
                if t.get("id"):
                    acp_of_target[t["id"]] = p["name"]
        done_pairs: set[str] = set()
        for dev in devices:
            cont = (dev.get("metadata") or {}).get("containerDetails") or {}
            pair = pair_of.get(dev["id"]) or (cont if cont.get("type") == "DeviceHAPair" else None)
            if pair:
                pid = pair.get("id")
                if pid in done_pairs:
                    skipped.append(f"{dev.get('name')}: member of HA pair {pair.get('name')}, read through its primary")
                    continue
                prim = (pair.get("primary") or {}).get("id") if isinstance(pair.get("primary"), dict) else None
                if prim and prim != dev["id"] and str(cont.get("role") or "").upper() != "PRIMARY":
                    # the primary comes later in the list: read it then
                    other = next((x for x in devices if x["id"] == prim), None)
                    if other is not None:
                        skipped.append(f"{dev.get('name')}: member of HA pair {pair.get('name')}, read through its primary")
                        continue
                done_pairs.add(pid)
                scope_name, vid, target_id = pair.get("name") or dev.get("name"), pid, pid
            else:
                scope_name, vid, target_id = dev.get("name"), dev["id"], dev["id"]
            drops = Drops()
            net = read_device_network(client, uid, dev, d, drops)
            nats: list[dict] = []
            for n in nat_of_target.get(target_id, []) + ([] if target_id == dev["id"] else nat_of_target.get(dev["id"], [])):
                nats.extend(read_nat_rules(client, uid, n, d, drops))
            for i, r in enumerate(nats):
                r["position"] = i
            fill_interface_nat(nats, net)
            refs: set[str] = set()
            for r in nats:
                refs |= d.closure(r["orig_src"] + r["orig_dst"] + r["orig_service"]
                                  + [x for x in (r.get("trans_src"), r.get("trans_dst"), r.get("trans_dst_port"))
                                     if x and "|" not in x])
            dom_scope["_referenced"] |= refs
            config = {"fmc": {"device_id": dev["id"], "domain": dname, "host": dev.get("hostName"),
                              "model": dev.get("model"), "version": dev.get("sw_version"),
                              "access_policy": acp_of_target.get(target_id) or acp_of_target.get(dev["id"]) or _name(dev.get("accessPolicy")),
                              "nat_policies": [n.get("name") for n in nat_of_target.get(target_id, [])]}}
            if pair:
                config["fmc"]["ha_pair"] = {"name": pair.get("name"), "primary": _name(pair.get("primary")) or dev.get("name"),
                                            "secondary": _name(pair.get("secondary"))}
            scopes.append({"type": "device", "name": scope_name, "vendor_id": vid, "role": "network", "parent": dname,
                           "members": None, "objs": d.rows(refs), "rules": [], "nats": nats, "net": net,
                           "drops": drops, "config": json.dumps(config)})
        for c in clusters:
            skipped.append(f"cluster {c.get('name')}: its members are read as devices, the cluster itself is not a scope yet")
        dom_scope["objs"] = d.rows(set(d.objects) - (d.predefined - dom_scope["_referenced"]))
        dom_scope["summary_predefined_unreferenced"] = len(d.predefined - dom_scope["_referenced"] - _ANY_NAMES)
        dom_scope["summary_overrides"] = sum(len(v) for v in d.overrides.values())
        dom_scope["summary_literals"] = d.literals
    for sc in scopes:
        sc.pop("_dict", None)
        sc.pop("_referenced", None)
    return {"scopes": scopes, "skipped": skipped, "version": version}


def import_fmc_source(device: dict) -> dict:
    """Fan a Management Center row into scope Devices through the rails
    (scopepersist), like the Enterprise manager imports. A re-import keeps
    the scope Devices by the FMC's ids and rewrites their content. Returns
    the per-scope summary the import log shows."""
    import datetime as _dt
    from sqlalchemy import text
    from main import get_engine, _normalize_with_retry
    from scopepersist import persist_network, persist_policy_scope, sync_scope_devices, write_scope_edge
    if not fmc_cfg(device):
        raise FmcImportError("the device row carries no config.fmc")
    client = _fmc.fmc_client_for(device)
    manager_id = device["id"]
    try:
        disco = discover_fmc_scopes(client)
    except _fmc.FmcError as exc:
        raise FmcImportError(str(exc))
    ts = _dt.datetime.now().replace(microsecond=0)
    summary: list = []
    normalize_ids: list = []
    with get_engine().begin() as conn:
        sync_scope_devices(conn, manager_id, "firepower", disco["scopes"])
        name_to_devid: dict = {}
        for sc in disco["scopes"]:
            name_to_devid[(sc["type"], sc["name"])] = sc["_sdid"]
        for sc in disco["scopes"]:
            sdid = sc["_sdid"]
            persist_policy_scope(conn, sdid, ts, sc["objs"] or [], sc["rules"], sc["nats"], [], [], [])
            if sc["rules"]:
                normalize_ids.append(sdid)
            nnet = 0
            if sc.get("net"):
                persist_network(conn, sdid, dict(sc["net"]))
                nnet = len(sc["net"]["interfaces"])
            drops = sc["drops"].by_channel if sc.get("drops") else {}
            if drops:
                conn.execute(text(
                    "INSERT INTO fw_import_drops (device_id, import_ts, field, rule_count, sample_names) "
                    "VALUES (:did, :ts, :field, :cnt, :samples)"),
                    [{"did": sdid, "ts": ts, "field": f[:64], "cnt": len(names), "samples": json.dumps(names[:5])}
                     for f, names in drops.items()])
            # the declaration of a policy scope whose counters were not read
            import hitcounts as _hits
            _box_row = _hits.declaration_params(sdid, ts, sc.get("box_declared"), sc["rules"])
            if _box_row:
                conn.execute(text(
                    "INSERT INTO fw_import_drops (device_id, import_ts, field, rule_count, sample_names) "
                    "VALUES (:did, :ts, :field, :cnt, :samples)"), _box_row)
            summary.append({"type": sc["type"], "name": sc["name"], "objects": len(sc["objs"] or []),
                            "rules": len(sc["rules"]), "nat": len(sc["nats"]), "interfaces": nnet,
                            "drops": {f: len(v) for f, v in drops.items()},
                            **{k[8:]: v for k, v in sc.items() if k.startswith("summary_")}})
        for sc in disco["scopes"]:
            parent = name_to_devid.get(("domain", sc["parent"])) if sc.get("parent") else None
            write_scope_edge(conn, manager_id, sc, sc["role"], parent, sc.get("members"))
        raw = conn.execute(text("SELECT config FROM fw_devices WHERE id = :id"), {"id": manager_id}).scalar()
        try:
            cfg = json.loads(raw) if raw else {}
        except Exception:
            cfg = {}
        cfg.setdefault("fmc", {})["version"] = disco.get("version") or ""
        cfg["fmc"]["spec_date"] = SPEC_DATE
        cfg["fmc"]["imported_at"] = ts.isoformat()
        conn.execute(text("UPDATE fw_devices SET config = :c, device_kind = 'manager-source' WHERE id = :id"),
                     {"c": json.dumps(cfg), "id": manager_id})
    for sdid in normalize_ids:
        try:
            _normalize_with_retry(sdid, ts)
        except Exception:
            pass
    return {"manager": device.get("display_name") or device.get("host_name"), "version": disco.get("version"),
            "scopes": summary, "skipped": disco["skipped"], "calls": client.calls}
