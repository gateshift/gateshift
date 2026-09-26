# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""Vendor-agnostic rule-shadowing analysis.

Detects FULL shadowing only: an earlier, always-active rule whose match
space is a superset of a later rule's match space makes that later rule
unreachable (first-match semantics on all supported vendors). Duplicates
are the special case of mutual coverage. Partial overlaps are deliberately
NOT reported - they are legal everywhere and belong to a future
optimization scope, not to correctness.

Vendor differences enter declaratively via ``ShadowProfile`` (today only:
do zones belong to the match space - Check Point is zoneless), never as
platform branches inside the engine. The engine consumes the EFFECTIVE
rules exactly as the Ruleset UI shows and the deploy renders them
(``_fetch_rules_and_devices`` order + overrides), so analysis, display
and push always agree.

Conservatism contract (no false positives over missed findings):
  - a rule can only SHADOW others when it is enabled and carries no
    negation, no schedule, no identities and no applications (all of
    which narrow or complicate its real match space);
  - a rule can only BE shadowed when it carries no negation (its own
    schedule/apps/identities merely narrow it further - a full cover of
    its declared space still covers the narrowed one);
  - anything that does not resolve to comparable sets (FQDN objects,
    unknown references, exotic service forms) makes that dimension
    non-comparable, unless the covering side is universal ('any').

What the static view can NOT see: render-time transformations (e.g. a
schedule the target cannot represent gets dropped declared, widening the
rule on the box). The authoritative post-publish conflict check on Check
Point targets remains the safety net for that class.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import json
import re

from sqlalchemy import text

_INT_MAX = 0xFFFFFFFF


@dataclasses.dataclass(frozen=True)
class ShadowProfile:
    """Per-target match-space semantics, supplied declaratively."""
    zones_in_match: bool = True


_PROFILES = {
    # Check Point access layers are zoneless - rules differing only by
    # zone still conflict at install time.
    "checkpoint": ShadowProfile(zones_in_match=False),
}


def profile_for(platform: str | None) -> ShadowProfile:
    return _PROFILES.get((platform or "").lower(), ShadowProfile())


# ── Dimension values ─────────────────────────────────────────────
# A dimension resolves to one of:
#   "universal"        - covers everything ('any')
#   ("set", frozenset) - a concrete, comparable set
#   "unresolved"       - could not be made comparable (conservative)

UNIVERSAL = "universal"
UNRESOLVED = "unresolved"


def _merge_ranges(ranges: list[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    if not ranges:
        return ()
    ranges = sorted(ranges)
    out = [list(ranges[0])]
    for lo, hi in ranges[1:]:
        if lo <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return tuple((lo, hi) for lo, hi in out)


def _ranges_subset(inner: tuple, outer: tuple) -> bool:
    """Every inner range fully inside some outer range (both merged+sorted)."""
    j = 0
    for lo, hi in inner:
        while j < len(outer) and outer[j][1] < lo:
            j += 1
        if j >= len(outer) or not (outer[j][0] <= lo and hi <= outer[j][1]):
            return False
    return True


class _AddrResolver:
    """name-or-literal → merged v4 ranges. Groups expand recursively."""

    def __init__(self, conn, device_id: int):
        self.objects: dict[str, str] = {}
        self.groups: dict[str, list[str]] = {}
        try:
            for name, value, obj_type in conn.execute(text(
                    "SELECT name, value, obj_type FROM fw_address_objects "
                    "WHERE device_id = :d"), {"d": device_id}):
                if name and value:
                    # fqdn/dynamic object types are not comparable sets
                    if (obj_type or "").lower() in ("fqdn", "dynamic", "geo",
                                                    "wildcard"):
                        self.objects[name] = "__unresolved__"
                    else:
                        self.objects[name] = value
        except Exception:
            pass
        try:
            for name, value in conn.execute(text(
                    "SELECT name, value FROM fw_imported_objects "
                    "WHERE device_id = :d AND obj_type = 'address_group'"),
                    {"d": device_id}):
                try:
                    members = (json.loads(value) or {}).get("members") or []
                except Exception:
                    members = None
                if name:
                    self.groups[name] = members if isinstance(members, list) else None
        except Exception:
            pass
        self._cache: dict[str, object] = {}

    @staticmethod
    def _literal(entry: str):
        entry = entry.strip()
        m = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})", entry)
        try:
            if m:
                lo = int(ipaddress.IPv4Address(m.group(1)))
                hi = int(ipaddress.IPv4Address(m.group(2)))
                return [(min(lo, hi), max(lo, hi))]
            net = ipaddress.ip_network(entry, strict=False)
            if net.version != 4:
                return None
            return [(int(net.network_address), int(net.broadcast_address))]
        except ValueError:
            return None

    def entry_ranges(self, entry: str, _seen: frozenset = frozenset()):
        """One entry → list[(lo,hi)] | UNIVERSAL | None (unresolved)."""
        if not entry or entry.lower() in ("any", "all"):
            return UNIVERSAL
        if entry in _seen:            # group cycle - refuse
            return None
        cached = self._cache.get(entry)
        if cached is not None:
            return cached
        result = None
        lit = self._literal(entry)
        if lit is not None:
            result = lit
        elif entry in self.groups:
            members = self.groups[entry]
            if members is None:
                result = None
            else:
                acc: list = []
                result = acc
                for m in members:
                    sub = self.entry_ranges(m, _seen | {entry})
                    if sub is UNIVERSAL:
                        result = UNIVERSAL
                        break
                    if sub is None:
                        result = None
                        break
                    acc.extend(sub)
        elif entry in self.objects:
            val = self.objects[entry]
            if val == "__unresolved__":
                result = None
            else:
                result = self._literal(val)
        if result is not None and result is not UNIVERSAL:
            if any(lo == 0 and hi == _INT_MAX for lo, hi in result):
                result = UNIVERSAL
        self._cache[entry] = result
        return result

    def side(self, entries: list[str]):
        """Whole src/dst side → (kind, merged ranges)."""
        if not entries:
            return (UNIVERSAL, ())
        acc: list = []
        for e in entries:
            r = self.entry_ranges(str(e))
            if r is UNIVERSAL:
                return (UNIVERSAL, ())
            if r is None:
                return (UNRESOLVED, ())
            acc.extend(r)
        return ("set", _merge_ranges(acc))


# tcp/udp carry port ranges; other protocols compare whole-proto.
_SVC_SPEC_RE = re.compile(r"^(tcp|udp)\s*/\s*(\d{1,5})(?:\s*-\s*(\d{1,5}))?$", re.I)


class _SvcResolver:
    """service name / literal spec → set of (proto, lo, hi)."""

    def __init__(self, conn, device_id: int):
        self.objects: dict[str, tuple[str, str]] = {}
        self.groups: dict[str, list[str]] = {}
        try:
            for name, proto, port in conn.execute(text(
                    "SELECT name, proto, port FROM fw_service_objects "
                    "WHERE device_id = :d"), {"d": device_id}):
                if name:
                    self.objects[name] = ((proto or "").lower(), str(port or ""))
        except Exception:
            pass
        try:
            for name, value in conn.execute(text(
                    "SELECT name, value FROM fw_imported_objects "
                    "WHERE device_id = :d AND obj_type = 'service_group'"),
                    {"d": device_id}):
                try:
                    members = (json.loads(value) or {}).get("members") or []
                except Exception:
                    members = None
                if name:
                    self.groups[name] = members if isinstance(members, list) else None
        except Exception:
            pass
        self._cache: dict[str, object] = {}

    @staticmethod
    def _ports(port: str):
        """'80' / '80-90' / '80,443' → list[(lo,hi)] | None."""
        out = []
        for part in str(port).split(","):
            part = part.strip()
            if not part:
                continue
            m = re.fullmatch(r"(\d{1,5})(?:\s*-\s*(\d{1,5}))?", part)
            if not m:
                return None
            lo = int(m.group(1))
            hi = int(m.group(2) or lo)
            if lo > 65535 or hi > 65535:
                return None
            out.append((min(lo, hi), max(lo, hi)))
        return out or None

    def entry_specs(self, entry: str, _seen: frozenset = frozenset()):
        """One entry → list[(proto, lo, hi)] | UNIVERSAL | None."""
        if not entry or str(entry).lower() in ("any", "all"):
            return UNIVERSAL
        entry = str(entry).strip()
        if entry in _seen:
            return None
        cached = self._cache.get(entry)
        if cached is not None:
            return cached
        result = None
        m = _SVC_SPEC_RE.fullmatch(entry)
        if m:
            lo = int(m.group(2)); hi = int(m.group(3) or lo)
            result = [(m.group(1).lower(), min(lo, hi), max(lo, hi))]
        elif entry in self.groups:
            members = self.groups[entry]
            if members is None:
                result = None
            else:
                acc: list = []
                result = acc
                for mm in members:
                    sub = self.entry_specs(mm, _seen | {entry})
                    if sub is UNIVERSAL:
                        result = UNIVERSAL
                        break
                    if sub is None:
                        result = None
                        break
                    acc.extend(sub)
        elif entry in self.objects:
            proto, port = self.objects[entry]
            if proto in ("tcp", "udp"):
                pr = self._ports(port)
                result = [(proto, lo, hi) for lo, hi in pr] if pr else None
            elif proto in ("ip", "any", ""):
                result = UNIVERSAL if proto != "" else None
            elif proto:
                # whole-protocol service (icmp, gre, esp, ...) - compare
                # proto-level; port qualifier (icmp type) folds into it
                # conservatively as whole-proto only when no port is set.
                result = [(proto, 0, 65535)] if not str(port or "").strip() else None
        self._cache[entry] = result
        return result

    def side(self, entries: list[str]):
        if not entries:
            return (UNIVERSAL, ())
        acc: list = []
        for e in entries:
            r = self.entry_specs(e)
            if r is UNIVERSAL:
                return (UNIVERSAL, ())
            if r is None:
                return (UNRESOLVED, ())
            acc.extend(r)
        # merge per proto
        per: dict[str, list] = {}
        for proto, lo, hi in acc:
            per.setdefault(proto, []).append((lo, hi))
        merged = {p: _merge_ranges(rs) for p, rs in per.items()}
        return ("set", merged)


def _dim_covers(a, b) -> bool:
    """Does dimension value a fully cover b? (addr sides)"""
    ka, va = a
    kb, vb = b
    if ka == UNIVERSAL:
        return True
    if ka == UNRESOLVED or kb == UNRESOLVED or kb == UNIVERSAL:
        return False
    return _ranges_subset(vb, va)


def _svc_covers(a, b) -> bool:
    ka, va = a
    kb, vb = b
    if ka == UNIVERSAL:
        return True
    if ka == UNRESOLVED or kb == UNRESOLVED or kb == UNIVERSAL:
        return False
    for proto, ranges in vb.items():
        cover = va.get(proto)
        if cover is None or not _ranges_subset(ranges, cover):
            return False
    return True


def _zones_covers(a: list[str], b: list[str]) -> bool:
    sa = {z.lower() for z in (a or []) if z}
    sb = {z.lower() for z in (b or []) if z}
    if not sa or "any" in sa:
        return True
    if not sb or "any" in sb:
        return False
    return sb <= sa


def _has_apps(rule: dict) -> bool:
    app = (rule.get("application") or "").strip().lower()
    return bool(app) and app not in ("any", "-")


def _negated(rule: dict) -> bool:
    return bool(rule.get("negate_source") or rule.get("negate_destination")
                or rule.get("negate_service"))


def analyze(conn, device_id: int, rules: list[dict],
            profile: ShadowProfile) -> dict:
    """Analyze an ordered effective ruleset.

    Returns::
        {"shadowed": {rhash: {"kind": "duplicate"|"shadowed",
                              "by": rule_name, "by_hash": rhash}},
         "shadowers": {rhash: n},
         "skipped": n_not_comparable}
    """
    addr = _AddrResolver(conn, device_id)
    svc = _SvcResolver(conn, device_id)

    prepared = []
    for rule in rules:
        rhash = rule.get("rhash") or ""
        entry = {
            "rhash": rhash,
            "name": rule.get("rule_name") or rule.get("name") or "",
            "disabled": bool(rule.get("disabled")),
            "negated": _negated(rule),
            "apps": _has_apps(rule),
            "schedule": bool((rule.get("schedule") or "").strip()),
            "idents": bool(rule.get("source_identities")),
            "src": addr.side(rule.get("sources") or []),
            "dst": addr.side(rule.get("destinations") or []),
            "svc": _svc_side_for_rule(rule, svc),
            "src_zones": rule.get("src_zones") or [],
            "dst_zones": rule.get("dst_zones") or [],
        }
        prepared.append(entry)

    shadowed: dict = {}
    shadowers: dict = {}
    skipped = 0
    # Shadower candidates seen so far, in order.
    candidates: list[dict] = []
    for e in prepared:
        # Can this rule BE shadowed? (own narrowing extras are fine)
        comparable_b = (not e["disabled"] and not e["negated"]
                        and e["src"][0] != UNRESOLVED
                        and e["dst"][0] != UNRESOLVED)
        if not comparable_b:
            skipped += 1
        elif e["rhash"]:
            for a in candidates:
                if not (_dim_covers(a["src"], e["src"])
                        and _dim_covers(a["dst"], e["dst"])
                        and _svc_covers(a["svc"], e["svc"])):
                    continue
                if profile.zones_in_match and not (
                        _zones_covers(a["src_zones"], e["src_zones"])
                        and _zones_covers(a["dst_zones"], e["dst_zones"])):
                    continue
                is_dup = (not e["apps"] and not e["schedule"]
                          and not e["idents"]
                          and _dim_covers(e["src"], a["src"])
                          and _dim_covers(e["dst"], a["dst"])
                          and _svc_covers(e["svc"], a["svc"])
                          and (not profile.zones_in_match or (
                              _zones_covers(e["src_zones"], a["src_zones"])
                              and _zones_covers(e["dst_zones"], a["dst_zones"]))))
                shadowed[e["rhash"]] = {
                    "kind": "duplicate" if is_dup else "shadowed",
                    "by": a["name"],
                    "by_hash": a["rhash"],
                }
                shadowers[a["rhash"]] = shadowers.get(a["rhash"], 0) + 1
                break
        # Can this rule SHADOW later ones? (must be always-active superset)
        if (not e["disabled"] and not e["negated"] and not e["apps"]
                and not e["schedule"] and not e["idents"]
                and e["src"][0] != UNRESOLVED and e["dst"][0] != UNRESOLVED
                and e["svc"][0] != UNRESOLVED
                and e["rhash"] not in shadowed):
            candidates.append(e)

    return {"shadowed": shadowed, "shadowers": shadowers, "skipped": skipped}


def _svc_side_for_rule(rule: dict, svc: "_SvcResolver"):
    """Service dimension of one effective rule.

    api_import rules carry service NAMES (import_services JSON, already
    surfaced by the loader); log-derived rules carry proto/port columns.
    """
    if rule.get("source_type") in ("api_import", "both"):
        names = rule.get("import_services")
        if isinstance(names, str):
            try:
                names = json.loads(names)
            except Exception:
                names = None
        if names is None:
            names = []
        return svc.side([n for n in names if n])
    proto = (rule.get("proto") or rule.get("protocol") or "").lower()
    pf, pt = rule.get("port_from"), rule.get("port_to")
    if not proto and pf is None:
        return (UNIVERSAL, ())
    if proto in ("tcp", "udp") and pf is not None:
        lo = int(pf)
        hi = int(pt if pt is not None else pf)
        return ("set", {proto: ((min(lo, hi), max(lo, hi)),)})
    if proto and pf is None:
        return ("set", {proto: ((0, 65535),)})
    return (UNRESOLVED, ())
