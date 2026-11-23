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
  - anything that does not resolve to comparable sets (unknown references,
    literals the engine cannot parse) makes that dimension non-comparable,
    unless the covering side is universal ('any');
  - an object the engine KNOWS but cannot expand (an FQDN, a dynamic, geo or
    wildcard object, a service whose port form it cannot compare) is an
    identity, not a hole: it is the same set wherever the same object is
    named, so it is covered by itself or by 'any' and by nothing else, and it
    covers nothing but itself.

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
# both families on one integer axis: IPv4 as is,
# IPv6 offset past it; the whole of each family as a range
_V6_OFFSET = 1 << 32
_FULL4 = (0, _INT_MAX)
_FULL6 = (_V6_OFFSET, _V6_OFFSET + (1 << 128) - 1)
# a known object the engine cannot expand into ranges: compared by identity
_OPAQUE = "__opaque__"


@dataclasses.dataclass(frozen=True)
class ShadowProfile:
    """Per-target match-space semantics, supplied declaratively.

    `apps_in_match` says whether a rule's applications narrow it ON THE
    TARGET: `all` where the target
    matches them (PA, a FortiGate in policy-based NGFW mode, no target),
    `override` where only an App-Site override is bound and the source's
    applications are declared drops (Check Point), `none` where nothing
    matches them (a FortiGate in profile-based mode, a UTM profile inspects
    but does not match). A rule the target matches wider than the source
    wrote it covers more, and the analysis has to see that or it stays
    silent where the target's own verification reports a conflict.
    """
    zones_in_match: bool = True
    apps_in_match: str = "all"


def apps_narrow(rule: dict, profile: ShadowProfile) -> bool:
    """Do this rule's applications narrow its match space on the target?"""
    if profile.apps_in_match == "none":
        return False
    if profile.apps_in_match == "override":
        return _has_apps(rule) and bool(rule.get("app_override_source"))
    return _has_apps(rule)


def profile_for(platform: str | None, ngfw_mode: str | None = None) -> ShadowProfile:
    """The profile of a target platform; a FortiGate needs its NGFW mode
    (the generate's `forti_ngfw_mode`, unknown reads as profile-based)."""
    p = (platform or "").lower()
    if p == "checkpoint":
        # access layers are zoneless, rules differing only by zone still
        # conflict at install time; source applications are declared drops
        return ShadowProfile(zones_in_match=False, apps_in_match="override")
    if p == "fortigate" and (ngfw_mode or "profile-based").lower() != "policy-based":
        return ShadowProfile(apps_in_match="none")
    return ShadowProfile()


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
            for name, value, value6, obj_type in conn.execute(text(
                    "SELECT name, value, value6, obj_type FROM fw_address_objects "
                    "WHERE device_id = :d"), {"d": device_id}):
                if name and value:
                    # fqdn/dynamic/geo/wildcard objects are no sets, but the
                    # same set wherever the object is named: an identity
                    if (obj_type or "").lower() in ("fqdn", "dynamic", "geo",
                                                    "wildcard"):
                        self.objects[name] = _OPAQUE
                    else:
                        # a dual-stack object carries both halves
                        self.objects[name] = f"{value}|{value6}" if value6 else value
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
        """A literal as integer ranges. Both families live on one axis: IPv4
        as is, IPv6 offset by 2^32, so a range
        of one family never contains one of the other and the subset test
        stays a range test. A dual-stack value ('v4|v6') is both."""
        entry = entry.strip()
        if "|" in entry:
            out: list = []
            for part in entry.split("|"):
                sub = _AddrResolver._literal(part)
                if sub is None:
                    return None
                out.extend(sub)
            return out
        try:
            if "-" in entry and "/" not in entry:
                a, _, b = entry.partition("-")
                lo_a, hi_a = ipaddress.ip_address(a.strip()), ipaddress.ip_address(b.strip())
                if lo_a.version != hi_a.version:
                    return None
                off = _V6_OFFSET if lo_a.version == 6 else 0
                lo, hi = int(lo_a) + off, int(hi_a) + off
                return [(min(lo, hi), max(lo, hi))]
            net = ipaddress.ip_network(entry, strict=False)
            off = _V6_OFFSET if net.version == 6 else 0
            return [(int(net.network_address) + off, int(net.broadcast_address) + off)]
        except ValueError:
            return None

    def entry_ranges(self, entry: str, _seen: frozenset = frozenset()):
        """One entry → (ranges, idents) | UNIVERSAL | None (unresolved).

        ranges is a list[(lo, hi)] of everything that expanded, idents the
        set of opaque objects the entry names (an FQDN, a dynamic, geo or
        wildcard object, or a group holding one, see the module docstring).
        A name the engine does not know and a literal it cannot parse are
        None: nothing it can vouch for, so nothing it may compare."""
        if not entry or entry.lower() in ("any", "all"):
            return UNIVERSAL
        if entry == "any4":               # the D5 tokens: one family's whole range
            return ([_FULL4], set())
        if entry == "any6":
            return ([_FULL6], set())
        if entry in _seen:            # group cycle - refuse
            return None
        cached = self._cache.get(entry)
        if cached is not None:
            return cached
        result = None
        lit = self._literal(entry)
        if lit is not None:
            result = (lit, set())
        elif entry in self.groups:
            members = self.groups[entry]
            if members is not None:
                acc_r: list = []
                acc_i: set = set()
                result = (acc_r, acc_i)
                for m in members:
                    sub = self.entry_ranges(m, _seen | {entry})
                    if sub is UNIVERSAL:
                        result = UNIVERSAL
                        break
                    if sub is None:
                        result = None
                        break
                    acc_r.extend(sub[0])
                    acc_i |= sub[1]
        elif entry in self.objects:
            val = self.objects[entry]
            if val == _OPAQUE:
                result = ([], {entry})
            else:
                lit = self._literal(val)
                result = (lit, set()) if lit is not None else None
        if result is not None and result is not UNIVERSAL:
            # both families whole is universal; one family's whole range stays a range
            if _FULL4 in result[0] and _FULL6 in result[0]:
                result = UNIVERSAL
        self._cache[entry] = result
        return result

    def side(self, entries: list[str]):
        """Whole src/dst side → (kind, merged ranges, identities)."""
        if not entries:
            return (UNIVERSAL, (), frozenset())
        acc: list = []
        idents: set = set()
        for e in entries:
            r = self.entry_ranges(str(e))
            if r is UNIVERSAL:
                return (UNIVERSAL, (), frozenset())
            if r is None:
                return (UNRESOLVED, (), frozenset())
            acc.extend(r[0])
            idents |= r[1]
        return ("set", _merge_ranges(acc), frozenset(idents))


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
        # fw_service_objects is UNIQUE on (device_id, proto, port), so an
        # imported service whose tuple a vendor default already holds never
        # lands there under its own name - measured 2026-10-20 on a FortiGate
        # source: factory IMAPS holds tcp/993, `gs-svc-imaps` is absent, and
        # every rule using it lost its service dimension, which cost the
        # analysis both its verdict and its right to shadow. The imported
        # object carries the name, so read single services from there as well
        # (groups already come from here). The table keeps precedence for the
        # names it does have, so nothing that resolves today changes.
        try:
            for name, value in conn.execute(text(
                    "SELECT name, value FROM fw_imported_objects "
                    "WHERE device_id = :d AND obj_type = 'service'"),
                    {"d": device_id}):
                if not name or name in self.objects:
                    continue
                try:
                    val = json.loads(value) or {}
                except Exception:
                    continue
                proto, port = val.get("protocol"), val.get("port")
                # a known object with a protocol or a port the engine cannot
                # expand is still a known object: entry_specs makes it an
                # identity instead of leaving the name unknown
                if proto or port not in (None, ""):
                    self.objects[name] = (str(proto or "").lower(), str(port or ""))
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
        """One entry → (specs, idents) | UNIVERSAL | None.

        specs is a list[(proto, lo, hi)], idents the set of known service
        objects the engine cannot compare (a port form like '<1024', an ICMP
        object carrying a type, an empty protocol): identities, the same
        service wherever the same object is named. An unknown name is None."""
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
            result = ([(m.group(1).lower(), min(lo, hi), max(lo, hi))], set())
        elif entry in self.groups:
            members = self.groups[entry]
            if members is not None:
                acc_s: list = []
                acc_i: set = set()
                result = (acc_s, acc_i)
                for mm in members:
                    sub = self.entry_specs(mm, _seen | {entry})
                    if sub is UNIVERSAL:
                        result = UNIVERSAL
                        break
                    if sub is None:
                        result = None
                        break
                    acc_s.extend(sub[0])
                    acc_i |= sub[1]
        elif entry in self.objects:
            proto, port = self.objects[entry]
            specs = None
            if proto in ("tcp", "udp"):
                pr = self._ports(port)
                specs = [(proto, lo, hi) for lo, hi in pr] if pr else None
            elif proto in ("ip", "any"):
                result = UNIVERSAL
            elif proto and not str(port or "").strip():
                # whole-protocol service (icmp, gre, esp, ...) - compare
                # proto-level; a port qualifier (icmp type) makes it opaque
                specs = [(proto, 0, 65535)]
            if result is not UNIVERSAL:
                result = (specs, set()) if specs is not None else ([], {entry})
        self._cache[entry] = result
        return result

    def side(self, entries: list[str]):
        if not entries:
            return (UNIVERSAL, (), frozenset())
        acc: list = []
        idents: set = set()
        for e in entries:
            r = self.entry_specs(e)
            if r is UNIVERSAL:
                return (UNIVERSAL, (), frozenset())
            if r is None:
                return (UNRESOLVED, (), frozenset())
            acc.extend(r[0])
            idents |= r[1]
        # merge per proto
        per: dict[str, list] = {}
        for proto, lo, hi in acc:
            per.setdefault(proto, []).append((lo, hi))
        merged = {p: _merge_ranges(rs) for p, rs in per.items()}
        return ("set", merged, frozenset(idents))


def _dim_covers(a, b) -> bool:
    """Does dimension value a fully cover b? (addr sides)

    Both halves: b's ranges inside a's ranges and b's identities among a's.
    An identity covers only itself, never a range, and no range covers an
    identity, so a subset of both halves is a subset of the real match
    space and the verdict stays free of false positives."""
    ka, va, ia = a
    kb, vb, ib = b
    if ka == UNIVERSAL:
        return True
    if ka == UNRESOLVED or kb == UNRESOLVED or kb == UNIVERSAL:
        return False
    return ib <= ia and _ranges_subset(vb, va)


def _svc_covers(a, b) -> bool:
    ka, va, ia = a
    kb, vb, ib = b
    if ka == UNIVERSAL:
        return True
    if ka == UNRESOLVED or kb == UNRESOLVED or kb == UNIVERSAL:
        return False
    if not ib <= ia:
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
         "skipped": n_without_a_verdict,
         "candidates": n_rules_that_could_cover,
         "no_cover": {reason: n_active_rules_kept_out_by_it}}

    ``skipped`` counts the ACTIVE rules the analysis has no opinion on
    (negation, or an address or service that does not resolve) - the number
    the UI shows so that silence is not read as "reachable".

    ``candidates`` and ``no_cover`` say whether anything could have covered
    at all: a source whose rules all carry applications (narrowing on the
    target) or ``application-default`` without applications the table knows
    has no covering rule, and an empty result then means nothing. The first
    gate that kept a rule out is counted (``explain_no_cover`` words it).
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
            "apps": apps_narrow(rule, profile),
            "schedule": bool((rule.get("schedule") or "").strip()),
            "idents": bool(rule.get("source_identities")),
            "src": addr.side(rule.get("sources") or []),
            "dst": addr.side(rule.get("destinations") or []),
            "svc": _svc_side_for_rule(rule, svc),
            "appdef": _uses_app_default(rule),
            "src_zones": rule.get("src_zones") or [],
            "dst_zones": rule.get("dst_zones") or [],
        }
        prepared.append(entry)

    shadowed: dict = {}
    shadowers: dict = {}
    skipped = 0
    no_cover: dict = {}
    # Shadower candidates seen so far, in order.
    candidates: list[dict] = []
    for e in prepared:
        # Can this rule BE shadowed? (own narrowing extras are fine)
        # A dimension that does not resolve is NOT a disqualification: the
        # conservatism contract above lets a UNIVERSAL covering side cover it,
        # and _dim_covers/_svc_covers are the only place that decides. Until
        # 2026-10-20 this gate rejected such a rule before any candidate was
        # consulted, so the documented exception was unreachable - an any/any
        # accept on top left every rule with an FQDN destination unreported.
        comparable_b = not e["disabled"] and not e["negated"]
        if comparable_b and e["rhash"]:
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
        # No verdict: an ACTIVE rule the analysis had nothing to say about, so
        # that silence is never mistaken for a clean bill (the count reaches
        # the Shadowed filter and the generate's note). A disabled rule is out
        # by the operator's own choice and does not count here; a negated one
        # or one whose address or service does not resolve does, and so does
        # one naming an opaque object: the analysis can say "the same object,
        # covered", it cannot say anything about the reach of an opaque set.
        if (not e["disabled"] and e["rhash"] not in shadowed
                and (e["negated"] or e["src"][0] == UNRESOLVED
                     or e["dst"][0] == UNRESOLVED or e["svc"][0] == UNRESOLVED
                     or e["src"][2] or e["dst"][2] or e["svc"][2])):
            skipped += 1
        # Can this rule SHADOW later ones? (must be always-active superset)
        # The first gate that holds it back is counted, so an empty result
        # can say why nothing could cover (a source of application-default
        # rules, measured 2026-10-20 on PA 95: 720 of 720, no candidate).
        if e["disabled"] or e["rhash"] in shadowed:
            continue
        gate = ("negation" if e["negated"] else "applications" if e["apps"]
                else "schedule" if e["schedule"] else "identities" if e["idents"]
                else "address" if (e["src"][0] == UNRESOLVED or e["dst"][0] == UNRESOLVED)
                else ("application-default" if e["appdef"] else "service") if e["svc"][0] == UNRESOLVED
                else None)
        if gate is None:
            candidates.append(e)
        else:
            no_cover[gate] = no_cover.get(gate, 0) + 1

    return {"shadowed": shadowed, "shadowers": shadowers, "skipped": skipped,
            "candidates": len(candidates), "no_cover": no_cover}


_NO_COVER_LABELS = {
    "applications": "carry applications, which narrow a rule on this target",
    "application-default": "use application-default without applications the analysis can resolve to ports",
    "service": "name a service that does not resolve",
    "address": "name an address that does not resolve",
    "negation": "negate a side",
    "schedule": "carry a schedule",
    "identities": "carry identities",
}


def explain_no_cover(result: dict) -> str:
    """Why nothing could cover, for an empty result. '' when at least one
    rule could act as a covering rule, so the caller shows it only when the
    silence needs the explanation (CE backlog 15b)."""
    if not isinstance(result, dict) or result.get("candidates"):
        return ""
    reasons = result.get("no_cover") or {}
    if not reasons:
        return ""
    total = sum(reasons.values())
    parts = [f"{n} {_NO_COVER_LABELS.get(k, k)}"
             for k, n in sorted(reasons.items(), key=lambda kv: (-kv[1], kv[0]))]
    return (f"No rule can act as a covering rule here: of {total} active rule"
            f"{'' if total == 1 else 's'}, " + ", ".join(parts) + ".")


def _uses_app_default(rule: dict) -> bool:
    """Does the rule's service list carry the application-default token?"""
    names = rule.get("import_services")
    if isinstance(names, str):
        try:
            names = json.loads(names)
        except Exception:
            names = None
    return any(str(n).strip().lower() == "application-default" for n in (names or []) if n)


def _app_default_entries(rule: dict, names: list) -> list | None:
    """``application-default`` as literal (proto,port) entries, or None.

    It names no service object: it means "the default ports of this rule's
    applications", and the deploy loader resolves it through
    ``deploy.app_defaults`` before rendering (synthesising app-<proto>-<port>
    objects). The analysis has to read it the same way or it has no opinion on
    such a rule at all - measured 2026-10-20 on a package where 436 of 722
    rules came from application-default, which left the whole filter mute.

    An application the table does not know, or one whose default is not a
    tcp/udp port, returns None: the rule's real match space is then wider
    than anything we can name, and guessing it is how a false positive is
    born. The literal ``tcp/443`` form goes straight through the resolver's
    own spec pattern, so nothing new has to understand it.
    """
    apps = rule.get("import_applications")
    if isinstance(apps, str):
        try:
            apps = json.loads(apps)
        except Exception:
            apps = None
    try:
        from deploy.app_defaults import resolve_app_default
        specs, unresolved = resolve_app_default([a for a in (apps or []) if a])
    except Exception:
        return None
    if unresolved or not specs:
        return None
    out = [n for n in names if str(n).strip().lower() != "application-default"]
    out.extend(f"{proto}/{port}" for proto, port in specs)
    return out


def _svc_side_for_rule(rule: dict, svc: "_SvcResolver"):
    """Service dimension of one effective rule.

    api_import rules carry service NAMES (import_services JSON, already
    surfaced by the loader); log-derived rules carry proto/port columns.
    """
    # the rule's service mode (the PA switch, honoured on every target since
    # item 16): `any` is every service, the universal side
    if str(rule.get("service_override") or "").strip().lower() == "any":
        return (UNIVERSAL, (), frozenset())
    if rule.get("source_type") in ("api_import", "both"):
        names = rule.get("import_services")
        if isinstance(names, str):
            try:
                names = json.loads(names)
            except Exception:
                names = None
        if names is None:
            names = []
        names = [n for n in names if n]
        if any(str(n).strip().lower() == "application-default" for n in names):
            names = _app_default_entries(rule, names)
            if names is None:
                return (UNRESOLVED, (), frozenset())
        return svc.side(names)
    proto = (rule.get("proto") or rule.get("protocol") or "").lower()
    pf, pt = rule.get("port_from"), rule.get("port_to")
    if not proto and pf is None:
        return (UNIVERSAL, (), frozenset())
    if proto in ("tcp", "udp") and pf is not None:
        lo = int(pf)
        hi = int(pt if pt is not None else pf)
        return ("set", {proto: ((min(lo, hi), max(lo, hi)),)}, frozenset())
    if proto and pf is None:
        return ("set", {proto: ((0, 65535),)}, frozenset())
    return (UNRESOLVED, (), frozenset())
