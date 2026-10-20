# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""
Abstract base class for vendor-specific deploy drivers.

Each vendor (panw, fortinet, checkpoint, …) implements a subclass of
DeployDriver.  The driver is responsible for:

  1. Declaring vendor-specific settings (default_settings)
  2. Converting the abstract ruleset → vendor config format (generate)
  3. Pushing that config to the device via vendor API (push)
"""

from __future__ import annotations

import contextlib
import dataclasses
import ipaddress
import json
import re
import threading
from abc import ABC, abstractmethod
from typing import Any, Iterator

# ── Transport retry context ─────────────────────────────────────
#
# The drivers' HTTP helpers retry connection-level failures with a long
# push-grade backoff (up to minutes total) - right for a push, wrong for an
# interactive request: a probe/validation/catalog read against a dead box
# stalled the whole app for the length of the backoff chain (fgt-lab find,
# 2026-09-22). Interactive entry points wrap driver calls in
# `fail_fast_transport()`; the helpers consult `transport_fail_fast()` and
# skip the long backoff for that thread.

_TRANSPORT_CTX = threading.local()


@contextlib.contextmanager
def fail_fast_transport():
    """Within this context, driver transport helpers fail fast instead of
    retrying with the push backoff profile. Thread-local, reentrant."""
    prev = getattr(_TRANSPORT_CTX, "fail_fast", False)
    _TRANSPORT_CTX.fail_fast = True
    try:
        yield
    finally:
        _TRANSPORT_CTX.fail_fast = prev


def _default_rule_pristine(rule: dict) -> bool:
    """Is a marked default rule still in its canonical shape (no narrowing,
    no logging enrichment, enabled)? Only then may it be skipped as
    'matches the target built-in'. gs-side enrichment (logging/track/
    schedule/identity/apps) and import-side PA log tweaks
    (default_rule_log_mods) force the EXPRESS path so the modification
    actually lands on the target."""
    def _any(v):
        vals = [x for x in (v or []) if x and str(x).lower() != "any"]
        return not vals
    if rule.get("disabled"):
        return False
    if rule.get("default_rule_log_mods"):
        return False
    if not (_any(rule.get("sources")) and _any(rule.get("destinations"))
            and _any(rule.get("services"))):
        return False
    if (rule.get("schedule") or rule.get("source_identities")
            or (rule.get("application") or "").strip() not in ("", "any")
            or rule.get("negate_source") or rule.get("negate_destination")
            or rule.get("negate_service")):
        return False
    if (rule.get("log_forwarding") or rule.get("log_traffic")
            or rule.get("log_start") or rule.get("track_type")):
        return False
    return True


# Effective default split per platform: FGT and PA both ship
# interzone-deny + intrazone-allow; CP's Cleanup denies everything
# (zoneless); ASA's implicit deny is per-ACL (intrazone n/a).
_DENY_DEFAULTS = {"fgt-implicit-deny", "asa-implicit-deny", "pa-interzone", "aws-sg-implicit-deny",
                  "gcp-implied-deny-ingress"}


def default_rule_disposition(rule: dict, target_platform: str):
    """Classify a marked vendor-default rule for this target.

    Returns (disposition, note): disposition is None (not a default rule -
    render normally), 'skip' (target enforces the same behavior built-in),
    'express' (push as an explicit rule so the - possibly modified -
    behavior lands verbatim) or 'drop' (inexpressible; declared).

    The equivalence table is deliberately conservative: only PRISTINE
    defaults may be skipped; anything modified is expressed so what you
    see in Gateshift is what the target enforces.
    """
    kind = (rule.get("default_rule_kind") or "").strip()
    if not kind:
        return None, ""
    pristine = _default_rule_pristine(rule)
    action = (rule.get("action") or "").lower()
    deny = action in ("deny", "drop", "reject")

    if kind in _DENY_DEFAULTS and deny and pristine:
        if target_platform == "fortigate":
            return "skip", ("matches the target's built-in Implicit Deny, "
                            "not pushed")
        if target_platform == "checkpoint":
            return "skip", ("matches the target's Cleanup rule (drop all), "
                            "not pushed")
        if target_platform == "panw":
            return "skip", ("matches the target's interzone-default (deny), "
                            "not pushed")
        if target_platform == "opnsense":
            return "skip", ("matches the firewall's own default-deny at the "
                            "end of the pf ruleset, not pushed")
    if kind == "cp-cleanup" and deny and pristine:
        if target_platform == "checkpoint":
            return "skip", ("target keeps its own Cleanup rule, not pushed "
                            "twice")
        if target_platform == "opnsense":
            # pf denies everything that no rule passed, with no intrazone
            # exception - the same semantics the Cleanup rule expresses.
            return "skip", ("matches the firewall's own default-deny, not "
                            "pushed twice")
        # CP denied EVERYTHING (zoneless); FGT/PA defaults allow intrazone -
        # express an explicit deny-all so the CP semantics land verbatim.
        return "express", ("expressed explicitly: the source denied all "
                           "traffic (Cleanup), the target's built-in default "
                           "allows intrazone")
    if kind == "pa-intrazone" and action == "allow" and pristine:
        if target_platform == "panw":
            return "skip", ("matches the target's intrazone-default (allow), "
                            "not pushed")
        if target_platform == "fortigate":
            return "skip", ("matches FortiOS zone behavior (intrazone allow "
                            "by default), not pushed")
        if target_platform == "checkpoint":
            return "drop", ("intrazone-allow is not expressible on a zoneless "
                            "target. Review: traffic between same-zone "
                            "networks is handled by the rules above / Cleanup")
        if target_platform == "opnsense":
            # An interface group is a zone, but pf has no notion of traffic
            # staying inside one: a pass rule on the group would also let
            # traffic leave it, which is wider than the source intended.
            return "drop", ("pf has no intrazone default: an equivalent "
                            "rule on the interface group would also permit "
                            "traffic leaving it, so this needs a deliberate "
                            "decision")
    if kind == "pa-intrazone" and target_platform in ("fortigate", "checkpoint",
                                                      "opnsense"):
        # modified intrazone default - no generic intrazone rule type there
        return "drop", ("modified intrazone-default is not expressible on "
                        "this target: re-create the intent manually "
                        "(FortiGate: per-zone intrazone flag)")
    # Everything else (modified deny-defaults, modified pa defaults on PA,
    # unusual actions): push explicitly so the modification lands.
    return "express", ("vendor default pushed as an explicit rule so its "
                       "(modified) behavior lands verbatim")


def transport_fail_fast() -> bool:
    return bool(getattr(_TRANSPORT_CTX, "fail_fast", False))


@dataclasses.dataclass
class StepResult:
    """Result of a single push step (e.g. 'delete rules', 'push zones').

    `data` carries vendor-specific structured payload - used today by the
    Check Point driver's final push step to hand a pending-session handle
    back to the caller (so the UI can wire Publish / Discard buttons).
    Other drivers leave it None.
    """
    step: str
    success: bool
    detail: str = ""
    data: dict | None = None


@dataclasses.dataclass
class DroppedField:
    """A field on a rule that the target vendor cannot represent.

    Surfaced to the user before push so silent degradation is impossible.
    """
    rule_id: str       # rule identifier (name or pipeline id)
    field: str         # field that was dropped, e.g. "user_identity", "fqdn"
    reason: str        # why - "not supported by target", "exceeds limit", …
    fallback: str = "" # what was used instead (empty if dropped outright)
    rhash: str = ""    # the rule's content hash (hex) when the drop belongs to a rule - the Review's change log keys on it (R2)
    explained: bool = False  # the item is not pushed and that is the COMPLETE
                             # outcome - the operator skipped it, the target
                             # derives or already has it, or it is folded into
                             # something else. The Review counts these as an
                             # explanation, not as a loss (matrix 0.9.4).
    synthesized: bool = False  # the OPPOSITE of a drop: the generate CREATED an
                               # entity the source does not carry as one - a
                               # literal turned into an object, one tcp+udp
                               # service split in two, a VIP's external
                               # address. rule_id names the created entity and
                               # fallback starts with "created". The Review
                               # subtracts these from a surplus, so a plus the
                               # generate cannot account for stays visible.
    issue: str = ""            # a validation kind this drop raises on top of the
                               # report entry (UNRESOLVED_REFERENCE): the generate
                               # lifts it into validation_issues, and a blocking
                               # kind refuses the push.

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


# The validation kind a pruned rule reference raises. The Review shows it as a
# blocker (BLOCKING_VALIDATION_KINDS in main) and the push refuses it: a rule
# side that lost a member matches wider than the source, so an unresolved
# reference is never pushed as "any" without the operator's decision (2026-10-10,
# until then it was a warning and the side went out as any).
UNRESOLVED_REFERENCE = "unresolved_reference"


_REF_LITERAL_RE = re.compile(r"^(\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?|\d{1,3}(\.\d{1,3}){3}-\d{1,3}(\.\d{1,3}){3}|"
                             r"(tcp|udp|sctp|icmp)/[\w-]+)$", re.I)


def unresolved_reference(rule_id: str, field: str, lost: list, kept: list, *,
                         what: str = "address", any_word: str = "any",
                         known: set | None = None) -> "DroppedField":
    """The drop a driver records when rule references point at objects this
    push does not create (integrity invariant I1): the side is pruned and
    the entry says what the target gets instead. `what` names the object
    kind for the message (address, service), `any_word` the target's
    spelling of the catch-all, `known` the names the source defines (objects
    and groups) when the driver can tell, None when it cannot.

    The entry BLOCKS (`issue`) when a lost reference is a literal (an
    address, a CIDR, a range, proto/port: no object defines it), an
    undefined name, or when the side became empty (the catch-all would match
    everything). A known object the push declaredly does not create (empty
    group, wildcard FQDN, IPv6) while other members remain narrows the rule
    and stays a warning: its own finding says why it was dropped."""
    lost = [str(x) for x in lost]
    lits = [x for x in lost if _REF_LITERAL_RE.match(x.strip())]
    names = [x for x in lost if x not in lits]
    undefined = [n for n in names if known is None or n not in known]
    declared = [n for n in names if n not in undefined]
    parts = []
    if lits:
        parts.append(f"the {what}{'es' if what == 'address' and len(lits) > 1 else ('s' if len(lits) > 1 else '')} "
                     + ", ".join(f"'{x}'" for x in lits) + f", which no {what} object defines")
    if undefined:
        parts.append(", ".join(f"'{x}'" for x in undefined) + ", which no object or group defines")
    if declared:
        parts.append(", ".join(f"'{x}'" for x in declared)
                     + (", an object" if len(declared) == 1 else ", objects")
                     + " this push does not create (empty or dropped for this target, see its own finding)")
    reason = f"{field} references " + " and ".join(parts)
    if not kept:
        reason += f": nothing is left on the side, {any_word} would match everything"
    blocking = bool(lits or undefined) or not kept
    return DroppedField(
        rule_id=rule_id, field=field, reason=reason,
        fallback=(f"replaced by {any_word} (the side became empty)" if not kept
                  else "remaining references kept"),
        issue=UNRESOLVED_REFERENCE if blocking else "")


# ── IPv6, phase 1 of docs/IPV6_PLAN.md (D6, D7) ──────────────────────
# A target that does not carry the family yet declares every IPv6 value it
# leaves out, on the object AND on the rule that loses it. The rule-level
# declaration is action-aware: an allow rule that loses IPv6 reach is
# narrower than the source and fails closed, a warning; a deny, drop or
# reject rule that loses it lets through what the source denied, which
# fails open, so this kind blocks the push until the operator skips the rule
# or accepts the loss. A side that empties stays unresolved_reference.
IPV6_DENY_LOSS = "ipv6_deny_loss"

_ALLOW_WORDS = frozenset({"permit", "allow", "accept", "pass"})


def is_deny_action(action) -> bool:
    """The renderers' own reading: every action that is not an allow word is
    rendered as a deny (FortiOS: accept or deny, Check Point: Drop by
    default), so the loss of an IPv6 member on it widens what passes."""
    return str(action or "permit").strip().lower() not in _ALLOW_WORDS


def ipv6_value(text) -> bool:
    """True for an IPv6 address, prefix or first-last range."""
    s = str(text or "").strip()
    if ":" not in s:
        return False
    try:
        if "-" in s and "/" not in s:
            a, _, b = s.partition("-")
            return (ipaddress.ip_address(a.strip()).version == 6
                    and ipaddress.ip_address(b.strip()).version == 6)
        return ipaddress.ip_network(s, strict=False).version == 6
    except ValueError:
        return False


def ipv6_object_drop(name: str, value, note: str) -> "DroppedField":
    """The object-level declaration of an IPv6 address object a renderer
    does not write in this version; `note` says where the target keeps the
    family. The renderer remembers the name so the rules that lose the
    member are declared too (ipv6_loss)."""
    return DroppedField(rule_id=name, field="address",
                        reason=f"IPv6 address object '{value}': {note} (docs/IPV6_PLAN.md)",
                        fallback="not pushed")


def split_ipv6_loss(lost: list, ipv6_names: set | None) -> tuple[list, list]:
    """(the lost references the push declared as IPv6 drops, the rest)."""
    if not ipv6_names:
        return [], list(lost or [])
    v6 = [x for x in (lost or []) if str(x) in ipv6_names]
    return v6, [x for x in (lost or []) if str(x) not in ipv6_names]


def ipv6_loss(rule_id: str, field: str, lost: list, kept: list, *, action,
              via: str = "", via_kind: str = "group", rhash: str = "") -> "DroppedField":
    """The rule-level declaration of IPv6 members a side loses on a target
    that does not carry the family yet (D7), action-aware per D6. `via`
    names the group the members were lost through, when they were, or the
    dual-stack object whose IPv6 half is not written (`via_kind`). The
    caller keeps an emptied side on unresolved_reference, which blocks on
    its own; `kept` is what remains and is pushed."""
    names = ", ".join(f"'{x}'" for x in lost)
    if via and via_kind == "object":
        what = f"the IPv6 half {names} of object '{via}'"
    else:
        what = f"the IPv6 member{'s' if len(lost) > 1 else ''} {names}"
        if via:
            what += f" of group '{via}'"
    deny = is_deny_action(action)
    reason = (f"{field} loses {what}, which this target does not carry in this version: "
              + ("the source denied IPv6 traffic the migrated rule lets through"
                 if deny else "the migrated rule is narrower than the source"))
    return DroppedField(rule_id=rule_id, field=field, reason=reason,
                        fallback="pushed with the remaining members",
                        issue=IPV6_DENY_LOSS if deny else "", rhash=rhash)


# ── Address values across families (docs/IPV6_PLAN.md, D1, phase 2) ──
# An address object's value document carries `value` (the representative:
# the IPv4 half where the object has one, the IPv6 value of a v6-only
# object) and, for a dual-stack object, `value6`, the IPv6 half. The
# pipeline, the hashes and the resolver read the representative; the
# renderers and the objects list read both through these helpers.

def host_cidr(ip) -> str:
    """'10.1.1.1' -> '10.1.1.1/32', '2001:db8::1' -> '2001:db8::1/128'; a
    value that already carries a prefix, or is not an address, unchanged."""
    s = str(ip or "").strip()
    if not s or "/" in s:
        return s
    try:
        return f"{s}/{ipaddress.ip_address(s).max_prefixlen}"
    except ValueError:
        return s


def is_host_cidr(text) -> bool:
    """True for a /32, a /128 or a bare address."""
    s = str(text or "").strip()
    if not s:
        return False
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        return False
    return net.prefixlen == net.max_prefixlen


def bare_host(text) -> str:
    """The address without its prefix when it is a host (/32, /128), else
    the value unchanged: the pipeline stores hosts bare."""
    s = str(text or "").strip()
    if "/" in s and is_host_cidr(s):
        return s.rsplit("/", 1)[0]
    return s


def is_ip_literal(text) -> bool:
    """An address or a prefix of either family (not a range, not a name)."""
    s = str(text or "").strip()
    if not s or "-" in s and ":" not in s:
        return False
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def catch_all_cidr(ip) -> str:
    """The default route of the address's family: '::/0' or '0.0.0.0/0'."""
    return "::/0" if ":" in str(ip or "") else "0.0.0.0/0"


def object_values(val) -> list[str]:
    """The address values an object carries: [value] or [value, value6]."""
    val = val if isinstance(val, dict) else {}
    out = [str(val.get("value") or "").strip()]
    v6 = str(val.get("value6") or "").strip()
    if v6:
        out.append(v6)
    return [x for x in out if x]


def is_dual_stack(val) -> bool:
    return bool(isinstance(val, dict) and val.get("value") and val.get("value6"))


def nat_rule_ipv6(n: dict, ipv6_names: set | None) -> str | None:
    """The first IPv6 value or IPv6-carrying object a NAT rule names on any
    of its address fields, or None (docs/IPV6_PLAN.md, section 8: NAT66,
    NPTv6 and NAT64 are not built on spec, so such a rule is declared and
    not pushed by the targets that cannot carry it)."""
    vals: list[str] = []
    for key in ("orig_src", "orig_dst", "trans_src", "trans_dst"):
        v = n.get(key)
        if isinstance(v, str) and v.strip().startswith("["):
            try:
                v = json.loads(v)
            except Exception:
                pass
        if isinstance(v, list):
            vals.extend(str(x) for x in v if x)
        elif v:
            vals.extend(str(x).strip() for x in str(v).split(",") if x.strip())
    for v in vals:
        if ipv6_value(v) or (ipv6_names and v in ipv6_names):
            return v
    return None


# The D5 catch-all tokens and the prefix each stands for (docs/IPV6_PLAN.md,
# phase 4): a source of one family per rule (FortiOS, OPNsense, Cisco ASA's
# any4/any6, FDM's any-ipv4/any-ipv6) emits them, a target that has no
# catch-all of one family creates the object.
CATCH_ALL_VALUES = {"any4": "0.0.0.0/0", "any6": "::/0"}
CATCH_ALL_NAMES = {"any4": "any-ipv4", "any6": "any-ipv6"}


def used_catch_all_tokens(*rule_lists) -> set[str]:
    """The family tokens ('any4', 'any6') the given rule lists name on any
    address side (rules, NAT rules, policy routes)."""
    toks: set[str] = set()
    for rules in rule_lists:
        for r in rules or ():
            for key in ("sources", "destinations", "orig_src", "orig_dst", "trans_src", "trans_dst"):
                v = r.get(key)
                vals = v if isinstance(v, list) else ([v] if isinstance(v, str) else [])
                toks |= {x for x in vals if x in CATCH_ALL_VALUES}
    return toks


def catch_all_objects(tokens, address_objects, address_groups) -> tuple[list[dict], dict[str, str]]:
    """The address objects a target creates for the tokens it meets, named
    any-ipv4 / any-ipv6 (suffixed while the source holds the name), and the
    token -> name map for its lookup."""
    taken = ({str(o.get("name") or "") for o in (address_objects or ())}
             | {str(g.get("name") or "") for g in (address_groups or ())})
    objs: list[dict] = []
    names: dict[str, str] = {}
    for tok in sorted(tokens):
        if tok not in CATCH_ALL_VALUES:
            continue
        name = CATCH_ALL_NAMES[tok]
        while name in taken:
            name += "-gs"
        taken.add(name)
        objs.append({"name": name, "obj_type": "address",
                     "value": {"type": "ip-netmask", "value": CATCH_ALL_VALUES[tok],
                               "description": "the catch-all of one address family (created by Gateshift)"}})
        names[tok] = name
    return objs, names


def selector_family(sel: dict) -> int | None:
    """4 or 6 for a traffic selector whose local and remote prefix are of
    one family (an absent side takes the other's), None for a mixed pair,
    which no vendor can express (docs/IPV6_PLAN.md, phase 5)."""
    fams = set()
    for key in ("local", "remote"):
        v = str((sel or {}).get(key) or "").strip()
        if v:
            fams.add(6 if ":" in v else 4)
    if len(fams) == 1:
        return fams.pop()
    return None if fams else 4


def split_selectors_by_family(selectors) -> tuple[list[dict], list[dict], list[dict]]:
    """(IPv4 pairs, IPv6 pairs, mixed pairs) of a tunnel's traffic selectors."""
    v4: list[dict] = []
    v6: list[dict] = []
    mixed: list[dict] = []
    for s in selectors or []:
        fam = selector_family(s)
        (v4 if fam == 4 else v6 if fam == 6 else mixed).append(s)
    return v4, v6, mixed


def mixed_selector_drop(rule_id: str, sel: dict):
    """The declaration of a selector pair of two families."""
    return DroppedField(
        rule_id=rule_id, field="traffic_selector",
        reason=f"selector pairs '{sel.get('local')}' with '{sel.get('remote')}', one address "
               "family each: no vendor matches IPv4 traffic against an IPv6 prefix",
        fallback="selector left out")


def peer_address6_drop(rule_id: str, addr6: str, vendor: str):
    """The declaration of a peer's second (IPv6) address a target binds no
    tunnel to (the tunnel negotiates over the IPv4 address)."""
    return DroppedField(
        rule_id=rule_id, field="peer_address6",
        reason=f"the peer also has the IPv6 address {addr6}, and {vendor} binds a tunnel "
               "to one address family",
        fallback="the tunnel negotiates over the IPv4 address")


def split_dual_stack_objects(objects: list, safe_name, dropped: list | None = None
                             ) -> tuple[list, list]:
    """For a target whose address object holds ONE value (PAN-OS): a
    dual-stack object becomes two objects, <name>-ip4 and <name>-ip6, under
    a static group that keeps the source's name, so every reference to the
    name keeps binding (both families in one group and one rule, section 2a).
    Returns (objects, groups) with the originals replaced. The IPv4 half
    takes the source entry's place and the IPv6 half and the group are
    declared as synthesized (the Review counts one source object against
    the two halves: one plus, not two)."""
    out_objs: list = []
    out_grps: list = []
    for obj in objects or []:
        val = obj.get("value") if isinstance(obj, dict) else None
        if not is_dual_stack(val):
            out_objs.append(obj)
            continue
        name = str(obj.get("name") or "")
        n4, n6 = safe_name(f"{name}-ip4"), safe_name(f"{name}-ip6")
        desc = (val.get("description") or "")
        out_objs.append({**obj, "name": n4, "value": {**val, "value": val["value"], "description": desc}})
        out_objs[-1]["value"].pop("value6", None)
        out_objs.append({**obj, "name": n6, "value": {**val, "value": val["value6"], "description": desc}})
        out_objs[-1]["value"].pop("value6", None)
        out_grps.append({"name": name, "value": {"type": "static", "members": [n4, n6], "description": desc}})
        if dropped is not None:
            dropped.append(DroppedField(
                rule_id=n6, field="address", synthesized=True,
                reason=f"'{name}' carries both families and this target holds one value per object",
                fallback=f"created as the IPv6 half of '{name}', next to the IPv4 half '{n4}'"))
            dropped.append(DroppedField(
                rule_id=name, field="address_group", synthesized=True,
                reason=f"'{name}' carries both families. The group keeps the source name so references stay valid",
                fallback=f"created from the two halves of '{name}'"))
    return out_objs, out_grps


# ── Management addresses (docs/IPV6_PLAN.md, D3 option A+) ───────────
class ManagementAddressError(RuntimeError):
    """A management address this version does not reach."""


def management_host(host, vendor: str = "") -> str:
    """The host part of a management address, refused when it is an IPv6
    literal: bare, bracketed, or with a zone index. Every driver builds its
    base URL through this, so a v6 address fails closed with a sentence
    before a socket opens. The Check Point splitter used to turn
    '2001:db8::5' into the host '2001', a bare DNS label that resolves
    wherever a search domain exists, and then pushed there (defect 4)."""
    text_ = str(host or "").strip()
    bare = text_[1:-1] if text_.startswith("[") and text_.endswith("]") else text_
    try:
        ipaddress.IPv6Address(bare.split("%", 1)[0])
    except ValueError:
        return text_
    raise ManagementAddressError(
        f"{vendor + ': ' if vendor else ''}the management address '{text_}' is an IPv6 "
        "address, which this version does not reach. Register the device under its IPv4 "
        "address or a host name.")


class DropTagger:
    """Wraps a renderer's `dropped` list so every DroppedField appended while
    `current` names a rule hash carries that hash (docs/REVIEW_TAB_DESIGN.md,
    R2: the change log keys on it). One assignment per rule iteration instead
    of one keyword per drop site; everything else delegates to the list, and
    the driver's final `[d.to_dict() for d in dropped]` iterates through."""
    def __init__(self, target: list):
        self.target = target
        self.current = ""
    def append(self, d) -> None:
        if isinstance(d, DroppedField) and not d.rhash and self.current:
            d.rhash = self.current
        self.target.append(d)
    def extend(self, items) -> None:
        for d in items:
            self.append(d)
    def __len__(self): return len(self.target)
    def __iter__(self): return iter(self.target)
    def __getitem__(self, i): return self.target[i]
    def __bool__(self): return True


def iface_subnets(interfaces: list[dict], vr_name: str | None = None) -> list:
    """The (network, interface name) pairs of these interfaces' own addresses.

    `vr_name` keeps only the interfaces of one virtual router, which is what a
    route's egress derivation needs: a gateway is on-link only within the
    routing table that holds the route. An address that does not parse is
    skipped, never guessed.
    """
    out = []
    for iface in interfaces or []:
        name = iface.get("interface_name") or iface.get("name") or ""
        if not name:
            continue
        if vr_name is not None and (iface.get("vr_name") or "default") != vr_name:
            continue
        ips = iface.get("ip_addresses") or []
        if isinstance(ips, str):
            try:
                ips = json.loads(ips)
            except Exception:
                ips = []
        for ip_str in ips:
            try:
                out.append((ipaddress.ip_network(str(ip_str), strict=False), name))
            except (ValueError, TypeError):
                continue
    return out


def egress_for_next_hop(next_hop: str, iface_nets: list) -> str | None:
    """The interface a packet to this next hop leaves through, or None.

    A next hop is "on-link" when it sits inside an interface's own subnet: the
    firewall can then ARP for it there. The longest prefix wins, as every
    vendor's FIB does it. None means no interface subnet holds it ("off-link"),
    and that is the case the targets disagree about: FortiOS refuses a static
    route without a device, PAN-OS refuses the whole candidate, Check Point's
    Gaia takes the route and leaves it inactive until the gateway becomes
    reachable (CE backlog 1). A next hop that is not a plain address returns
    None too - the caller decides what that means for its vendor.

    `iface_nets` comes from iface_subnets().
    """
    try:
        addr = ipaddress.ip_address(str(next_hop or "").strip())
    except ValueError:
        return None
    best = None
    for net, name in iface_nets:
        if addr in net and (best is None or net.prefixlen > best[0].prefixlen):
            best = (net, name)
    return best[1] if best else None


def error_hint(hint_fns, ctx: dict) -> str:
    """Return the first non-empty hint a driver's error-hint functions produce
    for the push-error `ctx`, or '' if none apply.

    Lets each driver keep a readable TABLE of (condition → explanatory message)
    instead of inline if/elif chains scattered at the push error sites - the
    push loop builds a `ctx` dict (step, errcode, status_code, cli_error, entry,
    …) at the failure point and asks the driver's `_ERROR_HINTS` list to explain
    it. Each fn takes `ctx` and returns the hint text *with its leading
    ' - …' separator* when it applies, else ''. A raising fn is skipped (a
    broken explainer must never mask the underlying error)."""
    for fn in hint_fns:
        try:
            h = fn(ctx)
            if h:
                return h
        except Exception:
            continue
    return ""


# ── Rollback of a broken-off push (docs/PUSH_ROLLBACK_PLAN.md) ───────────────
# A push that dies after it started writing must not leave the target in a
# state that poisons the next attempt, and must not destroy what an EARLIER
# push legitimately put there. Every vendor answers that differently, because
# their transaction models differ, so the driver DECLARES what it can undo and
# the platform owns the vocabulary, the arming rule and the phrasing.
#
#   none      the vendor has no transaction: a push is live the moment it is
#             written, so there is nothing to take back.
#   session   the push stages into a session of its own and discards it, which
#             touches exactly its own changes.
#   snapshot  the push stages into a candidate configuration shared with
#             everyone else, so taking it back means restoring a snapshot of
#             that candidate from before the push.
ROLLBACK_KINDS = ("none", "session", "snapshot")

# What the operator is told about the target after a push broke off. One
# sentence per kind, so every vendor says the same kind of thing.
_ROLLBACK_PHRASE = {
    "none": ("this vendor applies a push as it is written, so what went out "
             "before the failure stays on the target"),
    "session": ("the staged changes were discarded, so the target is "
                "untouched by this push"),
    "snapshot": ("the target is back to the state it had before this push"),
}

# A push step whose name starts with one of these WROTE to the target. The
# naming convention is the contract between a driver's push loop and its
# rollback: a failure BEFORE the first such step must never roll back, because
# at that point nothing of ours is on the target and a rollback would only
# discard someone else's work.
MODIFYING_STEP_PREFIXES = ("Delete ", "Push ")


def step_modifies(step: str) -> bool:
    """True when this step's name says it wrote to the target."""
    return str(step or "").startswith(MODIFYING_STEP_PREFIXES)


def rollback_phrase(kind: str) -> str:
    """The operator-facing guarantee for a rollback of this kind."""
    return _ROLLBACK_PHRASE.get(kind, _ROLLBACK_PHRASE["none"])


class DeployDriver(ABC):
    """Base class every vendor driver must implement."""

    platform: str  # e.g. "panw", "fortinet", "checkpoint"

    # What this driver can take back when a push breaks off mid-way, one of
    # ROLLBACK_KINDS. Declared, never inferred: a vendor without a transaction
    # says so, instead of leaving the operator to guess (D2).
    rollback_kind: str = "none"

    @abstractmethod
    def default_settings(self) -> list[dict]:
        """Return vendor-specific setting definitions for the UI.

        Each dict:
            {"key": "rule_prefix", "label": "Rule Prefix", "type": "text",
             "default": "Gateshift-", "placeholder": "e.g. Gateshift-"}
        Supported types:
          - ``text``           - free-text input
          - ``select``         - static dropdown, options in ``options`` list
          - ``select_remote``  - dropdown whose options are fetched live from
                                 the device via ``setting_options(...)``. The
                                 driver MUST implement ``setting_options`` for
                                 every key declared as ``select_remote``.
        """

    def setting_options(
        self,
        *,
        device: dict,
        key: str,
        settings: dict[str, str],
    ) -> list[str]:
        """Return the live option list for a ``select_remote`` setting.

        Called when the user opens / refreshes a ``select_remote`` dropdown
        in the UI. Drivers should query the device (via API/SSH/whatever the
        vendor offers) and return a flat list of valid string choices for
        the given key.

        ``settings`` carries the *currently saved* values for this device so
        dependent dropdowns can scope their query (e.g. CP layer-list filtered
        by the chosen policy_package).

        Default: not implemented. Drivers without any select_remote settings
        don't need to override.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not provide options for {key!r}"
        )

    @abstractmethod
    def generate(
        self,
        *,
        rules: list[dict],
        address_objects: list[dict],
        address_groups: list[dict],
        service_objects: list[dict],
        service_groups: list[dict],
        zones: list[dict],
        interfaces: list[dict],
        routes: list[dict],
        vrfs: list[dict],
        nat_rules: list[dict],
        settings: dict[str, str],
        tp_configs: list[dict] = (),
    ) -> tuple[dict[str, str], list[dict]]:
        """Convert the abstract ruleset into vendor-specific config sections.

        Returns (sections, dropped_fields):
          sections: dict mapping section name → rendered config string
                    e.g. {"Security Rules": "<security>…</security>", …}
          dropped_fields: list of DroppedField.to_dict() for every field on
                    every rule that the target cannot represent. Empty list
                    if nothing was dropped. UI surfaces this before push.

        ``tp_configs`` carries the per-(target, TP-layer) generator config
        rows loaded from ``fw_tp_layer_config``: each entry has keys
        ``layer_name``, ``strategy``, ``params``. Drivers without a TP
        rulebase concept (PA, Fortinet) ignore this argument. The CP
        driver uses it to emit a ``"TP Rules"`` section consumed by push.
        """

    @abstractmethod
    def push(
        self,
        *,
        device: dict,
        config: dict[str, str],
        strand: str = "policy",
    ) -> Iterator[StepResult]:
        """Push config to the device.  NO auto-commit.

        device: dict with mgmt_ip, mgmt_port, api_key, platform, …
        config: output of generate()
        strand: ``'policy'`` (rules / objects / NAT) or ``'network'``
                (zones / interfaces / routes). Each strand pushes only its
                own slice of ``config``; cross-strand sections are ignored.
                Two independently triggerable push buttons in the UI map to
                the two strands - see project_network_strand.md.

        Yields StepResult for each phase (enables live streaming).
        Stops on first failure.

        For vendors with a session-scoped staging model (e.g. Check Point),
        the final StepResult must set ``data["session_handle"]`` to a
        serializable dict that can be passed to ``commit_session`` /
        ``discard_session`` later. Vendors with global candidate-config
        (e.g. PAN-OS) leave ``data`` None - the user commits via the
        device UI instead.
        """

    def commit_session(
        self,
        *,
        device: dict,
        handle: dict,
    ) -> Iterator[StepResult]:
        """Finalize a staged push (publish / commit-on-management).

        Default: not implemented. Vendors with session-scoped staging
        (Check Point) override; vendors without a separate management
        commit step (PAN-OS, where the user commits on the device)
        don't need this and the UI shouldn't call it for them.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support session-scoped commit"
        )

    def discard_session(
        self,
        *,
        device: dict,
        handle: dict,
    ) -> Iterator[StepResult]:
        """Drop a staged push without committing it. See commit_session."""
        raise NotImplementedError(
            f"{type(self).__name__} does not support session-scoped discard"
        )

    def list_target_interfaces(self, *, device: dict) -> list[dict]:
        """Read the target's current interface configuration.

        Returns a list of dicts, one per interface, with at least:
          - ``name`` (str)
          - ``type`` (str, e.g. "ethernet", "tunnel", "loopback")
          - ``ip_addresses`` (list[str], CIDR strings; may be empty)
          - ``zone`` (str | None) - current zone binding at target, if known
          - ``description`` (str | None)
        Drivers may include extra vendor-specific keys; the UI ignores them.

        Snapshot for Discover-as-Verarbeitung-input (see
        project_network_strand.md "Target-read"). Stored in
        ``fw_target_discover``; the user explicitly saves selected rows into
        the source's ``fw_interfaces`` via the ``/network/discover/.../save``
        route. Never silent auto-merge into push.

        Default: NotImplementedError. UI hides the panel for drivers that
        don't implement it.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support target-interface discovery"
        )

    def list_target_zones(self, *, device: dict) -> list[dict]:
        """Read the target's current zone configuration.

        Returns a list of dicts, one per zone, with at least:
          - ``name`` (str)
          - ``interfaces`` (list[str]) - bound interface names
          - ``zone_type`` (str | None, e.g. "layer3")
        See ``list_target_interfaces`` for semantics.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support target-zone discovery"
        )

    def list_target_routes(self, *, device: dict) -> list[dict]:
        """Read the target's current routing table.

        Returns a list of dicts, one per route, with at least:
          - ``prefix`` (str, CIDR)
          - ``interface_name`` (str | None)
          - ``next_hop`` (str | None)
          - ``vr_name`` (str | None) - VR / VDOM / VS the route belongs to
          - ``is_connected`` (bool)
        See ``list_target_interfaces`` for semantics.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support target-route discovery"
        )

    def list_url_categories(self, *, device: dict) -> list[str]:
        """Read the target's predefined URL / application-site CATEGORY catalog
        - the category names a cross-vendor decryption rule can reference
        (site-category). Returns a sorted list of name strings.

        Snapshot for the URL-category mapping (project_cp_url_category_map_plan):
        the operator attaches a source category to one of these; the resolver
        name-matches against them. Default: NotImplementedError (target has no
        URL-category catalog, e.g. FortiGate does TLS inspection via profiles).
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not expose a URL-category catalog"
        )

    def list_target_vrfs(self, *, device: dict) -> list[dict]:
        """Read the target's VRF / virtual-router / VDOM list.

        Returns a list of dicts, one per VRF, with at least:
          - ``name`` (str)
          - ``interface_members`` (list[str])
          - ``properties`` (dict | None) - vendor-opaque (e.g. ``ecmp``)
        See ``list_target_interfaces`` for semantics.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support target-VRF discovery"
        )

    def list_zone_protection_profiles(self, *, device: dict) -> list[dict]:
        """Read the target's zone-protection-profile catalog (PA-specific).

        Returns ``[{"name": str, "description": str | None}, ...]``. Used by
        Enrichment > Zone Mapping > Interfaces to populate the
        ``pa_zone_protection_profile`` dropdown in the bulk-apply form.

        Default: empty list. Vendors without a zone-protection-profile
        concept (Forti, CP, ASA, OPNsense, FTD) leave this as-is - the
        Bulk-Form catalog field stays empty and the schema-driven UI shows
        a "No catalog" hint.
        """
        return []

    def list_target_addresses(self, *, device: dict) -> list[dict]:
        """Read the target's address-object catalog.

        Returns ``[{"name": str, "type": str | None, "value": str | None}, ...]``.
        Used by Enrichment > NAT > Mapping (Phase F) to populate per-rule
        translation-object pickers so cross-vendor pushes can re-bind
        trans_src / trans_dst to objects that exist at the target.

        Default: empty list. Source-only vendors (ASA, OPNsense) leave
        this as-is.
        """
        return []

    def list_target_services(self, *, device: dict) -> list[dict]:
        """Read the target's service-object catalog.

        Returns ``[{"name": str, "proto": str | None, "port": str | None}, ...]``.
        Same use-case as ``list_target_addresses`` but for service refs
        (NAT-rule trans_service slots when present).

        Default: empty list.
        """
        return []

    def list_security_profiles(self, *, device: dict) -> dict[str, list[dict]]:
        """Read the target's per-rule attachable profile catalog.

        Returns ``{category: [{"name": str, "predefined": bool}, ...]}`` where
        keys are vendor-specific category labels (e.g. PA: ``antivirus``,
        ``url-filtering``, ``profile-group``). The ``predefined`` flag marks
        vendor-shipped entries (cannot be edited by the customer) so the UI
        can distinguish them from user-created ones. Read-only catalog query
        - surfaces what's there; Gateshift doesn't manage profile contents. The UI
        iterates whatever the driver returns; it doesn't enumerate categories
        itself.

        Out-of-scope catalog read (see project_design_decisions.md
        "Target-read scoping"): customer manages these objects, Gateshift only
        observes/references them.

        Default: NotImplementedError. Drivers without remote catalog reads
        leave this unimplemented; the Enrichment vendor sub-tab shows an
        "unsupported" hint.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support security-profile listing"
        )

    def list_applications(self, *, device: dict) -> dict[str, list[dict]]:
        """Read the target's user-curated application catalog.

        Returns ``{category: [{"name": str, "predefined": bool}, ...]}``.
        Same shape as ``list_security_profiles`` so the UI can reuse the
        catalog renderer. Categories are vendor-specific (PA: ``application``
        custom + ``application-group`` + ``application-filter``). Predefined
        vendor app catalogs (PA: thousands of content-DB apps) are
        intentionally NOT enumerated - only customer-curated objects are
        surfaced, mirroring the rule-attachment dropdown semantics.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support application listing"
        )

    def list_threat_layers(self, *, device: dict) -> list[dict]:
        """Read the target's Threat-Prevention layer catalog.

        Returns a list of dicts, one per TP-layer:
          - ``name`` (str)         - full layer name (Gateshift stores this as key)
          - ``shared`` (bool)      - shared across packages?
          - ``uid`` (str | None)
        Read-only catalog query for the CP TP-enrichment UI; PA/Fortinet do
        not implement this (TP attaches per-rule via security-profile slot).

        Default: NotImplementedError. UI hides the TP-layer dropdown for
        drivers that don't implement it.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support threat-layer listing"
        )

    def list_threat_profiles(self, *, device: dict) -> list[dict]:
        """Read the target's Threat-Prevention profile catalog.

        Returns a list of dicts, one per TP-profile:
          - ``name`` (str)         - e.g. Basic, Optimized, Strict
          - ``predefined`` (bool)  - vendor-shipped, not user-editable
          - ``uid`` (str | None)
        Read-only; Gateshift only references profiles, doesn't manage their contents.

        Default: NotImplementedError. See ``list_threat_layers``.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support threat-profile listing"
        )

    def generate_tp_rules(
        self,
        *,
        layer_name: str,
        strategy: str,
        params: dict,
        rules: list[dict],
        zones: list[dict],
        address_objects: list[dict],
        address_groups: list[dict],
    ) -> list[dict]:
        """Deterministically generate TP-rules from a Strategy + Params.

        Pure function - no I/O - so the Preview UI and the eventual Push
        call the same code and there's no drift between what the user saw
        and what gets pushed.

        Strategy ``security-ruleset`` (V1):
          - Walk ``rules`` (the source Access-Rules) and emit one TP-rule
            per group-key (depends on ``params['scope']``).
          - Sane V1 default scope: ``source=destination=service=Any``,
            ``protected-scope`` = mapping target (e.g. dst-cidrs).

        Returns a list of dicts with the TP-rule shape (see
        project_cp_tp_rulebase_api.md for the response shape).

        Default: NotImplementedError. Drivers without a TP rulebase concept
        leave this unimplemented.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support TP-rule generation"
        )

    def canonical_port_apps(self) -> dict[tuple[str, int], list[str]]:
        """Curated (proto, port) → [app-name, …] map for the port→app
        auto-binder's tier-3 fallback.

        Drivers whose ``list_applications`` catalog already carries clean
        ``default_ports`` for every relevant app (CP's curated list) can
        leave this empty - the predefined-index tier resolves them.

        PA needs this because its predefined catalog's ``default_ports`` is
        incomplete (``imap`` handles 143 AND 993, but lists only tcp/143);
        the curated map fills those gaps. Names returned here are validated
        against the live catalog before use, so stale entries are harmless.
        """
        return {}


# ── Iface-name classification (vendor-agnostic) ──────────────────
#
# Both PA and CP encode iface type in the name. Single helper so both
# collectors classify identically, and so the lifespan-time backfill in
# main.py uses the same rules. CP-Network-Push V1 needs (parent, tag) for
# VLAN sub-IFs because Gaia's add-vlan-interface is typed.

import re as _re

_RE_TUNNEL    = _re.compile(r"^tunnel(\.|$)", _re.IGNORECASE)
_RE_LOOPBACK  = _re.compile(r"^(loopback|lo[0-9])", _re.IGNORECASE)
# 'bond' is the canonical type for both CP `bondN` and PA `aeN` aggregates.
# Vendor name pattern differs; canonical iface_type collapses both so the
# rest of the code (validation, push routing, member lookup) treats them
# uniformly.
_RE_BOND      = _re.compile(r"^(bond|ae)[0-9]+$", _re.IGNORECASE)
_RE_VLAN_TAG  = _re.compile(r"^[0-9]+$")


def parse_iface_name(name: str) -> tuple[str, str | None, int | None]:
    """Classify an interface name into (iface_type, parent, vlan_tag).

    Order is most-specific first: tunnel/loopback/bond names that happen to
    contain a dot must NOT be classified as VLAN. Returns:
      - iface_type: 'physical' | 'vlan' | 'loopback' | 'bond' | 'tunnel'
      - parent: parent IF name for VLAN sub-IFs (incl. VLAN-on-bond), else None
      - vlan_tag: VLAN ID for VLAN sub-IFs, else None
    """
    if not name:
        return "physical", None, None
    if _RE_TUNNEL.match(name):
        return "tunnel", None, None
    if _RE_LOOPBACK.match(name):
        return "loopback", None, None
    if _RE_BOND.match(name):
        return "bond", None, None
    if "." in name:
        head, _, tail = name.rpartition(".")
        if head and _RE_VLAN_TAG.match(tail):
            return "vlan", head, int(tail)
    return "physical", None, None


# ── Driver registry ──────────────────────────────────────────────

DRIVERS: dict[str, type[DeployDriver]] = {}


def register_driver(cls: type[DeployDriver]) -> type[DeployDriver]:
    """Class decorator - registers a driver by its platform attribute."""
    DRIVERS[cls.platform] = cls
    return cls


def expand_multiproto_services(
    service_objects: list[dict], service_groups: list[dict],
    dropped: list | None = None,
) -> tuple[list[dict], list[dict]]:
    """Fan out a source service that packs several (proto, port) combos into
    one object - multiple portrange families (Forti TCP+UDP+SCTP) and/or a
    space-separated port LIST per family (Forti ``"88 464"``) - into one
    single-(proto,port) service per combo PLUS a service-group with the
    ORIGINAL name holding them. Existing references (group members, rules)
    then stay valid against the group.

    Vendor-neutral: input and output are agnostic shapes
    (``{name, value:{protocol, port, description}}`` services,
    ``{name, value:{members, description}}`` groups). Single-proto, multi-port
    services on a target that natively supports them (Forti) should NOT call
    this - it is for targets whose service object is single-(proto,port)
    (Check Point, PAN-OS). A whitespace token is itself a single port ("88")
    or a hyphen range ("1-1024"), both valid. Single-combo services pass
    through (normalized to {protocol, port})."""
    families = (("tcp_portrange", "tcp"), ("udp_portrange", "udp"),
                ("sctp_portrange", "sctp"))
    new_objs: list[dict] = []
    extra_groups: list[dict] = []
    for obj in service_objects:
        val = obj.get("value") or {}
        name = obj.get("name") or ""
        desc = val.get("description") or ""

        combos: list[tuple[str, str]] = []
        fam_present = [(k, p) for k, p in families if str(val.get(k) or "").strip()]
        if fam_present:
            for k, proto in fam_present:
                for port in str(val.get(k)).split():
                    combos.append((proto, port))
        else:
            proto = (val.get("protocol") or "").strip().lower()
            portfield = str(val.get("port") or "").strip()
            if proto in ("tcp", "udp") and " " in portfield:
                for port in portfield.split():
                    combos.append((proto, port))

        if not combos:
            new_objs.append(obj)            # icmp / single-port / other → as-is
            continue
        if len(combos) == 1:
            proto, port = combos[0]
            new_objs.append({"name": name,
                             "value": {"protocol": proto, "port": port,
                                       "description": desc}})
            continue

        members: list[str] = []
        seen: set[str] = set()
        for proto, port in combos:
            sub = f"{name}_{proto}_{port}"
            if sub in seen:
                continue
            seen.add(sub)
            new_objs.append({"name": sub,
                             "value": {"protocol": proto, "port": port,
                                       "description": desc}})
            members.append(sub)
        extra_groups.append({"name": name,
                             "value": {"members": members, "description": desc}})
        if dropped is not None:
            # One source service became len(members) services and a group.
            # The first service stands for the source one; every further
            # service and the group are entities the generate created - said
            # so, or the Review's surplus check reads them as unexplained
            # (a FortiGate source: 30 such services, +64 and +30 on PAN-OS).
            for sub in members[1:]:
                dropped.append(DroppedField(
                    rule_id=sub, field="service", synthesized=True,
                    reason=f"split of '{name}': several protocols in one "
                           "source service, one protocol per target service",
                    fallback=f"created by splitting '{name}'"))
            dropped.append(DroppedField(
                rule_id=name, field="service_group", synthesized=True,
                reason=f"split of '{name}': the group keeps the source name so "
                       "references stay valid",
                fallback=f"created by splitting '{name}'"))
    # Prepend synthetic (leaf) groups so they're created before any group that
    # references them.
    return new_objs, extra_groups + list(service_groups)


def post_nat_destination_hits(rules: list[dict], nat_rules: list[dict],
                              address_objects: list[dict]) -> dict[str, list[dict]]:
    """Rules of a source that matched the TRANSLATED destination.

    A FortiGate in central NAT mode translates through its VIPs before the
    policy lookup, so its rules for a published server name the server's
    mapped (internal) address; the importer synthesises one dest-NAT rule
    per VIP and marks it ``central_nat`` with the VIP's name
    (docs/FGT_POLICY_MODE_PLAN.md, D11 and D12). Returns, per rule name, the
    destinations that are such a mapped address with the VIP and its
    external address, and nothing for a source that matched before
    translation (no marked rule)."""
    mapped: dict[str, list[tuple[str, str]]] = {}
    for n in nat_rules or ():
        props = n.get("properties")
        if isinstance(props, str):
            try:
                props = json.loads(props)
            except Exception:
                props = {}
        props = props or {}
        if not props.get("central_nat") or not props.get("vip_ref"):
            continue
        trans = str(n.get("trans_dst") or "").strip()
        orig = (n.get("orig_dst") or [""])[0]
        if trans and orig and str(orig).lower() != "any":
            mapped.setdefault(trans, []).append((str(props["vip_ref"]), str(orig)))
    if not mapped:
        return {}
    addr_ip: dict[str, str] = {}
    for o in address_objects or ():
        v = o.get("value") or {}
        if not isinstance(v, dict) or (v.get("type") or "") not in ("ip-netmask", "ipmask"):
            continue
        ip, _, mask = str(v.get("value") or "").partition("/")
        if ip and mask.strip() in ("", "32"):
            addr_ip[o.get("name") or ""] = ip.strip()
    hits: dict[str, list[dict]] = {}
    for r in rules or ():
        for d in (r.get("destinations") or []):
            ip = addr_ip.get(d) or (d if d in mapped else None)
            for vip, ext in mapped.get(ip or "", []):
                hits.setdefault(str(r.get("rule_name") or ""), []).append(
                    {"vip": vip, "ext_ip": ext, "mapped_ip": ip, "destination": d})
    return hits


def widen_post_nat_destinations(rules: list[dict], nat_rules: list[dict],
                                address_objects: list[dict], dropped: list,
                                target: str) -> list[dict]:
    """On a target that matches the ORIGINAL destination (PAN-OS, Check
    Point, a FortiGate in policy-NAT mode), a rule of a central-NAT source
    (post_nat_destination_hits) also needs the VIP as a destination: the
    VIP is an address object on PAN-OS and Check Point (its external
    address) and the VIP itself on a FortiGate, so the VIP's name is added
    beside the mapped address, which keeps matching the internal traffic.
    Returns the rules with the widened copies, declares each one."""
    hits = post_nat_destination_hits(rules, nat_rules, address_objects)
    if not hits:
        return list(rules or ())
    out: list[dict] = []
    for r in rules or ():
        h = hits.get(str(r.get("rule_name") or ""))
        if not h:
            out.append(r)
            continue
        dests = list(r.get("destinations") or [])
        added = [x["vip"] for x in h if x["vip"] not in dests]
        added = list(dict.fromkeys(added))
        if not added:
            out.append(r)
            continue
        nr = dict(r)
        nr["destinations"] = dests + added
        out.append(nr)
        dropped.append(DroppedField(
            rule_id=str(r.get("rule_name") or ""), field="dnat_post_nat_dst",
            reason="the source matched this destination after its dest-NAT "
                   "(FortiOS central NAT), " + target + " matches before it: the "
                   "VIP added as a destination (" + ", ".join(
                       f"{x['vip']} = {x['ext_ip']} for {x['destination']}" for x in h
                       if x["vip"] in added) + ")",
            fallback="destination widened by the VIP's external address, the "
                     "mapped address stays for the internal traffic",
            explained=True))
    return out
