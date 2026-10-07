# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""
Vendor-independent push-integrity invariants.

Every deploy driver has to satisfy the same handful of structural rules, no
matter which vendor it renders for. Before this module each driver
implemented them separately - and the QA campaign (2026-08-07) found five
defects that were exactly the same bug fixed in one driver and missing in
another: ghost UID members, forward references between groups and their
members, and rules pointing at objects the push never creates.

The rules live here as pure functions (no vendor imports, no side effects)
so a driver states its intent and the invariant is enforced identically
everywhere:

  I1 reference integrity - never reference an object this push does not
     create; prune and REPORT instead (a silently emptied side widens the
     rule, which the operator must see).
  I2 containers after members - group-like sections must be ordered so a
     member exists before the container that references it.
  I3 source UIDs are not names - a raw vendor UID that survived import
     (deleted / invisible object) can never resolve at the target.

Vendor-SPECIFIC constraints (Check Point reserved names, PAN-OS schema
versions, FortiOS enum spellings) deliberately stay in their driver.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Iterable, Sequence

# A raw vendor UID that survived import as if it were a name. Check Point
# emits these for group members whose object was deleted or isn't visible
# to the API user; the collector keeps the reference faithfully rather than
# inventing one. Optional 's_'/'_' prefix: _safe_name() sanitising can add
# it because CP names must start with a letter.
_UID_RE = re.compile(
    r"^[a-z]?_?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I,
)


def looks_like_uid(value: Any) -> bool:
    """True when `value` is a bare vendor UID rather than an object name."""
    return bool(_UID_RE.match(str(value or "").strip()))


def strip_uid_members(members: Iterable[Any]) -> tuple[list[Any], list[str]]:
    """(kept, dropped) - remove raw source UIDs from a member list (I3)."""
    kept, dropped = [], []
    for m in members or []:
        (dropped if looks_like_uid(m) else kept).append(m)
    return kept, [str(d) for d in dropped]


def prune_refs(
    refs: Sequence[Any],
    available: set[str] | None,
    *,
    keep: Iterable[str] = ("any",),
) -> tuple[list[Any], list[str]]:
    """(kept, dropped) - drop references to objects this push doesn't create.

    `available` is the set of names the push actually emits; None disables
    the check (the caller couldn't determine it - never guess). `keep` lists
    builtin sentinels that always resolve at the target ('any', 'Any', …).

    The caller MUST report the dropped names: pruning a side to empty makes
    it match everything, which is semantically wider than the source.
    """
    if available is None:
        return list(refs or []), []
    allowed = {k.lower() for k in keep}
    kept, dropped = [], []
    for r in refs or []:
        name = str(r or "")
        (kept if (name.lower() in allowed or name in available)
         else dropped).append(r)
    return kept, [str(d) for d in dropped]


def toposort_by_members(
    items: Sequence[Any],
    *,
    name_of: Callable[[Any], str | None],
    members_of: Callable[[Any], Iterable[str]],
) -> list[Any]:
    """Order `items` so a container follows the members it references (I2).

    Members that aren't themselves items are ignored for ordering. Stable
    and cycle-safe: a cycle degrades to the original relative order instead
    of raising - a broken source must not take the push down with it.

    Callers pass accessors because every driver carries its own entry shape
    (Forti dicts, CP {command,payload}, PA elements).
    """
    by_name: dict[str, Any] = {}
    for it in items:
        nm = name_of(it)
        if nm and nm not in by_name:
            by_name[nm] = it

    out: list[Any] = []
    placed: set[int] = set()
    visiting: set[int] = set()

    def visit(item: Any) -> None:
        key = id(item)
        if key in placed or key in visiting:
            return
        visiting.add(key)
        for m in members_of(item) or []:
            dep = by_name.get(str(m))
            if dep is not None and id(dep) not in placed:
                visit(dep)
        visiting.discard(key)
        placed.add(key)
        out.append(item)

    for it in items:
        visit(it)
    return out


# ── I4 the project view (docs/PROJECT_VIEW_DESIGN.md, D9) ─────────────────────
# What a project excluded ("deleted in this project") must never come out of
# a render. The loaders apply the view; this is the net under them: the
# generated sections are searched for the excluded names, and a hit is a
# blocker finding, never a silent push.

_ENTRY_NAME_RE = re.compile(r'<entry\s+name="([^"]*)"')


def _entry_names(body: str) -> set[str]:
    """Entry names of one rendered section: XML entry@name, or the name on a
    JSON command / one level down (payload, params) / a nested rules list."""
    names: set[str] = set()
    body = (body or "").strip()
    if not body:
        return names
    if body[0] == "<":
        names.update(_ENTRY_NAME_RE.findall(body))
        return names
    if body[0] not in "[{":
        return names
    try:
        data = json.loads(body)
    except Exception:
        return names
    for o in (data if isinstance(data, list) else [data]):
        if not isinstance(o, dict):
            continue
        if isinstance(o.get("name"), str):
            names.add(o["name"])
        for v in o.values():
            if isinstance(v, dict) and isinstance(v.get("name"), str):
                names.add(v["name"])
            elif isinstance(v, list):
                for r in v:
                    if isinstance(r, dict) and isinstance(r.get("name"), str):
                        names.add(r["name"])
    return names


def excluded_entries(sections: Sequence[dict], excluded: dict,
                     sections_for_kind: dict | None = None) -> list[dict]:
    """Hits of excluded names in rendered sections (I4).

    ``excluded`` maps a kind to the set of excluded names; ``sections_for_kind``
    (optional) maps a kind to the section names its items render into - a
    kind without a mapping is searched in every section. Returns
    [{kind, name, section}], empty when the render is clean."""
    wanted = {k: {str(n) for n in (names or ()) if n} for k, names in (excluded or {}).items()}
    wanted = {k: v for k, v in wanted.items() if v}
    if not wanted:
        return []
    by_section = {str(s.get("name") or "?"): _entry_names(str(s.get("xml") or "")) for s in sections or []}
    hits: list[dict] = []
    for kind, names in wanted.items():
        allowed = (sections_for_kind or {}).get(kind)
        for sec, present in by_section.items():
            if allowed is not None and sec not in allowed:
                continue
            for n in sorted(names & present):
                hits.append({"kind": kind, "name": n, "section": sec})
    return hits

