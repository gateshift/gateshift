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

import re
from typing import Any, Callable, Iterable, Sequence

# A raw vendor UID that survived import as if it were a name. CheckPoint
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
