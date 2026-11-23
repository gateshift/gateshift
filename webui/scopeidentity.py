# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""Gateshift Enterprise - which scope Device a discovered scope is.

A manager import used to delete every scope Device of the manager and insert
new rows, so the auto-increment id churned on every import and everything
keyed on it (the VPN secrets, the deploy settings, the project exclusions,
and through the rule hashes the overrides) was orphaned each time. A scope
Device is now matched on the id the vendor gives the scope and kept across
imports.

The vendor ids: a FortiManager ADOM's uuid (or oid), a package's oid, a
managed device's serial number; a Check Point domain's, package's and
gateway's uid; a Strata Cloud Manager folder's, snippet's and device's id.
Panorama gives a device-group, a template or a template-stack no id of its
own, so for a Panorama the id IS the name: a rename done in Gateshift moves
both, a rename done on the Panorama itself reads as one scope gone and
another new.

A scope row whose vendor id was never learned (it predates the column, or
was created by hand before the box answered with its id) is matched by its
type and name ONCE and learns the id in that import. Two discovered scopes
with one id, or one row claimed twice, are refused: a vendor that answers
the same id twice is a defect to surface, not two scopes to merge.

This module is DB-free so the host suite runs it; scopepersist does the
writes.
"""
from __future__ import annotations

from dataclasses import dataclass, field


def vendor_id_of(scope: dict) -> str:
    """The identity a discovered scope carries: the vendor's id when the
    discovery found one, the scope's name otherwise (the Panorama rule)."""
    vid = scope.get("vendor_id")
    vid = str(vid).strip() if vid is not None else ""
    return vid or str(scope["name"])


@dataclass
class ScopeSyncPlan:
    # (scope, scope_device_id, previous name, vendor id learned now or None)
    keep: list = field(default_factory=list)
    new: list = field(default_factory=list)          # scopes with no row yet
    retire: list = field(default_factory=list)       # (scope_device_id, scope_name)


def plan_scope_sync(existing, discovered: list) -> ScopeSyncPlan:
    """Match the manager's existing scope rows (scope_device_id, scope_type,
    scope_name, vendor_id) against the scopes an import discovered."""
    by_vendor: dict = {}
    by_name_unlearned: dict = {}
    for sid, stype, sname, vid in existing:
        if vid:
            key = (stype, str(vid))
            if key in by_vendor:
                raise ValueError(
                    f"two scope rows of type {stype!r} carry the vendor id {vid!r} "
                    f"(Devices #{by_vendor[key][0]} and #{sid})")
            by_vendor[key] = (sid, sname)
        else:
            by_name_unlearned[(stype, sname)] = (sid, sname)
    plan = ScopeSyncPlan()
    claimed: dict = {}
    seen: set = set()
    for sc in discovered:
        stype, name, vid = sc["type"], sc["name"], vendor_id_of(sc)
        key = (stype, vid)
        if key in seen:
            raise ValueError(
                f"the import found two {stype} scopes with the vendor id {vid!r} "
                f"({claimed.get(key, name)!r} and {name!r})")
        seen.add(key)
        claimed[key] = name
        hit = by_vendor.get(key)
        if hit is not None:
            plan.keep.append((sc, hit[0], hit[1], None))
            continue
        hit = by_name_unlearned.pop((stype, name), None)
        if hit is not None:
            plan.keep.append((sc, hit[0], hit[1], vid))
            continue
        plan.new.append(sc)
    kept = {sid for _sc, sid, _old, _v in plan.keep}
    for sid, _stype, sname, _vid in existing:
        if sid not in kept:
            plan.retire.append((sid, sname))
    return plan


def host_name_for(manager_id: int, scope: dict) -> str:
    """The scope Device's host_name: prefixed with the manager id so two
    managers that reach the same box never collide on the unique key.
    display_name stays the bare scope name."""
    return f"mgr{manager_id}:{scope['type']}:{scope['name']}"
