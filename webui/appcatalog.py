# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
"""The names of a target's stored application catalogue (CE backlog 23): the
Applications pane lets the operator pick applications by name from the
catalogue the target reported (PAN-OS App-ID objects, groups and filters,
FortiGuard signatures, custom applications and groups), and the apply route
accepts only names the catalogue carries. Applications are matched by name,
never translated."""
from __future__ import annotations


def catalog_names(catalog) -> set[str]:
    """Every name in every bucket of a catalogue as the drivers report it
    (`{bucket: [{"name": ...}, ...]}`, plain strings tolerated)."""
    names: set[str] = set()
    if not isinstance(catalog, dict):
        return names
    for items in catalog.values():
        for it in (items or []):
            name = it.get("name") if isinstance(it, dict) else it
            if isinstance(name, str) and name.strip():
                names.add(name.strip())
    return names


def missing_names(catalog, picked: list[str]) -> list[str]:
    """The picked names the catalogue does not carry, in the order picked."""
    known = catalog_names(catalog)
    return [n for n in picked if n not in known]
