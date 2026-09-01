# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""Vendor-specific schemas for `fw_interfaces.properties`.

Single source of truth for the keys/types/UI labels of per-interface
vendor knobs that don't fit into a top-level column. Mirrors
`webui/nat_schemas.py` and `webui/zone_schemas.py` - see
[[feedback_vendor_properties_schema_driven]].

Currently no per-iface vendor properties land here. The infrastructure
(properties JSON column, schema_for / coerce_value helpers, JSON_MERGE_PATCH
in /interfaces/<id>/update, toggleIfaceProperty JS) stays so the next
per-iface vendor knob plugs in as a single SCHEMA entry.
"""

# Field-type vocabulary (mirrors nat_schemas / zone_schemas):
#   bool    - yes/no toggle
#   string  - free-text
#   enum    - pick from fixed `options`

SCHEMA: dict[str, dict] = {
    "panw":       {"fields": []},
    "checkpoint": {"fields": []},
    "fortigate":  {"fields": []},
    "firepower":  {"fields": []},
}


def schema_for(platform: str | None) -> dict:
    """Return the schema dict for a platform, or an empty one when
    the platform is unknown."""
    if not platform:
        return {"fields": []}
    return SCHEMA.get(platform, {"fields": []})


def field_keys(platform: str | None) -> set[str]:
    """Whitelist of property-keys allowed for a given platform - used by
    PATCH / bulk endpoints to reject unknown keys."""
    return {f["key"] for f in schema_for(platform).get("fields") or []}


def coerce_value(field: dict, raw):
    """Normalize an incoming value to the field's declared type. Returns
    None for empty strings or the ``__clear__`` UI-sentinel on non-bool
    fields so JSON_MERGE_PATCH can drop the slot cleanly."""
    ftype = field.get("type")
    if ftype == "bool":
        if isinstance(raw, bool):
            return raw
        if isinstance(raw, str):
            return raw.strip().lower() in ("1", "true", "yes", "on")
        return bool(raw)
    if isinstance(raw, str) and raw.strip() == "__clear__":
        return None
    if ftype == "enum":
        if not raw:
            return None
        s = str(raw).strip()
        return s if s in (field.get("options") or []) else None
    if raw is None:
        return None
    s = str(raw).strip()
    return s or None
