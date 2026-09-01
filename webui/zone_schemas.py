# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""Vendor-specific schemas for `fw_zones.properties`.

Single source of truth for the keys/types/UI labels of zone-properties per
target platform. UI bulk-form + per-row display are rendered schema-driven
so the same form template covers PA and Forti without vendor branches.

Keys are vendor-prefixed (`pa_*`, `forti_*`) so cross-vendor migrations
(e.g. PA→Forti) keep both vendors' property-slots side-by-side in
`fw_zones.properties` without stomping each other.

Catalog-typed fields resolve their options from `fw_target_discover` at
render-time via the configured `catalog_kind`.
"""

# Field-type vocabulary:
#   bool    - yes/no toggle
#   string  - free-text
#   enum    - pick from fixed `options`
#   catalog - pick from `fw_target_discover.kind=catalog_kind` snapshot

SCHEMA: dict[str, dict] = {
    "panw": {
        "fields": [
            {
                "key":   "pa_zone_type",
                "label": "Type",
                "type":  "enum",
                "options": ["layer3", "layer2", "virtual-wire", "tap", "tunnel", "external"],
                "default": "layer3",
                # Existing zones: dropdown disabled (user does not change
                # an imported type by accident). Add-Zone: only layer3
                # enabled - anything else needs to come from a real source.
                "read_only_existing": True,
                "new_only_choices": ["layer3"],
            },
            {"key": "pa_enable_user_id",                  "label": "User Identification",     "type": "bool"},
            {"key": "pa_enable_device_id",                "label": "Device Identification",   "type": "bool"},
            {"key": "pa_enable_packet_buffer_protection", "label": "Packet Buffer Protection","type": "bool"},
            {"key": "pa_log_setting",                     "label": "Log Setting",             "type": "string"},
            {
                "key":   "pa_zone_protection_profile",
                "label": "Zone Protection Profile",
                "type":  "catalog",
                "catalog_kind": "zone_protection_profiles",
            },
        ],
    },
    "fortigate": {
        "fields": [
            {"key": "forti_intrazone_block", "label": "Block Intra-Zone Traffic", "type": "bool"},
            {"key": "forti_description",     "label": "Description",              "type": "string"},
        ],
    },
    # FTD not implemented yet - schema empty; the Sub-Sub-Tab still
    # appears because target_zone_native covers firepower, but the
    # bulk-form renders no fields.
    "firepower": {"fields": []},
}


def schema_for(platform: str | None) -> dict:
    """Return the schema dict for a target platform, or an empty one when
    the platform is not zone-native (CP / ASA / OPNsense / unknown)."""
    if not platform:
        return {"fields": []}
    return SCHEMA.get(platform, {"fields": []})


def field_keys(platform: str | None) -> set[str]:
    """Whitelist of property-keys allowed for a given platform - used by
    PATCH/bulk endpoints to reject unknown keys."""
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
    # __clear__ is the UI's explicit "drop this slot" sentinel for
    # catalog/string fields - recognised here as defense-in-depth so a
    # direct API call without the frontend's pre-mapping still clears
    # cleanly instead of storing the literal "__clear__".
    if isinstance(raw, str) and raw.strip() == "__clear__":
        return None
    if ftype == "enum":
        if not raw:
            return None
        s = str(raw).strip()
        return s if s in (field.get("options") or []) else None
    # string + catalog: keep the raw string; empty → None
    if raw is None:
        return None
    s = str(raw).strip()
    return s or None
