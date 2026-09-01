# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""Vendor-specific schemas for `fw_nat_rules.properties`.

Single source of truth for the keys/types/UI labels of NAT-rule properties
per target platform. Mirrors `webui/zone_schemas.py` - see
[[feedback_vendor_properties_schema_driven]].

Phase C ships an empty SCHEMA per platform so the endpoints can already
be schema-driven; Phase D fills in the real vendor-specific slots
(pa_bi_directional, cp_method, forti_fixedport, etc.) - see
[[project_nat_full_scope_plan]] decisions table.

Catalog-typed fields (if any in Phase D) resolve their options from
`fw_target_discover` at render-time via the configured `catalog_kind`.
"""

# Field-type vocabulary (mirrors zone_schemas):
#   bool    - yes/no toggle
#   string  - free-text
#   enum    - pick from fixed `options`
#   catalog - pick from `fw_target_discover.kind=catalog_kind` snapshot

SCHEMA: dict[str, dict] = {
    # Phase D: per-vendor NAT-properties that are NOT in nat_hash (so edits
    # don't invalidate override-bindings). Hash-input fields (zones,
    # orig_*, trans_*) stay non-editable in the UI; vendor-specific
    # modifiers live here. Renderers (Phase D3) read these slots and emit
    # vendor-side knobs accordingly.
    "panw": {
        "fields": [
            # Source Address Translation. The type slot overrides the
            # imported trans_src_type column when set (so the user can
            # promote `none` → `dynamic-ip-and-port` etc. without
            # touching the hash-input identity columns).
            {"key": "pa_src_translation_type", "label": "Source Translation Type",
             "type": "enum",
             "options": ["none", "dynamic-ip-and-port", "dynamic-ip", "static-ip"],
             "default": "none"},
            {"key": "pa_bi_directional", "label": "Bi-Directional NAT", "type": "bool"},
            # Destination Address Translation. dns_rewrite + direction
            # apply when dst type = static-ip; session_distribution_method
            # when dst type = dynamic-ip. Renderer reads them only in the
            # matching branch - setting them in the wrong combo is a no-op.
            {"key": "pa_dst_translation_type", "label": "Destination Translation Type",
             "type": "enum",
             "options": ["none", "static-ip", "dynamic-ip"],
             "default": "none"},
            {"key": "pa_dns_rewrite", "label": "DNS Rewrite", "type": "bool"},
            {"key": "pa_dns_direction", "label": "DNS Direction",
             "type": "enum",
             "options": ["reverse", "forward"],
             "default": "reverse"},
            {"key": "pa_session_distribution_method", "label": "Session Distribution Method",
             "type": "enum",
             "options": ["round-robin", "source-ip-hash", "ip-modulo", "ip-hash", "least-sessions"],
             "default": "round-robin"},
            # pa_group_tag is still imported by the source parser and emitted
            # by the renderer (<group-tag> entry-element) - only the UI slot
            # was removed to keep the Enrichment list lean.
            # Phase-F cross-vendor mapping slots - picker against the
            # target catalog. Renderer prefers these overrides over the
            # agnostic trans_src / trans_dst when set.
            {"key": "pa_trans_src_ref", "label": "Target trans_src",
             "type": "catalog", "catalog_kind": "address_objects"},
            {"key": "pa_trans_dst_ref", "label": "Target trans_dst",
             "type": "catalog", "catalog_kind": "address_objects"},
        ],
    },
    "checkpoint": {
        "fields": [
            {"key":   "cp_method",
             "label": "Method",
             "type":  "enum",
             "options": ["static", "hide", "nat-64"],
             "default": "static"},
            {"key": "cp_packet_mangling", "label": "Packet Mangling", "type": "bool"},
            {"key": "cp_trans_src_ref", "label": "Target trans_src",
             "type": "catalog", "catalog_kind": "address_objects"},
            {"key": "cp_trans_dst_ref", "label": "Target trans_dst",
             "type": "catalog", "catalog_kind": "address_objects"},
        ],
    },
    "fortigate": {
        "fields": [
            {"key": "forti_fixedport",   "label": "Fixed Port",      "type": "bool"},
            {"key": "forti_natoutbound", "label": "Outbound NAT",    "type": "bool"},
            {"key": "forti_trans_src_ref", "label": "Target trans_src",
             "type": "catalog", "catalog_kind": "address_objects"},
            {"key": "forti_trans_dst_ref", "label": "Target trans_dst",
             "type": "catalog", "catalog_kind": "address_objects"},
        ],
    },
    # FTD not implemented yet - empty schema.
    "firepower":  {"fields": []},
}


def schema_for(platform: str | None) -> dict:
    """Return the schema dict for a target platform, or an empty one when
    the platform is unknown."""
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
