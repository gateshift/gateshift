# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""Vendor-specific schemas for `fw_tags.properties`.

Single source of truth for the keys/types/UI labels of Tag-object
properties per target platform. Mirrors `webui/zone_schemas.py` and
`webui/nat_schemas.py` - see
[[feedback_vendor_properties_schema_driven]].

Forti is intentionally absent from SCHEMA: FortiGate policies have no
general-purpose tag concept (live-API schema-verified 2026-06-03), so the
Tags Sub-Tab hides itself on Forti-target via the existing
target-driven Sub-Tab gating in rules.html.

Cross-vendor Color-mapping is user-driven (`feedback_user_owns_migration_decisions`):
if a PA-source-tag with `pa_color="color5"` is mapped onto a CP-target,
the user picks the CP color explicitly in Enrichment > Tags. Default
fallback when unmapped at push-time: vendor-default ("color1" for PA,
"blue" for CP) + DroppedField warn.
"""

# Field-type vocabulary (mirrors zone_schemas / nat_schemas):
#   string  - free-text
#   enum    - pick from fixed `options`

# PA tag-object colors. PAN-OS accepts a fixed list color1..color42 (internal
# IDs); the UI shows the human-readable name + hex preview. Renderer validates
# before push, falling back to "color1" with a DroppedField warn when the
# user-supplied value is outside this set.
#
# Mapping: (id, label, hex) per official PAN-OS color enum (Web-UI shows
# these names; XML accepts only the colorN form).
_PA_COLOR_TABLE = [
    ("color1",  "Red",              "#dc2626"),
    ("color2",  "Green",            "#16a34a"),
    ("color3",  "Blue",             "#2563eb"),
    ("color4",  "Yellow",           "#facc15"),
    ("color5",  "Copper",           "#b45309"),
    ("color6",  "Orange",           "#ea580c"),
    ("color7",  "Purple",           "#7e22ce"),
    ("color8",  "Gray",             "#6b7280"),
    ("color9",  "Light Green",      "#86efac"),
    ("color10", "Cyan",             "#06b6d4"),
    ("color11", "Light Gray",       "#d1d5db"),
    ("color12", "Blue Gray",        "#64748b"),
    ("color13", "Lime",             "#a3e635"),
    ("color14", "Black",            "#000000"),
    ("color15", "Gold",             "#d4af37"),
    ("color16", "Brown",            "#8b4513"),
    ("color17", "Olive",            "#808000"),
    ("color18", "Maroon",           "#800000"),
    ("color19", "Red-Orange",       "#ff5349"),
    ("color20", "Yellow-Orange",    "#ffae42"),
    ("color21", "Forest Green",     "#228b22"),
    ("color22", "Turquoise Blue",   "#00ced1"),
    ("color23", "Azure Blue",       "#007fff"),
    ("color24", "Cerulean Blue",    "#2a52be"),
    ("color25", "Midnight Blue",    "#191970"),
    ("color26", "Medium Blue",      "#0000cd"),
    ("color27", "Cobalt Blue",      "#0047ab"),
    ("color28", "Violet Blue",      "#324ab2"),
    ("color29", "Blue Violet",      "#8a2be2"),
    ("color30", "Medium Violet",    "#9370db"),
    ("color31", "Medium Rose",      "#c08081"),
    ("color32", "Lavender",         "#b57edc"),
    ("color33", "Orchid",           "#da70d6"),
    ("color34", "Thistle",          "#d8bfd8"),
    ("color35", "Peach",            "#ffe5b4"),
    ("color36", "Salmon",           "#fa8072"),
    ("color37", "Magenta",          "#ff00ff"),
    ("color38", "Red Violet",       "#c71585"),
    ("color39", "Mahogany",         "#c04000"),
    ("color40", "Burnt Sienna",     "#e97451"),
    ("color41", "Chestnut",         "#954535"),
    ("color42", "Light Pink",       "#ffb6c1"),
]
_PA_COLORS = [t[0] for t in _PA_COLOR_TABLE]
_PA_COLOR_LABELS = {t[0]: t[1] for t in _PA_COLOR_TABLE}
_PA_COLOR_HEX = {t[0]: t[2] for t in _PA_COLOR_TABLE}

# CP named colors (Mgmt-API enum). The Mgmt-API rejects unknown names
# with HTTP 400 - renderer guards via show-tag + fallback "blue".
_CP_COLOR_TABLE = [
    ("aquamarine",     "#7fffd4"),
    ("black",          "#000000"),
    ("blue",           "#0000ff"),
    ("crete blue",     "#1f618d"),
    ("burlywood",      "#deb887"),
    ("cyan",           "#00ffff"),
    ("dark green",     "#006400"),
    ("khaki",          "#f0e68c"),
    ("orchid",         "#da70d6"),
    ("dark orange",    "#ff8c00"),
    ("dark sea green", "#8fbc8f"),
    ("pink",           "#ffc0cb"),
    ("turquoise",      "#40e0d0"),
    ("dark blue",      "#00008b"),
    ("firebrick",      "#b22222"),
    ("brown",          "#a52a2a"),
    ("forest green",   "#228b22"),
    ("gold",           "#ffd700"),
    ("dark gold",      "#b8860b"),
    ("gray",           "#808080"),
    ("dark gray",      "#a9a9a9"),
    ("light green",    "#90ee90"),
    ("lemon chiffon",  "#fffacd"),
    ("coral",          "#ff7f50"),
    ("sea green",      "#2e8b57"),
    ("sky blue",       "#87ceeb"),
    ("magenta",        "#ff00ff"),
    ("purple",         "#800080"),
    ("slate blue",     "#6a5acd"),
    ("violet red",     "#d02090"),
    ("navy blue",      "#000080"),
    ("olive",          "#808000"),
    ("orange",         "#ffa500"),
    ("red",            "#ff0000"),
    ("sienna",         "#a0522d"),
    ("yellow",         "#ffff00"),
]
_CP_COLORS    = [t[0] for t in _CP_COLOR_TABLE]
_CP_COLOR_HEX = {t[0]: t[1] for t in _CP_COLOR_TABLE}

SCHEMA: dict[str, dict] = {
    "panw": {
        "fields": [
            {"key": "pa_color",
             "label": "Color",
             "type": "enum",
             "options": _PA_COLORS,
             "option_labels": _PA_COLOR_LABELS,
             "option_hex":    _PA_COLOR_HEX,
             "default": "color1"},
            {"key": "pa_comments",
             "label": "Comments",
             "type": "string"},
        ],
    },
    "checkpoint": {
        "fields": [
            {"key": "cp_color",
             "label": "Color",
             "type": "enum",
             "options": _CP_COLORS,
             "option_hex": _CP_COLOR_HEX,
             "default": "blue"},
            {"key": "cp_icon",
             "label": "Icon",
             "type": "string",
             "default": "Tags/Tag"},
            {"key": "cp_comments",
             "label": "Comments",
             "type": "string"},
        ],
    },
    # FortiGate intentionally omitted - no tag concept on policies.
}


def tag_color_label(platform: str | None, color: str) -> str:
    """Human-readable label for a vendor color-ID. Falls back to the raw
    value if no mapping exists (e.g. CP named colors are already
    human-readable)."""
    for f in tag_schema_for(platform).get("fields") or []:
        if f["key"].endswith("_color"):
            labels = f.get("option_labels") or {}
            return labels.get(color, color)
    return color


def tag_color_hex(platform: str | None, color: str) -> str:
    """Hex code for a vendor color-ID. Empty string when unknown."""
    for f in tag_schema_for(platform).get("fields") or []:
        if f["key"].endswith("_color"):
            hexmap = f.get("option_hex") or {}
            return hexmap.get(color, "")
    return ""


def tag_schema_for(platform: str | None) -> dict:
    """Return schema dict for a target platform, empty if vendor has
    no tag concept (Forti) or unknown."""
    return SCHEMA.get(platform or "", {"fields": []})


def tag_field_keys(platform: str | None) -> set[str]:
    """All allowed property-keys for a target platform. Used by the
    PATCH-endpoint to filter unknown keys before JSON_SET."""
    return {f["key"] for f in tag_schema_for(platform).get("fields") or []}


def tag_color_default(platform: str | None) -> str:
    """Vendor-default color when source-color is missing or invalid."""
    for f in tag_schema_for(platform).get("fields") or []:
        if f["key"].endswith("_color"):
            return f.get("default") or ""
    return ""


def tag_color_valid(platform: str | None, color: str) -> bool:
    """True if `color` is in the vendor's accepted list. False for missing
    schema (Forti) or invalid value."""
    for f in tag_schema_for(platform).get("fields") or []:
        if f["key"].endswith("_color"):
            return color in (f.get("options") or [])
    return False
