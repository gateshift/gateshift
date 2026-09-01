# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""Check Point Phase-B promoter.

Reads fw_imported_rules.raw_extras (populated by main._parse_cp_access_rules
for a CP source device) and lifts CP-relevant slots into the rule-override
tables with source='auto':

  raw_extras key                 → override table / column
  ─────────────────────────────────  ───────────────────────────────────────
  track.type                       → fw_rule_track_overrides.track_type
  track.accounting   (bool)        → ...accounting
  track.per_session  (bool)        → ...per_session
  track.per_connection (bool=false)→ ...per_connection

CP defaults handled at parse time: type='Log', accounting=false,
per-session=false, per-connection=true. raw_extras["track"] only carries
*deviations*, so what arrives here is always non-default - the schema
defaults fill in unspecified columns at INSERT time.

Backward-compat: legacy imports stored raw_extras["track"] as a bare
string (the track type name). Promoter accepts both shapes.

Idempotency: wipes source='auto' rows for the device's content_hashes
before inserting. source='manual' rows are skipped (never overwritten
by the auto-binder).

Conflict policy: if multiple imported rules map to the same filtered
content_hash with disagreeing slot values, the slot is left empty -
caller surfaces the conflict via the returned `conflicts` counter.

Out of scope for Slice 3: CP-specific raw_extras fields without a
schema slot - vpn, install_on, time, inline_layer, cp_section. These
remain Drop-only until a schema-extension slice adds dedicated columns.

negate_source / negate_destination / negate_service got first-class
columns + a dedicated override table in the rule-negation scope (V1a–V1d,
see project_rule_negation_plan). The source-parser writes them directly
to fw_imported_rules, so this promoter no longer sees them in raw_extras.
"""

from __future__ import annotations

import json

from sqlalchemy import text


def _extract_slots(extras: dict) -> dict:
    """Pull track deviations out of raw_extras. Returns a dict of
    columns → values for fw_rule_track_overrides. Empty when raw_extras
    carries no track deviations."""
    track = extras.get("track")
    # Legacy format: raw_extras["track"] was a bare type-name string.
    if isinstance(track, str):
        s = track.strip()
        track = {"type": s} if s else {}
    if not isinstance(track, dict):
        return {}

    slots: dict = {}
    t = track.get("type")
    if isinstance(t, str) and t.strip() and t.strip() not in ("None", "Log"):
        slots["track_type"] = t.strip()
    if track.get("accounting") is True:
        slots["accounting"] = 1
    if track.get("per_session") is True:
        slots["per_session"] = 1
    if track.get("per_connection") is False:
        slots["per_connection"] = 0
    return slots


def _merge_with_conflict(target: dict, incoming: dict, conflicts: set) -> None:
    """Merge incoming into target. If a key exists with a different
    value, drop it and record the conflict."""
    for k, v in incoming.items():
        if k in conflicts:
            continue
        if k not in target:
            target[k] = v
        elif target[k] != v:
            conflicts.add(k)
            target.pop(k, None)


def promote_imported_to_overrides(conn, device_id: int) -> dict:
    """Lift CP raw_extras.track into fw_rule_track_overrides for one
    source device.

    Returns counts dict for caller logging. spov_written / log_written
    are kept at 0 so the dispatch wrapper can format every vendor's
    output uniformly.
    """
    counts = {"spov_written": 0, "log_written": 0, "track_written": 0,
              "conflicts": 0, "skipped_manual": 0}

    dev = conn.execute(text(
        "SELECT host_name, display_name, platform "
        "FROM fw_devices WHERE id = :id"
    ), {"id": device_id}).mappings().fetchone()
    if not dev or (dev["platform"] or "").lower() != "checkpoint":
        return counts

    device_host = dev["display_name"] or dev["host_name"]
    if not device_host:
        return counts

    rows = conn.execute(text("""
        SELECT rule_name, raw_extras, tags
        FROM fw_imported_rules
        WHERE device_id = :id
          AND (raw_extras IS NOT NULL OR tags IS NOT NULL)
    """), {"id": device_id}).mappings().all()

    if not rows:
        return counts

    by_name: dict[str, dict] = {}
    by_name_tags: dict[str, list] = {}
    for r in rows:
        extras = r["raw_extras"]
        if isinstance(extras, str):
            try:
                extras = json.loads(extras)
            except Exception:
                extras = None
        if not isinstance(extras, dict):
            extras = {}
        by_name[r["rule_name"]] = extras
        raw_tags = r["tags"]
        if isinstance(raw_tags, str):
            try:
                raw_tags = json.loads(raw_tags)
            except Exception:
                raw_tags = None
        if isinstance(raw_tags, list):
            by_name_tags[r["rule_name"]] = raw_tags

    # content_hash lookup across all pipeline stages that carry
    # (device_host, rule_name, content_hash). Hash formula is stable
    # across stages - UNION DISTINCT works regardless of which modules
    # are enabled for this device. Same trick as the Forti / PA promoters.
    name_to_hashes: dict[str, list[bytes]] = {}
    for name in by_name:
        hashes = conn.execute(text("""
            SELECT DISTINCT content_hash FROM fw_rules_filtered
              WHERE device_host = :h AND rule_name = :n AND content_hash IS NOT NULL
            UNION
            SELECT DISTINCT content_hash FROM fw_rules_subnet
              WHERE device_host = :h AND rule_name = :n AND content_hash IS NOT NULL
            UNION
            SELECT DISTINCT content_hash FROM fw_rules_accumulated
              WHERE device_host = :h AND rule_name = :n AND content_hash IS NOT NULL
            UNION
            SELECT DISTINCT content_hash FROM fw_rules_consolidated_1
              WHERE device_host = :h AND rule_name = :n AND content_hash IS NOT NULL
        """), {"h": device_host, "n": name}).scalars().all()
        if hashes:
            name_to_hashes[name] = hashes

    if not name_to_hashes:
        return counts

    hash_to_track: dict[bytes, dict] = {}
    hash_to_tag: dict[bytes, dict] = {}
    hash_conflicts: dict[bytes, set] = {}

    for name, hashes in name_to_hashes.items():
        extras = by_name[name]
        slots = _extract_slots(extras)
        # Tags - pa_tags-equivalent stored in cp_tags slot. List from
        # fw_imported_rules.tags JSON (resolved tag-names at source-parser
        # via odict).
        raw_tags = by_name_tags.get(name) or []
        tag_slots: dict = {}
        if isinstance(raw_tags, list):
            clean = [t for t in raw_tags if isinstance(t, str) and t.strip()]
            if clean:
                tag_slots["cp_tags"] = json.dumps(clean)
        for h in hashes:
            conflicts = hash_conflicts.setdefault(h, set())
            if slots:
                _merge_with_conflict(hash_to_track.setdefault(h, {}), slots, conflicts)
            if tag_slots:
                _merge_with_conflict(hash_to_tag.setdefault(h, {}), tag_slots, conflicts)

    counts["conflicts"] = sum(len(c) for c in hash_conflicts.values())

    all_hashes = list(hash_to_track.keys() | hash_to_tag.keys())
    if all_hashes:
        ph = ", ".join(f":h{i}" for i in range(len(all_hashes)))
        params = {f"h{i}": h for i, h in enumerate(all_hashes)}
        conn.execute(text(
            f"DELETE FROM fw_rule_track_overrides "
            f"WHERE source = 'auto' AND rule_hash IN ({ph})"
        ), params)
        conn.execute(text(
            f"DELETE FROM fw_rule_tag_overrides "
            f"WHERE source = 'auto' AND rule_hash IN ({ph})"
        ), params)

    for h, slots in hash_to_track.items():
        if not slots:
            continue
        has_manual = conn.execute(text(
            "SELECT 1 FROM fw_rule_track_overrides "
            "WHERE rule_hash = :h AND source = 'manual'"
        ), {"h": h}).first()
        if has_manual:
            counts["skipped_manual"] += 1
            continue
        cols = list(slots.keys())
        col_list = ", ".join(cols)
        val_ph = ", ".join(f":{c}" for c in cols)
        upd = ", ".join(f"{c} = VALUES({c})" for c in cols)
        params = {c: slots[c] for c in cols}
        params["h"] = h
        conn.execute(text(f"""
            INSERT INTO fw_rule_track_overrides
              (rule_hash, {col_list}, source)
            VALUES (:h, {val_ph}, 'auto')
            ON DUPLICATE KEY UPDATE
              {upd}, source = 'auto'
        """), params)
        counts["track_written"] += 1

    for h, slots in hash_to_tag.items():
        if not slots:
            continue
        has_manual = conn.execute(text(
            "SELECT 1 FROM fw_rule_tag_overrides "
            "WHERE rule_hash = :h AND source = 'manual'"
        ), {"h": h}).first()
        if has_manual:
            counts["skipped_manual"] += 1
            continue
        cols = list(slots.keys())
        col_list = ", ".join(cols)
        val_ph = ", ".join(f":{c}" for c in cols)
        upd = ", ".join(f"{c} = VALUES({c})" for c in cols)
        params = {c: slots[c] for c in cols}
        params["h"] = h
        conn.execute(text(f"""
            INSERT INTO fw_rule_tag_overrides
              (rule_hash, {col_list}, source)
            VALUES (:h, {val_ph}, 'auto')
            ON DUPLICATE KEY UPDATE
              {upd}, source = 'auto'
        """), params)
        counts["tag_written"] = counts.get("tag_written", 0) + 1

    return counts
