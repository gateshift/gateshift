# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""PAN-OS Phase-B promoter.

Reads fw_imported_rules.raw_extras + .tags (populated by main._parse_panw_rules
for a PA source device) and lifts PA-relevant slots into the rule-override
tables with source='auto':

  source key                                      → override table / column
  ───────────────────────────────────────────────  ──────────────────────────────────────
  security_profile_group[0]                       → fw_rule_security_profile_overrides.profile_group
  security_profile_individual.virus[0]            → ...av_profile
  security_profile_individual.url-filtering[0]    → ...webfilter_profile
  security_profile_individual.spyware[0]          → ...pa_spyware_profile
  security_profile_individual.vulnerability[0]    → ...pa_vulnerability_profile
  security_profile_individual.file-blocking[0]    → ...pa_file_blocking_profile
  security_profile_individual.wildfire-analysis[0]→ ...pa_wildfire_profile
  security_profile_individual.data-filtering[0]   → ...pa_data_filtering_profile
  log_setting                                     → fw_rule_log_overrides.log_forwarding
  log_start (bool, only present if non-default)   → fw_rule_log_overrides.log_start
  log_end   (bool, only present if non-default)   → fw_rule_log_overrides.log_end
  raw_extras.pa_group_tag                         → fw_rule_tag_overrides.pa_group_tag
  fw_imported_rules.tags (JSON array)             → fw_rule_tag_overrides.pa_tags

Exclusivity: PAN-OS rules carry either a profile-group OR individual
profiles, never both. Mirror that at write time - when raw_extras carries
both (defensive: shouldn't happen from a well-formed PA config), the
group wins and individual slots are dropped.

Idempotency: wipes source='auto' rows for the device's content_hashes
before inserting. source='manual' rows are skipped (never overwritten
by the auto-binder).

Conflict policy: if multiple imported rules map to the same filtered
content_hash with disagreeing slot values, the slot is left empty -
caller surfaces the conflict via the returned `conflicts` counter.
"""

from __future__ import annotations

import json

from sqlalchemy import text


_PA_INDIVIDUAL_MAP = (
    # (raw_extras key under security_profile_individual, override column)
    ("virus",             "av_profile"),
    ("url-filtering",     "webfilter_profile"),
    ("spyware",           "pa_spyware_profile"),
    ("vulnerability",     "pa_vulnerability_profile"),
    ("file-blocking",     "pa_file_blocking_profile"),
    ("wildfire-analysis", "pa_wildfire_profile"),
    ("data-filtering",    "pa_data_filtering_profile"),
)


def _first_member(v) -> str | None:
    """raw_extras values for PA profile categories are member-lists.
    Take the first non-empty string, else None."""
    if isinstance(v, list):
        for item in v:
            if isinstance(item, str) and item.strip():
                return item.strip()
    elif isinstance(v, str) and v.strip():
        return v.strip()
    return None


def _extract_slots(extras: dict, raw_tags=None) -> tuple[dict, dict, dict]:
    """Split raw_extras + raw_tags into (spov_slots, log_slots, tag_slots).
    Empty values are omitted so the dynamic INSERT only touches columns
    we have data for. profile-group/individual mutually exclusive: group
    wins. raw_tags is the fw_imported_rules.tags JSON array (already
    decoded) - fed through to fw_rule_tag_overrides.pa_tags."""
    spov: dict = {}
    log: dict = {}
    tag: dict = {}

    group = _first_member(extras.get("security_profile_group"))
    if group:
        spov["profile_group"] = group
    else:
        sec_indiv = extras.get("security_profile_individual") or {}
        if isinstance(sec_indiv, dict):
            for src_key, dst_col in _PA_INDIVIDUAL_MAP:
                val = _first_member(sec_indiv.get(src_key))
                if val:
                    spov[dst_col] = val

    log_setting = extras.get("log_setting")
    # Skip PA's default log-forwarding profile name ("default"): promoting it
    # writes a no-op override row (the renderer falls back to the device
    # default anyway), cluttering fw_rule_log_overrides with amber rows.
    if (isinstance(log_setting, str) and log_setting.strip()
            and log_setting.strip().lower() != "default"):
        log["log_forwarding"] = log_setting.strip()

    # log_start / log_end land in raw_extras only when they deviate from
    # PA defaults (start=no, end=yes) - see _parse_panw_rules.
    if extras.get("log_start") is True:
        log["log_start"] = 1
    if extras.get("log_end") is False:
        log["log_end"] = 0

    # Tags - pa_group_tag comes from raw_extras, pa_tags from the
    # imported rule's tags-JSON.
    gt = (extras.get("pa_group_tag") or "").strip() if isinstance(extras.get("pa_group_tag"), str) else None
    if gt:
        tag["pa_group_tag"] = gt
    if isinstance(raw_tags, list):
        clean = [t for t in raw_tags if isinstance(t, str) and t.strip()]
        if clean:
            tag["pa_tags"] = json.dumps(clean)

    return spov, log, tag


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
    """Lift PA raw_extras into override tables for one source device.

    Returns counts dict for caller logging:
      {"spov_written": int, "log_written": int, "conflicts": int,
       "skipped_manual": int}
    """
    counts = {"spov_written": 0, "log_written": 0,
              "conflicts": 0, "skipped_manual": 0}

    dev = conn.execute(text(
        "SELECT host_name, display_name, platform "
        "FROM fw_devices WHERE id = :id"
    ), {"id": device_id}).mappings().fetchone()
    if not dev or (dev["platform"] or "").lower() != "panw":
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
    # are enabled for this device. Same trick as the Forti promoter.
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

    hash_to_spov: dict[bytes, dict] = {}
    hash_to_log: dict[bytes, dict] = {}
    hash_to_tag: dict[bytes, dict] = {}
    hash_conflicts: dict[bytes, set] = {}

    for name, hashes in name_to_hashes.items():
        extras = by_name[name]
        spov, log, tag = _extract_slots(extras, by_name_tags.get(name))
        for h in hashes:
            conflicts = hash_conflicts.setdefault(h, set())
            _merge_with_conflict(hash_to_spov.setdefault(h, {}), spov, conflicts)
            _merge_with_conflict(hash_to_log.setdefault(h, {}), log, conflicts)
            _merge_with_conflict(hash_to_tag.setdefault(h, {}), tag, conflicts)

    counts["conflicts"] = sum(len(c) for c in hash_conflicts.values())

    all_hashes = list(hash_to_spov.keys() | hash_to_log.keys() | hash_to_tag.keys())
    if all_hashes:
        ph = ", ".join(f":h{i}" for i in range(len(all_hashes)))
        params = {f"h{i}": h for i, h in enumerate(all_hashes)}
        conn.execute(text(
            f"DELETE FROM fw_rule_security_profile_overrides "
            f"WHERE source = 'auto' AND rule_hash IN ({ph})"
        ), params)
        conn.execute(text(
            f"DELETE FROM fw_rule_log_overrides "
            f"WHERE source = 'auto' AND rule_hash IN ({ph})"
        ), params)
        conn.execute(text(
            f"DELETE FROM fw_rule_tag_overrides "
            f"WHERE source = 'auto' AND rule_hash IN ({ph})"
        ), params)

    for h, slots in hash_to_spov.items():
        if not slots:
            continue
        has_manual = conn.execute(text(
            "SELECT 1 FROM fw_rule_security_profile_overrides "
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
            INSERT INTO fw_rule_security_profile_overrides
              (rule_hash, {col_list}, source)
            VALUES (:h, {val_ph}, 'auto')
            ON DUPLICATE KEY UPDATE
              {upd}, source = 'auto'
        """), params)
        counts["spov_written"] += 1

    for h, slots in hash_to_log.items():
        if not slots:
            continue
        has_manual = conn.execute(text(
            "SELECT 1 FROM fw_rule_log_overrides "
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
            INSERT INTO fw_rule_log_overrides
              (rule_hash, {col_list}, source)
            VALUES (:h, {val_ph}, 'auto')
            ON DUPLICATE KEY UPDATE
              {upd}, source = 'auto'
        """), params)
        counts["log_written"] += 1

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
