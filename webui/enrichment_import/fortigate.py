# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""FortiGate Phase-B promoter.

Reads fw_imported_rules.raw_extras (populated by
deploy/_forti_common.parse_rules) for a Forti source device and lifts
Forti-relevant slots into the rule-override tables with source='auto':

  raw_extras key            → override table / column
  ─────────────────────────   ──────────────────────────────────────────
  security_profile_individual.av-profile        → fw_rule_security_profile_overrides.av_profile
  security_profile_individual.webfilter-profile → ...webfilter_profile
  security_profile_individual.dnsfilter-profile → ...dnsfilter_profile
  security_profile_individual.ips-sensor        → ...ips_sensor
  security_profile_individual.ssl-ssh-profile   → ...ssl_ssh_profile
  application_ctrl[0]                           → ...application_list
  log_setting                                   → fw_rule_log_overrides.log_traffic
  logtraffic_start                              → ...log_start
  capture_packet                                → ...capture_packet

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


_UTM_FIELD_MAP = (
    # (raw_extras key under security_profile_individual, override column)
    ("av-profile",        "av_profile"),
    ("webfilter-profile", "webfilter_profile"),
    ("dnsfilter-profile", "dnsfilter_profile"),
    ("ips-sensor",        "ips_sensor"),
    ("ssl-ssh-profile",   "ssl_ssh_profile"),
)


def _extract_slots(extras: dict) -> tuple[dict, dict]:
    """Split raw_extras into (spov_slots, log_slots) dicts. Empty values
    are omitted so the dynamic INSERT only touches columns we have data
    for."""
    spov: dict = {}
    log: dict = {}

    sec_indiv = extras.get("security_profile_individual") or {}
    if isinstance(sec_indiv, dict):
        for src_key, dst_col in _UTM_FIELD_MAP:
            v = sec_indiv.get(src_key)
            if isinstance(v, str) and v.strip():
                spov[dst_col] = v.strip()

    # application_ctrl is a list (Forti's application-list is singular per
    # policy - take first non-empty)
    app_ctrl = extras.get("application_ctrl") or []
    if isinstance(app_ctrl, list):
        for v in app_ctrl:
            if isinstance(v, str) and v.strip():
                spov["application_list"] = v.strip()
                break

    log_setting = extras.get("log_setting")
    if isinstance(log_setting, str):
        lt = log_setting.strip().lower()
        if lt in ("all", "utm", "disable"):
            log["log_traffic"] = lt

    if extras.get("logtraffic_start") is True:
        log["log_start"] = 1
    if extras.get("capture_packet") is True:
        log["capture_packet"] = 1

    return spov, log


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
    """Lift Forti raw_extras into override tables for one source device.

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
    if not dev or (dev["platform"] or "").lower() != "fortigate":
        return counts

    device_host = dev["display_name"] or dev["host_name"]
    if not device_host:
        return counts

    # 1. Pull every (rule_name, raw_extras) for this device, latest import.
    rows = conn.execute(text("""
        SELECT rule_name, raw_extras
        FROM fw_imported_rules
        WHERE device_id = :id AND raw_extras IS NOT NULL
    """), {"id": device_id}).mappings().all()

    if not rows:
        return counts

    by_name: dict[str, dict] = {}
    for r in rows:
        extras = r["raw_extras"]
        if isinstance(extras, str):
            try:
                extras = json.loads(extras)
            except Exception:
                continue
        if not isinstance(extras, dict):
            continue
        # Multiple imported rows with same rule_name shouldn't happen
        # (FortiOS policy names are unique per VDOM), but be defensive:
        # later writes overwrite earlier ones.
        by_name[r["rule_name"]] = extras

    # 2. Resolve rule_name → content_hash list. Look across every
    #    pipeline stage that carries (device_host, rule_name,
    #    content_hash) - the hash formula is stable across stages, but
    #    not every device runs every module (quality_filter / subnet /
    #    accumulate can be disabled per-device). UNION DISTINCT gives
    #    us coverage from whichever stage(s) materialized the rule.
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

    # 3. Build per-content_hash slot dicts. Multiple rule_names mapping
    #    to the same hash can disagree → mark slot as conflict, drop it.
    hash_to_spov: dict[bytes, dict] = {}
    hash_to_log: dict[bytes, dict] = {}
    hash_conflicts: dict[bytes, set] = {}

    for name, hashes in name_to_hashes.items():
        extras = by_name[name]
        spov, log = _extract_slots(extras)
        for h in hashes:
            conflicts = hash_conflicts.setdefault(h, set())
            _merge_with_conflict(hash_to_spov.setdefault(h, {}), spov, conflicts)
            _merge_with_conflict(hash_to_log.setdefault(h, {}), log, conflicts)

    counts["conflicts"] = sum(len(c) for c in hash_conflicts.values())

    # 4. Pre-wipe source='auto' rows for the affected hashes. Manual
    #    survives. Doing this in bulk keeps the loop below simple.
    all_hashes = list(hash_to_spov.keys() | hash_to_log.keys())
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

    # 5. Insert per-hash. Skip when a source='manual' row already exists.
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

    return counts
