# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

import datetime
import json
import os
import re
from sqlalchemy import text


def _read_sql(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def _split_sql(sql: str):
    parts = []
    buf = []
    in_squote = False
    in_dquote = False
    in_bquote = False
    in_line_comment = False
    escape = False
    i = 0
    chars = sql

    while i < len(chars):
        ch = chars[i]

        # End of line comment on newline
        if in_line_comment:
            buf.append(ch)
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue

        if escape:
            buf.append(ch)
            escape = False
            i += 1
            continue

        if ch == "\\" and (in_squote or in_dquote):
            buf.append(ch)
            escape = True
            i += 1
            continue

        # Detect -- line comment (only outside strings)
        if ch == "-" and not in_squote and not in_dquote and not in_bquote:
            if i + 1 < len(chars) and chars[i + 1] == "-":
                in_line_comment = True
                buf.append(ch)
                i += 1
                continue

        if ch == "'" and not in_dquote and not in_bquote:
            in_squote = not in_squote
            buf.append(ch)
            i += 1
            continue
        if ch == '"' and not in_squote and not in_bquote:
            in_dquote = not in_dquote
            buf.append(ch)
            i += 1
            continue
        if ch == "`" and not in_squote and not in_dquote:
            in_bquote = not in_bquote
            buf.append(ch)
            i += 1
            continue
        if ch == ";" and not in_squote and not in_dquote and not in_bquote:
            stmt = "".join(buf).strip()
            if stmt:
                parts.append(stmt)
            buf = []
            i += 1
            continue

        buf.append(ch)
        i += 1

    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def _load_pipeline_config(conn) -> dict:
    """Load fw_pipeline_config; returns empty dict if table does not exist."""
    try:
        rows = conn.execute(
            text("SELECT job_name, enabled, params FROM fw_pipeline_config")
        ).fetchall()
    except Exception:
        return {}
    cfg = {}
    for row in rows:
        params = {}
        if row[2]:
            try:
                params = json.loads(row[2]) if isinstance(row[2], str) else row[2]
            except Exception:
                pass
        cfg[row[0]] = {"enabled": bool(row[1]), "params": params}
    return cfg


# Module names and their output tables in pipeline order
MODULES = [
    ("52_accumulate",     "fw_rules_accumulated"),
    ("53_subnet",         "fw_rules_subnet"),
    ("55_quality_filter", "fw_rules_filtered"),
    ("56_endpoint_pairs", "fw_rules_endpoint_pairs"),
]


# Stable per-rule identity hash. Same SHA1 input across every pipeline stage,
# so an override applied on one stage's view binds equally on the next stage
# whenever the underlying rule signature is unchanged. Override tables
# (apps, zones, logging, track, security_profile, service) all key on this.
# See feedback_rule_identity_hash + project_enrichment_hash_drift memos.
#
# The ZONE is DELIBERATELY EXCLUDED: it is route-DERIVED, so a network edit
# (zone delete, interface/route change) re-derives it and would shift the hash
# → every hash-keyed override would orphan, even for rules the user never
# touched. Instead config (api_import) rules carry their stable rule_name in
# the hash (see _hash_sha1_expr); syslog rules have no name and their derived
# zone was IP-redundant anyway, so the (proto, port, src_ip, dst_ip[, dst_nat])
# tuple identifies them. dst_nat stays (syslog NAT signature; api_import=none).
#
# NULL src_ip/dst_ip in consolidated_1 ⇒ subtable variant produces no row at
# all, so its GROUP_CONCAT collapses to NULL → ''. Inline mirrors that: '' when
# the IP is NULL, else the (ip[, nat]) tuple - config rules are object-based
# (NULL IPs) and rely on rule_name in the SHA1 to stay unique.
_HASH_SRC_INLINE = "CASE WHEN r.src_ip IS NULL THEN '' ELSE r.src_ip END"
_HASH_DST_INLINE = ("CASE WHEN r.dst_ip IS NULL THEN '' ELSE "
                    "CONCAT_WS('\t', r.dst_ip, COALESCE(r.dst_nat,'')) END")
_HASH_SRC_SUBTABLE = (
    "GROUP_CONCAT(src_ip ORDER BY src_ip SEPARATOR '\n')"
)
_HASH_DST_SUBTABLE = (
    "GROUP_CONCAT(CONCAT_WS('\t', dst_ip, COALESCE(dst_nat,'')) "
    "ORDER BY dst_ip, COALESCE(dst_nat,'') "
    "SEPARATOR '\n')"
)


def _hash_sha1_expr(src_sig_sql: str, dst_sig_sql: str) -> str:
    """Build the SHA1 expression from src/dst signature SQL fragments.
    Single source of truth for the hash input across all stages. Config
    (api_import) rules add their stable rule_name so they stay unique even
    when zone-differentiated or object-based (NULL IPs); syslog rules use ''
    (no stable name) and rely on the IP/proto/port signature. The route-derived
    zone is excluded so network edits don't orphan overrides - see header."""
    return f"""UNHEX(SHA1(CONCAT_WS(0x1f,
        COALESCE(r.device_host,''), r.action, r.direction,
        COALESCE(r.proto,''), COALESCE(r.dst_port, 0),
        COALESCE({src_sig_sql},''), COALESCE({dst_sig_sql},''),
        CASE WHEN r.source_type = 'api_import'
             THEN COALESCE(r.rule_name,'') ELSE '' END
    )))"""


def _write_content_hash_inline(conn, table: str):
    """Write content_hash for tables that store src_ip/dst_ip inline per row
    (fw_rules_consolidated_1). Each row hashes its own single src/dst pair."""
    expr = _hash_sha1_expr(_HASH_SRC_INLINE, _HASH_DST_INLINE)
    conn.execute(text(f"""
        UPDATE {table} r
        SET r.content_hash = {expr}
        WHERE r.generated_at = @run_ts
    """))


def _write_content_hash_subtable(conn, table: str):
    """Write content_hash for tables with separate _sources / _destinations
    sub-tables (accumulated, subnet, filtered). GROUP_CONCATs the src/dst
    sets per rule before hashing - same string format as the inline variant
    for the single-pair case, so hashes match across stages by construction."""
    sha1_expr = _hash_sha1_expr("s.s", "d.d")
    conn.execute(text(f"""
        UPDATE {table} r
        LEFT JOIN (
          SELECT rule_id, {_HASH_SRC_SUBTABLE} AS s
          FROM {table}_sources GROUP BY rule_id
        ) s ON s.rule_id = r.id
        LEFT JOIN (
          SELECT rule_id, {_HASH_DST_SUBTABLE} AS d
          FROM {table}_destinations GROUP BY rule_id
        ) d ON d.rule_id = r.id
        SET r.content_hash = {sha1_expr}
        WHERE r.generated_at = @run_ts
    """))


_QF_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _run_quality_filter(conn, src_table: str, params: dict):
    """Execute quality filter copying from src_table into fw_rules_filtered.

    Params (all optional, with defaults):
      min_hit_count    int  ≥ 1, default 10
      min_days_active  int  ≥ 0, default 1 - INCLUSIVE day count: a flow
                       first- and last-seen on the same calendar day was
                       active 1 day (DATEDIFF + 1). 2+ starts requiring a
                       multi-day span; 0/1 impose no day requirement.
      last_seen_after  date YYYY-MM-DD; default = today − 30 days
                       (UNSET stays rolling on each pipeline run)

    api_import rules bypass the gate entirely (real-config rules are
    independent of hit-derived signals); only syslog-derived rules go
    through the thresholds.
    """
    min_hits = int(params.get("min_hit_count",  10))
    min_days = int(params.get("min_days_active", 1))
    last_seen_after = params.get("last_seen_after")
    # Empty/unset → rolling default (today − 30). Once the user pins
    # an explicit date, it stays as written (migration-snapshot
    # semantics). Defense-in-depth: regex-validate every run so a
    # garbled JSON-cell can't inject SQL.
    if not last_seen_after or not _QF_DATE_RE.fullmatch(str(last_seen_after).strip()):
        last_seen_after = (datetime.date.today()
                           - datetime.timedelta(days=30)).isoformat()
    else:
        last_seen_after = str(last_seen_after).strip()

    conn.execute(text("TRUNCATE TABLE fw_rules_filtered"))
    conn.execute(text("TRUNCATE TABLE fw_rules_filtered_sources"))
    conn.execute(text("TRUNCATE TABLE fw_rules_filtered_destinations"))

    # consolidated_1 has no src_count/dst_count columns (one row = one src/dst pair)
    count_cols = "1 AS src_count, 1 AS dst_count" if src_table == "fw_rules_consolidated_1" else "src_count, dst_count"

    conn.execute(text(f"""
        INSERT INTO fw_rules_filtered (
          generated_at, vendor, device_host, action, direction,
          proto, dst_port,
          application, rule_name, security_profile, security_profile_group,
          hit_count, src_count, dst_count, first_seen, last_seen,
          src_rule_id, source_type,
          negate_source, negate_destination, negate_service,
          seq_num, schedule
        )
        SELECT
          @run_ts, vendor, device_host, action, direction,
          proto, dst_port,
          application, rule_name, security_profile, security_profile_group,
          hit_count, {count_cols}, first_seen, last_seen,
          id AS src_rule_id, source_type,
          negate_source, negate_destination, negate_service,
          seq_num, schedule
        FROM {src_table}
        WHERE generated_at = @run_ts
          AND (
            source_type = 'api_import'
            OR (
              hit_count        >= {min_hits}
              AND DATEDIFF(last_seen, first_seen) + 1 >= {min_days}
              AND last_seen    >= '{last_seen_after}'
            )
          )
    """))

    # accumulated/subnet have dedicated _sources/_destinations sub-tables.
    # consolidated_1 stores src_ip/dst_ip directly in the main row.
    if src_table == "fw_rules_consolidated_1":
        conn.execute(text("""
            INSERT INTO fw_rules_filtered_sources (rule_id, src_ip, src_zone, iface_in, hit_count)
            SELECT f.id, r.src_ip, r.src_zone, r.iface_in, r.hit_count
            FROM fw_rules_filtered f
            JOIN fw_rules_consolidated_1 r ON r.id = f.src_rule_id
            WHERE r.src_ip IS NOT NULL
        """))
        conn.execute(text("""
            INSERT INTO fw_rules_filtered_destinations (rule_id, dst_ip, dst_zone, dst_nat, hit_count)
            SELECT f.id, r.dst_ip, r.dst_zone, r.dst_nat, r.hit_count
            FROM fw_rules_filtered f
            JOIN fw_rules_consolidated_1 r ON r.id = f.src_rule_id
            WHERE r.dst_ip IS NOT NULL
        """))
    else:
        conn.execute(text(f"""
            INSERT INTO fw_rules_filtered_sources (rule_id, src_ip, src_zone, iface_in, hit_count)
            SELECT f.id, s.src_ip, s.src_zone, s.iface_in, s.hit_count
            FROM fw_rules_filtered f
            JOIN {src_table}_sources s ON s.rule_id = f.src_rule_id
        """))
        conn.execute(text(f"""
            INSERT INTO fw_rules_filtered_destinations (rule_id, dst_ip, dst_zone, dst_nat, hit_count)
            SELECT f.id, d.dst_ip, d.dst_zone, d.dst_nat, d.hit_count
            FROM fw_rules_filtered f
            JOIN {src_table}_destinations d ON d.rule_id = f.src_rule_id
        """))

    _write_content_hash_subtable(conn, "fw_rules_filtered")

    print(f"[generate] quality_filter: src={src_table}, "
          f"min_hits={min_hits}, min_days={min_days}, last_seen_after={last_seen_after}")


def _run_endpoint_pairs(conn, src_table: str):
    """Group src_table rules by (vendor, device_host, action, direction, dst_ip),
    accumulating all ports and source IPs. Works on any accumulated/subnet/filtered table."""

    # fw_rules_accumulated stores dst_ip inline; subnet/filtered use a _destinations table
    inline_dst = (src_table == "fw_rules_accumulated")
    dst_col  = "r.dst_ip" if inline_dst else "d.dst_ip"
    dst_join = "" if inline_dst else f"JOIN {src_table}_destinations d ON d.rule_id = r.id"

    conn.execute(text("TRUNCATE TABLE fw_rules_endpoint_pairs"))
    conn.execute(text("TRUNCATE TABLE fw_rules_endpoint_pairs_sources"))

    conn.execute(text(f"""
        INSERT INTO fw_rules_endpoint_pairs (
          generated_at, vendor, device_host, action, direction,
          dst_ip, ports, applications,
          rule_name, security_profile, security_profile_group,
          hit_count, first_seen, last_seen, source_type,
          negate_source, negate_destination, negate_service,
          seq_num, schedule
        )
        SELECT
          @run_ts, r.vendor, r.device_host, r.action, r.direction,
          {dst_col},
          NULLIF(GROUP_CONCAT(DISTINCT
            CASE
              WHEN r.proto IS NOT NULL AND r.dst_port IS NOT NULL
                THEN CONCAT(r.proto, '/', r.dst_port)
              WHEN r.proto IS NOT NULL THEN r.proto
              ELSE NULL
            END
            ORDER BY r.proto, r.dst_port SEPARATOR ','
          ), '') AS ports,
          NULLIF(GROUP_CONCAT(DISTINCT r.application
            ORDER BY r.application SEPARATOR ','), '') AS applications,
          MIN(r.rule_name),
          MIN(r.security_profile),
          MIN(r.security_profile_group),
          SUM(r.hit_count),
          MIN(r.first_seen),
          MAX(r.last_seen),
          CASE
            WHEN SUM(r.source_type = 'syslog') > 0 AND SUM(r.source_type = 'api_import') > 0 THEN 'both'
            WHEN SUM(r.source_type = 'api_import') > 0 THEN 'api_import'
            ELSE 'syslog'
          END,
          r.negate_source, r.negate_destination, r.negate_service,
          MIN(r.seq_num),
          MIN(r.schedule)
        FROM {src_table} r
        {dst_join}
        WHERE r.generated_at = @run_ts
        GROUP BY r.vendor, r.device_host, r.action, r.direction, {dst_col},
                 r.negate_source, r.negate_destination, r.negate_service
    """))

    # Sources: join back to pick up all src_ips for each merged rule
    if inline_dst:
        ep_match = f"""
            JOIN {src_table} r
              ON  r.generated_at  = @run_ts
              AND r.vendor        <=> ep.vendor
              AND r.device_host   <=> ep.device_host
              AND r.action         =  ep.action
              AND r.direction      =  ep.direction
              AND r.dst_ip        <=> ep.dst_ip"""
    else:
        ep_match = f"""
            JOIN {src_table} r
              ON  r.generated_at  = @run_ts
              AND r.vendor        <=> ep.vendor
              AND r.device_host   <=> ep.device_host
              AND r.action         =  ep.action
              AND r.direction      =  ep.direction
            JOIN {src_table}_destinations d
              ON  d.rule_id  = r.id
              AND d.dst_ip  <=> ep.dst_ip"""

    conn.execute(text(f"""
        INSERT INTO fw_rules_endpoint_pairs_sources (rule_id, src_ip, src_zone, iface_in, hit_count)
        SELECT ep.id, s.src_ip, MIN(s.src_zone), MIN(s.iface_in), SUM(s.hit_count)
        FROM fw_rules_endpoint_pairs ep
        {ep_match}
        JOIN {src_table}_sources s ON s.rule_id = r.id
        WHERE ep.generated_at = @run_ts
        GROUP BY ep.id, s.src_ip
        ON DUPLICATE KEY UPDATE hit_count = hit_count + VALUES(hit_count)
    """))

    conn.execute(text("""
        UPDATE fw_rules_endpoint_pairs ep
        JOIN (
          SELECT rule_id, COUNT(*) AS n
          FROM fw_rules_endpoint_pairs_sources
          GROUP BY rule_id
        ) s ON s.rule_id = ep.id
        SET ep.src_count = s.n
        WHERE ep.generated_at = @run_ts
    """))

    print(f"[generate] endpoint_pairs: src={src_table}")


# MIN(NULLIF(vendor,'')) so the aggregate's '' sentinel (COALESCE(vendor,''))
# behaves like a flow's NULL vendor under MIN - i.e. it's skipped, matching the
# old fw_flows MIN(vendor).
_VENDOR_TO_PLATFORM = """
    CASE MIN(NULLIF(vendor, ''))
        WHEN 'opnsense'  THEN 'opnsense'
        WHEN 'palo-alto' THEN 'panw'
        WHEN 'fortinet'  THEN 'fortigate'
        ELSE NULL
    END
"""


def _auto_register_devices(conn):
    """Register new syslog device_hosts and fill in platform from vendor where
    detectable.

    Reads the ingest-maintained fw_rule_aggregates (~15k rows; carries
    device_host, vendor and seen_syslog) instead of scanning raw fw_flows -
    same invariant as 27_infer_nat_rules ("generate derives only from
    aggregates; ingest owns raw-flow aggregation"). seen_syslog=1 selects rows
    that had a syslog source; the '' device_host sentinel is excluded (matches
    the old `device_host IS NOT NULL`).

    Plan: project_nat_evidence_aggregate_active_plan (P4 - second invariant
    violator found during smoke; 2.8M-row scan, ~129 s → sub-second).
    """
    try:
        conn.execute(text(f"""
            INSERT IGNORE INTO fw_devices (host_name, platform, role)
            SELECT device_host, {_VENDOR_TO_PLATFORM}, 'source'
            FROM fw_rule_aggregates
            WHERE device_host != '' AND seen_syslog = 1
              AND device_host NOT IN (SELECT host_name FROM fw_devices)
            GROUP BY device_host
        """))
        # Also fill in platform for existing auto-registered devices (platform IS NULL)
        conn.execute(text(f"""
            UPDATE fw_devices d
            JOIN (
                SELECT device_host, {_VENDOR_TO_PLATFORM} AS platform
                FROM fw_rule_aggregates
                WHERE device_host != '' AND seen_syslog = 1
                GROUP BY device_host
            ) t ON t.device_host = d.host_name
            SET d.platform = t.platform
            WHERE d.platform IS NULL AND t.platform IS NOT NULL
        """))
    except Exception as e:
        print(f"[generate] auto_register_devices failed: {e}")


def run_sql_jobs(engine0, db_name: str, jobs_dir: str, since_dt=None, until_dt=None, days_back: int = 7) -> int:
    if not os.path.isdir(jobs_dir):
        return 0

    _PIPELINE_SKIP: set[str] = set()
    files = sorted(
        os.path.join(jobs_dir, name)
        for name in os.listdir(jobs_dir)
        if name.endswith(".sql") and name not in _PIPELINE_SKIP
    )
    if not files:
        return 0

    from datetime import datetime, timezone, timedelta
    if since_dt is None:
        since_dt = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days_back)
    if until_dt is None:
        until_dt = datetime.now(timezone.utc).replace(tzinfo=None)

    executed = 0

    with engine0.begin() as conn:
        conn.execute(text(f"USE `{db_name}`"))
        conn.execute(text("SET @run_ts = NOW()"))
        conn.execute(text("SET @since_ts = :v"), {"v": since_dt})
        conn.execute(text("SET @until_ts = :v"), {"v": until_dt})

        total_events = conn.execute(text("""
            SELECT COUNT(*) FROM fw_flows
            WHERE event_ts IS NOT NULL AND event_ts >= @since_ts
        """)).scalar()
        print(f"[generate] days_back={int(days_back)} events_in_scope={int(total_events or 0)}")

        _auto_register_devices(conn)

        pipeline_cfg = _load_pipeline_config(conn)

        # Determine which modules are enabled
        enabled_modules = {
            name: pipeline_cfg.get(name, {}).get("enabled", True)
            for name, _ in MODULES
        }

        # Determine quality filter source: highest active module before it
        qf_src = "fw_rules_consolidated_1"
        if enabled_modules.get("53_subnet"):
            qf_src = "fw_rules_subnet"
        elif enabled_modules.get("52_accumulate"):
            qf_src = "fw_rules_accumulated"

        # Endpoint pairs reads from the highest active module (including quality filter)
        ep_src = qf_src
        if enabled_modules.get("55_quality_filter"):
            ep_src = "fw_rules_filtered"

        for path in files:
            basename = os.path.basename(path)
            job_name = basename[:-4]
            job_cfg  = pipeline_cfg.get(job_name, {})

            # Always-on jobs (stage 1 pipeline)
            always_on = job_name in (
                "20_generate_rule_candidates",
                "22_cleanup_nat_duplicates",
                "23_build_rules_consolidated",
                "27_infer_nat_rules",
                "28_aggregate_nat",
            )

            if not always_on and not job_cfg.get("enabled", True):
                print(f"[generate] skipping {basename} (disabled)")
                continue

            # Quality filter: handle dynamically in Python
            if job_name == "55_quality_filter":
                print(f"[generate] running {basename}")
                _run_quality_filter(conn, qf_src, job_cfg.get("params", {}))
                executed += 1
                continue

            # Endpoint pairs: handle dynamically in Python (source table varies)
            if job_name == "56_endpoint_pairs":
                print(f"[generate] running {basename}")
                _run_endpoint_pairs(conn, ep_src)
                executed += 1
                continue

            # Set job parameters as SQL variables
            for k, v in job_cfg.get("params", {}).items():
                if isinstance(v, str):
                    conn.execute(text(f"SET @`{k}` = :val"), {"val": v})
                else:
                    conn.execute(text(f"SET @`{k}` = {float(v) if isinstance(v, float) else int(v)}"))

            print(f"[generate] running {basename}")
            sql = _read_sql(path)
            for stmt in _split_sql(sql):
                conn.execute(text(stmt))
            executed += 1

            # Stamp content_hash on the stage's output table. Same SHA1 input
            # for every stage so overrides bind by hash regardless of which
            # module is the active tail. We hash after 23_build_rules_consolidated
            # (always-on); 24_zone_enrich is deactivated (Refactor 2026-06-01 -
            # source→target zone translation is now user-driven, not pipeline).
            if job_name == "23_build_rules_consolidated":
                _write_content_hash_inline(conn, "fw_rules_consolidated_1")
            elif job_name == "52_accumulate":
                _write_content_hash_subtable(conn, "fw_rules_accumulated")
            elif job_name == "53_subnet":
                _write_content_hash_subtable(conn, "fw_rules_subnet")

        rule_count = conn.execute(text("""
            SELECT COUNT(*) FROM fw_rule_candidates WHERE generated_at >= @run_ts
        """)).scalar()
        print(f"[generate] new_rule_candidates={int(rule_count or 0)}")

        # Assign sequence numbers for api_import rules from the original import order
        try:
            for tbl in ("fw_rules_consolidated_1", "fw_rules_accumulated",
                        "fw_rules_subnet", "fw_rules_filtered"):
                conn.execute(text(f"""
                    UPDATE {tbl} c
                    JOIN fw_devices d
                      ON d.display_name = c.device_host OR d.host_name = c.device_host
                    JOIN fw_imported_rules ir
                      ON ir.device_id = d.id AND ir.rule_name = c.rule_name
                     AND ir.import_ts = (
                           SELECT MAX(import_ts) FROM fw_imported_rules
                           WHERE device_id = d.id
                         )
                    SET c.`sequence` = ir.seq_num
                    WHERE c.source_type = 'api_import'
                      AND c.generated_at = @run_ts
                """))
            print("[generate] api_import sequences assigned")
        except Exception as e:
            print(f"[generate] sequence assignment failed: {e}")

        # Count unzoned sources and destinations (excluding internet_public)
        # Used by the UI to lock/unlock the Grouping tab
        try:
            # Exclude api_import rows - their zones come from device policy, not IP mappings
            unzoned_src = conn.execute(text("""
                SELECT COUNT(*) FROM fw_rules_consolidated_1
                WHERE src_zone IS NULL AND src_ip IS NOT NULL
                  AND source_type != 'api_import'
                UNION ALL
                SELECT COUNT(*) FROM fw_rules_accumulated_sources
                WHERE src_zone IS NULL AND src_ip IS NOT NULL AND src_ip != 'internet_public'
            """)).fetchall()
            unzoned_dst = conn.execute(text("""
                SELECT COUNT(*) FROM fw_rules_consolidated_1
                WHERE dst_zone IS NULL AND dst_ip IS NOT NULL
                  AND source_type != 'api_import'
                UNION ALL
                SELECT COUNT(*) FROM fw_rules_accumulated_destinations
                WHERE dst_zone IS NULL AND dst_ip IS NOT NULL AND dst_ip != 'internet_public'
            """)).fetchall()
            unzoned = sum(int(r[0]) for r in unzoned_src) + sum(int(r[0]) for r in unzoned_dst)
            conn.execute(text("""
                INSERT INTO fw_pipeline_config (job_name, enabled, params)
                VALUES ('_zone_status', 1, :p)
                ON DUPLICATE KEY UPDATE params = :p
            """), {"p": json.dumps({"unzoned_count": unzoned})})
            print(f"[generate] unzoned_ips={unzoned}")
        except Exception as e:
            print(f"[generate] zone_status check failed: {e}")

        # Orphan-override cleanup intentionally lives in the webui
        # (_cleanup_override_drift, single source of truth): it checks the
        # ACTIVE tail (fw_rules_consolidated_1) at its latest generated_at and
        # covers every rule_hash-keyed override table. A second cleanup here
        # used to delete against fw_rules_filtered - but that stage is disabled
        # (2026-06-01 refactor), so its content_hash is stale and the check
        # wrongly orphaned valid app/zone/log/security_profile/service
        # overrides on every generate. Removed rather than duplicated; orphans
        # are harmless (they simply don't bind) and the webui cleans them after
        # the pipeline returns. See project_enrichment_hash_drift memo.

    return executed
