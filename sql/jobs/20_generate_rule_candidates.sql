-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- Remove candidates from all previous runs; keep only the current run.
DELETE FROM fw_rule_candidates WHERE generated_at < @run_ts;

-- Phase 3 of rule-aggregate-persistence: this job no longer scans the
-- full fw_flows table (~2.6 M rows, full-scan + filesort, 20+ min). The
-- write-through pattern in webui/main.py (api_import) and
-- pyapp/gateshift/modules/ingest.py (syslog) maintains fw_rule_aggregates
-- incrementally - ~1.500 distinct rule_hashes / ~15.000 group rows. The
-- 14-column GROUP BY moved into the ingest V-step (EVA-conform).
--
-- Quality-filter semantic preserved via hit_count_quality_passed counter
-- (set per-row at ingest time by the same CASE predicate the original
-- WHERE clause used). api_import bypass via seen_api_import per
-- project_qf_api_import_bypass.
--
-- days_back is now obsolete (all-time aggregate state by design);
-- the @since_ts / @until_ts engine bindings are accepted but unused.
-- last_seen + first_seen per row still reveal age for any read-side
-- filtering that wants it.

INSERT INTO fw_rule_candidates (
  generated_at,
  vendor,
  device_host,
  action,
  direction,
  iface_in,
  iface_out,
  src_zone,
  dst_zone,
  proto,
  src_ip,
  src_nat,
  dst_ip,
  dst_nat,
  dst_port_from,
  dst_port_to,
  application,
  rule_name,
  security_profile,
  security_profile_group,
  url_category,
  rule_hash,
  first_seen,
  last_seen,
  hit_count,
  src_ip_count,
  dst_ip_count,
  quality_score,
  sample_raw_id,
  source_type,
  negate_source,
  negate_destination,
  negate_service,
  seq_num,
  schedule
)
SELECT
  @run_ts AS generated_at,
  vendor,
  device_host,
  action,
  direction,
  iface_in,
  iface_out,
  src_zone,
  dst_zone,
  proto,
  INET6_NTOA(src_ip)     AS src_ip,
  INET6_NTOA(nat_src_ip) AS src_nat,
  INET6_NTOA(dst_ip)     AS dst_ip,
  INET6_NTOA(nat_dst_ip) AS dst_nat,
  effective_port AS dst_port_from,
  effective_port AS dst_port_to,
  application,
  rule_name,
  security_profile,
  security_profile_group,
  url_category,
  rule_hash,
  first_seen,
  last_seen,
  hit_count_quality_passed AS hit_count,
  -- COUNT(DISTINCT src_ip)/dst_ip were trivially 1 in the old GROUP BY
  -- (src_ip + dst_ip were both GROUP BY columns). Hardcode here so the
  -- output schema stays identical; the column has no real distinct-
  -- counting semantic anyway.
  1 AS src_ip_count,
  1 AS dst_ip_count,
  NULL AS quality_score,
  sample_raw_id,
  CASE
    WHEN seen_syslog = 1 AND seen_api_import = 1 THEN 'both'
    WHEN seen_api_import = 1 THEN 'api_import'
    ELSE 'syslog'
  END AS source_type,
  negate_source,
  negate_destination,
  negate_service,
  seq_num,
  schedule
FROM fw_rule_aggregates
WHERE hit_count_quality_passed > 0
   OR seen_api_import = 1;
