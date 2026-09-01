-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

TRUNCATE TABLE fw_rules_consolidated_1;

INSERT INTO fw_rules_consolidated_1 (
  generated_at, vendor, device_host, action, direction,
  iface_in, iface_out, src_zone, dst_zone,
  src_ip, src_nat, dst_ip, dst_nat,
  proto, dst_port, application, rule_name,
  security_profile, security_profile_group, url_category,
  hit_count, first_seen, last_seen, source_type,
  negate_source, negate_destination, negate_service,
  seq_num, schedule
)
SELECT
  @run_ts,
  vendor, device_host, action, direction,
  MIN(iface_in)     AS iface_in,
  MIN(iface_out)    AS iface_out,
  MIN(src_zone)     AS src_zone,
  MIN(dst_zone)     AS dst_zone,
  src_ip,
  MIN(src_nat)      AS src_nat,
  dst_ip,
  MIN(dst_nat)      AS dst_nat,
  proto,
  dst_port,
  MIN(application)  AS application,
  MIN(rule_name)    AS rule_name,
  MIN(security_profile) AS security_profile,
  MIN(security_profile_group) AS security_profile_group,
  MIN(url_category) AS url_category,
  SUM(hit_count)    AS hit_count,
  MIN(first_seen)   AS first_seen,
  MAX(last_seen)    AS last_seen,
  CASE
    WHEN SUM(source_type = 'syslog') > 0 AND SUM(source_type = 'api_import') > 0 THEN 'both'
    WHEN SUM(source_type = 'api_import') > 0 THEN 'api_import'
    ELSE 'syslog'
  END AS source_type,
  negate_source, negate_destination, negate_service,
  MIN(seq_num) AS seq_num,
  MIN(schedule) AS schedule
FROM (
  SELECT
    c.vendor, c.device_host, c.action, c.direction,
    c.iface_in, c.iface_out, c.src_zone, c.dst_zone,
    c.src_ip,
    c.src_nat,
    c.dst_ip,
    c.dst_nat,
    c.proto,
    c.dst_port_from AS dst_port,
    c.application,
    c.rule_name,
    c.security_profile,
    c.security_profile_group,
    c.url_category,
    c.hit_count,
    c.first_seen,
    c.last_seen,
    c.source_type,
    c.negate_source,
    c.negate_destination,
    c.negate_service,
    c.seq_num,
    c.schedule
  FROM fw_rule_candidates c
  WHERE c.generated_at = @run_ts
) t
GROUP BY
  vendor, device_host, action, direction,
  src_ip, dst_ip, dst_nat, proto, dst_port,
  rule_name,
  -- Negate-split per project_rule_negation_plan conflict-policy
  negate_source, negate_destination, negate_service;
