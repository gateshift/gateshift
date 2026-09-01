-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- Module: Accumulate (destination-centric)
-- Groups consolidated_1 by (vendor, device_host, action, direction, proto, dst_port, effective_dst_ip)
-- internet_public_dst / internet_public_src collapse public IPs independently per side.

SET @ip_dst_on = IFNULL(
  (SELECT CAST(JSON_UNQUOTE(JSON_EXTRACT(params, '$.internet_public_dst')) AS UNSIGNED)
   FROM fw_pipeline_config WHERE job_name = '_display' LIMIT 1), 0);

SET @ip_dst_threshold = IFNULL(
  (SELECT CAST(JSON_UNQUOTE(JSON_EXTRACT(params, '$.internet_public_dst_threshold')) AS UNSIGNED)
   FROM fw_pipeline_config WHERE job_name = '_display' LIMIT 1), 1);

SET @ip_src_on = IFNULL(
  (SELECT CAST(JSON_UNQUOTE(JSON_EXTRACT(params, '$.internet_public_src')) AS UNSIGNED)
   FROM fw_pipeline_config WHERE job_name = '_display' LIMIT 1), 0);

SET @ip_src_threshold = IFNULL(
  (SELECT CAST(JSON_UNQUOTE(JSON_EXTRACT(params, '$.internet_public_src_threshold')) AS UNSIGNED)
   FROM fw_pipeline_config WHERE job_name = '_display' LIMIT 1), 1);

-- Legacy alias: if old key present and new key absent, inherit dst setting
SET @ip_dst_on = IFNULL(@ip_dst_on,
  (SELECT CAST(JSON_UNQUOTE(JSON_EXTRACT(params, '$.internet_public')) AS UNSIGNED)
   FROM fw_pipeline_config WHERE job_name = '_display' LIMIT 1));

TRUNCATE TABLE fw_rules_accumulated;
TRUNCATE TABLE fw_rules_accumulated_sources;
TRUNCATE TABLE fw_rules_accumulated_destinations;

-- ============================================================
-- 0a. Pre-compute COUNT(DISTINCT public dst_ip) per group
-- ============================================================
DROP TEMPORARY TABLE IF EXISTS tmp_pub_dst_count;
CREATE TEMPORARY TABLE tmp_pub_dst_count
CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
AS
SELECT vendor, device_host, action, direction, proto, dst_port,
       COUNT(DISTINCT dst_ip) AS pub_dst_count
FROM fw_rules_consolidated_1
WHERE generated_at = @run_ts
  AND dst_ip IS NOT NULL
  AND dst_nat IS NULL
  AND INET_ATON(dst_ip) IS NOT NULL
  AND NOT (
       INET_ATON(dst_ip) BETWEEN INET_ATON('10.0.0.0')    AND INET_ATON('10.255.255.255')
    OR INET_ATON(dst_ip) BETWEEN INET_ATON('172.16.0.0')  AND INET_ATON('172.31.255.255')
    OR INET_ATON(dst_ip) BETWEEN INET_ATON('192.168.0.0') AND INET_ATON('192.168.255.255')
    OR INET_ATON(dst_ip) BETWEEN INET_ATON('127.0.0.0')   AND INET_ATON('127.255.255.255')
    OR INET_ATON(dst_ip) BETWEEN INET_ATON('169.254.0.0') AND INET_ATON('169.254.255.255')
  )
GROUP BY vendor, device_host, action, direction, proto, dst_port;

-- ============================================================
-- 0b. Pre-compute COUNT(DISTINCT public src_ip) per group
-- ============================================================
DROP TEMPORARY TABLE IF EXISTS tmp_pub_src_count;
CREATE TEMPORARY TABLE tmp_pub_src_count
CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
AS
SELECT vendor, device_host, action, direction, proto, dst_port,
       COUNT(DISTINCT src_ip) AS pub_src_count
FROM fw_rules_consolidated_1
WHERE generated_at = @run_ts
  AND src_ip IS NOT NULL
  AND INET_ATON(src_ip) IS NOT NULL
  AND NOT (
       INET_ATON(src_ip) BETWEEN INET_ATON('10.0.0.0')    AND INET_ATON('10.255.255.255')
    OR INET_ATON(src_ip) BETWEEN INET_ATON('172.16.0.0')  AND INET_ATON('172.31.255.255')
    OR INET_ATON(src_ip) BETWEEN INET_ATON('192.168.0.0') AND INET_ATON('192.168.255.255')
    OR INET_ATON(src_ip) BETWEEN INET_ATON('127.0.0.0')   AND INET_ATON('127.255.255.255')
    OR INET_ATON(src_ip) BETWEEN INET_ATON('169.254.0.0') AND INET_ATON('169.254.255.255')
  )
GROUP BY vendor, device_host, action, direction, proto, dst_port;

-- ============================================================
-- 0c. Build effective_dst_ip and effective_src_ip
-- ============================================================
DROP TEMPORARY TABLE IF EXISTS tmp_c1_effective;
CREATE TEMPORARY TABLE tmp_c1_effective
CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
AS
SELECT c.*,
  -- effective_dst_ip
  CASE
    WHEN @ip_dst_on = 0 THEN c.dst_ip
    WHEN c.dst_ip IS NULL THEN NULL
    WHEN INET_ATON(c.dst_ip) IS NULL THEN c.dst_ip
    WHEN (
         INET_ATON(c.dst_ip) BETWEEN INET_ATON('10.0.0.0')    AND INET_ATON('10.255.255.255')
      OR INET_ATON(c.dst_ip) BETWEEN INET_ATON('172.16.0.0')  AND INET_ATON('172.31.255.255')
      OR INET_ATON(c.dst_ip) BETWEEN INET_ATON('192.168.0.0') AND INET_ATON('192.168.255.255')
      OR INET_ATON(c.dst_ip) BETWEEN INET_ATON('127.0.0.0')   AND INET_ATON('127.255.255.255')
      OR INET_ATON(c.dst_ip) BETWEEN INET_ATON('169.254.0.0') AND INET_ATON('169.254.255.255')
    ) THEN c.dst_ip
    WHEN c.dst_nat IS NOT NULL THEN c.dst_ip   -- NAT'd target: always keep real IP, never collapse
    WHEN COALESCE(pd.pub_dst_count, 0) >= @ip_dst_threshold THEN 'internet_public'
    ELSE c.dst_ip
  END AS effective_dst_ip,
  -- effective_src_ip
  CASE
    WHEN @ip_src_on = 0 THEN c.src_ip
    WHEN c.src_ip IS NULL THEN NULL
    WHEN INET_ATON(c.src_ip) IS NULL THEN c.src_ip
    WHEN (
         INET_ATON(c.src_ip) BETWEEN INET_ATON('10.0.0.0')    AND INET_ATON('10.255.255.255')
      OR INET_ATON(c.src_ip) BETWEEN INET_ATON('172.16.0.0')  AND INET_ATON('172.31.255.255')
      OR INET_ATON(c.src_ip) BETWEEN INET_ATON('192.168.0.0') AND INET_ATON('192.168.255.255')
      OR INET_ATON(c.src_ip) BETWEEN INET_ATON('127.0.0.0')   AND INET_ATON('127.255.255.255')
      OR INET_ATON(c.src_ip) BETWEEN INET_ATON('169.254.0.0') AND INET_ATON('169.254.255.255')
    ) THEN c.src_ip
    WHEN COALESCE(ps.pub_src_count, 0) >= @ip_src_threshold THEN 'internet_public'
    ELSE c.src_ip
  END AS effective_src_ip
FROM fw_rules_consolidated_1 c
LEFT JOIN tmp_pub_dst_count pd
  ON  pd.vendor      <=> c.vendor
  AND pd.device_host <=> c.device_host
  AND pd.action       =  c.action
  AND pd.direction    =  c.direction
  AND pd.proto       <=> c.proto
  AND pd.dst_port    <=> c.dst_port
LEFT JOIN tmp_pub_src_count ps
  ON  ps.vendor      <=> c.vendor
  AND ps.device_host <=> c.device_host
  AND ps.action       =  c.action
  AND ps.direction    =  c.direction
  AND ps.proto       <=> c.proto
  AND ps.dst_port    <=> c.dst_port
WHERE c.generated_at = @run_ts;

-- ============================================================
-- 1. One rule per (proto, port, effective_dst_ip)
-- ============================================================
INSERT INTO fw_rules_accumulated (
  generated_at, vendor, device_host, action, direction,
  proto, dst_port,
  application, rule_name, security_profile, security_profile_group,
  dst_ip,
  hit_count, first_seen, last_seen, source_type,
  negate_source, negate_destination, negate_service,
  seq_num, schedule
)
SELECT
  @run_ts,
  vendor, device_host, action, direction,
  proto, dst_port,
  MIN(application), MIN(rule_name), MIN(security_profile), MIN(security_profile_group),
  effective_dst_ip,
  SUM(hit_count), MIN(first_seen), MAX(last_seen),
  CASE
    WHEN SUM(source_type = 'syslog') > 0 AND SUM(source_type = 'api_import') > 0 THEN 'both'
    WHEN SUM(source_type = 'api_import') > 0 THEN 'api_import'
    ELSE 'syslog'
  END AS source_type,
  negate_source, negate_destination, negate_service,
  MIN(seq_num) AS seq_num,
  MIN(schedule) AS schedule
FROM tmp_c1_effective
GROUP BY vendor, device_host, action, direction, proto, dst_port, effective_dst_ip,
  CASE WHEN source_type = 'api_import' THEN rule_name ELSE NULL END,
  -- Negate flags split: rules with disagreeing negate-flags on the same
  -- (proto, port, dst_ip) tuple stay separate after aggregation. Per
  -- project_rule_negation_plan conflict-policy.
  negate_source, negate_destination, negate_service;

-- ============================================================
-- 2. Accumulate sources (use effective_src_ip)
-- ============================================================
INSERT INTO fw_rules_accumulated_sources (rule_id, src_ip, src_zone, iface_in, hit_count)
SELECT r.id, c.effective_src_ip, MIN(c.src_zone), MIN(c.iface_in), SUM(c.hit_count)
FROM fw_rules_accumulated r
JOIN tmp_c1_effective c
  ON  c.vendor           <=> r.vendor
  AND c.device_host      <=> r.device_host
  AND c.action            =  r.action
  AND c.direction         =  r.direction
  AND c.proto            <=> r.proto
  AND c.dst_port         <=> r.dst_port
  AND c.effective_dst_ip <=> r.dst_ip
  AND (CASE WHEN c.source_type = 'api_import' THEN c.rule_name ELSE NULL END)
      <=> (CASE WHEN r.source_type = 'api_import' THEN r.rule_name ELSE NULL END)
WHERE r.generated_at = @run_ts
  AND c.effective_src_ip IS NOT NULL
GROUP BY r.id, c.effective_src_ip
ON DUPLICATE KEY UPDATE hit_count = VALUES(hit_count);

-- ============================================================
-- 3. Populate _destinations (effective_dst_ip, not raw dst_ip)
-- ============================================================
INSERT INTO fw_rules_accumulated_destinations (rule_id, dst_ip, dst_zone, dst_nat, hit_count)
SELECT r.id, r.dst_ip, MIN(c.dst_zone), MIN(c.dst_nat), SUM(c.hit_count)
FROM fw_rules_accumulated r
JOIN fw_rules_consolidated_1 c
  ON  c.generated_at  = @run_ts
  AND c.vendor        <=> r.vendor
  AND c.device_host   <=> r.device_host
  AND c.action         =  r.action
  AND c.direction      =  r.direction
  AND c.proto         <=> r.proto
  AND c.dst_port      <=> r.dst_port
  AND (CASE WHEN c.source_type = 'api_import' THEN c.rule_name ELSE NULL END)
      <=> (CASE WHEN r.source_type = 'api_import' THEN r.rule_name ELSE NULL END)
  AND (
    c.dst_ip <=> r.dst_ip
    OR (r.dst_ip = 'internet_public' AND @ip_dst_on = 1 AND c.dst_nat IS NULL
        AND INET_ATON(c.dst_ip) IS NOT NULL AND NOT (
             INET_ATON(c.dst_ip) BETWEEN INET_ATON('10.0.0.0')    AND INET_ATON('10.255.255.255')
          OR INET_ATON(c.dst_ip) BETWEEN INET_ATON('172.16.0.0')  AND INET_ATON('172.31.255.255')
          OR INET_ATON(c.dst_ip) BETWEEN INET_ATON('192.168.0.0') AND INET_ATON('192.168.255.255')
          OR INET_ATON(c.dst_ip) BETWEEN INET_ATON('127.0.0.0')   AND INET_ATON('127.255.255.255')
          OR INET_ATON(c.dst_ip) BETWEEN INET_ATON('169.254.0.0') AND INET_ATON('169.254.255.255')
        ))
  )
WHERE r.generated_at = @run_ts
  AND r.dst_ip IS NOT NULL
GROUP BY r.id
ON DUPLICATE KEY UPDATE hit_count = VALUES(hit_count);

-- ============================================================
-- 4. Update counts
-- ============================================================
UPDATE fw_rules_accumulated r
LEFT JOIN (SELECT rule_id, COUNT(*) AS n FROM fw_rules_accumulated_sources      GROUP BY rule_id) s ON s.rule_id = r.id
LEFT JOIN (SELECT rule_id, COUNT(*) AS n FROM fw_rules_accumulated_destinations  GROUP BY rule_id) d ON d.rule_id = r.id
SET r.src_count = COALESCE(s.n, 0),
    r.dst_count = COALESCE(d.n, 0)
WHERE r.generated_at = @run_ts;
