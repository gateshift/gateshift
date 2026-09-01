-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- Module: Subnet aggregation
-- Reads from fw_rules_accumulated if available (dst-centric), else fw_rules_consolidated_1
-- Aggregates private IPs into subnets based on global density thresholds
-- Uses src_rule_id to directly reference source rules (no complex grouping-key joins)

SET @src_subnet_on    = IFNULL(@src_subnet_on,    1);
SET @dst_subnet_on    = IFNULL(@dst_subnet_on,    1);
SET @src_threshold_28 = IFNULL(@src_threshold_28, 4);
SET @src_threshold_24 = IFNULL(@src_threshold_24, 3);
SET @src_threshold_16 = IFNULL(@src_threshold_16, 5);
SET @src_threshold_8  = IFNULL(@src_threshold_8,  10);
SET @dst_threshold_28 = IFNULL(@dst_threshold_28, 4);
SET @dst_threshold_24 = IFNULL(@dst_threshold_24, 3);
SET @dst_threshold_16 = IFNULL(@dst_threshold_16, 5);
SET @dst_threshold_8  = IFNULL(@dst_threshold_8,  10);

TRUNCATE TABLE fw_rules_subnet;
TRUNCATE TABLE fw_rules_subnet_sources;
TRUNCATE TABLE fw_rules_subnet_destinations;

-- ============================================================
-- 1. Copy rules from accumulated (preserving dst-centric structure + src_rule_id)
-- ============================================================
INSERT INTO fw_rules_subnet (
  generated_at, vendor, device_host, action, direction,
  proto, dst_port,
  application, rule_name, security_profile, security_profile_group,
  hit_count, first_seen, last_seen,
  src_rule_id, source_type,
  negate_source, negate_destination, negate_service,
  seq_num, schedule
)
SELECT
  @run_ts, vendor, device_host, action, direction,
  proto, dst_port,
  application, rule_name, security_profile, security_profile_group,
  hit_count, first_seen, last_seen,
  id AS src_rule_id, source_type,
  negate_source, negate_destination, negate_service,
  seq_num, schedule
FROM fw_rules_accumulated
WHERE generated_at = @run_ts
  AND EXISTS (SELECT 1 FROM fw_rules_accumulated WHERE generated_at = @run_ts LIMIT 1);

-- Fallback: consolidated_1 (when accumulate module is disabled)
-- Groups dst-centrically to match the expected structure
INSERT INTO fw_rules_subnet (
  generated_at, vendor, device_host, action, direction,
  proto, dst_port,
  application, rule_name, security_profile, security_profile_group,
  hit_count, first_seen, last_seen,
  src_rule_id, source_type,
  negate_source, negate_destination, negate_service,
  seq_num, schedule
)
SELECT
  @run_ts, vendor, device_host, action, direction,
  proto, dst_port,
  MIN(application), MIN(rule_name), MIN(security_profile), MIN(security_profile_group),
  SUM(hit_count), MIN(first_seen), MAX(last_seen),
  NULL AS src_rule_id,
  CASE
    WHEN SUM(source_type = 'syslog') > 0 AND SUM(source_type = 'api_import') > 0 THEN 'both'
    WHEN SUM(source_type = 'api_import') > 0 THEN 'api_import'
    ELSE 'syslog'
  END AS source_type,
  negate_source, negate_destination, negate_service,
  MIN(seq_num) AS seq_num,
  MIN(schedule) AS schedule
FROM fw_rules_consolidated_1
WHERE generated_at = @run_ts
  AND NOT EXISTS (SELECT 1 FROM fw_rules_accumulated WHERE generated_at = @run_ts LIMIT 1)
GROUP BY vendor, device_host, action, direction, proto, dst_port,
  CASE WHEN source_type = 'api_import' THEN rule_name ELSE NULL END,
  -- Negate-split per project_rule_negation_plan conflict-policy
  negate_source, negate_destination, negate_service;

-- ============================================================
-- 2. Build source IP pool
-- ============================================================
DROP TEMPORARY TABLE IF EXISTS tmp_src_pool;
CREATE TEMPORARY TABLE tmp_src_pool
CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
AS
-- Accumulated path: direct join via src_rule_id
SELECT r.id AS rule_id, s.src_ip, s.src_zone, s.iface_in, s.hit_count
FROM fw_rules_subnet r
JOIN fw_rules_accumulated_sources s ON s.rule_id = r.src_rule_id
WHERE r.generated_at = @run_ts
  AND r.src_rule_id IS NOT NULL

UNION ALL

-- Consolidated_1 fallback: join via grouping keys
SELECT r.id AS rule_id, c.src_ip, c.src_zone, c.iface_in, c.hit_count
FROM fw_rules_subnet r
JOIN fw_rules_consolidated_1 c
  ON  c.generated_at  = @run_ts
  AND c.vendor        <=> r.vendor
  AND c.device_host   <=> r.device_host
  AND c.action         =  r.action
  AND c.direction      =  r.direction
  AND c.proto         <=> r.proto
  AND c.dst_port      <=> r.dst_port
WHERE r.generated_at = @run_ts
  AND r.src_rule_id IS NULL;

-- ============================================================
-- 3. Build destination IP pool
-- ============================================================
DROP TEMPORARY TABLE IF EXISTS tmp_dst_pool;
CREATE TEMPORARY TABLE tmp_dst_pool
CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
AS
-- Accumulated path: direct join via src_rule_id
SELECT r.id AS rule_id, d.dst_ip, d.dst_zone, d.dst_nat, d.hit_count
FROM fw_rules_subnet r
JOIN fw_rules_accumulated_destinations d ON d.rule_id = r.src_rule_id
WHERE r.generated_at = @run_ts
  AND r.src_rule_id IS NOT NULL

UNION ALL

-- Consolidated_1 fallback
SELECT r.id AS rule_id, c.dst_ip, c.dst_zone, c.dst_nat, c.hit_count
FROM fw_rules_subnet r
JOIN fw_rules_consolidated_1 c
  ON  c.generated_at  = @run_ts
  AND c.vendor        <=> r.vendor
  AND c.device_host   <=> r.device_host
  AND c.action         =  r.action
  AND c.direction      =  r.direction
  AND c.proto         <=> r.proto
  AND c.dst_port      <=> r.dst_port
WHERE r.generated_at = @run_ts
  AND r.src_rule_id IS NULL;

-- ============================================================
-- 4. Compute subnet prefixes for sources
-- ============================================================
DROP TEMPORARY TABLE IF EXISTS tmp_src;
CREATE TEMPORARY TABLE tmp_src
CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
AS
SELECT
  rule_id, src_ip, src_zone, iface_in, hit_count,
  CASE WHEN is_private THEN CONCAT(SUBSTRING_INDEX(src_ip, '.', 3), '.', FLOOR(SUBSTRING_INDEX(src_ip, '.', -1) / 16) * 16, '/28') ELSE NULL END AS prefix_28,
  CASE WHEN is_private THEN CONCAT(SUBSTRING_INDEX(src_ip, '.', 3), '.0/24')    ELSE NULL END AS prefix_24,
  CASE WHEN is_private THEN CONCAT(SUBSTRING_INDEX(src_ip, '.', 2), '.0.0/16')  ELSE NULL END AS prefix_16,
  CASE WHEN is_private THEN CONCAT(SUBSTRING_INDEX(src_ip, '.', 1), '.0.0.0/8') ELSE NULL END AS prefix_8
FROM (
  SELECT rule_id, src_ip, src_zone, iface_in, hit_count,
    INET_ATON(src_ip) IS NOT NULL AND (
      INET_ATON(src_ip) BETWEEN INET_ATON('10.0.0.0')    AND INET_ATON('10.255.255.255')
   OR INET_ATON(src_ip) BETWEEN INET_ATON('172.16.0.0')  AND INET_ATON('172.31.255.255')
   OR INET_ATON(src_ip) BETWEEN INET_ATON('192.168.0.0') AND INET_ATON('192.168.255.255')
   OR INET_ATON(src_ip) BETWEEN INET_ATON('127.0.0.0')   AND INET_ATON('127.255.255.255')
   OR INET_ATON(src_ip) BETWEEN INET_ATON('169.254.0.0') AND INET_ATON('169.254.255.255')
    ) AS is_private
  FROM tmp_src_pool
) base;

-- ============================================================
-- 5. Compute subnet prefixes for destinations
-- ============================================================
DROP TEMPORARY TABLE IF EXISTS tmp_dst;
CREATE TEMPORARY TABLE tmp_dst
CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
AS
SELECT
  rule_id, dst_ip, dst_zone, dst_nat, hit_count,
  CASE WHEN is_private THEN CONCAT(SUBSTRING_INDEX(dst_ip, '.', 3), '.', FLOOR(SUBSTRING_INDEX(dst_ip, '.', -1) / 16) * 16, '/28') ELSE NULL END AS prefix_28,
  CASE WHEN is_private THEN CONCAT(SUBSTRING_INDEX(dst_ip, '.', 3), '.0/24')    ELSE NULL END AS prefix_24,
  CASE WHEN is_private THEN CONCAT(SUBSTRING_INDEX(dst_ip, '.', 2), '.0.0/16')  ELSE NULL END AS prefix_16,
  CASE WHEN is_private THEN CONCAT(SUBSTRING_INDEX(dst_ip, '.', 1), '.0.0.0/8') ELSE NULL END AS prefix_8
FROM (
  SELECT rule_id, dst_ip, dst_zone, dst_nat, hit_count,
    dst_ip IS NOT NULL AND dst_ip != 'internet_public'
    AND INET_ATON(dst_ip) IS NOT NULL AND (
      INET_ATON(dst_ip) BETWEEN INET_ATON('10.0.0.0')    AND INET_ATON('10.255.255.255')
   OR INET_ATON(dst_ip) BETWEEN INET_ATON('172.16.0.0')  AND INET_ATON('172.31.255.255')
   OR INET_ATON(dst_ip) BETWEEN INET_ATON('192.168.0.0') AND INET_ATON('192.168.255.255')
   OR INET_ATON(dst_ip) BETWEEN INET_ATON('127.0.0.0')   AND INET_ATON('127.255.255.255')
   OR INET_ATON(dst_ip) BETWEEN INET_ATON('169.254.0.0') AND INET_ATON('169.254.255.255')
    ) AS is_private
  FROM tmp_dst_pool
) base;

-- ============================================================
-- 6. Per-rule qualifying source subnets (broadest-wins)
--    Each prefix level counts ALL its IPs independently - no exclusion
--    of nested prefixes.  When the output picks a prefix per IP it
--    favours the broadest qualifying one (/8 > /16 > /24 > /28), so
--    nested prefixes naturally collapse into their enclosing /24 etc.
-- ============================================================
DROP TEMPORARY TABLE IF EXISTS tmp_lsrc_28;
CREATE TEMPORARY TABLE tmp_lsrc_28 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
AS SELECT rule_id, prefix_28 FROM tmp_src WHERE prefix_28 IS NOT NULL
GROUP BY rule_id, prefix_28 HAVING COUNT(DISTINCT src_ip) >= IF(@src_subnet_on, @src_threshold_28, 999999999);

DROP TEMPORARY TABLE IF EXISTS tmp_lsrc_24;
CREATE TEMPORARY TABLE tmp_lsrc_24 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
AS SELECT rule_id, prefix_24 FROM tmp_src WHERE prefix_24 IS NOT NULL
GROUP BY rule_id, prefix_24 HAVING COUNT(DISTINCT src_ip) >= IF(@src_subnet_on, @src_threshold_24, 999999999);

DROP TEMPORARY TABLE IF EXISTS tmp_lsrc_16;
CREATE TEMPORARY TABLE tmp_lsrc_16 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
AS SELECT rule_id, prefix_16 FROM tmp_src WHERE prefix_16 IS NOT NULL
GROUP BY rule_id, prefix_16 HAVING COUNT(DISTINCT src_ip) >= IF(@src_subnet_on, @src_threshold_16, 999999999);

DROP TEMPORARY TABLE IF EXISTS tmp_lsrc_8;
CREATE TEMPORARY TABLE tmp_lsrc_8 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
AS SELECT rule_id, prefix_8 FROM tmp_src WHERE prefix_8 IS NOT NULL
GROUP BY rule_id, prefix_8 HAVING COUNT(DISTINCT src_ip) >= IF(@src_subnet_on, @src_threshold_8, 999999999);

-- ============================================================
-- 7. Per-rule qualifying destination subnets (broadest-wins)
-- ============================================================
DROP TEMPORARY TABLE IF EXISTS tmp_ldst_28;
CREATE TEMPORARY TABLE tmp_ldst_28 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
AS SELECT rule_id, prefix_28 FROM tmp_dst WHERE prefix_28 IS NOT NULL
GROUP BY rule_id, prefix_28 HAVING COUNT(DISTINCT dst_ip) >= IF(@dst_subnet_on, @dst_threshold_28, 999999999);

DROP TEMPORARY TABLE IF EXISTS tmp_ldst_24;
CREATE TEMPORARY TABLE tmp_ldst_24 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
AS SELECT rule_id, prefix_24 FROM tmp_dst WHERE prefix_24 IS NOT NULL
GROUP BY rule_id, prefix_24 HAVING COUNT(DISTINCT dst_ip) >= IF(@dst_subnet_on, @dst_threshold_24, 999999999);

DROP TEMPORARY TABLE IF EXISTS tmp_ldst_16;
CREATE TEMPORARY TABLE tmp_ldst_16 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
AS SELECT rule_id, prefix_16 FROM tmp_dst WHERE prefix_16 IS NOT NULL
GROUP BY rule_id, prefix_16 HAVING COUNT(DISTINCT dst_ip) >= IF(@dst_subnet_on, @dst_threshold_16, 999999999);

DROP TEMPORARY TABLE IF EXISTS tmp_ldst_8;
CREATE TEMPORARY TABLE tmp_ldst_8 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
AS SELECT rule_id, prefix_8 FROM tmp_dst WHERE prefix_8 IS NOT NULL
GROUP BY rule_id, prefix_8 HAVING COUNT(DISTINCT dst_ip) >= IF(@dst_subnet_on, @dst_threshold_8, 999999999);

-- ============================================================
-- 8. Insert aggregated sources - pick broadest qualifying prefix per IP,
--    then group across IPs that landed on the same prefix.
--    iface_in is only meaningful for un-aggregated entries.
-- ============================================================
INSERT INTO fw_rules_subnet_sources (rule_id, src_ip, src_zone, iface_in, hit_count)
SELECT
  rule_id, chosen_ip,
  NULLIF(GROUP_CONCAT(DISTINCT src_zone ORDER BY src_zone SEPARATOR '\n'), ''),
  MAX(CASE WHEN chosen_ip = src_ip_orig THEN iface_in END) AS iface_in,
  SUM(hit_count) AS hit_count
FROM (
  SELECT s.rule_id, s.src_ip AS src_ip_orig, s.src_zone, s.iface_in, s.hit_count,
    CASE
      WHEN EXISTS (SELECT 1 FROM tmp_lsrc_8  l WHERE l.rule_id = s.rule_id AND l.prefix_8  = s.prefix_8 ) THEN s.prefix_8
      WHEN EXISTS (SELECT 1 FROM tmp_lsrc_16 l WHERE l.rule_id = s.rule_id AND l.prefix_16 = s.prefix_16) THEN s.prefix_16
      WHEN EXISTS (SELECT 1 FROM tmp_lsrc_24 l WHERE l.rule_id = s.rule_id AND l.prefix_24 = s.prefix_24) THEN s.prefix_24
      WHEN EXISTS (SELECT 1 FROM tmp_lsrc_28 l WHERE l.rule_id = s.rule_id AND l.prefix_28 = s.prefix_28) THEN s.prefix_28
      ELSE s.src_ip
    END AS chosen_ip
  FROM tmp_src s
) t
GROUP BY rule_id, chosen_ip
ON DUPLICATE KEY UPDATE hit_count = VALUES(hit_count);

-- ============================================================
-- 9. Insert aggregated destinations - same broadest-wins logic.
-- ============================================================
INSERT INTO fw_rules_subnet_destinations (rule_id, dst_ip, dst_zone, dst_nat, hit_count)
SELECT
  rule_id, chosen_ip,
  NULLIF(GROUP_CONCAT(DISTINCT dst_zone ORDER BY dst_zone SEPARATOR '\n'), ''),
  MAX(CASE WHEN chosen_ip = dst_ip_orig THEN dst_nat END) AS dst_nat,
  SUM(hit_count) AS hit_count
FROM (
  SELECT d.rule_id, d.dst_ip AS dst_ip_orig, d.dst_zone, d.dst_nat, d.hit_count,
    CASE
      WHEN EXISTS (SELECT 1 FROM tmp_ldst_8  l WHERE l.rule_id = d.rule_id AND l.prefix_8  = d.prefix_8 ) THEN d.prefix_8
      WHEN EXISTS (SELECT 1 FROM tmp_ldst_16 l WHERE l.rule_id = d.rule_id AND l.prefix_16 = d.prefix_16) THEN d.prefix_16
      WHEN EXISTS (SELECT 1 FROM tmp_ldst_24 l WHERE l.rule_id = d.rule_id AND l.prefix_24 = d.prefix_24) THEN d.prefix_24
      WHEN EXISTS (SELECT 1 FROM tmp_ldst_28 l WHERE l.rule_id = d.rule_id AND l.prefix_28 = d.prefix_28) THEN d.prefix_28
      ELSE d.dst_ip
    END AS chosen_ip
  FROM tmp_dst d
) t
GROUP BY rule_id, chosen_ip
ON DUPLICATE KEY UPDATE hit_count = VALUES(hit_count);

-- ============================================================
-- 10. Update counts
-- ============================================================
UPDATE fw_rules_subnet r
LEFT JOIN (SELECT rule_id, COUNT(*) AS n FROM fw_rules_subnet_sources      GROUP BY rule_id) s ON s.rule_id = r.id
LEFT JOIN (SELECT rule_id, COUNT(*) AS n FROM fw_rules_subnet_destinations  GROUP BY rule_id) d ON d.rule_id = r.id
SET r.src_count = COALESCE(s.n, 0),
    r.dst_count = COALESCE(d.n, 0)
WHERE r.generated_at = @run_ts;
