-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- ═══════════════════════════════════════════════════════════════════════════
-- Module: NAT-rule subnet aggregation (always-on)
--
-- Mirrors the /28 → /24 → /16 → /8 density logic from 53_subnet.sql, but
-- operates on fw_nat_rules.orig_src / orig_dst (JSON arrays).  Reads its
-- thresholds from the same pipeline-config row used by 53_subnet so the
-- "Aggregate sources/destinations" UI toggles apply to NAT too.
--
-- Per rule, the most-specific qualifying prefix wins; IPs not in any
-- qualifying prefix pass through unchanged.  Non-IP entries (zone names,
-- group refs, "any", IPv6 literals) are preserved as-is.
-- ═══════════════════════════════════════════════════════════════════════════

-- ── Pull thresholds from 53_subnet's pipeline_config ──────────────────────
-- Falls back to the same defaults 53_subnet.sql carries when the row or
-- individual params are missing.

SET @_nat_subnet_params = (
  SELECT params FROM fw_pipeline_config WHERE job_name = '53_subnet'
);

SET @src_subnet_on    = COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(@_nat_subnet_params, '$.src_subnet_on'))    AS UNSIGNED), 1);
SET @src_threshold_28 = COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(@_nat_subnet_params, '$.src_threshold_28')) AS UNSIGNED), 4);
SET @src_threshold_24 = COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(@_nat_subnet_params, '$.src_threshold_24')) AS UNSIGNED), 3);
SET @src_threshold_16 = COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(@_nat_subnet_params, '$.src_threshold_16')) AS UNSIGNED), 5);
SET @src_threshold_8  = COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(@_nat_subnet_params, '$.src_threshold_8'))  AS UNSIGNED), 10);
SET @dst_subnet_on    = COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(@_nat_subnet_params, '$.dst_subnet_on'))    AS UNSIGNED), 1);
SET @dst_threshold_28 = COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(@_nat_subnet_params, '$.dst_threshold_28')) AS UNSIGNED), 4);
SET @dst_threshold_24 = COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(@_nat_subnet_params, '$.dst_threshold_24')) AS UNSIGNED), 3);
SET @dst_threshold_16 = COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(@_nat_subnet_params, '$.dst_threshold_16')) AS UNSIGNED), 5);
SET @dst_threshold_8  = COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(@_nat_subnet_params, '$.dst_threshold_8'))  AS UNSIGNED), 10);

-- ── Helpers: explode orig_src / orig_dst into per-rule rows ───────────────
-- Each row holds one IP from one NAT rule, plus its candidate prefixes
-- (computed only when the IP is private - non-private and non-IP entries
-- get prefix_28..8 = NULL and pass through the aggregation untouched).

DROP TEMPORARY TABLE IF EXISTS tmp_nat_src;
CREATE TEMPORARY TABLE tmp_nat_src (
  rule_id   BIGINT UNSIGNED NOT NULL,
  ip_str    VARCHAR(64) NOT NULL,
  prefix_28 VARCHAR(64) NULL,
  prefix_24 VARCHAR(64) NULL,
  prefix_16 VARCHAR(64) NULL,
  prefix_8  VARCHAR(64) NULL,
  KEY (rule_id)
) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

INSERT INTO tmp_nat_src (rule_id, ip_str, prefix_28, prefix_24, prefix_16, prefix_8)
SELECT
  r.id, jt.ip_str,
  CASE WHEN base.is_private THEN CONCAT(SUBSTRING_INDEX(jt.ip_str, '.', 3), '.',
       FLOOR(SUBSTRING_INDEX(jt.ip_str, '.', -1) / 16) * 16, '/28') ELSE NULL END,
  CASE WHEN base.is_private THEN CONCAT(SUBSTRING_INDEX(jt.ip_str, '.', 3), '.0/24')   ELSE NULL END,
  CASE WHEN base.is_private THEN CONCAT(SUBSTRING_INDEX(jt.ip_str, '.', 2), '.0.0/16') ELSE NULL END,
  CASE WHEN base.is_private THEN CONCAT(SUBSTRING_INDEX(jt.ip_str, '.', 1), '.0.0.0/8') ELSE NULL END
FROM fw_nat_rules r
JOIN JSON_TABLE(
  COALESCE(r.orig_src, JSON_ARRAY()),
  '$[*]' COLUMNS (ip_str VARCHAR(64) PATH '$')
) jt
JOIN (
  -- Re-evaluate is_private once, alongside ip_str - cheaper than nesting
  -- a CASE that re-runs all four BETWEEN comparisons four times above.
  SELECT
    rid, ip_str_inner,
    INET_ATON(ip_str_inner) IS NOT NULL AND (
         INET_ATON(ip_str_inner) BETWEEN INET_ATON('10.0.0.0')      AND INET_ATON('10.255.255.255')
      OR INET_ATON(ip_str_inner) BETWEEN INET_ATON('172.16.0.0')    AND INET_ATON('172.31.255.255')
      OR INET_ATON(ip_str_inner) BETWEEN INET_ATON('192.168.0.0')   AND INET_ATON('192.168.255.255')
      OR INET_ATON(ip_str_inner) BETWEEN INET_ATON('100.64.0.0')    AND INET_ATON('100.127.255.255')
    ) AS is_private
  FROM (
    SELECT r2.id AS rid, jt2.ip_str_inner
    FROM fw_nat_rules r2
    JOIN JSON_TABLE(
      COALESCE(r2.orig_src, JSON_ARRAY()),
      '$[*]' COLUMNS (ip_str_inner VARCHAR(64) PATH '$')
    ) jt2
  ) flat
) base ON base.rid = r.id AND base.ip_str_inner = jt.ip_str;

DROP TEMPORARY TABLE IF EXISTS tmp_nat_dst;
CREATE TEMPORARY TABLE tmp_nat_dst (
  rule_id   BIGINT UNSIGNED NOT NULL,
  ip_str    VARCHAR(64) NOT NULL,
  prefix_28 VARCHAR(64) NULL,
  prefix_24 VARCHAR(64) NULL,
  prefix_16 VARCHAR(64) NULL,
  prefix_8  VARCHAR(64) NULL,
  KEY (rule_id)
) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

INSERT INTO tmp_nat_dst (rule_id, ip_str, prefix_28, prefix_24, prefix_16, prefix_8)
SELECT
  r.id, jt.ip_str,
  CASE WHEN base.is_private THEN CONCAT(SUBSTRING_INDEX(jt.ip_str, '.', 3), '.',
       FLOOR(SUBSTRING_INDEX(jt.ip_str, '.', -1) / 16) * 16, '/28') ELSE NULL END,
  CASE WHEN base.is_private THEN CONCAT(SUBSTRING_INDEX(jt.ip_str, '.', 3), '.0/24')   ELSE NULL END,
  CASE WHEN base.is_private THEN CONCAT(SUBSTRING_INDEX(jt.ip_str, '.', 2), '.0.0/16') ELSE NULL END,
  CASE WHEN base.is_private THEN CONCAT(SUBSTRING_INDEX(jt.ip_str, '.', 1), '.0.0.0/8') ELSE NULL END
FROM fw_nat_rules r
JOIN JSON_TABLE(
  COALESCE(r.orig_dst, JSON_ARRAY()),
  '$[*]' COLUMNS (ip_str VARCHAR(64) PATH '$')
) jt
JOIN (
  SELECT
    rid, ip_str_inner,
    INET_ATON(ip_str_inner) IS NOT NULL AND (
         INET_ATON(ip_str_inner) BETWEEN INET_ATON('10.0.0.0')      AND INET_ATON('10.255.255.255')
      OR INET_ATON(ip_str_inner) BETWEEN INET_ATON('172.16.0.0')    AND INET_ATON('172.31.255.255')
      OR INET_ATON(ip_str_inner) BETWEEN INET_ATON('192.168.0.0')   AND INET_ATON('192.168.255.255')
      OR INET_ATON(ip_str_inner) BETWEEN INET_ATON('100.64.0.0')    AND INET_ATON('100.127.255.255')
    ) AS is_private
  FROM (
    SELECT r2.id AS rid, jt2.ip_str_inner
    FROM fw_nat_rules r2
    JOIN JSON_TABLE(
      COALESCE(r2.orig_dst, JSON_ARRAY()),
      '$[*]' COLUMNS (ip_str_inner VARCHAR(64) PATH '$')
    ) jt2
  ) flat
) base ON base.rid = r.id AND base.ip_str_inner = jt.ip_str;

-- ── Per-rule qualifying prefixes (broadest-wins) ──────────────────────────
-- Each level counts ALL its IPs independently - no exclusion of nested
-- prefixes.  The output picks the BROADEST qualifying prefix per IP
-- (/8 > /16 > /24 > /28), so a denser /28 inside an already-qualifying /24
-- collapses into the /24 instead of producing redundant overlapping entries.

DROP TEMPORARY TABLE IF EXISTS tmp_nat_lsrc_28;
CREATE TEMPORARY TABLE tmp_nat_lsrc_28 (rule_id BIGINT UNSIGNED, prefix_28 VARCHAR(64), KEY (rule_id, prefix_28))
ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
AS SELECT rule_id, prefix_28 FROM tmp_nat_src WHERE prefix_28 IS NOT NULL
GROUP BY rule_id, prefix_28
HAVING COUNT(DISTINCT ip_str) >= IF(@src_subnet_on, @src_threshold_28, 999999999);

DROP TEMPORARY TABLE IF EXISTS tmp_nat_lsrc_24;
CREATE TEMPORARY TABLE tmp_nat_lsrc_24 (rule_id BIGINT UNSIGNED, prefix_24 VARCHAR(64), KEY (rule_id, prefix_24))
ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
AS SELECT rule_id, prefix_24 FROM tmp_nat_src WHERE prefix_24 IS NOT NULL
GROUP BY rule_id, prefix_24
HAVING COUNT(DISTINCT ip_str) >= IF(@src_subnet_on, @src_threshold_24, 999999999);

DROP TEMPORARY TABLE IF EXISTS tmp_nat_lsrc_16;
CREATE TEMPORARY TABLE tmp_nat_lsrc_16 (rule_id BIGINT UNSIGNED, prefix_16 VARCHAR(64), KEY (rule_id, prefix_16))
ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
AS SELECT rule_id, prefix_16 FROM tmp_nat_src WHERE prefix_16 IS NOT NULL
GROUP BY rule_id, prefix_16
HAVING COUNT(DISTINCT ip_str) >= IF(@src_subnet_on, @src_threshold_16, 999999999);

DROP TEMPORARY TABLE IF EXISTS tmp_nat_lsrc_8;
CREATE TEMPORARY TABLE tmp_nat_lsrc_8 (rule_id BIGINT UNSIGNED, prefix_8 VARCHAR(64), KEY (rule_id, prefix_8))
ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
AS SELECT rule_id, prefix_8 FROM tmp_nat_src WHERE prefix_8 IS NOT NULL
GROUP BY rule_id, prefix_8
HAVING COUNT(DISTINCT ip_str) >= IF(@src_subnet_on, @src_threshold_8, 999999999);

DROP TEMPORARY TABLE IF EXISTS tmp_nat_ldst_28;
CREATE TEMPORARY TABLE tmp_nat_ldst_28 (rule_id BIGINT UNSIGNED, prefix_28 VARCHAR(64), KEY (rule_id, prefix_28))
ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
AS SELECT rule_id, prefix_28 FROM tmp_nat_dst WHERE prefix_28 IS NOT NULL
GROUP BY rule_id, prefix_28
HAVING COUNT(DISTINCT ip_str) >= IF(@dst_subnet_on, @dst_threshold_28, 999999999);

DROP TEMPORARY TABLE IF EXISTS tmp_nat_ldst_24;
CREATE TEMPORARY TABLE tmp_nat_ldst_24 (rule_id BIGINT UNSIGNED, prefix_24 VARCHAR(64), KEY (rule_id, prefix_24))
ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
AS SELECT rule_id, prefix_24 FROM tmp_nat_dst WHERE prefix_24 IS NOT NULL
GROUP BY rule_id, prefix_24
HAVING COUNT(DISTINCT ip_str) >= IF(@dst_subnet_on, @dst_threshold_24, 999999999);

DROP TEMPORARY TABLE IF EXISTS tmp_nat_ldst_16;
CREATE TEMPORARY TABLE tmp_nat_ldst_16 (rule_id BIGINT UNSIGNED, prefix_16 VARCHAR(64), KEY (rule_id, prefix_16))
ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
AS SELECT rule_id, prefix_16 FROM tmp_nat_dst WHERE prefix_16 IS NOT NULL
GROUP BY rule_id, prefix_16
HAVING COUNT(DISTINCT ip_str) >= IF(@dst_subnet_on, @dst_threshold_16, 999999999);

DROP TEMPORARY TABLE IF EXISTS tmp_nat_ldst_8;
CREATE TEMPORARY TABLE tmp_nat_ldst_8 (rule_id BIGINT UNSIGNED, prefix_8 VARCHAR(64), KEY (rule_id, prefix_8))
ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
AS SELECT rule_id, prefix_8 FROM tmp_nat_dst WHERE prefix_8 IS NOT NULL
GROUP BY rule_id, prefix_8
HAVING COUNT(DISTINCT ip_str) >= IF(@dst_subnet_on, @dst_threshold_8, 999999999);

-- ── Build replacement JSON arrays per rule ────────────────────────────────
-- For each (rule, ip): emit the BROADEST qualifying prefix, or the raw IP
-- if no prefix qualifies.  DISTINCT collapses many contributing IPs into
-- one entry per chosen prefix.

DROP TEMPORARY TABLE IF EXISTS tmp_nat_src_out;
CREATE TEMPORARY TABLE tmp_nat_src_out (
  rule_id BIGINT UNSIGNED, item VARCHAR(64), KEY (rule_id)
) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

INSERT INTO tmp_nat_src_out (rule_id, item)
SELECT DISTINCT s.rule_id,
  CASE
    WHEN EXISTS (SELECT 1 FROM tmp_nat_lsrc_8  l WHERE l.rule_id = s.rule_id AND l.prefix_8  = s.prefix_8 ) THEN s.prefix_8
    WHEN EXISTS (SELECT 1 FROM tmp_nat_lsrc_16 l WHERE l.rule_id = s.rule_id AND l.prefix_16 = s.prefix_16) THEN s.prefix_16
    WHEN EXISTS (SELECT 1 FROM tmp_nat_lsrc_24 l WHERE l.rule_id = s.rule_id AND l.prefix_24 = s.prefix_24) THEN s.prefix_24
    WHEN EXISTS (SELECT 1 FROM tmp_nat_lsrc_28 l WHERE l.rule_id = s.rule_id AND l.prefix_28 = s.prefix_28) THEN s.prefix_28
    ELSE s.ip_str
  END
FROM tmp_nat_src s;

DROP TEMPORARY TABLE IF EXISTS tmp_nat_dst_out;
CREATE TEMPORARY TABLE tmp_nat_dst_out (
  rule_id BIGINT UNSIGNED, item VARCHAR(64), KEY (rule_id)
) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

INSERT INTO tmp_nat_dst_out (rule_id, item)
SELECT DISTINCT d.rule_id,
  CASE
    WHEN EXISTS (SELECT 1 FROM tmp_nat_ldst_8  l WHERE l.rule_id = d.rule_id AND l.prefix_8  = d.prefix_8 ) THEN d.prefix_8
    WHEN EXISTS (SELECT 1 FROM tmp_nat_ldst_16 l WHERE l.rule_id = d.rule_id AND l.prefix_16 = d.prefix_16) THEN d.prefix_16
    WHEN EXISTS (SELECT 1 FROM tmp_nat_ldst_24 l WHERE l.rule_id = d.rule_id AND l.prefix_24 = d.prefix_24) THEN d.prefix_24
    WHEN EXISTS (SELECT 1 FROM tmp_nat_ldst_28 l WHERE l.rule_id = d.rule_id AND l.prefix_28 = d.prefix_28) THEN d.prefix_28
    ELSE d.ip_str
  END
FROM tmp_nat_dst d;

-- ── UPDATE fw_nat_rules with the rewritten arrays ─────────────────────────
-- Skip rules where the JSON array was empty/NULL (nothing exploded).

UPDATE fw_nat_rules r
JOIN (
  SELECT rule_id, JSON_ARRAYAGG(item) AS arr
  FROM tmp_nat_src_out GROUP BY rule_id
) agg ON agg.rule_id = r.id
SET r.orig_src = agg.arr;

UPDATE fw_nat_rules r
JOIN (
  SELECT rule_id, JSON_ARRAYAGG(item) AS arr
  FROM tmp_nat_dst_out GROUP BY rule_id
) agg ON agg.rule_id = r.id
SET r.orig_dst = agg.arr;

DROP TEMPORARY TABLE IF EXISTS tmp_nat_src;
DROP TEMPORARY TABLE IF EXISTS tmp_nat_dst;
DROP TEMPORARY TABLE IF EXISTS tmp_nat_lsrc_28;
DROP TEMPORARY TABLE IF EXISTS tmp_nat_lsrc_24;
DROP TEMPORARY TABLE IF EXISTS tmp_nat_lsrc_16;
DROP TEMPORARY TABLE IF EXISTS tmp_nat_lsrc_8;
DROP TEMPORARY TABLE IF EXISTS tmp_nat_ldst_28;
DROP TEMPORARY TABLE IF EXISTS tmp_nat_ldst_24;
DROP TEMPORARY TABLE IF EXISTS tmp_nat_ldst_16;
DROP TEMPORARY TABLE IF EXISTS tmp_nat_ldst_8;
DROP TEMPORARY TABLE IF EXISTS tmp_nat_src_out;
DROP TEMPORARY TABLE IF EXISTS tmp_nat_dst_out;

-- ── Hash-stage tail (Phase A3) ────────────────────────────────────────────
-- This job rewrites orig_src / orig_dst (subnet aggregation) - that changes
-- nat_hash inputs. Recompute the hash for every row so overrides bind to
-- the post-aggregation rule shape. Mirrors _NAT_HASH_EXPR (webui/main.py).
UPDATE fw_nat_rules n
JOIN fw_devices d ON d.id = n.device_id
SET n.nat_hash = UNHEX(SHA1(CONCAT_WS(0x1f,
    COALESCE(d.host_name, d.display_name, ''),
    n.nat_type,
    COALESCE(n.interface_name, ''),
    COALESCE(JSON_EXTRACT(n.src_zones,    '$'), ''),
    COALESCE(JSON_EXTRACT(n.dst_zones,    '$'), ''),
    COALESCE(JSON_EXTRACT(n.orig_src,     '$'), ''),
    COALESCE(JSON_EXTRACT(n.orig_dst,     '$'), ''),
    COALESCE(JSON_EXTRACT(n.orig_service, '$'), ''),
    COALESCE(n.trans_src, ''),
    n.trans_src_type,
    COALESCE(n.trans_dst, ''),
    COALESCE(n.trans_dst_port, '')
)));
