-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- ═══════════════════════════════════════════════════════════════════════════
-- Module: NAT-rule inference (always-on) - SHAPING stage
--
-- Reconstructs NAT rules from observed-traffic evidence.  Two paths:
--   A) Direct  - vendors whose syslog carries translation fields
--                (PA, Forti via `nat_src_ip`/`nat_dst_ip`).
--   B) Indirect - vendors whose syslog does NOT carry translation
--                 (OPNsense filterlog).  Inferred via:
--                   * private src + outbound via external interface  → SNAT
--                   * private dst + inbound  from external interface → DNAT
--                 The translated address is the external interface's IP.
--
-- Source of truth is `fw_nat_evidence` - the ingest-maintained, NAT-faithful
-- aggregate (one row per distinct flow shape; original + translated dst_port
-- kept separate, zones in the key, private/public IP class precomputed).  This
-- stage no longer scans raw `fw_flows`: per the pipeline invariant, `generate`
-- derives only from aggregates while ingest owns raw-flow aggregation.  Counts
-- are SUM(hit_count) and are lifetime-cumulative (no time window) - consistent
-- with 20_generate_rule_candidates.  NULLable evidence dimensions use sentinels
-- (all-zero 16-byte binary, port 0); `!= X'00..'` / `> 0` recover NULL-ness.
--
-- "External" interfaces are identified by the explicit `fw_zones.is_external`
-- flag (seeded from the legacy name heuristic + FortiOS role='wan', then
-- user-authoritative) - no more zone-name string matching.
--
-- Rows written here carry `properties.inferred = true` and an
-- `inference_path` tag so re-runs can distinguish them from
-- config-imported NAT rules and rewrite only the inferred set.
--
-- Plan: project_nat_evidence_aggregate_active_plan (P3).
-- ═══════════════════════════════════════════════════════════════════════════

SET @nat_hit_threshold = 5;

-- ── Step 0: clear previous inferred rows (preserve config-imported) ───────
-- Inferred rows always carry an `inference_path` tag - config-imported rows
-- never set this, so the presence of the tag is the only marker we need.

DELETE FROM fw_nat_rules
WHERE JSON_EXTRACT(properties, '$.inference_path') IS NOT NULL;

-- ── Helpers: per-device external interface ───────────────────────────────
-- One row per device, holding the device's external zone name and the
-- first IP of any interface bound to a zone flagged `is_external`.  Used by
-- the indirect path as the synthetic translated source for SNAT and the
-- synthetic original destination for DNAT.

DROP TEMPORARY TABLE IF EXISTS tmp_ext_dev;
CREATE TEMPORARY TABLE tmp_ext_dev (
  device_id  INT NOT NULL PRIMARY KEY,
  ext_zone   VARCHAR(128) NULL,
  ext_ip     VARCHAR(64) NULL,
  ext_iface  VARCHAR(64) NULL
) ENGINE=InnoDB;

INSERT INTO tmp_ext_dev (device_id, ext_zone, ext_ip, ext_iface)
SELECT
  iz.device_id,
  MIN(iz.zone_name)                                                AS ext_zone,
  MIN(SUBSTRING_INDEX(JSON_UNQUOTE(JSON_EXTRACT(iz.ip_addresses, '$[0]')), '/', 1)) AS ext_ip,
  MIN(iz.interface_name)                                           AS ext_iface
FROM fw_interfaces iz
JOIN fw_zones z
  ON z.device_id = iz.device_id
 AND z.name      = iz.zone_name
 AND z.is_external = 1
WHERE iz.ip_addresses IS NOT NULL
  AND JSON_LENGTH(iz.ip_addresses) > 0
GROUP BY iz.device_id;

-- ── Step A1: Direct SNAT - translated source in evidence ──────────────────
-- PA-OS rejects to="any" on NAT rules; the to-zone must be a concrete
-- zone.  For SNAT (outbound) the to-zone is the device's external zone
-- (where translated traffic exits).  Without an external zone for the
-- device we skip - better no rule than an invalid one.

INSERT INTO fw_nat_rules (
  device_id, position, name, nat_type,
  src_zones, dst_zones,
  orig_src, orig_dst, orig_service,
  trans_src, trans_src_type,
  description, properties
)
SELECT
  d.id AS device_id,
  ROW_NUMBER() OVER (PARTITION BY d.id ORDER BY agg.hits DESC, agg.trans_src) AS position,
  CONCAT('inferred-snat-', d.id, '-',
         ROW_NUMBER() OVER (PARTITION BY d.id ORDER BY agg.hits DESC, agg.trans_src)) AS name,
  'snat' AS nat_type,
  CASE WHEN agg.src_zone IS NOT NULL AND agg.src_zone != ''
       THEN JSON_ARRAY(agg.src_zone) ELSE JSON_ARRAY('any') END AS src_zones,
  JSON_ARRAY(e.ext_zone) AS dst_zones,
  agg.orig_src_list AS orig_src,
  JSON_ARRAY('any') AS orig_dst,
  JSON_ARRAY('any') AS orig_service,
  agg.trans_src,
  'dynamic-ip-and-port' AS trans_src_type,
  CONCAT('Inferred from ', agg.hits, ' log events (translation in log)') AS description,
  JSON_OBJECT(
    'inferred', TRUE,
    'inference_path', 'log_translation',
    'hit_count', agg.hits
  ) AS properties
FROM (
  SELECT
    ev.device_host,
    ev.src_zone,
    ev.dst_zone,
    INET6_NTOA(ev.nat_src_ip) AS trans_src,
    JSON_ARRAYAGG(DISTINCT INET6_NTOA(ev.src_ip)) AS orig_src_list,
    SUM(ev.hit_count) AS hits
  FROM fw_nat_evidence ev
  WHERE ev.nat_src_ip != _binary X'00000000000000000000000000000000'
    AND ev.src_ip     != _binary X'00000000000000000000000000000000'
  GROUP BY ev.device_host, ev.src_zone, ev.dst_zone, ev.nat_src_ip
  HAVING hits >= @nat_hit_threshold
) agg
JOIN fw_devices d
  ON d.host_name = agg.device_host OR d.display_name = agg.device_host
JOIN tmp_ext_dev e ON e.device_id = d.id;

-- ── Step A2: Direct DNAT - translated destination in evidence ─────────────
-- DNAT zone semantics: the packet arrives from outside and matches against
-- the public IP, which "lives" in the external zone *before* translation.
-- PA-OS rejects to="any" on NAT rules, so both src_zones and dst_zones get
-- pinned to the device's external zone.  Without an external zone for the
-- device we skip the join (no rule emitted) - better no rule than invalid.

INSERT INTO fw_nat_rules (
  device_id, position, name, nat_type,
  src_zones, dst_zones,
  orig_src, orig_dst, orig_service,
  trans_dst, trans_dst_port,
  description, properties
)
SELECT
  d.id AS device_id,
  COALESCE((SELECT MAX(position) FROM fw_nat_rules WHERE device_id = d.id), 0)
    + ROW_NUMBER() OVER (PARTITION BY d.id ORDER BY agg.hits DESC, agg.orig_dst) AS position,
  CONCAT('inferred-dnat-', d.id, '-',
         ROW_NUMBER() OVER (PARTITION BY d.id ORDER BY agg.hits DESC, agg.orig_dst)) AS name,
  'dnat' AS nat_type,
  JSON_ARRAY(e.ext_zone) AS src_zones,
  JSON_ARRAY(e.ext_zone) AS dst_zones,
  JSON_ARRAY('any') AS orig_src,
  JSON_ARRAY(agg.orig_dst) AS orig_dst,
  CASE WHEN agg.dst_port > 0
       THEN JSON_ARRAY(CONCAT(LOWER(COALESCE(agg.proto,'tcp')), '/', agg.dst_port))
       ELSE JSON_ARRAY('any') END AS orig_service,
  agg.trans_dst,
  CAST(NULLIF(agg.nat_dst_port, 0) AS CHAR) AS trans_dst_port,
  CONCAT('Inferred from ', agg.hits, ' log events (translation in log)') AS description,
  JSON_OBJECT(
    'inferred', TRUE,
    'inference_path', 'log_translation',
    'hit_count', agg.hits
  ) AS properties
FROM (
  SELECT
    ev.device_host,
    ev.src_zone,
    ev.dst_zone,
    ev.proto,
    INET6_NTOA(ev.dst_ip) AS orig_dst,
    ev.dst_port,
    INET6_NTOA(ev.nat_dst_ip) AS trans_dst,
    ev.nat_dst_port,
    SUM(ev.hit_count) AS hits
  FROM fw_nat_evidence ev
  WHERE ev.nat_dst_ip != _binary X'00000000000000000000000000000000'
    AND ev.dst_ip     != _binary X'00000000000000000000000000000000'
  GROUP BY ev.device_host, ev.src_zone, ev.dst_zone, ev.proto,
           ev.dst_ip, ev.dst_port, ev.nat_dst_ip, ev.nat_dst_port
  HAVING hits >= @nat_hit_threshold
) agg
JOIN fw_devices d
  ON d.host_name = agg.device_host OR d.display_name = agg.device_host
JOIN tmp_ext_dev e ON e.device_id = d.id;

-- ── Step B1: Indirect SNAT - private src + outbound, no translation ──────
-- For devices whose logs lack translation fields, we infer SNAT from
-- direction + IP-class: outbound flows with a private src and a public
-- dst imply an SNAT rule "src_subnets → device's WAN-IP".  We don't tie
-- the rule to a specific iface_in/iface_out match (log interface names
-- often differ from the renamed UI names), just to the device.
-- IP-class is precomputed in fw_nat_evidence; the LENGTH(dst_ip)=4 guard
-- restricts the public side to IPv4 (matches the old INET_ATON behavior,
-- which yielded NULL - and thus excluded - for IPv6).

INSERT INTO fw_nat_rules (
  device_id, position, name, nat_type,
  src_zones, dst_zones, interface_name,
  orig_src, orig_dst, orig_service,
  trans_src, trans_src_type,
  description, properties
)
SELECT
  d.id AS device_id,
  COALESCE((SELECT MAX(position) FROM fw_nat_rules WHERE device_id = d.id), 0)
    + ROW_NUMBER() OVER (PARTITION BY d.id ORDER BY agg.hits DESC) AS position,
  CONCAT('inferred-snat-corr-', d.id, '-',
         ROW_NUMBER() OVER (PARTITION BY d.id ORDER BY agg.hits DESC)) AS name,
  'snat' AS nat_type,
  JSON_ARRAY('any') AS src_zones,
  JSON_ARRAY(e.ext_zone) AS dst_zones,
  e.ext_iface AS interface_name,
  agg.orig_src_list AS orig_src,
  JSON_ARRAY('any') AS orig_dst,
  JSON_ARRAY('any') AS orig_service,
  CONCAT(e.ext_iface, '|', e.ext_ip) AS trans_src,
  'interface-address' AS trans_src_type,
  CONCAT('Inferred from ', agg.hits, ' log events (no translation in log)') AS description,
  JSON_OBJECT(
    'inferred', TRUE,
    'inference_path', 'interface_correlation',
    'hit_count', agg.hits
  ) AS properties
FROM (
  SELECT
    ev.device_host,
    JSON_ARRAYAGG(DISTINCT INET6_NTOA(ev.src_ip)) AS orig_src_list,
    SUM(ev.hit_count) AS hits
  FROM fw_nat_evidence ev
  WHERE ev.nat_src_ip = _binary X'00000000000000000000000000000000'
    AND ev.src_ip     != _binary X'00000000000000000000000000000000'
    AND ev.dst_ip     != _binary X'00000000000000000000000000000000'
    AND ev.direction = 'out'
    AND ev.src_is_private = 1          -- private src (IPv4 by construction)
    AND ev.dst_is_private = 0          -- dst NOT private …
    AND LENGTH(ev.dst_ip) = 4          -- … and IPv4 public (exclude IPv6)
  GROUP BY ev.device_host
  HAVING hits >= @nat_hit_threshold
) agg
JOIN fw_devices d
  ON d.host_name = agg.device_host OR d.display_name = agg.device_host
JOIN tmp_ext_dev e ON e.device_id = d.id;

-- ── Step B2: Indirect DNAT - private dst + inbound from public src ───────
-- Inbound flows from a public src to a private dst imply a port-forward.
-- We can't see the original public dst from the log so we use the
-- device's WAN-IP as orig_dst.  Ports preserved (logs don't reveal
-- port-remapping when translation isn't recorded).  LENGTH(src_ip)=4
-- restricts the public side to IPv4 (matches old INET_ATON-NULL exclusion).

INSERT INTO fw_nat_rules (
  device_id, position, name, nat_type,
  src_zones, dst_zones, interface_name,
  orig_src, orig_dst, orig_service,
  trans_dst, trans_dst_port,
  description, properties
)
SELECT
  d.id AS device_id,
  COALESCE((SELECT MAX(position) FROM fw_nat_rules WHERE device_id = d.id), 0)
    + ROW_NUMBER() OVER (PARTITION BY d.id ORDER BY agg.hits DESC, agg.trans_dst, agg.dst_port) AS position,
  CONCAT('inferred-dnat-corr-', d.id, '-',
         ROW_NUMBER() OVER (PARTITION BY d.id ORDER BY agg.hits DESC, agg.trans_dst, agg.dst_port)) AS name,
  'dnat' AS nat_type,
  JSON_ARRAY(e.ext_zone) AS src_zones,
  JSON_ARRAY(e.ext_zone) AS dst_zones,
  e.ext_iface AS interface_name,
  JSON_ARRAY('any') AS orig_src,
  JSON_ARRAY(e.ext_ip) AS orig_dst,
  CASE WHEN agg.dst_port > 0
       THEN JSON_ARRAY(CONCAT(LOWER(COALESCE(agg.proto,'tcp')), '/', agg.dst_port))
       ELSE JSON_ARRAY('any') END AS orig_service,
  agg.trans_dst,
  CAST(NULLIF(agg.dst_port, 0) AS CHAR) AS trans_dst_port,
  CONCAT('Inferred from ', agg.hits, ' log events (no translation in log)') AS description,
  JSON_OBJECT(
    'inferred', TRUE,
    'inference_path', 'interface_correlation',
    'hit_count', agg.hits
  ) AS properties
FROM (
  SELECT
    ev.device_host,
    ev.proto,
    INET6_NTOA(ev.dst_ip) AS trans_dst,
    ev.dst_port,
    SUM(ev.hit_count) AS hits
  FROM fw_nat_evidence ev
  WHERE ev.nat_dst_ip = _binary X'00000000000000000000000000000000'
    AND ev.dst_ip     != _binary X'00000000000000000000000000000000'
    AND ev.src_ip     != _binary X'00000000000000000000000000000000'
    AND ev.direction = 'in'
    AND ev.dst_is_private = 1          -- private dst (IPv4 by construction)
    AND ev.src_is_private = 0          -- src NOT private …
    AND LENGTH(ev.src_ip) = 4          -- … and IPv4 public (exclude IPv6)
  GROUP BY ev.device_host, ev.proto, ev.dst_ip, ev.dst_port
  HAVING hits >= @nat_hit_threshold
) agg
JOIN fw_devices d
  ON d.host_name = agg.device_host OR d.display_name = agg.device_host
JOIN tmp_ext_dev e ON e.device_id = d.id;

DROP TEMPORARY TABLE IF EXISTS tmp_ext_dev;

-- ── Hash-stage tail (Phase A3) ────────────────────────────────────────────
-- All four inferred-NAT INSERTs above leave nat_hash NULL. Compute it now
-- so override-bindings (Phase A4) can match these inferred rules too.
-- Mirrors the canonical _NAT_HASH_EXPR from webui/main.py - keep in sync.
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
)))
WHERE n.nat_hash IS NULL;
