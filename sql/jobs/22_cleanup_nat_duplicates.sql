-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- Build a lookup table: which proto+port+dst_ip combinations have another
-- candidate with dst_nat pointing to that internal IP?
DROP TEMPORARY TABLE IF EXISTS tmp_nat_covered;

CREATE TEMPORARY TABLE tmp_nat_covered AS
SELECT DISTINCT
  vendor, device_host, proto, dst_port_from, dst_nat AS internal_ip
FROM fw_rule_candidates
WHERE generated_at >= @run_ts
  AND dst_nat IS NOT NULL;

ALTER TABLE tmp_nat_covered ADD INDEX idx (vendor(64), device_host(255), proto(16), dst_port_from, internal_ip(16));

-- Remove NatCache-miss candidates: internal dst_ip without dst_nat,
-- where a correct candidate with dst_nat=dst_ip already exists
DELETE c FROM fw_rule_candidates c
JOIN tmp_nat_covered t
  ON t.vendor       <=> c.vendor
 AND t.device_host  <=> c.device_host
 AND t.proto         =  c.proto
 AND t.dst_port_from =  c.dst_port_from
 AND t.internal_ip   =  c.dst_ip
WHERE c.generated_at >= @run_ts
  AND c.dst_nat IS NULL;
