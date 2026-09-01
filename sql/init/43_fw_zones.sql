-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

CREATE TABLE IF NOT EXISTS fw_zones (
  id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  device_id         INT NULL,
  name              VARCHAR(128) NOT NULL,
  color             VARCHAR(32)  NOT NULL DEFAULT 'blue',
  properties        JSON NULL,
  -- import_zone_name = source-of-truth name as observed at import time.
  -- Re-import resets `name` back to import_zone_name after user-confirm.
  -- User edits to `name` cascade to fw_interfaces / fw_zone_mappings /
  -- consolidated rule tables in one transaction (Slice 6).
  import_zone_name  VARCHAR(128) NULL,
  -- is_external = explicit WAN/external flag. Supersedes the zone-name
  -- string-match heuristic in 27_infer_nat_rules. Seeded from that heuristic
  -- + FortiOS interface role='wan' on first migrate, then user-authoritative.
  is_external       TINYINT(1) NOT NULL DEFAULT 0,
  created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_zone_device (device_id, name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
