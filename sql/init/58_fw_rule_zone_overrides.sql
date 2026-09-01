-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- User-curated zone overrides that survive Generate.
--
-- Parallel to fw_rule_app_overrides (see 57_fw_rule_app_overrides.sql).
-- Generate truncates and rebuilds the consolidated rule tables; this overlay
-- holds user-decided zones per rule, keyed by content_hash so it survives
-- across runs. rules_query LEFT JOINs and COALESCEs over the aggregated
-- src/dst zones, so overrides win whenever present.
--
-- src_zone and dst_zone are scalar (not lists): the override flattens any
-- per-source/per-destination zone variation under one zone label. For the
-- "Set all zones to any" use case that's the whole point; per-IP zone
-- overrides would need a different shape and aren't needed yet.
--
-- Replaced the legacy (device_host, action, proto, dst_port) "natkey" PK
-- (Slice C, see feedback_rule_identity_hash memory). Existing deployments
-- are migrated cartesian-explode style by main.py on first start.

CREATE TABLE IF NOT EXISTS fw_rule_zone_overrides (
  rule_hash  BINARY(20)            NOT NULL PRIMARY KEY,
  src_zone   VARCHAR(128)          NULL,
  dst_zone   VARCHAR(128)          NULL,
  source     ENUM('manual','auto') NOT NULL DEFAULT 'manual',
  updated_at TIMESTAMP             NOT NULL DEFAULT CURRENT_TIMESTAMP
                                     ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
