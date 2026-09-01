-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- Cross-device zone translation: when migrating rules from a source device to
-- a target device, source-zone names usually do not exist verbatim on the
-- target. This table maps (source_id, target_id, source_zone) → target_zone
-- per migration pair.
--
-- Distinct from fw_zone_mappings (CIDR → zone, used to fill missing zone
-- attribution from logs within a single device).

CREATE TABLE IF NOT EXISTS fw_zone_xmap (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  source_id    INT NOT NULL,
  target_id    INT NOT NULL,
  source_zone  VARCHAR(128) NOT NULL,
  target_zone  VARCHAR(128) NOT NULL,
  created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_xmap (source_id, target_id, source_zone),
  KEY idx_pair (source_id, target_id),
  FOREIGN KEY (source_id) REFERENCES fw_devices(id) ON DELETE CASCADE,
  FOREIGN KEY (target_id) REFERENCES fw_devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
