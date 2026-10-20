-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- Module: Endpoint pairs
-- One rule per exact (src-set, dst-set) pair - ports and applications accumulated.
-- src_hash = SHA2 over the sorted set of source IPs for the upstream accumulated rule.

CREATE TABLE IF NOT EXISTS fw_rules_endpoint_pairs (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  generated_at TIMESTAMP NOT NULL,
  vendor       VARCHAR(64) NULL,
  -- the Device, the key once phase 7 drops the name (docs/DEVICE_IDENTITY_PLAN.md)
  device_id  INT NULL,
  action       ENUM('allow','deny','drop','reject','unknown') NOT NULL DEFAULT 'unknown',
  direction    ENUM('in','out','forward','unknown') NOT NULL DEFAULT 'unknown',
  dst_ip       VARCHAR(128) NULL,         -- single destination (from accumulated)
  ports        TEXT NULL,                 -- GROUP_CONCAT of proto/port, e.g. "tcp/80,tcp/443"
  applications TEXT NULL,                 -- GROUP_CONCAT of distinct application names
  rule_name    VARCHAR(255) NULL,
  security_profile       VARCHAR(255) NULL,
  security_profile_group VARCHAR(255) NULL,
  hit_count    BIGINT UNSIGNED NOT NULL DEFAULT 0,
  src_count    INT UNSIGNED NOT NULL DEFAULT 0,
  first_seen   DATETIME NULL,
  last_seen    DATETIME NULL,
  source_type  VARCHAR(16) NOT NULL DEFAULT 'syslog',
  KEY idx_device_id (device_id),
  PRIMARY KEY (id),
  KEY idx_generated (generated_at),
  KEY idx_ep_group (generated_at, vendor(32), device_id, action, direction, dst_ip(64)),
  FOREIGN KEY (device_id) REFERENCES fw_devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS fw_rules_endpoint_pairs_sources (
  rule_id   BIGINT UNSIGNED NOT NULL,
  src_ip    VARCHAR(128) NOT NULL,
  src_zone  VARCHAR(128) NULL,
  iface_in  VARCHAR(64) NULL,
  hit_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (rule_id, src_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
