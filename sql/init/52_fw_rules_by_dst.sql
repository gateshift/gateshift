-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

CREATE TABLE IF NOT EXISTS fw_rules_consolidated_2 (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  generated_at TIMESTAMP NOT NULL,
  vendor VARCHAR(64) NULL,
  device_host VARCHAR(255) NULL,
  action ENUM('allow','deny','drop','reject','unknown') NOT NULL DEFAULT 'unknown',
  direction ENUM('in','out','forward','unknown') NOT NULL DEFAULT 'unknown',
  iface_out VARCHAR(64) NULL,
  dst_zone VARCHAR(128) NULL,
  dst_ip VARCHAR(128) NOT NULL,
  dst_nat VARCHAR(45) NULL,
  proto VARCHAR(16) NULL,
  dst_port SMALLINT UNSIGNED NULL,
  hit_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
  src_ip_count INT UNSIGNED NOT NULL DEFAULT 0,
  first_seen DATETIME NULL,
  last_seen DATETIME NULL,

  PRIMARY KEY (id),
  KEY idx_generated (generated_at),
  KEY idx_dst (dst_ip, proto, dst_port)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS fw_rules_consolidated_2_sources (
  rule_id BIGINT UNSIGNED NOT NULL,
  src_ip VARCHAR(128) NOT NULL,
  src_zone VARCHAR(128) NULL,
  iface_in VARCHAR(64) NULL,
  hit_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (rule_id, src_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
