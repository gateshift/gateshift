-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

CREATE TABLE IF NOT EXISTS fw_rule_candidates (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  generated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  vendor VARCHAR(64) NULL,
  device_host VARCHAR(255) NULL,

  action ENUM('allow','deny','drop','reject','unknown') NOT NULL DEFAULT 'unknown',
  direction ENUM('in','out','forward','unknown') NOT NULL DEFAULT 'unknown',
  iface_in VARCHAR(64) NULL,
  iface_out VARCHAR(64) NULL,
  src_zone VARCHAR(128) NULL,
  dst_zone VARCHAR(128) NULL,

  proto VARCHAR(16) NULL,

  src_ip VARCHAR(45) NULL,
  src_nat VARCHAR(45) NULL,
  dst_ip VARCHAR(45) NULL,
  dst_nat VARCHAR(45) NULL,
  dst_port_from SMALLINT UNSIGNED NULL,
  dst_port_to SMALLINT UNSIGNED NULL,

  application VARCHAR(128) NULL,
  security_profile VARCHAR(255) NULL,
  security_profile_group VARCHAR(255) NULL,
  url_category VARCHAR(255) NULL,
  rule_hash BINARY(32) NULL,

  first_seen DATETIME NULL,
  last_seen DATETIME NULL,
  hit_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
  src_ip_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
  dst_ip_count BIGINT UNSIGNED NOT NULL DEFAULT 0,

  quality_score FLOAT NULL,
  sample_raw_id BIGINT UNSIGNED NULL,

  source_type  VARCHAR(16) NOT NULL DEFAULT 'syslog',
  PRIMARY KEY (id),
  KEY idx_generated (generated_at),
  KEY idx_host (device_host, generated_at),
  KEY idx_rulehash (rule_hash, generated_at),
  KEY idx_tuple (action, direction, iface_in, proto, dst_port_from, generated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
