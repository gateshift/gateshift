-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

CREATE TABLE IF NOT EXISTS fw_rules_consolidated_1 (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  generated_at TIMESTAMP NOT NULL,
  vendor VARCHAR(64) NULL,
  device_host VARCHAR(255) NULL,
  action ENUM('allow','deny','drop','reject','unknown') NOT NULL DEFAULT 'unknown',
  direction ENUM('in','out','forward','unknown') NOT NULL DEFAULT 'unknown',
  iface_in VARCHAR(64) NULL,
  iface_out VARCHAR(64) NULL,
  src_zone VARCHAR(128) NULL,
  dst_zone VARCHAR(128) NULL,
  src_ip VARCHAR(45) NULL,
  src_nat VARCHAR(45) NULL,
  dst_ip VARCHAR(128) NULL,
  dst_nat VARCHAR(45) NULL,
  proto VARCHAR(16) NULL,
  dst_port SMALLINT UNSIGNED NULL,
  application VARCHAR(128) NULL,
  security_profile VARCHAR(255) NULL,
  security_profile_group VARCHAR(255) NULL,
  url_category VARCHAR(255) NULL,
  hit_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
  first_seen DATETIME NULL,
  last_seen DATETIME NULL,

  source_type  VARCHAR(16) NOT NULL DEFAULT 'syslog',
  -- Stable per-rule identity hash. Same SHA1 input as fw_rules_filtered.content_hash
  -- (see gateshift/modules/db_jobs.py::_CONTENT_HASH_INPUT_SQL). Filled at the end of
  -- sql/jobs/23_build_rules_consolidated.sql so override tables can bind to rules
  -- even when no pipeline modules are enabled (i.e. tail = consolidated_1).
  content_hash BINARY(20) NULL,
  PRIMARY KEY (id),
  KEY idx_generated (generated_at),
  KEY idx_dst (dst_ip, proto, dst_port),
  KEY idx_src (src_ip),
  KEY idx_content_hash (content_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
