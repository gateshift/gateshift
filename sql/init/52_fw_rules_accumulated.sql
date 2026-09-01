-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- Module: Accumulate
-- Groups Stage 1 rules by (vendor, device_host, action, direction, proto, dst_port)
-- Sources and destinations stored in separate tables as individual IPs (no aggregation)

CREATE TABLE IF NOT EXISTS fw_rules_accumulated (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  generated_at TIMESTAMP NOT NULL,
  vendor       VARCHAR(64) NULL,
  device_host  VARCHAR(255) NULL,
  action       ENUM('allow','deny','drop','reject','unknown') NOT NULL DEFAULT 'unknown',
  direction    ENUM('in','out','forward','unknown') NOT NULL DEFAULT 'unknown',
  proto        VARCHAR(16) NULL,
  dst_port     SMALLINT UNSIGNED NULL,
  application  VARCHAR(128) NULL,
  rule_name    VARCHAR(255) NULL,
  security_profile VARCHAR(255) NULL,
  security_profile_group VARCHAR(255) NULL,
  dst_ip       VARCHAR(128) NULL,
  hit_count    BIGINT UNSIGNED NOT NULL DEFAULT 0,
  src_count    INT UNSIGNED NOT NULL DEFAULT 0,
  dst_count    INT UNSIGNED NOT NULL DEFAULT 0,
  first_seen   DATETIME NULL,
  last_seen    DATETIME NULL,

  source_type  VARCHAR(16) NOT NULL DEFAULT 'syslog',
  `sequence`   SMALLINT UNSIGNED NULL,
  -- Stable per-rule identity hash; written post-stage from db_jobs.py.
  -- See gateshift/modules/db_jobs.py::_write_content_hash_subtable.
  content_hash BINARY(20) NULL,
  PRIMARY KEY (id),
  KEY idx_generated  (generated_at),
  KEY idx_proto_port (proto, dst_port),
  KEY idx_content_hash (content_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS fw_rules_accumulated_sources (
  rule_id   BIGINT UNSIGNED NOT NULL,
  src_ip    VARCHAR(128) NOT NULL,
  src_zone  VARCHAR(128) NULL,
  iface_in  VARCHAR(64) NULL,
  hit_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (rule_id, src_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS fw_rules_accumulated_destinations (
  rule_id   BIGINT UNSIGNED NOT NULL,
  dst_ip    VARCHAR(128) NOT NULL,
  dst_zone  VARCHAR(128) NULL,
  dst_nat   VARCHAR(45) NULL,
  hit_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (rule_id, dst_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
