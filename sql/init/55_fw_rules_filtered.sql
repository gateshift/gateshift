-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- Module: Quality filter
-- Filters rules from the highest active upstream module

CREATE TABLE IF NOT EXISTS fw_rules_filtered (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  generated_at TIMESTAMP NOT NULL,
  vendor       VARCHAR(64) NULL,
  -- the Device, the key once phase 7 drops the name (docs/DEVICE_IDENTITY_PLAN.md)
  device_id  INT NULL,
  action       ENUM('allow','deny','drop','reject','unknown') NOT NULL DEFAULT 'unknown',
  direction    ENUM('in','out','forward','unknown') NOT NULL DEFAULT 'unknown',
  proto        VARCHAR(16) NULL,
  dst_port     SMALLINT UNSIGNED NULL,
  application  VARCHAR(128) NULL,
  rule_name    VARCHAR(255) NULL,
  security_profile VARCHAR(255) NULL,
  security_profile_group VARCHAR(255) NULL,
  src_rule_id  BIGINT UNSIGNED NULL,
  hit_count    BIGINT UNSIGNED NOT NULL DEFAULT 0,
  src_count    INT UNSIGNED NOT NULL DEFAULT 0,
  dst_count    INT UNSIGNED NOT NULL DEFAULT 0,
  first_seen   DATETIME NULL,
  last_seen    DATETIME NULL,

  `sequence`   SMALLINT UNSIGNED NULL,
  source_type  VARCHAR(16) NOT NULL DEFAULT 'syslog',
  -- Stable per-rule identity for override tables (apps, zones, logging, …).
  -- gs_rule_hash (48_fn_rule_hash.sql) over the Device's id + action +
  -- direction + proto + dst_port + the sorted src/dst signatures. Filled in a
  -- post-pipeline UPDATE (see gateshift/modules/db_jobs.py::_run_quality_filter).
  -- Replaces the legacy (device_host, action, proto, dst_port) "natkey",
  -- which conflated distinct rules - see feedback_rule_identity_hash memory.
  content_hash BINARY(20) NULL,
  KEY idx_device_id (device_id),
  PRIMARY KEY (id),
  KEY idx_generated    (generated_at),
  KEY idx_proto_port   (proto, dst_port),
  KEY idx_content_hash (content_hash),
  FOREIGN KEY (device_id) REFERENCES fw_devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS fw_rules_filtered_sources (
  rule_id   BIGINT UNSIGNED NOT NULL,
  src_ip    VARCHAR(128) NOT NULL,
  src_zone  VARCHAR(128) NULL,
  iface_in  VARCHAR(64) NULL,
  hit_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (rule_id, src_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS fw_rules_filtered_destinations (
  rule_id   BIGINT UNSIGNED NOT NULL,
  dst_ip    VARCHAR(128) NOT NULL,
  dst_zone  VARCHAR(128) NULL,
  dst_nat   VARCHAR(45) NULL,
  hit_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (rule_id, dst_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
