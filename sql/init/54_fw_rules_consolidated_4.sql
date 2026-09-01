-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

CREATE TABLE IF NOT EXISTS fw_rules_consolidated_4 (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  generated_at TIMESTAMP NOT NULL,
  vendor       VARCHAR(64) NULL,
  device_host  VARCHAR(255) NULL,
  action       ENUM('allow','deny','drop','reject','unknown') NOT NULL DEFAULT 'unknown',
  direction    ENUM('in','out','forward','unknown') NOT NULL DEFAULT 'unknown',
  iface_out    VARCHAR(64) NULL,
  proto        VARCHAR(16) NULL,
  port_from    SMALLINT UNSIGNED NULL,
  port_to      SMALLINT UNSIGNED NULL,
  hit_count    BIGINT UNSIGNED NOT NULL DEFAULT 0,
  src_count    INT UNSIGNED NOT NULL DEFAULT 0,
  dst_count    INT UNSIGNED NOT NULL DEFAULT 0,
  first_seen   DATETIME NULL,
  last_seen    DATETIME NULL,

  PRIMARY KEY (id),
  KEY idx_generated  (generated_at),
  KEY idx_proto_port (proto, port_from, port_to)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Sources per rule
CREATE TABLE IF NOT EXISTS fw_rules_consolidated_4_sources (
  rule_id   BIGINT UNSIGNED NOT NULL,
  src_ip    VARCHAR(128) NOT NULL,
  src_zone  VARCHAR(128) NULL,
  iface_in  VARCHAR(64) NULL,
  hit_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (rule_id, src_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Destinations per rule
CREATE TABLE IF NOT EXISTS fw_rules_consolidated_4_destinations (
  rule_id   BIGINT UNSIGNED NOT NULL,
  dst_ip    VARCHAR(128) NOT NULL,
  dst_zone  VARCHAR(128) NULL,
  dst_nat   VARCHAR(45) NULL,
  hit_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (rule_id, dst_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Ports per rule (for later stages: multiple ranges per rule possible)
CREATE TABLE IF NOT EXISTS fw_rules_consolidated_4_ports (
  rule_id   BIGINT UNSIGNED NOT NULL,
  proto     VARCHAR(16) NOT NULL,
  port_from SMALLINT UNSIGNED NOT NULL,
  port_to   SMALLINT UNSIGNED NOT NULL,
  hit_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (rule_id, proto, port_from, port_to)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
