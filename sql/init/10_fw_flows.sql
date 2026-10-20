-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

CREATE TABLE IF NOT EXISTS fw_flows (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  received_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  event_ts DATETIME NULL,
  vendor VARCHAR(64) NULL,
  program VARCHAR(128) NULL,
  facility TINYINT UNSIGNED NULL,
  severity TINYINT UNSIGNED NULL,
  action ENUM('allow','deny','drop','reject','unknown') NOT NULL DEFAULT 'unknown',
  direction ENUM('in','out','forward','unknown') NOT NULL DEFAULT 'unknown',
  iface_in VARCHAR(64) NULL,
  iface_out VARCHAR(64) NULL,
  src_zone VARCHAR(128) NULL,
  dst_zone VARCHAR(128) NULL,
  proto VARCHAR(16) NULL,
  src_ip VARBINARY(16) NULL,
  src_port SMALLINT UNSIGNED NULL,
  dst_ip VARBINARY(16) NULL,
  dst_port SMALLINT UNSIGNED NULL,
  nat_src_ip VARBINARY(16) NULL,
  nat_src_port SMALLINT UNSIGNED NULL,
  nat_dst_ip VARBINARY(16) NULL,
  nat_dst_port SMALLINT UNSIGNED NULL,
  application VARCHAR(128) NULL,
  security_profile VARCHAR(255) NULL,
  security_profile_group VARCHAR(255) NULL,
  url_category VARCHAR(255) NULL,
  rule_hash BINARY(32) NULL,
  rule_id VARCHAR(128) NULL,
  rule_name VARCHAR(255) NULL,
  rule_text TEXT NULL,
  raw_message TEXT NOT NULL,
  raw_hash BINARY(32) NOT NULL,
  extra JSON NULL,
  source_type  VARCHAR(16) NOT NULL DEFAULT 'syslog',
  -- the row's origin: a syslog sender, or a Device's own configuration
  -- import (fw_log_senders, docs/DEVICE_IDENTITY_PLAN.md phase 4). The
  -- evidence hangs on the sender, never on a Device: deleting a Device
  -- releases the mapping and keeps what the wire said.
  sender_id INT NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_raw_hash (raw_hash),
  KEY idx_time (event_ts, received_at),
  KEY idx_5tuple (proto, src_ip, src_port, dst_ip, dst_port),
  KEY idx_action_time (action, event_ts),
  KEY idx_rule (rule_hash, event_ts),
  KEY idx_source_type (source_type, sender_id),
  KEY idx_flows_sender (sender_id, event_ts),
  FOREIGN KEY (sender_id) REFERENCES fw_log_senders(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
