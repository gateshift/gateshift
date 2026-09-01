-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- Agnostic NAT-rule entity. One row per rule, per device.
-- Two top-level flavours covered by `nat_type`:
--   snat     - source NAT (outbound: hide internal source behind translated address)
--   dnat     - destination NAT (inbound port-forward: translate dst to internal host)
--   static   - bidirectional 1:1 (rare, but keep distinct from snat/dnat)
--
-- JSON columns hold lists of strings (zone/object names or literals like "any").
-- Translation fields nullable: an SNAT rule typically has no translated dst,
-- a DNAT rule typically has no translated src.

CREATE TABLE IF NOT EXISTS fw_nat_rules (
  id              INT UNSIGNED NOT NULL AUTO_INCREMENT,
  device_id       INT NOT NULL,
  position        INT NOT NULL DEFAULT 0,
  name            VARCHAR(255) NOT NULL,
  nat_type        ENUM('snat','dnat','static') NOT NULL,
  disabled        TINYINT(1) NOT NULL DEFAULT 0,

  src_zones       JSON NULL,
  dst_zones       JSON NULL,
  interface_name  VARCHAR(64) NULL,

  orig_src        JSON NULL,
  orig_dst        JSON NULL,
  orig_service    JSON NULL,

  trans_src       VARCHAR(255) NULL,
  trans_src_type  ENUM('static-ip','dynamic-ip','dynamic-ip-and-port','interface-address','none') NOT NULL DEFAULT 'none',
  trans_dst       VARCHAR(255) NULL,
  trans_dst_port  VARCHAR(64) NULL,

  description     TEXT NULL,
  properties      JSON NULL,
  -- Content-hash identity. SHA1 over the traffic-defining fields so
  -- overrides bind to a stable rule regardless of position/name edits.
  -- See feedback_rule_identity_hash (rules) - same pattern, NAT-specific
  -- field set documented in project_nat_phase_a_audit.
  nat_hash        BINARY(20) NULL,
  created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_dev_name (device_id, name),
  KEY idx_device_pos (device_id, position),
  KEY idx_nat_hash (nat_hash),
  FOREIGN KEY (device_id) REFERENCES fw_devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
