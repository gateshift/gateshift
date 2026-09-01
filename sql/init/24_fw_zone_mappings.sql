-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- Zone mapping: CIDR → zone name
-- Used by 24_zone_enrich.sql to fill NULL src_zone/dst_zone in consolidated_1
-- when the source firewall does not supply zone information.
-- Longest-prefix match wins.

CREATE TABLE IF NOT EXISTS fw_zone_mappings (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  cidr         VARCHAR(43) NOT NULL,          -- e.g. 10.0.0.0/8
  prefix_len   TINYINT UNSIGNED NOT NULL,     -- extracted from cidr for ordering
  ip_from      VARBINARY(16) NOT NULL,        -- INET6_ATON(network address)
  ip_to        VARBINARY(16) NOT NULL,        -- INET6_ATON(broadcast address)
  zone_name    VARCHAR(128) NOT NULL,
  interface_name VARCHAR(64) NULL,            -- raw egress iface for the prefix
                                              -- (auto-derive resolves to this,
                                              -- override-mapped, for Forti targets)
  description  VARCHAR(255) NULL,
  created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_cidr (cidr),
  KEY idx_prefix (prefix_len DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
