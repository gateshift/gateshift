-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- Zone mapping: (device, CIDR) -> zone name, derived from the device's routes
-- and connected interface subnets by _sync_route_zone_mappings (webui/main.py)
-- at the start of every generate. Read by the LPM zone lookups in main.py
-- (_ZONE_LPM_SQL, _resolve_zones_from_routes, _enrich_zones_in_display_tables),
-- always scoped by device. Longest-prefix match wins.
--
-- This DDL matches the runtime schema. device_id and the (cidr, device_id)
-- unique key were first added by lifespan ALTERs in main.py and the file
-- lagged behind - which read as a global, colliding table to anyone trusting
-- the file (design review 2026-10-01). The ALTERs stay for older databases.

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
  device_id    INT NULL,                      -- the device whose routes produced
                                              -- the row; NULL only in legacy data
  description  VARCHAR(255) NULL,
  created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_cidr_device (cidr, device_id),
  KEY idx_prefix (prefix_len DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
