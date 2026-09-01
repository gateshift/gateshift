-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- Routing table per device: prefix → interface (+ next-hop, VR).
-- Combined with fw_interfaces gives deterministic IP → zone mapping.
-- Populated by device import (API/SSH).
--
-- interface_name is NULLABLE: PA allows next-hop-only static routes (no
-- <interface> element). UNIQUE key includes vr_name because the same prefix
-- can legitimately exist in two virtual routers; without it the second
-- INSERT IGNOREs into a silent no-op.

CREATE TABLE IF NOT EXISTS fw_routes (
  id             INT UNSIGNED NOT NULL AUTO_INCREMENT,
  device_id      INT NOT NULL,
  prefix         VARCHAR(43) NOT NULL,             -- e.g. 192.168.10.0/24
  prefix_len     TINYINT UNSIGNED NOT NULL,
  ip_from        INT UNSIGNED NULL,                -- INET_ATON(network address)
  ip_to          INT UNSIGNED NULL,                -- INET_ATON(broadcast address)
  interface_name VARCHAR(64) NULL,
  next_hop       VARCHAR(64) NULL,
  vr_name        VARCHAR(128) NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_dev_prefix_vr (device_id, prefix, vr_name),
  KEY idx_ip_range (device_id, ip_from, ip_to),
  FOREIGN KEY (device_id) REFERENCES fw_devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
