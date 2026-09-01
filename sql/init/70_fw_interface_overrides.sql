-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- Per-source-device interface-RENAME intent - translates an interface name
-- from the immutable collector-name space into the target-device's name space
-- at Push time (cascade-rename, re-import-safe). Mirrors the app's
-- _ensure_iface_overrides_table() so a fresh initdb and the lifespan helper
-- agree; keep the two in sync.
--
-- device_id              - source device (the one being pushed)
-- import_interface_name  - soft-FK to fw_interfaces.import_interface_name
--                          (the collector's immutable name); keyed here so the
--                          override survives cascade-renames + re-imports.
-- interface_name         - chosen target-space interface name.
CREATE TABLE IF NOT EXISTS fw_interface_overrides (
  device_id              INT          NOT NULL,
  import_interface_name  VARCHAR(64)  NOT NULL,
  interface_name         VARCHAR(64)  NOT NULL,
  updated_at             TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
                                        ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (device_id, import_interface_name),
  FOREIGN KEY (device_id) REFERENCES fw_devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
