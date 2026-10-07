-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- Per-source-device, re-import-proof EDITS of an imported interface (zone
-- binding, type/parent/VLAN, deploy-skip), keyed on the collector's
-- immutable interface name and re-applied onto the fresh row after every
-- collect. Renames are NOT here: a rename is a row of the project's name
-- map (fw_project_name_map, rename model A). Mirrors the app's
-- _ensure_iface_overrides_table(); keep the two in sync.
--
-- device_id              - source device
-- import_interface_name  - soft-FK to fw_interfaces.import_interface_name
--                          (the collector's immutable name)
-- edits                  - JSON {zone_name, iface_type, parent_iface_name,
--                          vlan_tag, deploy_skip} as the operator set them
CREATE TABLE IF NOT EXISTS fw_interface_overrides (
  device_id              INT          NOT NULL,
  import_interface_name  VARCHAR(64)  NOT NULL,
  edits                  JSON         NULL,
  updated_at             TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
                                        ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (device_id, import_interface_name),
  FOREIGN KEY (device_id) REFERENCES fw_devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
