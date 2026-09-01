-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- Network-Strang VRF entity (Slice 5). Promotes the previously-free-string
-- fw_routes.vr_name to a first-class entity with per-VR properties + rename
-- overlay. Mirrors fw_zones shape - symmetric design (zone vs VRF, both
-- per-device named entities with a render-time rename overlay).
--
-- Vendor mapping: PA virtual-router ↔ Forti VDOM-routing-instance ↔ CP
-- virtual-system. The agnostic name is "VRF" / vr_name.
--
-- Soft reference (no hard FK) from fw_routes.vr_name and fw_interfaces.vr_name
-- to fw_vrfs(device_id, name) - same reasoning as zones (save-cascade order,
-- multi-source spec semantics, future per-(source,target) overlay table).
-- Validation happens at push time, not at the storage layer.
--
-- name           = current (editable) VR name; drives push output. User edits
--                  cascade to fw_interfaces.vr_name + fw_routes.vr_name in one
--                  transaction (Slice 6).
-- import_vr_name = source-of-truth VR name from the collector. Re-import resets
--                  name back to import_vr_name after user confirms the wipe.
--                  Also used as the system-default sentinel: `import_vr_name =
--                  'default'` is the always-present fallback VR - code branches
--                  on it (not on `name`), so the user can rename the visible
--                  name without breaking the sentinel.

CREATE TABLE IF NOT EXISTS fw_vrfs (
  id              INT UNSIGNED NOT NULL AUTO_INCREMENT,
  device_id       INT NOT NULL,
  name            VARCHAR(128) NOT NULL,
  properties      JSON NULL,
  import_vr_name  VARCHAR(128) NULL,
  created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_dev_vrf (device_id, name),
  UNIQUE KEY uq_dev_vrf_import (device_id, import_vr_name),
  FOREIGN KEY (device_id) REFERENCES fw_devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
