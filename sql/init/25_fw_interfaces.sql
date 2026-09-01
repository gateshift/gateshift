-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- Network-Strang interface table - supersedes fw_interface_zones (Slice 2).
-- Per-interface attributes including the inline zone-binding column. Cardinality
-- is 1:1 (each interface binds to one zone in PA / Forti / CP / OPNsense), so a
-- separate binding-only table buys nothing today. Future M&A (per-(source,target)
-- overlay) gets its own dedicated table when that use case lands.
--
-- interface_name        = current (editable) name; drives push output. User edits
--                         cascade to fw_routes.interface_name in one transaction.
-- import_interface_name = source-of-truth name from the collector (immutable
--                         through user edits; reset to interface_name on re-import
--                         after the user confirms the wipe). Slice 6 (2026-05-06).
-- import_zone_name      = original zone-binding as imported (drives traffic-log /
--                         imported-rule rename propagation when binding changes).
-- vr_name               = VRF membership (Slice 5). Soft reference to fw_vrfs(name)
--                         per device. Default 'default' for sources without a
--                         native VRF concept (OPNsense / ASA).
-- iface_type            = physical / vlan / loopback / bond / tunnel / other.
--                         CP-Network-Push V1: Gaia commands are typed, so we
--                         can't infer at push time. PA derives at collect time.
--                         Note: PA aggregate-ethernet (ae*) maps to 'bond' here
--                         - same canonical type, vendor-specific name pattern.
-- parent_iface_name     = for VLAN: parent IF name (e.g. 'eth1' for 'eth1.100',
--                         or 'bond0' / 'ae1' for VLAN-on-bond).
-- vlan_tag              = VLAN ID; NULL for non-VLAN interfaces.
-- member_iface_names    = JSON array of physical IF names that compose a bond
--                         (PA: aggregate-ethernet members; CP: bonding members).
--                         NULL for non-bond IFs. V1.5 - Discover-only in Slice 1,
--                         push wires up later.
-- role                  = FortiOS interface role (lan/wan/dmz/undefined). Pure
--                         GUI/Template metadata in FortiOS - NOT consulted by
--                         the policy engine. NULL for vendors without the
--                         concept (PA/CP/OPNsense/ASA). Forti-only collector +
--                         renderer in V1.5.

CREATE TABLE IF NOT EXISTS fw_interfaces (
  id                     INT UNSIGNED NOT NULL AUTO_INCREMENT,
  device_id              INT NOT NULL,
  interface_name         VARCHAR(64)  NOT NULL,
  zone_name              VARCHAR(128) NULL,
  description            VARCHAR(255) NULL,
  ip_addresses           JSON NULL,
  import_zone_name       VARCHAR(128) NULL,
  import_interface_name  VARCHAR(64)  NULL,
  vr_name                VARCHAR(128) NOT NULL DEFAULT 'default',
  iface_type             VARCHAR(16)  NULL,
  parent_iface_name      VARCHAR(64)  NULL,
  vlan_tag               SMALLINT UNSIGNED NULL,
  member_iface_names     JSON NULL,
  role                   ENUM('lan','wan','dmz','undefined') NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_dev_iface (device_id, interface_name),
  FOREIGN KEY (device_id) REFERENCES fw_devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
