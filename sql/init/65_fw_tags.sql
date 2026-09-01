-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- Tag-Catalog per Source-Device.
--
-- Vendor-specific concept (PA + CP have tag-objects with color+comments;
-- Forti has no policy tags). UI tab is target-driven - see
-- feedback_enrichment_target_driven. Cross-vendor migration is
-- user-driven (feedback_user_owns_migration_decisions): no auto color
-- translation, user explicitly maps a source-tag onto a target-tag.
--
-- Properties JSON holds vendor-prefixed slots (pa_color, pa_comments,
-- cp_color, cp_icon, cp_comments) per webui/tag_schemas.py - single
-- source of truth, mirrors zone_schemas / nat_schemas pattern.
--
-- source ENUM:
--   'import'  → from source-parser; overwritten on re-import
--   'manual'  → user-edited in Enrichment > Tags; survives re-import
--   'auto'    → derived by Phase-B promoter (rule-level only - tag
--               objects are written directly by source-parsers)

CREATE TABLE IF NOT EXISTS fw_tags (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  device_id   INT NOT NULL,
  name        VARCHAR(255) NOT NULL,
  properties  JSON NULL,
  source      ENUM('import','manual','auto') NOT NULL DEFAULT 'import',
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                                ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_dev_name (device_id, name),
  FOREIGN KEY (device_id) REFERENCES fw_devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;


-- Per-rule Tag-Override.
--
-- Vendor-specific columns since each vendor has its own tag-list/format:
--   pa_tags        - PA <tag><member>X</member></tag> array
--   pa_group_tag   - PA <group-tag>X</group-tag> single value
--                    (drives PA Web-UI / Panorama rule-grouping view;
--                     value is a tag-name from the PA catalog)
--   cp_tags        - CP rule.tags array (UID-refs at source, names at Gateshift)
--
-- Forti has no slot - Forti policies don't support tags.
--
-- rule_hash keyed → survives Re-Generate (content_hash is stable across
-- runs; tag flags are ephemeral like description/disabled/negate).
-- devices_reset must JOIN-wipe via fw_rules_consolidated_1 BEFORE the
-- consolidated_1 wipe runs (T7 audit, mirrors fw_rule_negate_overrides).

CREATE TABLE IF NOT EXISTS fw_rule_tag_overrides (
  rule_hash       BINARY(20)            NOT NULL PRIMARY KEY,
  pa_tags         JSON                  NULL,
  pa_group_tag    VARCHAR(127)          NULL,
  cp_tags         JSON                  NULL,
  source          ENUM('manual','auto') NOT NULL DEFAULT 'manual',
  updated_at      TIMESTAMP             NOT NULL DEFAULT CURRENT_TIMESTAMP
                                            ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
