-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- User-curated rule field-negation overrides that survive Generate.
--
-- Parallel to fw_rule_zone_overrides / fw_rule_service_overrides etc.
-- Generate truncates and rebuilds fw_rules_consolidated_1; this overlay
-- holds user-decided negate flags per rule, keyed by content_hash so they
-- survive across runs. rules_query LEFT JOINs and COALESCEs over the
-- consolidated negate columns, so overrides win whenever present
-- (respecting source='manual' marker per feedback_override_marker_in_postprocessors).
--
-- Three independent boolean flags - negate_source, negate_destination,
-- negate_service - match the PA / Forti / CP per-rule semantics
-- (see project_rule_negation_plan). Each can be overridden independently.
-- NULL = no override; falls back to consolidated value via COALESCE.

CREATE TABLE IF NOT EXISTS fw_rule_negate_overrides (
  rule_hash           BINARY(20)            NOT NULL PRIMARY KEY,
  negate_source       TINYINT(1)            NULL,
  negate_destination  TINYINT(1)            NULL,
  negate_service      TINYINT(1)            NULL,
  source              ENUM('manual','auto') NOT NULL DEFAULT 'manual',
  updated_at          TIMESTAMP             NOT NULL DEFAULT CURRENT_TIMESTAMP
                                              ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
