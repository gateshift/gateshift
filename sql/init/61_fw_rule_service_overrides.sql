-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- User-curated PA <service> override per rule, keyed by content_hash.
--
-- Two values only - both are PA-defined service literals:
--   'any'                 → match any proto/port
--   'application-default' → match the bound app's default ports
--
-- The presence of a row replaces the proto/port-derived service objects the
-- driver would otherwise emit (panw.py _gen_rules). Absence = keep current
-- behaviour (named service objects from r.proto + r.dst_port).
--
-- Override does not change content_hash - that's deliberate: proto/port
-- still identify the rule for consolidation; the override only changes what
-- the deploy XML emits for that rule's <service> element.
--
-- See feedback_rule_identity_hash memory: override tables key on rule_hash.

CREATE TABLE IF NOT EXISTS fw_rule_service_overrides (
  project_id  INT                   NOT NULL DEFAULT 0,
  rule_hash   BINARY(20)                            NOT NULL,
  service     ENUM('any','application-default')     NOT NULL,
  source      ENUM('manual','auto')                 NOT NULL DEFAULT 'manual',
  updated_at  TIMESTAMP                             NOT NULL DEFAULT CURRENT_TIMESTAMP
                                                       ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (project_id, rule_hash),
  KEY ix_fw_rule_service_overrides_key (rule_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
