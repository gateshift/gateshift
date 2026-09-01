-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- User-curated app bindings that survive Generate.
--
-- Generate truncates and rebuilds fw_rules_filtered every run, but
-- content_hash is deterministic (SHA1 over device_host + action + direction
-- + proto + dst_port + sorted src/dst tuples - see 55_fw_rules_filtered.sql),
-- so overrides survive across runs by joining on r.content_hash.
--
-- Replaced the legacy (device_host, action, proto, dst_port) "natkey" PK
-- (Slice C, see feedback_rule_identity_hash memory) - that key conflated
-- distinct rules and made one user edit silently apply to N rules.
--
-- Existing deployments are migrated cartesian-explode style by
-- webui/main.py::_migrate_overrides_to_rule_hash on first start.

CREATE TABLE IF NOT EXISTS fw_rule_app_overrides (
  rule_hash    BINARY(20)            NOT NULL PRIMARY KEY,
  applications VARCHAR(2048)         NOT NULL,
  source       ENUM('manual','auto') NOT NULL DEFAULT 'manual',
  updated_at   TIMESTAMP             NOT NULL DEFAULT CURRENT_TIMESTAMP
                                       ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
