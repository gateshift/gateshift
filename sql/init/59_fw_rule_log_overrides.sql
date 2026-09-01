-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- User-curated log-forwarding profile + log-start/log-end flags per rule,
-- keyed by content_hash.
--
-- Generate truncates and rebuilds fw_rules_filtered every run, but
-- content_hash is deterministic (SHA1 over device_host + action + direction
-- + proto + dst_port + sorted src/dst tuples - see 55_fw_rules_filtered.sql),
-- so overrides survive across runs by joining on r.content_hash.
--
-- Replaces the device-default log_forwarding emitted uniformly by the PA
-- driver (panw.py _gen_rules) - when a row exists here, the driver should
-- prefer it; otherwise fall back to settings.log_forwarding.
--
-- log_start / log_end are not nullable: the row's existence already encodes
-- "user touched logging for this rule"; the bool then just says start/end.
-- Defaults match PA's own defaults (start=no, end=yes), so existing rows
-- backfilled by the column-add migration behave identically to PA's
-- implicit defaults.
--
-- See feedback_rule_identity_hash memory: override tables key on rule_hash,
-- not the legacy (device_host, action, proto, dst_port) natkey.

-- log_forwarding is the PA-specific column; nullable so Forti-only override
-- rows (log_traffic / capture_packet set, no PA profile) can exist. Same
-- schema-as-superset pattern used elsewhere - vendor-specific slots are
-- additive and nullable.
--
-- log_traffic / capture_packet are FortiOS per-policy fields; log_start is
-- shared (PA log-at-start = Forti logtraffic-start). log_end is PA-only.
CREATE TABLE IF NOT EXISTS fw_rule_log_overrides (
  rule_hash      BINARY(20)                       NOT NULL PRIMARY KEY,
  log_forwarding VARCHAR(255)                     NULL,
  log_start      TINYINT(1)                       NOT NULL DEFAULT 0,
  log_end        TINYINT(1)                       NOT NULL DEFAULT 1,
  log_traffic    ENUM('all','utm','disable')      NULL,
  capture_packet TINYINT(1)                       NULL,
  source         ENUM('manual','auto')            NOT NULL DEFAULT 'manual',
  updated_at     TIMESTAMP                        NOT NULL DEFAULT CURRENT_TIMESTAMP
                                                    ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
