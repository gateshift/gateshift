-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- User-curated CP track settings per rule, keyed by content_hash.
--
-- CP's rule.track is a struct:
--   {type, accounting, per-session, per-connection, alert}
--
-- The deploy renderer (checkpoint.py _render_access_rules) hardcodes
-- track="Log" today. When a row exists here, the renderer should prefer
-- it; otherwise the device default (Log) stands.
--
-- Discover-side (main.py _parse_cp_access_rules) writes auto-source rows
-- when it sees a non-default track on the imported rulebase, so the user
-- sees what the source firewall actually configured. Manual edits in the
-- enrichment tab promote source='manual' so the auto-binder won't stomp.
--
-- Scope: track_type + accounting + per_session + per_connection.
-- track_type stores the CP-API string verbatim - values include
-- "None", "Log", "Account", "Alert", "SNMP Trap", "Mail",
-- "User Defined Alert no.1..3", "Detailed Log", "Extended Log".
-- The renderer downgrades "Detailed Log"/"Extended Log" to "Log" on
-- Firewall-only Layers (CP refuses them without App-Control etc.);
-- everything else passes through as-is.
--
-- See feedback_rule_identity_hash memory: override tables key on rule_hash,
-- not the legacy (device_host, action, proto, dst_port) natkey.

CREATE TABLE IF NOT EXISTS fw_rule_track_overrides (
  rule_hash       BINARY(20)            NOT NULL PRIMARY KEY,
  track_type      VARCHAR(64)           NOT NULL DEFAULT 'Log',
  accounting      TINYINT(1)            NOT NULL DEFAULT 0,
  per_session     TINYINT(1)            NOT NULL DEFAULT 0,
  per_connection  TINYINT(1)            NOT NULL DEFAULT 1,
  source          ENUM('manual','auto') NOT NULL DEFAULT 'manual',
  updated_at      TIMESTAMP             NOT NULL DEFAULT CURRENT_TIMESTAMP
                                          ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
