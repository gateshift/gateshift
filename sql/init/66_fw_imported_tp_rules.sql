-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

-- Check Point source TP rulebase, imported per device (CP->CP fidelity).
-- One row per threat rule; exception rows carry exception_of = parent
-- rule name. Profile/protection references stay ref-only (names).
CREATE TABLE IF NOT EXISTS fw_imported_tp_rules (
  id                   INT           NOT NULL AUTO_INCREMENT,
  device_id            INT           NOT NULL,
  source_layer         VARCHAR(255)  NOT NULL,
  seq                  INT           NOT NULL,
  rule_name            VARCHAR(255)  NOT NULL,
  exception_of         VARCHAR(255)  NULL,
  enabled              TINYINT(1)    NOT NULL DEFAULT 1,
  action_profile       VARCHAR(255)  NULL,
  src_json             JSON          NULL,
  dst_json             JSON          NULL,
  svc_json             JSON          NULL,
  protected_scope_json JSON          NULL,
  protections_json     JSON          NULL,
  track_json           JSON          NULL,
  comments             TEXT          NULL,
  PRIMARY KEY (id),
  KEY idx_device (device_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
