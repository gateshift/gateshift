-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- Per-Device, per-TP-Layer generator configuration for CP Threat-
-- Prevention enrichment.
--
-- CP TP is a separate rulebase from access-control (see
-- project_cp_tp_separate_rulebase memory). Gateshift generates
-- TP-rules deterministically from a Strategy + Params; the generated
-- rules are NOT persisted here - Preview (frontend) and Push both call
-- the generator on demand, so there is no drift between what the user
-- saw and what gets pushed.
--
-- One row per (Target-Device, TP-Layer). Layer-name is the FULL CP
-- layer name (e.g. "newcpgwpolicy Threat Prevention"), not a short
-- alias. Strategy values: V1 only "security-ruleset"; V2+ may add
-- "best-practice-template" etc. params_json shape varies per strategy
-- (validated in the driver, not by the schema).
--
-- Wipe-and-push semantics in the push phase: Gateshift owns the target
-- TP-Layer. Push wipes every threat-rule in the layer (scope-based,
-- analog to access-rulebase wipe) and re-pushes from the generator.
-- Any user-authored rules in the same TP-Layer get lost on the next
-- push - that is the explicit Gateshift ownership contract.
-- Generated rules carry name-prefix "ff-tp-" and a JSON marker in
-- comments (gateshift:strategy:...) for audit identification only,
-- not as a wipe gate. See project_cp_tp_rulebase_api memory for the
-- Tombstone-Pattern that handles CP's "TP-Layer must have >=1 rule"
-- constraint.

CREATE TABLE IF NOT EXISTS fw_tp_layer_config (
  device_id    INT          NOT NULL,
  layer_name   VARCHAR(255) NOT NULL,
  strategy     VARCHAR(64)  NOT NULL,
  params_json  JSON         NOT NULL,
  updated_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
                                       ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (device_id, layer_name),
  KEY idx_device (device_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
