-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- User-editable overlays on top of fw_nat_rules, keyed by nat_hash.
--
-- nat_hash IS the rule identity (SHA1 over traffic-defining fields -
-- see project_nat_phase_a_audit + feedback_rule_identity_hash). Override
-- bindings survive re-imports, position re-orderings and user-renames of
-- the source NAT-rule, as long as the traffic-defining fields stay the
-- same.
--
-- Override slots cover the *non*-identity-stable columns: name, description,
-- disabled (toggle), and vendor-prefixed properties (pa_* / forti_* / cp_*).
-- Editing one of the hash-input fields (orig_*/trans_*) does not flow through
-- an override row - the user does that directly on fw_nat_rules at the
-- source side. See [[project_nat_full_scope_plan]] Decisions table.
--
-- source enum:
--   auto    - promoted from raw_extras by Phase-B-Roundtrip promoters
--             (Forti policy.nat-flag, PA bi-directional, …)
--   manual  - user-edited via Enrichment > NAT (Phase D)

CREATE TABLE IF NOT EXISTS fw_nat_rule_overrides (
  nat_hash    BINARY(20)            NOT NULL PRIMARY KEY,
  name        VARCHAR(255)          NULL,
  description TEXT                  NULL,
  disabled    TINYINT(1)            NULL,
  properties  JSON                  NULL,
  -- Route-derive overlay (Auto-derive button, Forti target): the NAT rule's
  -- srcintf/dstintf resolved from a route lookup to the target interface, so
  -- the policy-NAT SNAT<->rule correlation overlaps. Kept separate from the
  -- `properties` negate overlay so neither write clobbers the other.
  src_zones   JSON                  NULL,
  dst_zones   JSON                  NULL,
  source      ENUM('manual','auto') NOT NULL DEFAULT 'manual',
  updated_at  TIMESTAMP             NOT NULL DEFAULT CURRENT_TIMESTAMP
                                      ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
