-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

CREATE TABLE IF NOT EXISTS fw_pipeline_config (
  job_name    VARCHAR(128) NOT NULL  COMMENT 'Job filename without .sql extension',
  enabled     TINYINT(1)  NOT NULL DEFAULT 1,
  params      JSON        NULL      COMMENT 'Job parameters as JSON object',
  description TEXT        NULL,
  PRIMARY KEY (job_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Default configuration (not overwritten if already present)
INSERT IGNORE INTO fw_pipeline_config (job_name, enabled, params, description) VALUES
  ('20_generate_rule_candidates',  1, NULL,
   'Stage 0: aggregate raw candidates from fw_flows'),

  ('22_cleanup_nat_duplicates',    1, NULL,
   'Stage 0b: remove duplicate candidates missing a NAT match'),

  ('23_build_rules_consolidated',  1, NULL,
   'Stage 1: base-tuple consolidation + internet_public abstraction'),

  ('52_build_rules_by_dst',        1, NULL,
   'Stage 2: group by destination, accumulate sources'),

  ('53_build_rules_consolidated_3', 1,
   JSON_OBJECT(
     'threshold_24', 3,
     'threshold_16', 5,
     'threshold_8',  10
   ),
   'Stage 3: subnet aggregation of sources and destinations (configurable thresholds)');
