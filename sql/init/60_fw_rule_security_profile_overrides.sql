-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- User-curated security profile-group per rule, keyed by content_hash.
--
-- Mirrors fw_rule_log_overrides: when a row exists, the PA driver prefers
-- this profile_group over settings.security_profile_group (the device
-- default emitted uniformly by panw.py _gen_rules).
--
-- See feedback_rule_identity_hash memory: override tables key on rule_hash,
-- not the legacy (device_host, action, proto, dst_port) natkey.

-- profile_group (PA) is now nullable so Forti-only rows (no PA profile-group,
-- only individual UTM slots) can exist. Same schema-as-superset pattern used
-- on fw_rule_log_overrides for the Forti logtraffic slot.
--
-- Forti V2 UTM slots: each FortiOS policy has separate profile-name fields
-- per UTM type (no profile-group container). NULL = "(none)" (renderer skips
-- the field on push) → fallback to FortiOS default behaviour. Slot absent
-- from API payload = "(keep)" (UPDATE leaves the column untouched).
--
-- Vendor scope per column:
--   profile_group              - PA only (individual slots ignored when set)
--   av_profile / webfilter_profile / dnsfilter_profile
--                              - shared Forti + PA (PA maps virus→av_profile,
--                                url-filtering→webfilter_profile)
--   ips_sensor / application_list / ssl_ssh_profile
--                              - Forti only (no PA equivalent in this schema)
--   pa_spyware_profile / pa_vulnerability_profile / pa_file_blocking_profile /
--   pa_wildfire_profile / pa_data_filtering_profile
--                              - PA only (individual security-profile slots
--                                with no Forti counterpart)
CREATE TABLE IF NOT EXISTS fw_rule_security_profile_overrides (
  rule_hash                 BINARY(20)            NOT NULL PRIMARY KEY,
  profile_group             VARCHAR(255)          NULL,
  av_profile                VARCHAR(255)          NULL,
  webfilter_profile         VARCHAR(255)          NULL,
  dnsfilter_profile         VARCHAR(255)          NULL,
  ips_sensor                VARCHAR(255)          NULL,
  application_list          VARCHAR(255)          NULL,
  ssl_ssh_profile           VARCHAR(255)          NULL,
  pa_spyware_profile        VARCHAR(255)          NULL,
  pa_vulnerability_profile  VARCHAR(255)          NULL,
  pa_file_blocking_profile  VARCHAR(255)          NULL,
  pa_wildfire_profile       VARCHAR(255)          NULL,
  pa_data_filtering_profile VARCHAR(255)          NULL,
  source                    ENUM('manual','auto') NOT NULL DEFAULT 'manual',
  updated_at                TIMESTAMP             NOT NULL DEFAULT CURRENT_TIMESTAMP
                                                  ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
