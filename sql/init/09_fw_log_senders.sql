-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1
--
-- The senders of the rows in fw_flows: the ONE place a sender string is
-- resolved to a Device (docs/DEVICE_IDENTITY_PLAN.md, phase 4, D1/D2/D9).
--
-- A syslog sender is what the receiver observed, three fields together
-- (decision D9): the hostname in the syslog header, the address the packet
-- came from, and the vendor's own identity inside the message (a FortiOS
-- serial, a Check Point origin), empty where the vendor sends none. The
-- collector creates and counts sender rows and NEVER creates a Device; the
-- mapping to a Device (device_id) is the operator's act in the webapp, and
-- "unattributed" is the absence of that mapping, not a sentinel value.
--
-- A Device's own configuration import writes its rules into fw_flows too
-- (source_type api_import, so the pipeline treats rules like observed
-- flows); those rows hang on a sender of source_type 'api_import' that the
-- import creates for the Device and replaces with the rows.
--
-- The webapp's lifespan carries the same CREATE for an upgraded
-- installation; tools/check_schema_parity.sh keeps the two equal.
USE gateshift;

CREATE TABLE IF NOT EXISTS fw_log_senders (
  id            INT NOT NULL AUTO_INCREMENT,
  source_type   VARCHAR(16)  NOT NULL DEFAULT 'syslog',
  header_host   VARCHAR(255) NOT NULL DEFAULT '',
  source_addr   VARCHAR(45)  NOT NULL DEFAULT '',
  vendor_serial VARCHAR(128) NOT NULL DEFAULT '',
  vendor        VARCHAR(64)  NOT NULL DEFAULT '',
  device_id     INT NULL,
  first_seen    DATETIME NULL,
  last_seen     DATETIME NULL,
  line_count    BIGINT UNSIGNED NOT NULL DEFAULT 0,
  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_sender (source_type, header_host, source_addr, vendor_serial),
  KEY idx_sender_device (device_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
