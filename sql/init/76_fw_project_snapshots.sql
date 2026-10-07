-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- Project snapshots (projects P1.5).
--
-- A snapshot freezes a project's decisions: the manual rows of the rule
-- override tables plus its TP-layer config and deploy settings, as JSON
-- (payload, see docs/CURATION_OWNERSHIP_DESIGN.md section 5.6). Auto rows
-- are not part of it - generate re-derives them. Secrets never are: the
-- VPN secret and certificate tables are keyed on the device.
-- kind 'original' is the empty decision set every project starts from; it
-- is created with the project and cannot be deleted. import_marks records
-- the source's and target's latest import timestamp at snapshot time, so a
-- restore can say whether the source changed since.
-- Matches the lifespan DDL in main.py (_ensure_projects_tables).

CREATE TABLE IF NOT EXISTS fw_project_snapshots (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  project_id   INT          NOT NULL,
  name         VARCHAR(128) NOT NULL,
  kind         ENUM('original','manual','auto') NOT NULL DEFAULT 'manual',
  note         TEXT         NULL,
  created_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  import_marks TEXT         NULL,
  row_count    INT          NOT NULL DEFAULT 0,
  payload      LONGTEXT     NOT NULL,
  KEY ix_snapshots_project (project_id),
  FOREIGN KEY (project_id) REFERENCES fw_projects(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
