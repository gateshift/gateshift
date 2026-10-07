-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- Project name map (rename model A, docs/CURATION_OWNERSHIP_DESIGN.md 5).
--
-- The imported data keeps its source names for good. A rename made in a
-- project - an interface to the target's naming scheme, a zone, a VRF, an
-- object or a service - is one row here: source name -> target name per
-- kind, and the map is applied when the data is read (the rules view, the
-- network tab, generate), never written back. Two projects of one source
-- can therefore carry different names, snapshots carry the names with the
-- decisions, and hashes stay what the import computed. Several source
-- names may map to one target name (a merge).
-- Matches the lifespan DDL in main.py (_ensure_projects_tables).

CREATE TABLE IF NOT EXISTS fw_project_name_map (
  project_id   INT          NOT NULL,
  kind         ENUM('interface','zone','vrf','object','service') NOT NULL,
  source_name  VARCHAR(255) NOT NULL,
  target_name  VARCHAR(255) NOT NULL,
  updated_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
                              ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (project_id, kind, source_name),
  KEY ix_name_map_target (project_id, kind, target_name),
  FOREIGN KEY (project_id) REFERENCES fw_projects(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
