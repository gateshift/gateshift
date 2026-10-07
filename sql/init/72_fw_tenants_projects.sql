-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- Tenants and projects (projects P1.1).
--
-- A tenant keeps customers' estates apart in one installation: it owns
-- devices (fw_devices.tenant_id, see 01_fw_devices.sql) and projects. A
-- project is one migration - a source, a target, and from P1.2 on the
-- decisions made for that pair and its snapshots. ref_kind is reserved for
-- the manager tier (scope references); the Community Edition writes
-- 'device'. There is deliberately no unique key on the pair: two projects
-- on one pair are allowed (a branch from a snapshot).
--
-- fw_meta holds one-time migration markers (e.g. projects_implicit_v1).
-- Matches the lifespan DDL in main.py (_ensure_projects_tables).

CREATE TABLE IF NOT EXISTS fw_tenants (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  name       VARCHAR(128) NOT NULL,
  created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_tenant_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO fw_tenants (id, name) VALUES (1, 'default');

-- 01_fw_devices.sql carries the column; the constraint can only be added
-- once fw_tenants exists.
ALTER TABLE fw_devices ADD CONSTRAINT fk_devices_tenant
  FOREIGN KEY IF NOT EXISTS (tenant_id) REFERENCES fw_tenants(id);

CREATE TABLE IF NOT EXISTS fw_projects (
  id              INT AUTO_INCREMENT PRIMARY KEY,
  tenant_id       INT          NOT NULL DEFAULT 1,
  name            VARCHAR(128) NOT NULL,
  source_ref_kind ENUM('device') NOT NULL DEFAULT 'device',
  source_ref_id   INT          NOT NULL,
  target_ref_kind ENUM('device') NOT NULL DEFAULT 'device',
  target_ref_id   INT          NOT NULL,
  status          ENUM('draft','curated','generated','pushed','verified','closed')
                               NOT NULL DEFAULT 'draft',
  created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
                                 ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_project_name (tenant_id, name),
  KEY ix_project_source (source_ref_id),
  KEY ix_project_target (target_ref_id),
  FOREIGN KEY (tenant_id) REFERENCES fw_tenants(id),
  FOREIGN KEY (source_ref_id) REFERENCES fw_devices(id) ON DELETE CASCADE,
  FOREIGN KEY (target_ref_id) REFERENCES fw_devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS fw_meta (
  k          VARCHAR(64) NOT NULL PRIMARY KEY,
  v          TEXT        NULL,
  updated_at TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
                           ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
