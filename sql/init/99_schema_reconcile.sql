-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- Schema reconciliation - runs LAST, after all base CREATE TABLE files.
-- These columns exist on the (incrementally-grown) dev DB but were never
-- folded back into the base CREATE TABLE files above, and no app-side
-- ensure_* helper adds them. On a clean initdb from an empty volume they
-- would be missing, and the device-context rules query 500s on them.
--
-- ONLY columns on init-created tables belong here. Do NOT add columns for
-- app-created tables (e.g. fw_imported_rules) - those don't exist during
-- the MariaDB initdb phase, the ALTER errors, and the mysql client aborts
-- the rest of this file. The app's lifespan ensure_* helpers own those.
ALTER TABLE fw_rules_consolidated_1 ADD COLUMN IF NOT EXISTS rule_name VARCHAR(255) NULL;
ALTER TABLE fw_rule_candidates      ADD COLUMN IF NOT EXISTS rule_name VARCHAR(255) NULL;
ALTER TABLE fw_zones                ADD COLUMN IF NOT EXISTS description VARCHAR(255) NULL;
ALTER TABLE fw_zones                ADD COLUMN IF NOT EXISTS source ENUM('inferred','api','manual') NOT NULL DEFAULT 'inferred';
ALTER TABLE fw_interface_overrides  ADD COLUMN IF NOT EXISTS interface_name VARCHAR(64) NOT NULL;
