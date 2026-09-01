-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1

USE gateshift;

-- Module: Quality filter
-- Filters rules from the highest active upstream module.
-- Source table is determined by db_jobs.py via @quality_filter_src variable.

SET @min_hit_count      = IFNULL(@min_hit_count,      10);
SET @min_days_active    = IFNULL(@min_days_active,     1);
SET @max_last_seen_days = IFNULL(@max_last_seen_days,  30);

-- @quality_filter_src is set by db_jobs.py to the active upstream table name
-- Default: fw_rules_subnet
-- NOTE: This file sets default parameter values only.
-- db_jobs.py intercepts this job and calls _run_quality_filter() directly,
-- which handles TRUNCATE + INSERT with a dynamically chosen source table.
