-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1
--
-- The rule's identity hash (content_hash on the four rule stage tables), as
-- ONE function in the database, the way gs_nat_hash is (47_fn_nat_hash.sql).
-- Phase 6 of docs/DEVICE_IDENTITY_PLAN.md: the Device's row id is term 1,
-- where the Device's name used to be, so a rename moves no override and two
-- Devices with one name hash apart. The route-derived zone stays excluded
-- (a network edit must not orphan the overrides), and config (api_import)
-- rules carry their rule name so object-based rules with NULL IPs stay
-- distinct; syslog rules have no stable name and rely on the signature.
--
-- The source and destination signatures are parameters because the
-- collector composes them per stage (modules/db_jobs.py: the inline pair
-- for fw_rules_consolidated_1, GROUP_CONCAT over the sub-tables for
-- accumulated, subnet and filtered). The webapp's lifespan carries the same
-- CREATE statement for an upgraded installation whose init scripts never run
-- again; a host test and tools/check_schema_parity.sh keep the two equal.
--
-- CONCAT_WS skips a NULL argument: action and direction are passed raw, the
-- rest wrapped, exactly as the expression this replaces did.
--
-- A single statement on purpose: the collector's bootstrap splits init files
-- on ';' and a BEGIN ... END body would not survive it.
CREATE OR REPLACE FUNCTION gs_rule_hash(
    p_device_id   INT,
    p_action      VARCHAR(32),
    p_direction   VARCHAR(32),
    p_proto       VARCHAR(32),
    p_dst_port    INT,
    p_src_sig     LONGTEXT,
    p_dst_sig     LONGTEXT,
    p_source_type VARCHAR(16),
    p_rule_name   VARCHAR(255)
) RETURNS BINARY(20)
DETERMINISTIC NO SQL SQL SECURITY INVOKER
RETURN UNHEX(SHA1(CONCAT_WS(0x1f,
    COALESCE(p_device_id, ''),
    p_action,
    p_direction,
    COALESCE(p_proto, ''),
    COALESCE(p_dst_port, 0),
    COALESCE(p_src_sig, ''),
    COALESCE(p_dst_sig, ''),
    CASE WHEN p_source_type = 'api_import' THEN COALESCE(p_rule_name, '') ELSE '' END
)));
