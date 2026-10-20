-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1
--
-- The NAT rule's identity hash, as ONE function in the database. The
-- Device's row id and eleven traffic-defining fields in a fixed order
-- (position, name, description, disabled, properties and the timestamps are
-- excluded: volatile or user-editable). The JSON arrays serialise through
-- JSON_EXTRACT at $, which depends on the source parsers' stable ordering.
-- Term 1 was the Device's name until phase 6 of docs/DEVICE_IDENTITY_PLAN.md.
--
-- Until phase 2 of docs/DEVICE_IDENTITY_PLAN.md this expression existed three
-- times, once in webui/main.py and once in each of sql/jobs/27 and 28, kept
-- equal by a comment, with the webapp's copy baked into one image and the
-- jobs' copies mounted from the checkout. Both halves of the product read it
-- from here now. The webapp's lifespan carries the same CREATE statement for
-- an upgraded installation whose init scripts never run again, and
-- tools/check_schema_parity.sh compares the routine so the two cannot drift.
--
-- A single statement on purpose: the collector's bootstrap splits init files
-- on ';' and a BEGIN ... END body would not survive it.
CREATE OR REPLACE FUNCTION gs_nat_hash(
    p_device_id     INT,
    p_nat_type      VARCHAR(16),
    p_interface     VARCHAR(64),
    p_src_zones     LONGTEXT,
    p_dst_zones     LONGTEXT,
    p_orig_src      LONGTEXT,
    p_orig_dst      LONGTEXT,
    p_orig_service  LONGTEXT,
    p_trans_src     VARCHAR(255),
    p_trans_src_type VARCHAR(32),
    p_trans_dst     VARCHAR(255),
    p_trans_dst_port VARCHAR(64)
) RETURNS BINARY(20)
DETERMINISTIC NO SQL SQL SECURITY INVOKER
RETURN UNHEX(SHA1(CONCAT_WS(0x1f,
    COALESCE(p_device_id, ''),
    p_nat_type,
    COALESCE(p_interface, ''),
    COALESCE(JSON_EXTRACT(p_src_zones,    '$'), ''),
    COALESCE(JSON_EXTRACT(p_dst_zones,    '$'), ''),
    COALESCE(JSON_EXTRACT(p_orig_src,     '$'), ''),
    COALESCE(JSON_EXTRACT(p_orig_dst,     '$'), ''),
    COALESCE(JSON_EXTRACT(p_orig_service, '$'), ''),
    COALESCE(p_trans_src, ''),
    p_trans_src_type,
    COALESCE(p_trans_dst, ''),
    COALESCE(p_trans_dst_port, '')
)));
