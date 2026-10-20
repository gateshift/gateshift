-- Copyright (c) 2026 Timo Duttine
-- SPDX-License-Identifier: BUSL-1.1
--
-- "Is this address private" as ONE function in the database, the way the
-- two identity hashes are (47_fn_nat_hash.sql, 48_fn_rule_hash.sql). Phase 1
-- of docs/IPV6_PLAN.md: the test existed in three independent copies in the
-- webapp and the collector and inline in three jobs, with two different
-- range lists (the internet_public detection knew loopback and link-local,
-- the NAT evidence knew the CGNAT range). This is their union, the IPv4
-- addresses that are never routed on the internet. The parameter is the
-- packed address (INET6_ATON of a text column, or a VARBINARY(16) column
-- as stored): NULL stays NULL, so NOT gs_ip_is_private(INET6_ATON(x)) is
-- false for a value that is no address (a CIDR string, a name, the
-- pipeline's catch-all text), the way the INET_ATON test it replaced was. The IPv6
-- half (phase 2) is the set that is never globally reachable: unique
-- local, link-local, the unspecified and loopback addresses, the
-- documentation prefix and the v4-mapped block.
--
-- The webapp's lifespan carries the same CREATE statement for an upgraded
-- installation whose init scripts never run again; a host test and
-- tools/check_schema_parity.sh keep the two equal. A single statement on
-- purpose: the collector's bootstrap splits init files on ';'.
CREATE OR REPLACE FUNCTION gs_ip_is_private(
    p_ip VARBINARY(16)
) RETURNS TINYINT(1)
DETERMINISTIC NO SQL SQL SECURITY INVOKER
RETURN CASE WHEN p_ip IS NULL THEN NULL ELSE (
    (LENGTH(p_ip) = 4 AND (
       p_ip BETWEEN INET6_ATON('10.0.0.0')    AND INET6_ATON('10.255.255.255')
    OR p_ip BETWEEN INET6_ATON('172.16.0.0')  AND INET6_ATON('172.31.255.255')
    OR p_ip BETWEEN INET6_ATON('192.168.0.0') AND INET6_ATON('192.168.255.255')
    OR p_ip BETWEEN INET6_ATON('100.64.0.0')  AND INET6_ATON('100.127.255.255')
    OR p_ip BETWEEN INET6_ATON('127.0.0.0')   AND INET6_ATON('127.255.255.255')
    OR p_ip BETWEEN INET6_ATON('169.254.0.0') AND INET6_ATON('169.254.255.255')
    )) OR (LENGTH(p_ip) = 16 AND (
       p_ip BETWEEN INET6_ATON('fc00::')      AND INET6_ATON('fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
    OR p_ip BETWEEN INET6_ATON('fe80::')      AND INET6_ATON('febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
    OR p_ip BETWEEN INET6_ATON('2001:db8::')  AND INET6_ATON('2001:db8:ffff:ffff:ffff:ffff:ffff:ffff')
    OR p_ip BETWEEN INET6_ATON('::')          AND INET6_ATON('::1')
    OR p_ip BETWEEN INET6_ATON('::ffff:0:0')  AND INET6_ATON('::ffff:ffff:ffff')
    ))
) END;
