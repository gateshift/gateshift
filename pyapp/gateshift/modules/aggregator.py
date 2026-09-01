# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

import ipaddress
import os
from sqlalchemy import text


MIN_DENSITY = float(os.getenv("SUBNET_MIN_DENSITY", "0.10"))
MAX_PREFIX = int(os.getenv("SUBNET_MAX_PREFIX", "24"))
MIN_PREFIX = int(os.getenv("SUBNET_MIN_PREFIX", "28"))


def _candidate_subnet(hosts: list, min_prefix: int, max_prefix: int, min_density: float):
    if not hosts:
        return None

    for prefix in range(min_prefix, max_prefix - 1, -1):
        subnet = ipaddress.IPv4Network(f"{hosts[0]}/{prefix}", strict=False)
        capacity = subnet.num_addresses - 2
        density = len(hosts) / capacity
        all_in = all(h in subnet for h in hosts)
        if all_in and density >= min_density:
            return subnet

    return None


def _load_host_ips(conn, run_ts, since_ts):
    rows = conn.execute(text("""
        SELECT DISTINCT
            c.vendor,
            c.device_host,
            c.src_ip AS ip,
            c.src_prefix AS prefix,
            z.name AS zone_name,
            z.id AS zone_id
        FROM fw_rule_candidates c
        LEFT JOIN fw_rule_candidate_refs r ON r.candidate_id = c.id
        LEFT JOIN fw_zones z ON z.id = r.src_zone_id
        WHERE c.generated_at >= :run_ts
          AND c.src_ip IS NOT NULL
          AND c.src_prefix = 32
          AND (
              INET_ATON(INET6_NTOA(c.src_ip)) BETWEEN INET_ATON('10.0.0.0')    AND INET_ATON('10.255.255.255')
           OR INET_ATON(INET6_NTOA(c.src_ip)) BETWEEN INET_ATON('172.16.0.0')  AND INET_ATON('172.31.255.255')
           OR INET_ATON(INET6_NTOA(c.src_ip)) BETWEEN INET_ATON('192.168.0.0') AND INET_ATON('192.168.255.255')
          )

        UNION

        SELECT DISTINCT
            c.vendor,
            c.device_host,
            c.dst_ip AS ip,
            c.dst_prefix AS prefix,
            z.name AS zone_name,
            z.id AS zone_id
        FROM fw_rule_candidates c
        LEFT JOIN fw_rule_candidate_refs r ON r.candidate_id = c.id
        LEFT JOIN fw_zones z ON z.id = r.dst_zone_id
        WHERE c.generated_at >= :run_ts
          AND c.dst_ip IS NOT NULL
          AND c.dst_prefix = 32
          AND (
              INET_ATON(INET6_NTOA(c.dst_ip)) BETWEEN INET_ATON('10.0.0.0')    AND INET_ATON('10.255.255.255')
           OR INET_ATON(INET6_NTOA(c.dst_ip)) BETWEEN INET_ATON('172.16.0.0')  AND INET_ATON('172.31.255.255')
           OR INET_ATON(INET6_NTOA(c.dst_ip)) BETWEEN INET_ATON('192.168.0.0') AND INET_ATON('192.168.255.255')
          )
    """), {"run_ts": run_ts, "since_ts": since_ts}).fetchall()
    return rows


def _group_hosts(rows):
    groups = {}
    for row in rows:
        try:
            ip = ipaddress.ip_address(row.ip)
            if not isinstance(ip, ipaddress.IPv4Address):
                continue
        except Exception:
            continue

        key = (row.vendor, row.device_host, row.zone_name, row.zone_id)
        groups.setdefault(key, []).append(ip)
    return groups


def _ensure_subnet_object(conn, subnet, vendor, device_host, zone_name, db_name):
    conn.execute(text(f"USE `{db_name}`"))

    name = f"n_{subnet.network_address}-{subnet.prefixlen}"
    if zone_name:
        name = f"{name}_{zone_name}"

    network_packed = subnet.network_address.packed
    prefix = subnet.prefixlen

    conn.execute(text("""
        INSERT IGNORE INTO fw_objects (obj_type, name, ip, ip_prefix, vendor, device_host)
        VALUES ('network', :name, :ip, :prefix, :vendor, :device_host)
    """), {
        "name": name,
        "ip": network_packed,
        "prefix": prefix,
        "vendor": vendor,
        "device_host": device_host,
    })

    row = conn.execute(text("""
        SELECT id FROM fw_objects
        WHERE obj_type = 'network'
          AND ip = :ip
          AND ip_prefix = :prefix
          AND vendor <=> :vendor
          AND device_host <=> :device_host
        LIMIT 1
    """), {
        "ip": network_packed,
        "prefix": prefix,
        "vendor": vendor,
        "device_host": device_host,
    }).first()

    return row.id if row else None


def _replace_host_with_subnet(conn, subnet, subnet_obj_id, vendor, device_host, run_ts, db_name):
    conn.execute(text(f"USE `{db_name}`"))

    network_packed = subnet.network_address.packed
    broadcast_packed = subnet.broadcast_address.packed

    conn.execute(text("""
        UPDATE fw_rule_candidate_refs r
        JOIN fw_rule_candidates c ON c.id = r.candidate_id
        JOIN fw_objects o ON o.id = r.src_object_id
        SET r.src_object_id = :subnet_obj_id
        WHERE c.generated_at >= :run_ts
          AND c.vendor <=> :vendor
          AND c.device_host <=> :device_host
          AND o.obj_type = 'ip'
          AND o.ip_prefix = 32
          AND o.ip >= :network
          AND o.ip <= :broadcast
    """), {
        "subnet_obj_id": subnet_obj_id,
        "run_ts": run_ts,
        "vendor": vendor,
        "device_host": device_host,
        "network": network_packed,
        "broadcast": broadcast_packed,
    })

    conn.execute(text("""
        UPDATE fw_rule_candidate_refs r
        JOIN fw_rule_candidates c ON c.id = r.candidate_id
        JOIN fw_objects o ON o.id = r.dst_object_id
        SET r.dst_object_id = :subnet_obj_id
        WHERE c.generated_at >= :run_ts
          AND c.vendor <=> :vendor
          AND c.device_host <=> :device_host
          AND o.obj_type = 'ip'
          AND o.ip_prefix = 32
          AND o.ip >= :network
          AND o.ip <= :broadcast
    """), {
        "subnet_obj_id": subnet_obj_id,
        "run_ts": run_ts,
        "vendor": vendor,
        "device_host": device_host,
        "network": network_packed,
        "broadcast": broadcast_packed,
    })


def aggregate_subnets(engine, run_ts, since_ts, db_name="gateshift",
                      min_density=MIN_DENSITY,
                      max_prefix=MAX_PREFIX,
                      min_prefix=MIN_PREFIX):
    created = 0

    with engine.begin() as conn:
        conn.execute(text(f"USE `{db_name}`"))
        rows = _load_host_ips(conn, run_ts, since_ts)
        print(f"[aggregator] loaded {len(rows)} host IPs")
        groups = _group_hosts(rows)
        print(f"[aggregator] groups: {len(groups)}")

        for (vendor, device_host, zone_name, zone_id), hosts in groups.items():
            print(f"[aggregator] group vendor={vendor} device={device_host} zone={zone_name} hosts={len(hosts)}")
            blocks = {}
            for host in hosts:
                block = ipaddress.IPv4Network(f"{host}/{min_prefix}", strict=False)
                blocks.setdefault(block, []).append(host)

            for block, block_hosts in blocks.items():
                print(f"[aggregator]   block={block} hosts={len(block_hosts)}")
                subnet = _candidate_subnet(block_hosts, min_prefix, max_prefix, min_density)
                print(f"[aggregator]   subnet={subnet}")
                if subnet is None:
                    continue

                try:
                    subnet_obj_id = _ensure_subnet_object(
                        conn, subnet, vendor, device_host, zone_name, db_name
                    )
                    print(f"[aggregator]   subnet_obj_id={subnet_obj_id}")
                    if subnet_obj_id is None:
                        continue

                    _replace_host_with_subnet(
                        conn, subnet, subnet_obj_id, vendor, device_host, run_ts, db_name
                    )
                    created += 1
                except Exception as e:
                    print(f"[aggregator]   ERROR: {e}")

    return created