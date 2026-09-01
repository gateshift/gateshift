# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

import os
import re
import json
import hashlib
from datetime import datetime, timezone, timedelta
from collections import deque, defaultdict

from sqlalchemy import bindparam, create_engine, text

from modules.parsers.router import parse as route_parse


def rfc3339_to_naive_utc(ts: str):
    ts = (ts or "").replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return None
    if dt.tzinfo:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


_BSD_RE = re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.+)$')


def _bsd_ts_to_naive_utc(ts_str: str):
    year = datetime.now(timezone.utc).year
    normalized = re.sub(r'\s+', ' ', ts_str.strip())
    try:
        dt = datetime.strptime(f"{year} {normalized}", "%Y %b %d %H:%M:%S")
        # If parsed month is ahead of current month, it's likely from last year
        now = datetime.now(timezone.utc)
        if dt.month > now.month:
            dt = dt.replace(year=year - 1)
        return dt
    except ValueError:
        return None


def sha256(b: bytes):
    return hashlib.sha256(b).digest()


class NatCache:
    def __init__(self, max_per_key=200, window_seconds=10):
        self.max_per_key = max_per_key
        self.window_seconds = window_seconds
        self._by_key = defaultdict(deque)

    @staticmethod
    def _key_for_dnat(r):
        return (
            r.get("vendor"),
            r.get("device_host"),
            r.get("direction"),
            r.get("iface_in"),
            r.get("proto"),
            r.get("dst_port"),
        )

    def add_dnat(self, event_ts, r):
        k = self._key_for_dnat(r)
        dq = self._by_key[k]
        dq.appendleft(
            {
                "t": event_ts,
                "orig_dst_ip": r.get("dst_ip"),
                "orig_dst_port": r.get("dst_port"),
            }
        )
        while len(dq) > self.max_per_key:
            dq.pop()

    def pop_dnat(self, event_ts, r):
        k = self._key_for_dnat(r)
        dq = self._by_key.get(k)
        if not dq:
            return None
        if event_ts:
            cutoff = event_ts.timestamp() - self.window_seconds
            while dq and dq[-1]["t"] and dq[-1]["t"].timestamp() < cutoff:
                dq.pop()
        return dq.popleft() if dq else None


_nat_cache = NatCache(max_per_key=500, window_seconds=60)


def parse_syslog_line(line: str):
    line = (line or "").rstrip("\n")
    if not line:
        return None

    if line[0].isdigit():
        # RFC3339 format: "2026-02-15T16:46:36+00:00 HOST PROGRAM: PAYLOAD"
        a = line.split(" ", 2)
        if len(a) < 3:
            return None
        event_ts = rfc3339_to_naive_utc(a[0])
        host = a[1]
        rest = a[2]
    else:
        # BSD syslog format: "Apr  4 00:00:04 HOST PROGRAM[PID]: PAYLOAD"
        m = _BSD_RE.match(line)
        if not m:
            return None
        event_ts = _bsd_ts_to_naive_utc(m.group(1))
        host = m.group(2)
        rest = m.group(3)

    header, payload = (rest.split(": ", 1) + [""])[:2]
    header = (header or "").strip()

    parsed = route_parse(header, payload)
    if not parsed:
        return None

    raw_hash = sha256(line.encode("utf-8", "ignore"))

    parsed.update(
        {
            "event_ts": event_ts,
            "device_host": host,
            "facility": None,
            "severity": None,
            "raw_message": line,
            "raw_hash": raw_hash,
        }
    )

    # Ensure all INSERT columns exist - parsers may omit optional NGFW fields
    for _col in ("src_zone", "dst_zone", "application",
                 "security_profile", "security_profile_group", "url_category"):
        parsed.setdefault(_col, None)

    try:
        if parsed.get("vendor") == "opnsense" and parsed.get("program") == "filterlog":
            extra = parsed.get("extra") or {}
            pf_action = extra.get("pf_action")

            if pf_action == "rdr":
                _nat_cache.add_dnat(event_ts, parsed)
                return None  # rdr events are NAT setup records; relevant info
                              # is stored in the NatCache and applied to the pass event

            elif pf_action == "pass":
                m = _nat_cache.pop_dnat(event_ts, parsed)
                if m and m.get("orig_dst_ip") and parsed.get("dst_ip") and parsed["dst_ip"] != m["orig_dst_ip"]:
                    parsed["nat_dst_ip"] = parsed["dst_ip"]
                    parsed["nat_dst_port"] = parsed.get("dst_port")
                    parsed["dst_ip"] = m["orig_dst_ip"]
                    parsed["dst_port"] = m.get("orig_dst_port") or parsed.get("dst_port")

                    extra = parsed.get("extra") or {}
                    extra["nat_inferred"] = True
                    extra["nat_type"] = "dnat_pat"
                    parsed["extra"] = extra
    except Exception:
        pass

    parsed["extra"] = json.dumps(parsed.get("extra"), ensure_ascii=False)

    return parsed


INSERT_SQL = text(
    """
INSERT IGNORE INTO fw_flows
(event_ts, vendor, device_host, program, facility, severity, action, direction, iface_in, iface_out,
 proto, src_ip, src_port, dst_ip, dst_port, nat_src_ip, nat_src_port, nat_dst_ip, nat_dst_port,
 rule_hash, rule_id, rule_name, rule_text, raw_message, raw_hash, extra,
 src_zone, dst_zone, application, security_profile, security_profile_group, url_category)
VALUES
(:event_ts, :vendor, :device_host, :program, :facility, :severity, :action, :direction, :iface_in, :iface_out,
 :proto, :src_ip, :src_port, :dst_ip, :dst_port, :nat_src_ip, :nat_src_port, :nat_dst_ip, :nat_dst_port,
 :rule_hash, :rule_id, :rule_name, :rule_text, :raw_message, :raw_hash, :extra,
 :src_zone, :dst_zone, :application, :security_profile, :security_profile_group, :url_category)
"""
)


_UPSERT_AGGREGATE_SQL = text("""
    INSERT INTO fw_rule_aggregates (
        vendor, device_host, action, direction, iface_in, iface_out,
        proto, src_ip, dst_ip, effective_port, rule_hash,
        negate_source, negate_destination, negate_service,
        src_zone, dst_zone, nat_src_ip, nat_dst_ip, application,
        rule_name, security_profile, security_profile_group,
        url_category, schedule, seq_num, first_seen, last_seen,
        sample_raw_id, hit_count_total, hit_count_quality_passed,
        seen_syslog, seen_api_import
    )
    SELECT
        COALESCE(vendor, ''),
        COALESCE(device_host, ''),
        COALESCE(action, 'unknown'),
        COALESCE(direction, 'unknown'),
        COALESCE(iface_in, ''),
        COALESCE(iface_out, ''),
        COALESCE(proto, ''),
        COALESCE(src_ip, _binary X'00000000000000000000000000000000'),
        COALESCE(dst_ip, _binary X'00000000000000000000000000000000'),
        COALESCE(COALESCE(nat_dst_port, dst_port), 0),
        COALESCE(rule_hash, _binary X'0000000000000000000000000000000000000000000000000000000000000000'),
        COALESCE(negate_source, 0),
        COALESCE(negate_destination, 0),
        COALESCE(negate_service, 0),

        src_zone, dst_zone,
        nat_src_ip, nat_dst_ip,
        application, rule_name,
        security_profile, security_profile_group,
        url_category, schedule,
        seq_num,
        event_ts, event_ts, id,
        1,
        CASE
            WHEN source_type = 'api_import' THEN 1
            WHEN source_type = 'syslog'
                 AND event_ts IS NOT NULL
                 AND action <> 'unknown'
                 AND direction <> 'out'
                 AND proto IS NOT NULL
                 AND src_ip IS NOT NULL
                 AND dst_ip IS NOT NULL
                 AND dst_port IS NOT NULL
              THEN 1
            ELSE 0
        END,
        CASE WHEN source_type = 'syslog'     THEN 1 ELSE 0 END,
        CASE WHEN source_type = 'api_import' THEN 1 ELSE 0 END
    FROM fw_flows
    WHERE raw_hash IN :hashes
    ON DUPLICATE KEY UPDATE
        -- MIN-semantic with NULL-skip: keep existing when new is NULL,
        -- swap to new when existing is NULL, else LEAST(). Bare column
        -- refs would be ambiguous (same name exists in fw_flows source),
        -- so target columns are qualified `fw_rule_aggregates.col`.
        src_zone               = CASE
            WHEN fw_rule_aggregates.src_zone IS NULL THEN VALUES(src_zone)
            WHEN VALUES(src_zone) IS NULL THEN fw_rule_aggregates.src_zone
            ELSE LEAST(fw_rule_aggregates.src_zone, VALUES(src_zone)) END,
        dst_zone               = CASE
            WHEN fw_rule_aggregates.dst_zone IS NULL THEN VALUES(dst_zone)
            WHEN VALUES(dst_zone) IS NULL THEN fw_rule_aggregates.dst_zone
            ELSE LEAST(fw_rule_aggregates.dst_zone, VALUES(dst_zone)) END,
        nat_src_ip             = CASE
            WHEN fw_rule_aggregates.nat_src_ip IS NULL THEN VALUES(nat_src_ip)
            WHEN VALUES(nat_src_ip) IS NULL THEN fw_rule_aggregates.nat_src_ip
            ELSE LEAST(fw_rule_aggregates.nat_src_ip, VALUES(nat_src_ip)) END,
        nat_dst_ip             = CASE
            WHEN fw_rule_aggregates.nat_dst_ip IS NULL THEN VALUES(nat_dst_ip)
            WHEN VALUES(nat_dst_ip) IS NULL THEN fw_rule_aggregates.nat_dst_ip
            ELSE LEAST(fw_rule_aggregates.nat_dst_ip, VALUES(nat_dst_ip)) END,
        application            = CASE
            WHEN fw_rule_aggregates.application IS NULL THEN VALUES(application)
            WHEN VALUES(application) IS NULL THEN fw_rule_aggregates.application
            ELSE LEAST(fw_rule_aggregates.application, VALUES(application)) END,
        rule_name              = CASE
            WHEN fw_rule_aggregates.rule_name IS NULL THEN VALUES(rule_name)
            WHEN VALUES(rule_name) IS NULL THEN fw_rule_aggregates.rule_name
            ELSE LEAST(fw_rule_aggregates.rule_name, VALUES(rule_name)) END,
        security_profile       = CASE
            WHEN fw_rule_aggregates.security_profile IS NULL THEN VALUES(security_profile)
            WHEN VALUES(security_profile) IS NULL THEN fw_rule_aggregates.security_profile
            ELSE LEAST(fw_rule_aggregates.security_profile, VALUES(security_profile)) END,
        security_profile_group = CASE
            WHEN fw_rule_aggregates.security_profile_group IS NULL THEN VALUES(security_profile_group)
            WHEN VALUES(security_profile_group) IS NULL THEN fw_rule_aggregates.security_profile_group
            ELSE LEAST(fw_rule_aggregates.security_profile_group, VALUES(security_profile_group)) END,
        url_category           = CASE
            WHEN fw_rule_aggregates.url_category IS NULL THEN VALUES(url_category)
            WHEN VALUES(url_category) IS NULL THEN fw_rule_aggregates.url_category
            ELSE LEAST(fw_rule_aggregates.url_category, VALUES(url_category)) END,
        schedule               = CASE
            WHEN fw_rule_aggregates.schedule IS NULL THEN VALUES(schedule)
            WHEN VALUES(schedule) IS NULL THEN fw_rule_aggregates.schedule
            ELSE LEAST(fw_rule_aggregates.schedule, VALUES(schedule)) END,
        seq_num                = CASE
            WHEN fw_rule_aggregates.seq_num IS NULL THEN VALUES(seq_num)
            WHEN VALUES(seq_num) IS NULL THEN fw_rule_aggregates.seq_num
            ELSE LEAST(fw_rule_aggregates.seq_num, VALUES(seq_num)) END,
        first_seen             = LEAST(fw_rule_aggregates.first_seen, VALUES(first_seen)),
        last_seen              = GREATEST(fw_rule_aggregates.last_seen, VALUES(last_seen)),
        sample_raw_id          = LEAST(fw_rule_aggregates.sample_raw_id, VALUES(sample_raw_id)),
        hit_count_total          = fw_rule_aggregates.hit_count_total + 1,
        hit_count_quality_passed = fw_rule_aggregates.hit_count_quality_passed + VALUES(hit_count_quality_passed),
        seen_syslog              = GREATEST(fw_rule_aggregates.seen_syslog, VALUES(seen_syslog)),
        seen_api_import          = GREATEST(fw_rule_aggregates.seen_api_import, VALUES(seen_api_import))
""")


def _upsert_rule_aggregates_for_hashes(conn, raw_hashes):
    """Incremental write-through into fw_rule_aggregates for a batch of
    just-inserted fw_flows raw_hashes. Reads canonical rows back from
    fw_flows so INSERT IGNORE deduping by raw_hash is honoured - each row
    in fw_flows fires exactly one ON DUPLICATE KEY UPDATE that increments
    hit_count_total by 1.

    Plan: project_rule_aggregate_persistence_active_plan (Phase 2 step 2).
    """
    if not raw_hashes:
        return
    # SQLAlchemy `expanding=True` for IN-clause; bind via .bindparams later.
    conn.execute(
        _UPSERT_AGGREGATE_SQL.bindparams(
            bindparam("hashes", expanding=True)
        ),
        {"hashes": list(raw_hashes)},
    )


# fw_nat_evidence write-through (project_nat_evidence_aggregate_active_plan P1).
# Same exactly-once mechanics as _UPSERT_AGGREGATE_SQL, but with the
# NAT-faithful key: zones IN the key (no flatten) and the original + translated
# dst_port kept SEPARATE (no effective_port collapse → port-forwarding
# survives). The private/public IP class is precomputed here via a binary
# BETWEEN on the 4-byte IPv4 form (LENGTH=4 guard); IPv6 / all-zero-sentinel
# rows are non-private, matching the old 27_infer_nat_rules INET_ATON-NULL
# behavior. The range list + sentinel are mirrored in webui/main.py
# (_nat_ev_is_private / _NAT_EV_SENTINEL) - keep in sync.
_NAT_EV_SK = "_binary X'00000000000000000000000000000000'"


def _nat_ev_priv(col: str) -> str:
    return (
        f"(LENGTH({col}) = 4 AND ("
        f"{col} BETWEEN INET6_ATON('10.0.0.0')      AND INET6_ATON('10.255.255.255') OR "
        f"{col} BETWEEN INET6_ATON('172.16.0.0')    AND INET6_ATON('172.31.255.255') OR "
        f"{col} BETWEEN INET6_ATON('192.168.0.0')   AND INET6_ATON('192.168.255.255') OR "
        f"{col} BETWEEN INET6_ATON('100.64.0.0')    AND INET6_ATON('100.127.255.255')))"
    )


_UPSERT_NAT_EVIDENCE_SQL = text(f"""
    INSERT INTO fw_nat_evidence (
        device_host, direction, src_zone, dst_zone, proto,
        src_ip, dst_ip, dst_port, nat_src_ip, nat_dst_ip, nat_dst_port,
        src_is_private, dst_is_private, hit_count, first_seen, last_seen
    )
    SELECT
        COALESCE(device_host, ''),
        COALESCE(direction, 'unknown'),
        COALESCE(src_zone, ''),
        COALESCE(dst_zone, ''),
        COALESCE(proto, ''),
        COALESCE(src_ip, {_NAT_EV_SK}),
        COALESCE(dst_ip, {_NAT_EV_SK}),
        COALESCE(dst_port, 0),
        COALESCE(nat_src_ip, {_NAT_EV_SK}),
        COALESCE(nat_dst_ip, {_NAT_EV_SK}),
        COALESCE(nat_dst_port, 0),
        {_nat_ev_priv(f"COALESCE(src_ip, {_NAT_EV_SK})")},
        {_nat_ev_priv(f"COALESCE(dst_ip, {_NAT_EV_SK})")},
        1, event_ts, event_ts
    FROM fw_flows
    WHERE raw_hash IN :hashes
    ON DUPLICATE KEY UPDATE
        hit_count  = fw_nat_evidence.hit_count + 1,
        first_seen = LEAST(fw_nat_evidence.first_seen, VALUES(first_seen)),
        last_seen  = GREATEST(fw_nat_evidence.last_seen, VALUES(last_seen))
""")


def _upsert_nat_evidence_for_hashes(conn, raw_hashes):
    """Incremental write-through into fw_nat_evidence for a batch of
    just-inserted fw_flows raw_hashes - same exactly-once-per-row mechanics as
    _upsert_rule_aggregates_for_hashes.

    Plan: project_nat_evidence_aggregate_active_plan (P1).
    """
    if not raw_hashes:
        return
    conn.execute(
        _UPSERT_NAT_EVIDENCE_SQL.bindparams(
            bindparam("hashes", expanding=True)
        ),
        {"hashes": list(raw_hashes)},
    )


def make_engines(db_name: str):
    host = os.getenv("DB_HOST", "mariadb")
    port = os.getenv("DB_PORT", "3306")
    # Prefer the unprivileged application account; fall back to root for
    # installations that predate the dedicated user.
    user = os.getenv("DB_USER") or "root"
    pw = ((os.getenv("DB_PASSWORD") or "") if os.getenv("DB_USER")
          else (os.getenv("MARIADB_ROOT_PASSWORD") or ""))

    engine0 = create_engine(
        f"mysql+pymysql://{user}:{pw}@{host}:{port}/?charset=utf8mb4",
        pool_pre_ping=True,
    )

    engine = create_engine(
        f"mysql+pymysql://{user}:{pw}@{host}:{port}/{db_name}?charset=utf8mb4",
        pool_pre_ping=True,
    )

    return engine0, engine


def ensure_db(engine0, db_name: str):
    with engine0.begin() as conn:
        conn.execute(
            text(
                f"CREATE DATABASE IF NOT EXISTS `{db_name}` "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
        )


def ensure_table(engine):
    ddl = """
CREATE TABLE IF NOT EXISTS fw_flows (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  received_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  event_ts DATETIME NULL,
  vendor VARCHAR(64) NULL,
  device_host VARCHAR(255) NULL,
  program VARCHAR(128) NULL,
  facility TINYINT UNSIGNED NULL,
  severity TINYINT UNSIGNED NULL,
  action ENUM('allow','deny','drop','reject','unknown') NOT NULL DEFAULT 'unknown',
  direction ENUM('in','out','forward','unknown') NOT NULL DEFAULT 'unknown',
  iface_in VARCHAR(64) NULL,
  iface_out VARCHAR(64) NULL,
  proto VARCHAR(16) NULL,
  src_ip VARBINARY(16) NULL,
  src_port SMALLINT UNSIGNED NULL,
  dst_ip VARBINARY(16) NULL,
  dst_port SMALLINT UNSIGNED NULL,
  nat_src_ip VARBINARY(16) NULL,
  nat_src_port SMALLINT UNSIGNED NULL,
  nat_dst_ip VARBINARY(16) NULL,
  nat_dst_port SMALLINT UNSIGNED NULL,
  rule_hash BINARY(32) NULL,
  rule_id VARCHAR(128) NULL,
  rule_name VARCHAR(255) NULL,
  rule_text TEXT NULL,
  raw_message TEXT NOT NULL,
  raw_hash BINARY(32) NOT NULL,
  extra JSON NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_raw_hash (raw_hash),
  KEY idx_time (event_ts, received_at),
  KEY idx_device_time (device_host, event_ts),
  KEY idx_5tuple (proto, src_ip, src_port, dst_ip, dst_port),
  KEY idx_action_time (action, event_ts),
  KEY idx_rule (rule_hash, event_ts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_unicode_ci;
"""
    with engine.begin() as conn:
        conn.execute(text(ddl))


def discover_devices_from_logs(files):
    """Scan log files and return unique {device_host: vendor} pairs.

    Only parses enough lines per host to identify the vendor, then skips
    remaining lines for that host - very fast even on large log volumes.
    """
    seen = {}  # host -> vendor

    for path in files:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue

                # Extract host from syslog header (cheap, no full parse)
                if line[0].isdigit():
                    a = line.split(" ", 2)
                    if len(a) < 3:
                        continue
                    host = a[1]
                    rest = a[2]
                else:
                    m = _BSD_RE.match(line)
                    if not m:
                        continue
                    host = m.group(2)
                    rest = m.group(3)

                if host in seen:
                    continue

                # Parse payload to detect vendor
                header, payload = (rest.split(": ", 1) + [""])[:2]
                parsed = route_parse(header.strip(), payload)
                if parsed and parsed.get("vendor"):
                    seen[host] = parsed["vendor"]

    return seen


def ingest_logfiles(engine, files, batch_size: int = 2000, since_dt=None, until_dt=None, days_back: int = None,
                    device_filter: str = None):
    debug = os.getenv("DEBUG", "0") == "1"

    if since_dt is None and days_back is not None:
        since_dt = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days_back)

    total_lines = 0
    parsed_ok = 0
    parsed_none = 0
    inserted_attempt = 0
    nat_marked = 0

    batch = []

    def flush(conn):
        nonlocal inserted_attempt, batch
        if not batch:
            return
        conn.execute(INSERT_SQL, batch)
        inserted_attempt += len(batch)
        # Phase-2b write-through for rule-aggregate-persistence: incremental
        # upsert from the just-inserted batch into fw_rule_aggregates. Reads
        # back from fw_flows by raw_hash so INSERT IGNORE skips (duplicate
        # raw_hash from re-ingested logs) don't over-count. Each per-row
        # SELECT triggers either a fresh INSERT or an ON DUPLICATE KEY UPDATE
        # that increments hit_count_total += 1 - exactly-once per fw_flows
        # row.
        hashes = [r["raw_hash"] for r in batch if r.get("raw_hash") is not None]
        if hashes:
            _upsert_rule_aggregates_for_hashes(conn, hashes)
            _upsert_nat_evidence_for_hashes(conn, hashes)
        batch = []

    if debug:
        print(f"files={len(files)}")
        if files:
            print(f"first_file={files[0]}")

    total_files = len(files)
    print(f"[ingest] total {total_files}", flush=True)

    for file_idx, path in enumerate(files, 1):
        print(f"[ingest] file {file_idx}/{total_files} {os.path.basename(path)}", flush=True)
        if debug:
            print(f"reading={path}")
        with engine.begin() as conn:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    total_lines += 1
                    row = parse_syslog_line(line)
                    if not row:
                        parsed_none += 1
                        continue
                    ts = row.get("event_ts")
                    if since_dt and ts and ts < since_dt:
                        parsed_none += 1
                        continue
                    if until_dt and ts and ts > until_dt:
                        parsed_none += 1
                        continue
                    if device_filter and row.get("device_host") != device_filter:
                        parsed_none += 1
                        continue
                    parsed_ok += 1
                    if debug:
                        try:
                            if json.loads(row.get("extra") or "{}").get("nat_inferred"):
                                nat_marked += 1
                        except Exception:
                            pass
                    batch.append(row)
                    if len(batch) >= batch_size:
                        flush(conn)
            flush(conn)

    if debug:
        print(
            f"lines={total_lines} parsed_ok={parsed_ok} parsed_none={parsed_none} inserted_attempt={inserted_attempt} nat_marked={nat_marked}"
        )

    return inserted_attempt