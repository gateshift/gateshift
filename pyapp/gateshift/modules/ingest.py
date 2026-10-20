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
# The envelope (timestamp, host, tag, payload) lives in a database-free module
# so it can be tested on the host; the old names stay importable from here.
from modules.parsers.syslog import (BSD_RE as _BSD_RE, rfc3339_to_naive_utc,
                                    bsd_ts_to_naive_utc as _bsd_ts_to_naive_utc,
                                    split_line)
# The sender identity (header host, source address, vendor serial) and the
# flow hash over sender plus line (docs/DEVICE_IDENTITY_PLAN.md, phase 4).
from modules.parsers.sender import (raw_hash as _sender_raw_hash, sender_key,
                                    source_addr_from_path, vendor_serial)


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
            r.get("sender_key"),
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


def parse_syslog_line(line: str, source_addr: str = ""):
    """One line into a flow row. `source_addr` is the address the receiver
    wrote into the file name ('' for a file that carries none). The row
    carries its sender key (header host, source address, vendor serial) and
    a raw_hash over sender plus line, so the same line from two senders is
    two flows and the same line twice from one sender is one."""
    line = (line or "").rstrip("\n")
    env = split_line(line)
    if not env:
        return None
    event_ts, host, header, payload = env

    parsed = route_parse(header, payload)
    if not parsed:
        return None

    key = sender_key(host, source_addr, vendor_serial(parsed))

    parsed.update(
        {
            "event_ts": event_ts,
            "sender_key": key,
            "facility": None,
            "severity": None,
            "raw_message": line,
            "raw_hash": _sender_raw_hash(key, line),
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


# A plain INSERT (decision D8): the rows that are new are decided BEFORE the
# write (flush below), so a failed row is an error that stops the run with
# its message, not a gap under a "0 errors" line. The old INSERT IGNORE
# dropped every failed row without a word, not only a duplicate.
INSERT_SQL = text(
    """
INSERT INTO fw_flows
(event_ts, vendor, sender_id, program, facility, severity, action, direction, iface_in, iface_out,
 proto, src_ip, src_port, dst_ip, dst_port, nat_src_ip, nat_src_port, nat_dst_ip, nat_dst_port,
 rule_hash, rule_id, rule_name, rule_text, raw_message, raw_hash, extra,
 src_zone, dst_zone, application, security_profile, security_profile_group, url_category)
VALUES
(:event_ts, :vendor, :sender_id, :program, :facility, :severity, :action, :direction, :iface_in, :iface_out,
 :proto, :src_ip, :src_port, :dst_ip, :dst_port, :nat_src_ip, :nat_src_port, :nat_dst_ip, :nat_dst_port,
 :rule_hash, :rule_id, :rule_name, :rule_text, :raw_message, :raw_hash, :extra,
 :src_zone, :dst_zone, :application, :security_profile, :security_profile_group, :url_category)
"""
)


class SenderResolver:
    """The sender rows of one run, resolved once per sender key and cached
    for the run (the collector is not long-running, so a run-local cache is
    correct by construction). Creates and counts SENDER rows; it never
    creates a Device. What a sender maps to (the Device, its platform, its
    name in the pipeline) is read back from the mapping the operator made.

    Rows of a sender that maps to no Device land in fw_flows and nowhere
    else: the aggregates are written only for mapped senders, and the
    webapp's bounded rebuild pulls the stored evidence in when the operator
    maps the sender."""

    _UPSERT = text("""
        INSERT INTO fw_log_senders
            (source_type, header_host, source_addr, vendor_serial, vendor, first_seen, last_seen)
        VALUES ('syslog', :host, :addr, :serial, :vendor, :ts, :ts)
        ON DUPLICATE KEY UPDATE
            vendor     = IF(VALUES(vendor) = '', vendor, VALUES(vendor)),
            first_seen = LEAST(COALESCE(first_seen, VALUES(first_seen)), VALUES(first_seen)),
            last_seen  = GREATEST(COALESCE(last_seen, VALUES(last_seen)), VALUES(last_seen))
    """)
    _READ = text("""
        SELECT s.id, s.device_id, d.platform, COALESCE(d.display_name, d.host_name)
        FROM fw_log_senders s LEFT JOIN fw_devices d ON d.id = s.device_id
        WHERE s.source_type = 'syslog' AND s.header_host = :host
          AND s.source_addr = :addr AND s.vendor_serial = :serial
    """)

    def __init__(self):
        self._cache: dict = {}
        self._lines: dict = defaultdict(int)

    def resolve(self, conn, key, vendor: str, event_ts) -> dict:
        hit = self._cache.get(key)
        if hit is not None:
            return hit
        host, addr, serial = key
        params = {"host": host, "addr": addr, "serial": serial,
                  "vendor": vendor or "", "ts": event_ts}
        conn.execute(self._UPSERT, params)
        row = conn.execute(self._READ, params).fetchone()
        if row is None:
            raise RuntimeError(f"sender row for {key!r} was not written")
        hit = {"id": int(row[0]), "device_id": row[1], "platform": row[2], "name": row[3]}
        self._cache[key] = hit
        return hit

    def count(self, key, n: int = 1) -> None:
        self._lines[key] += n

    def write_counts(self, conn) -> None:
        """line_count = the lines this run saw for the sender in the files it
        read: what the operator sees next to a sender, refreshed by every
        scan and every ingest of the spool."""
        for key, n in self._lines.items():
            hit = self._cache.get(key)
            if hit is None:
                continue
            conn.execute(text("UPDATE fw_log_senders SET line_count = :n WHERE id = :id"),
                         {"n": n, "id": hit["id"]})

    def mapped(self) -> int:
        return sum(1 for h in self._cache.values() if h["device_id"])

    def unmapped(self) -> int:
        return sum(1 for h in self._cache.values() if not h["device_id"])


# The write-through reads the flow rows back THROUGH their sender's mapping:
# only a mapped sender's rows reach the aggregates, and they land under the
# Device (its platform as the vendor, its row id in device_id), never under
# the sender string. The name column left the tables in phase 7 of
# docs/DEVICE_IDENTITY_PLAN.md.
_FLOW_SOURCE = """
    FROM fw_flows f
    JOIN fw_log_senders s ON s.id = f.sender_id
    JOIN fw_devices d ON d.id = s.device_id
    WHERE f.raw_hash IN :hashes
"""

_UPSERT_AGGREGATE_SQL = text(f"""
    INSERT INTO fw_rule_aggregates (
        vendor, device_id, action, direction, iface_in, iface_out,
        proto, src_ip, dst_ip, effective_port, rule_hash,
        negate_source, negate_destination, negate_service,
        src_zone, dst_zone, nat_src_ip, nat_dst_ip, application,
        rule_name, security_profile, security_profile_group,
        url_category, schedule, seq_num, first_seen, last_seen,
        sample_raw_id, hit_count_total, hit_count_quality_passed,
        seen_syslog, seen_api_import
    )
    SELECT
        COALESCE(d.platform, ''),
        d.id,
        COALESCE(f.action, 'unknown'),
        COALESCE(f.direction, 'unknown'),
        COALESCE(f.iface_in, ''),
        COALESCE(f.iface_out, ''),
        COALESCE(f.proto, ''),
        COALESCE(f.src_ip, _binary X'00000000000000000000000000000000'),
        COALESCE(f.dst_ip, _binary X'00000000000000000000000000000000'),
        COALESCE(COALESCE(f.nat_dst_port, f.dst_port), 0),
        COALESCE(f.rule_hash, _binary X'0000000000000000000000000000000000000000000000000000000000000000'),
        COALESCE(f.negate_source, 0),
        COALESCE(f.negate_destination, 0),
        COALESCE(f.negate_service, 0),

        f.src_zone, f.dst_zone,
        f.nat_src_ip, f.nat_dst_ip,
        f.application, f.rule_name,
        f.security_profile, f.security_profile_group,
        f.url_category, f.schedule,
        f.seq_num,
        f.event_ts, f.event_ts, f.id,
        1,
        CASE
            WHEN f.source_type = 'api_import' THEN 1
            WHEN f.source_type = 'syslog'
                 AND f.event_ts IS NOT NULL
                 AND f.action <> 'unknown'
                 AND f.direction <> 'out'
                 AND f.proto IS NOT NULL
                 AND f.src_ip IS NOT NULL
                 AND f.dst_ip IS NOT NULL
                 AND f.dst_port IS NOT NULL
              THEN 1
            ELSE 0
        END,
        CASE WHEN f.source_type = 'syslog'     THEN 1 ELSE 0 END,
        CASE WHEN f.source_type = 'api_import' THEN 1 ELSE 0 END
    {_FLOW_SOURCE}
    ON DUPLICATE KEY UPDATE
        -- MIN-semantic with NULL-skip: keep existing when new is NULL,
        -- swap to new when existing is NULL, else LEAST(). Target columns
        -- are qualified `fw_rule_aggregates.col`.
        device_id              = VALUES(device_id),
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
    just-inserted fw_flows raw_hashes (the NEW ones only, the caller decides
    that before the write). Each stored row fires exactly one ON DUPLICATE
    KEY UPDATE that increments hit_count_total by 1. Rows of an unmapped
    sender are not reached (the join), they wait in fw_flows.

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
    """The one private-range test, gs_ip_is_private (sql/init/49_fn_ip_private.sql,
    mirrored by the webapp's lifespan): the ranges live in the database."""
    return f"gs_ip_is_private({col})"


_UPSERT_NAT_EVIDENCE_SQL = text(f"""
    INSERT INTO fw_nat_evidence (
        device_id, direction, src_zone, dst_zone, proto,
        src_ip, dst_ip, dst_port, nat_src_ip, nat_dst_ip, nat_dst_port,
        src_is_private, dst_is_private, hit_count, first_seen, last_seen
    )
    SELECT
        d.id,
        COALESCE(f.direction, 'unknown'),
        COALESCE(f.src_zone, ''),
        COALESCE(f.dst_zone, ''),
        COALESCE(f.proto, ''),
        COALESCE(f.src_ip, {_NAT_EV_SK}),
        COALESCE(f.dst_ip, {_NAT_EV_SK}),
        COALESCE(f.dst_port, 0),
        COALESCE(f.nat_src_ip, {_NAT_EV_SK}),
        COALESCE(f.nat_dst_ip, {_NAT_EV_SK}),
        COALESCE(f.nat_dst_port, 0),
        {_nat_ev_priv(f"COALESCE(f.src_ip, {_NAT_EV_SK})")},
        {_nat_ev_priv(f"COALESCE(f.dst_ip, {_NAT_EV_SK})")},
        1, f.event_ts, f.event_ts
    {_FLOW_SOURCE}
    ON DUPLICATE KEY UPDATE
        device_id  = VALUES(device_id),
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


def scan_senders(engine, files) -> list:
    """Read the spool and refresh the sender rows: every (header host,
    source address, serial) the receiver has heard, with its vendor, first
    and last timestamp and line count. Writes no flow row and no Device:
    this is what fills the candidate list the operator maps from. Returns
    the senders seen, for the run log."""
    seen: dict = {}
    for path in files:
        addr = source_addr_from_path(path)
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                env = split_line(line)
                if not env:
                    continue
                ts, host, header, payload = env
                parsed = route_parse(header, payload)
                if not parsed:
                    continue
                key = sender_key(host, addr, vendor_serial(parsed))
                rec = seen.get(key)
                if rec is None:
                    rec = seen[key] = {"vendor": parsed.get("vendor") or "", "n": 0,
                                       "first": ts, "last": ts}
                rec["n"] += 1
                if ts is not None:
                    rec["first"] = ts if rec["first"] is None else min(rec["first"], ts)
                    rec["last"] = ts if rec["last"] is None else max(rec["last"], ts)
    out = []
    resolver = SenderResolver()
    with engine.begin() as conn:
        for key, rec in seen.items():
            hit = resolver.resolve(conn, key, rec["vendor"], rec["last"])
            if rec["first"] is not None:
                conn.execute(text(
                    "UPDATE fw_log_senders SET first_seen = LEAST(COALESCE(first_seen, :t), :t) "
                    "WHERE id = :id"), {"t": rec["first"], "id": hit["id"]})
            resolver.count(key, rec["n"])
            out.append({"id": hit["id"], "header_host": key[0], "source_addr": key[1],
                        "vendor_serial": key[2], "vendor": rec["vendor"], "lines": rec["n"],
                        "device_id": hit["device_id"]})
        resolver.write_counts(conn)
    print(f"[scan] senders={len(out)} mapped={resolver.mapped()} "
          f"unattributed={resolver.unmapped()}", flush=True)
    return out


def ingest_logfiles(engine, files, batch_size: int = 2000, since_dt=None, until_dt=None, days_back: int = None,
                    device_filter: int = None):
    """Read the spool into fw_flows. `device_filter` keeps the rows of the
    senders mapped to that Device (its row id); a sender no Device is mapped
    to never matches a filter."""
    debug = os.getenv("DEBUG", "0") == "1"

    if since_dt is None and days_back is not None:
        since_dt = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days_back)

    total_lines = 0
    parsed_ok = 0
    parsed_none = 0
    inserted_new = 0
    nat_marked = 0

    batch = []
    resolver = SenderResolver()

    def flush(conn):
        nonlocal inserted_new, batch
        if not batch:
            return
        # The rows that are NEW are decided here, before the write: the
        # same line twice in one batch keeps its first copy, and a hash the
        # table already holds is not written again. The write-through sees
        # only the rows that landed, so a re-ingest leaves every hit count
        # alone (measured 2026-10-14 before this: a second ingest doubled
        # them). A plain INSERT then: a row that fails is an error (D8).
        fresh: dict = {}
        for r in batch:
            h = r.get("raw_hash")
            if h is not None and h not in fresh:
                fresh[h] = r
        existing = set()
        if fresh:
            rows = conn.execute(
                text("SELECT raw_hash FROM fw_flows WHERE raw_hash IN :hashes")
                .bindparams(bindparam("hashes", expanding=True)),
                {"hashes": list(fresh)},
            ).fetchall()
            existing = {r[0] for r in rows}
        new_rows = [r for h, r in fresh.items() if h not in existing]
        if new_rows:
            conn.execute(INSERT_SQL, new_rows)
            new_hashes = [r["raw_hash"] for r in new_rows]
            inserted_new += len(new_hashes)
            _upsert_rule_aggregates_for_hashes(conn, new_hashes)
            _upsert_nat_evidence_for_hashes(conn, new_hashes)
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
        file_lines = file_ok = file_unparsed = 0
        addr = source_addr_from_path(path)
        with engine.begin() as conn:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    total_lines += 1
                    file_lines += 1
                    row = parse_syslog_line(line, addr)
                    if not row:
                        parsed_none += 1
                        file_unparsed += 1
                        continue
                    ts = row.get("event_ts")
                    if since_dt and ts and ts < since_dt:
                        parsed_none += 1
                        continue
                    if until_dt and ts and ts > until_dt:
                        parsed_none += 1
                        continue
                    sender = resolver.resolve(conn, row["sender_key"], row.get("vendor") or "", ts)
                    if device_filter and sender.get("device_id") != device_filter:
                        parsed_none += 1
                        continue
                    resolver.count(row["sender_key"])
                    row["sender_id"] = sender["id"]
                    parsed_ok += 1
                    file_ok += 1
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
        # One line per file, always. The webapp's progress reader keys on
        # "[ingest] total", "[ingest] file" and a line carrying "events";
        # this one is none of those.
        print(f"[ingest] parsed file={os.path.basename(path)} lines={file_lines} "
              f"ok={file_ok} unparsed={file_unparsed} "
              f"outside_window={file_lines - file_ok - file_unparsed}", flush=True)

    with engine.begin() as conn:
        resolver.write_counts(conn)
    print(f"[ingest] senders={len(resolver._cache)} mapped={resolver.mapped()} "
          f"unattributed={resolver.unmapped()}", flush=True)

    if debug:
        print(
            f"lines={total_lines} parsed_ok={parsed_ok} parsed_none={parsed_none} inserted_new={inserted_new} nat_marked={nat_marked}"
        )

    return inserted_new
