# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
"""Hit counts from the box.

The vendors' own per-rule counters, read in the import's session beside the
rules and again on demand by the refresh, kept on the imported rows in five
columns of their own: box_hits, box_first_hit, box_last_hit, box_hits_since
and box_hits_read_at. NULL means not read, 0 means read as zero. They are
never mixed with the log-derived usage (hit_count, first_seen, last_seen),
and no pipeline stage, generator or driver reads them (D2). This module
holds what every vendor reader shares: the reading shape, the attach to the
rule dicts, the declaration of a source whose counters were not read (D8),
the refresh writer (D3) and the usage tokens of the ruleset page (D7).
"""
from __future__ import annotations

import datetime as _dt
import json as _json

COLUMNS = ("box_hits", "box_first_hit", "box_last_hit", "box_hits_since", "box_hits_read_at")
DECLARATION_FIELD = "hit_counts"
STALE_DAYS = (30, 90, 180)
SORTS = ("hits_desc", "hits_asc", "last_desc", "last_asc")
USAGE_FILTERS = ("zero", "stale30", "stale90", "stale180", "unread")

# The reason a source declares when its import reads no counters by design.
_DEFAULT_DECLARATIONS = {
    "asa": "file import, no session to the Device",
    "aws": "no per-rule counters in the provider's API (flow logs are a log source)",
    "azure": "no per-rule counters in the provider's API (flow logs are a log source)",
    "gcp": "no per-rule counters in the provider's API (flow logs are a log source)",
}


class Reading:
    """What a vendor reader answers: the counters keyed by the vendor's own
    rule id (`rules`, and `nats` by NAT rule name where the vendor's NAT
    rulebase answers), the read time, the since-time the vendor states for
    the whole read (None when it states one per rule, or none), and
    `declared` with the reason when the counters were not read (D8)."""

    def __init__(self, *, rules=None, nats=None, read_at=None, since=None, declared=None):
        self.rules: dict = dict(rules or {})
        self.nats: dict = dict(nats or {})
        self.read_at = read_at or utcnow()
        self.since = since
        self.declared = declared


def utcnow() -> _dt.datetime:
    return _dt.datetime.utcnow().replace(microsecond=0)


def declared(reason: str) -> Reading:
    """A reading that read nothing, with the reason the import log and the
    Review name."""
    return Reading(declared=str(reason or "the counters were not read"))


def entry(hits, first=None, last=None, since=None) -> dict:
    """One rule's counters as the vendor states them (D4): the hits since
    the vendor's reset, the first and last hit, and the reset or creation
    time when the vendor offers one."""
    try:
        n = int(hits or 0)
    except (TypeError, ValueError):
        n = 0
    return {"hits": max(n, 0), "first": first, "last": last, "since": since}


def from_epoch(value) -> _dt.datetime | None:
    """A vendor's epoch time as a naive UTC datetime: seconds, or
    milliseconds (Check Point's posix). None for 0, empty or unreadable."""
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    if n <= 0:
        return None
    if n > 1e11:
        n = n / 1000.0
    try:
        return _dt.datetime.utcfromtimestamp(n).replace(microsecond=0)
    except (OverflowError, OSError, ValueError):
        return None


def from_iso(value) -> _dt.datetime | None:
    """An ISO-8601 stamp (Cisco's `2026-11-05T10:00:00Z`, Check Point's
    `2026-11-05T10:00+0100`) as a naive UTC datetime, None when absent or
    unreadable."""
    s = str(value or "").strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    if len(s) >= 5 and s[-5] in "+-" and s[-3] != ":" and s[-5:-2].lstrip("+-").isdigit():
        s = s[:-2] + ":" + s[-2:]
    try:
        d = _dt.datetime.fromisoformat(s)
    except ValueError:
        return None
    if d.tzinfo is not None:
        d = d.astimezone(_dt.timezone.utc).replace(tzinfo=None)
    return d.replace(microsecond=0)


def from_cp_date(value) -> _dt.datetime | None:
    """Check Point's date object ({iso-8601, posix}) or a bare stamp."""
    if isinstance(value, dict):
        return from_epoch(value.get("posix")) or from_iso(value.get("iso-8601"))
    return from_iso(value)


def _set(row: dict, e: dict | None, reading: Reading) -> None:
    if e is None:
        for c in COLUMNS:
            row[c] = None
        return
    row["box_hits"] = int(e.get("hits") or 0)
    row["box_first_hit"] = e.get("first")
    row["box_last_hit"] = e.get("last")
    row["box_hits_since"] = e.get("since") if e.get("since") is not None else reading.since
    row["box_hits_read_at"] = reading.read_at


def attach(rules: list, reading: Reading, *, key: str = "source_vendor_id", nats: list | None = None) -> int:
    """Set the five fields on every rule dict: the entry the reading carries
    under the rule's vendor id (`key`, then the rule name), NULL where it
    carries none or the reading is declared (D6). NAT rule dicts match by
    name. Returns how many rules got an entry."""
    n = 0
    for r in rules or []:
        e = None
        if not reading.declared:
            e = reading.rules.get(str(r.get(key) or "")) or reading.rules.get(str(r.get("rule_name") or ""))
        _set(r, e, reading)
        if e is not None:
            n += 1
    for nr in nats or []:
        e = None if reading.declared else reading.nats.get(str(nr.get("name") or ""))
        _set(nr, e, reading)
    return n


def mismatch(reading: Reading, attached: int, reason: str) -> Reading:
    """A reading the box answered that matched none of the import's rules
    becomes a declaration with `reason` (D8): the counters were read, but
    they count another configuration, an uploaded one that is not the
    box's current configuration (measured on OPNsense 2026-11-09). Without
    it the Review would say the counters were not read and ask for a
    re-import, which reads the same upload again. A declared reading, an
    empty one, or one that matched, is answered unchanged."""
    if reading.declared or not reading.rules or attached:
        return reading
    return declared(reason)


def usage_of(reading: Reading, rules: list | None = None) -> dict:
    """The import result's `box_usage` slot: the declared reason or the
    count of rules that got a counter."""
    return {"declared": reading.declared,
            "read": 0 if reading.declared else sum(1 for r in (rules or []) if r.get("box_hits") is not None),
            "read_at": reading.read_at.isoformat(sep=" ") if reading.read_at else None}


def default_declaration(platform: str | None) -> str:
    """The reason for a source whose importer attaches no counters at all."""
    return _DEFAULT_DECLARATIONS.get(str(platform or ""), "this import does not read the Device's counters")


def params(row: dict) -> dict:
    """The bind parameters of the five columns for an insert."""
    return {"bhits": row.get("box_hits"), "bfirst": row.get("box_first_hit"),
            "blast": row.get("box_last_hit"), "bsince": row.get("box_hits_since"),
            "bread": row.get("box_hits_read_at")}


def declaration_params(device_id: int, import_ts, reason: str, rules: list) -> dict | None:
    """The fw_import_drops row of a declared source (D8): the field, the
    rules without a counter, the reason as the sample. None without rules."""
    n = sum(1 for r in rules or [] if r.get("box_hits") is None)
    if not rules or not reason:
        return None
    return {"did": device_id, "ts": import_ts, "field": DECLARATION_FIELD, "cnt": n,
            "samples": _json.dumps([str(reason)[:300]])}


# The SQL of the refresh and the summaries as strings: the module stays importable
# without SQLAlchemy (the parsers' host tests import it through fmcsource).
_UPDATE_RULES = (
    "UPDATE fw_imported_rules SET box_hits = :bhits, box_first_hit = :bfirst, box_last_hit = :blast, "
    "box_hits_since = :bsince, box_hits_read_at = :bread WHERE id = :id")
_UPDATE_NATS = (
    "UPDATE fw_nat_rules SET box_hits = :bhits, box_first_hit = :bfirst, box_last_hit = :blast, "
    "box_hits_since = :bsince, box_hits_read_at = :bread WHERE id = :id")


def refresh_rows(conn, device_id: int, reading: Reading) -> dict:
    """The refresh (D3): write a fresh reading onto the rows of the Device's
    latest import, keyed by source_vendor_id, then by rule name, NAT by
    name. Never creates or deletes a row, never touches the pipeline. A
    declared reading sets every row to NULL and writes the declaration;
    a read one removes an older declaration."""
    from sqlalchemy import text
    ts = conn.execute(text("SELECT MAX(import_ts) FROM fw_imported_rules WHERE device_id = :d"),
                      {"d": device_id}).scalar()
    out = {"rules": 0, "matched": 0, "nats": 0, "nats_matched": 0, "declared": reading.declared}
    if ts is None:
        return out
    rows = conn.execute(text(
        "SELECT id, rule_name, source_vendor_id FROM fw_imported_rules "
        "WHERE device_id = :d AND import_ts = :ts"), {"d": device_id, "ts": ts}).mappings().all()
    updates = []
    for r in rows:
        e = None
        if not reading.declared:
            e = (reading.rules.get(str(r["source_vendor_id"] or ""))
                 or reading.rules.get(str(r["rule_name"] or "")))
        row: dict = {}
        _set(row, e, reading)
        updates.append({"id": int(r["id"]), **params(row)})
        if e is not None:
            out["matched"] += 1
    out["rules"] = len(rows)
    if rows and not out["matched"] and not reading.declared:
        # the box answered, but under ids the rows do not carry (imported before the
        # vendor id was stored, or a rulebase that changed): not a read, declared (D8)
        reading = declared("the Device's counters name none of the imported rules, re-import the Device")
        out["declared"] = reading.declared
        updates = []
        for r in rows:
            row = {}
            _set(row, None, reading)
            updates.append({"id": int(r["id"]), **params(row)})
    if updates:
        conn.execute(text(_UPDATE_RULES), updates)
    nat_rows = conn.execute(text(
        "SELECT id, name FROM fw_nat_rules WHERE device_id = :d AND (project_id IS NULL OR project_id = 0)"),
        {"d": device_id}).mappings().all()
    nat_updates = []
    for r in nat_rows:
        e = None if reading.declared else reading.nats.get(str(r["name"] or ""))
        row = {}
        _set(row, e, reading)
        nat_updates.append({"id": int(r["id"]), **params(row)})
        if e is not None:
            out["nats_matched"] += 1
    out["nats"] = len(nat_rows)
    if nat_updates:
        conn.execute(text(_UPDATE_NATS), nat_updates)
    conn.execute(text("DELETE FROM fw_import_drops WHERE device_id = :d AND field = :f"),
                 {"d": device_id, "f": DECLARATION_FIELD})
    if reading.declared and rows:
        conn.execute(text(
            "INSERT INTO fw_import_drops (device_id, import_ts, field, rule_count, sample_names) "
            "VALUES (:did, :ts, :field, :cnt, :samples)"),
            {"did": device_id, "ts": ts, "field": DECLARATION_FIELD, "cnt": len(rows),
             "samples": _json.dumps([str(reading.declared)[:300]])})
    return out


def usage_tokens(row: dict, now: _dt.datetime | None = None) -> str:
    """The ruleset page's usage filter tokens of one row (D7): `unread` for
    a rule without a counter, else `read`, `zero` when the box counted no
    hit, and `staleN` for every N of 30, 90 and 180 days without a hit
    (a last hit older than N days, or none at all)."""
    hits = row.get("box_hits")
    if hits is None:
        return "unread"
    now = now or utcnow()
    tokens = ["read"]
    if int(hits) == 0:
        tokens.append("zero")
    last = row.get("box_last_hit")
    for days in STALE_DAYS:
        if last is None or last < now - _dt.timedelta(days=days):
            tokens.append(f"stale{days}")
    return " ".join(tokens)


def order_prefix(sort: str | None) -> str:
    """The ORDER BY prefix of a box column sort on the imported join `_ir`
    (rows without a counter last), '' for the source order."""
    if sort == "hits_desc":
        return "(_ir.box_hits IS NULL), _ir.box_hits DESC, "
    if sort == "hits_asc":
        return "(_ir.box_hits IS NULL), _ir.box_hits ASC, "
    if sort == "last_desc":
        return "(_ir.box_last_hit IS NULL), _ir.box_last_hit DESC, "
    if sort == "last_asc":
        return "(_ir.box_last_hit IS NULL), _ir.box_last_hit ASC, "
    return ""


def summary(conn, device_id: int, now: _dt.datetime | None = None) -> dict | None:
    """The Review's `box_usage` of one source (D7): the rules of the latest
    import, how many carry a counter, how many the box counted zero for,
    how many saw no hit for 90 days, the read time, the earliest since, and
    the declared reason when the counters were not read. None without an
    import."""
    from sqlalchemy import text
    now = now or utcnow()
    row = conn.execute(text(
        "SELECT COUNT(*) AS total, "
        "       SUM(box_hits IS NOT NULL) AS read_n, "
        "       SUM(box_hits = 0) AS zero_n, "
        "       SUM(box_hits IS NOT NULL AND (box_last_hit IS NULL OR box_last_hit < :cut)) AS stale90, "
        "       MAX(box_hits_read_at) AS read_at, MIN(box_hits_since) AS since "
        "FROM fw_imported_rules "
        "WHERE device_id = :d AND import_ts = (SELECT MAX(import_ts) FROM fw_imported_rules WHERE device_id = :d)"),
        {"d": device_id, "cut": now - _dt.timedelta(days=90)}).mappings().fetchone()
    if not row or not int(row["total"] or 0):
        return None
    reason = conn.execute(text(
        "SELECT sample_names FROM fw_import_drops WHERE device_id = :d AND field = :f "
        "ORDER BY import_ts DESC LIMIT 1"), {"d": device_id, "f": DECLARATION_FIELD}).scalar()
    declared_reason = None
    if reason:
        try:
            lst = _json.loads(reason) if isinstance(reason, str) else reason
            declared_reason = str(lst[0]) if lst else None
        except (ValueError, TypeError, IndexError):
            declared_reason = None

    if not declared_reason and not int(row["read_n"] or 0):
        # rows without a counter and without a declaration: imported before the
        # counters were read, or never refreshed. Said so, never "0 of 0".
        declared_reason = ("the counters were not read for this import: re-import the Device "
                           "or read its hit counts on the Overview")

    def _ts(v):
        return v.strftime("%Y-%m-%d %H:%M") if isinstance(v, _dt.datetime) else None
    return {"rules_total": int(row["total"] or 0), "rules_read": int(row["read_n"] or 0),
            "rules_zero": int(row["zero_n"] or 0), "rules_stale_90d": int(row["stale90"] or 0),
            "read_at": _ts(row["read_at"]), "since": _ts(row["since"]), "declared": declared_reason}


def last_read_at(conn, device_ids: list) -> _dt.datetime | None:
    """When the counters of these Devices (a box and its instances) were
    last read, None when never."""
    from sqlalchemy import text
    ids = [int(i) for i in device_ids if i]
    if not ids:
        return None
    marks = ", ".join(f":i{n}" for n in range(len(ids)))
    row = conn.execute(text(f"SELECT MAX(box_hits_read_at) FROM fw_imported_rules WHERE device_id IN ({marks})"),
                       {f"i{n}": v for n, v in enumerate(ids)}).scalar()
    return row if isinstance(row, _dt.datetime) else None


def decorate(rule: dict, now: _dt.datetime | None = None) -> None:
    """The ruleset page's rendering of one row (D7): the Box hits and Last
    hit texts, the tooltip naming the read time and the since-date, and
    the usage filter tokens. A row without a counter reads as a dash."""
    hits = rule.get("box_hits")
    rule["box_usage_tokens"] = usage_tokens(rule, now)
    if hits is None:
        rule["box_hits_text"] = "-"
        rule["box_last_text"] = "-"
        # FortiOS keeps no counter for a disabled policy (measured 2026-11-09),
        # so a read box can leave its disabled rules without one.
        rule["box_title"] = ("Not read from the Device: the rule is disabled, and a Device "
                             "may keep no counter for a disabled rule"
                             if rule.get("disabled") else "Not read from the Device")
        return
    rule["box_hits_text"] = f"{int(hits):,}"
    last = rule.get("box_last_hit")
    if isinstance(last, _dt.datetime):
        rule["box_last_text"] = last.strftime("%Y-%m-%d %H:%M")
    else:
        rule["box_last_text"] = "never" if int(hits) == 0 else "-"
    read_at = rule.get("box_hits_read_at")
    since = rule.get("box_hits_since")
    first = rule.get("box_first_hit")
    parts = ["The Device's own counter"]
    parts.append("since " + (since.strftime("%Y-%m-%d %H:%M") if isinstance(since, _dt.datetime) else "unknown"))
    if isinstance(first, _dt.datetime):
        parts.append("first hit " + first.strftime("%Y-%m-%d %H:%M"))
    parts.append("read " + (read_at.strftime("%Y-%m-%d %H:%M") if isinstance(read_at, _dt.datetime) else "?"))
    rule["box_title"] = ", ".join(parts)
