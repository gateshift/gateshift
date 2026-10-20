# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
"""The syslog envelope: timestamp, host, program tag, payload.

Pure text handling with no database behind it, so it can be tested on the
host without the collector's dependencies. The receiver (syslog-ng) writes
one of two line shapes, and both end in an optional program TAG followed by
the vendor's payload:

    2026-02-15T16:46:36+00:00 HOST filterlog[12345]: 5,,,0,igb0,...
    Apr  4 00:00:04 HOST date=2026-04-04 time=00:00:04 devname="fgt" ...

A tag is the program name, optionally with a bracketed pid, and nothing else.
The text before the first ": " used to be taken as the tag unconditionally,
which left an EMPTY payload for every vendor whose lines carry no tag at all
(FortiOS and Check Point write key=value from the first byte) and discarded
them in silence (docs/DEVICE_IDENTITY_PLAN.md, section 3a). Now the tag is
taken only when it looks like one, and otherwise the whole rest is payload.
"""
import re
from datetime import datetime, timezone

BSD_RE = re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.+)$')

# A program tag: name, optional [pid]. No spaces, no '=', no quotes, no '%'.
TAG_RE = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.\-/]{0,63}(\[\d+\])?$')


def rfc3339_to_naive_utc(ts: str):
    ts = (ts or "").replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return None
    if dt.tzinfo:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def bsd_ts_to_naive_utc(ts_str: str):
    year = datetime.now(timezone.utc).year
    normalized = re.sub(r'\s+', ' ', ts_str.strip())
    try:
        dt = datetime.strptime(f"{year} {normalized}", "%Y %b %d %H:%M:%S")
        # A month ahead of the current one is last year's log.
        now = datetime.now(timezone.utc)
        if dt.month > now.month:
            dt = dt.replace(year=year - 1)
        return dt
    except ValueError:
        return None


def split_header(rest: str) -> tuple[str, str]:
    """(tag, payload) of everything after the host.

    The tag is taken only when the text before the first ": " looks like a
    program tag. A key=value record, a CSV record or a message code is not a
    tag, and for those the whole rest is the payload.
    """
    head, sep, tail = (rest or "").partition(": ")
    head = head.strip()
    if sep and TAG_RE.match(head):
        return head, tail
    return "", rest or ""


def split_line(line: str):
    """(event_ts, host, tag, payload), or None when the line is no syslog
    envelope at all. The caller keeps the stripped line for the raw record."""
    line = (line or "").rstrip("\n")
    if not line:
        return None
    if line[0].isdigit():
        # RFC3339: "2026-02-15T16:46:36+00:00 HOST REST"
        a = line.split(" ", 2)
        if len(a) < 3:
            return None
        event_ts = rfc3339_to_naive_utc(a[0])
        host, rest = a[1], a[2]
    else:
        # BSD: "Apr  4 00:00:04 HOST REST"
        m = BSD_RE.match(line)
        if not m:
            return None
        event_ts = bsd_ts_to_naive_utc(m.group(1))
        host, rest = m.group(2), m.group(3)
    tag, payload = split_header(rest)
    return event_ts, host, tag, payload
