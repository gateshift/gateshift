# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
"""The sender of a syslog line: what the receiver can observe about who sent
it (docs/DEVICE_IDENTITY_PLAN.md, phase 4, decision D9).

A sender is three observed fields together: the hostname the box writes
into the syslog header, the address the packet came from, and the vendor's
own identity inside the message (a FortiOS unit's serial number, a Check
Point gateway's origin). One field is not enough: a FortiGate writes no
header hostname and lands under its address, an OPNsense writes a hostname
and no serial, and two boxes behind one syslog relay share the address. A
sender string may POINT at a Device, it never creates one; the mapping is
the operator's act, made in the webapp.

The receiver writes the source address into the file name
(syslog-ng.conf: ${HOST}_${SOURCEIP}_${YEAR}-${MONTH}-${DAY}.log); a file
named otherwise, a capture the operator uploaded or a file from before the
address was recorded, carries no address. Database-free so the host suite
runs it.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re

# ${HOST} may hold anything the sender wrote, so the name is read from the
# end: the last two underscore-separated parts are the address and the day.
_PATH_RE = re.compile(r"^(?P<host>.+)_(?P<addr>[0-9A-Fa-f:.]+)_(?P<day>\d{4}-\d{2}-\d{2})\.log$")

SERIAL_MAX = 128


def source_addr_from_path(path: str) -> str:
    """The source address the receiver wrote into the file name, normalised
    (IPv6 compressed), or '' for a file that carries none."""
    m = _PATH_RE.match(os.path.basename(path or ""))
    if not m:
        return ""
    try:
        return str(ipaddress.ip_address(m.group("addr")))
    except ValueError:
        return ""


def vendor_serial(parsed: dict) -> str:
    """The vendor's own identity inside the message: a FortiOS line carries
    the unit's serial as devid, a Check Point line its origin. '' where the
    vendor sends none (OPNsense), so the field is empty, never guessed."""
    extra = parsed.get("extra") if isinstance(parsed, dict) else None
    if not isinstance(extra, dict):
        return ""
    vendor = parsed.get("vendor")
    if vendor == "fortinet":
        s = extra.get("devid") or ""
    elif vendor == "checkpoint":
        s = extra.get("origin_sic_name") or extra.get("origin") or ""
    else:
        s = ""
    return str(s).strip()[:SERIAL_MAX]


def sender_key(header_host: str, source_addr: str, serial: str) -> tuple[str, str, str]:
    """The identity tuple a sender row is unique on."""
    return ((header_host or "").strip()[:255], (source_addr or "").strip()[:45],
            (serial or "").strip()[:SERIAL_MAX])


def raw_hash(key: tuple[str, str, str], line: str) -> bytes:
    """The flow row's dedup hash: the sender plus the line. The same line
    from two senders is two flows; the same line twice from one sender is
    one."""
    material = "|".join(key) + "\n" + (line or "")
    return hashlib.sha256(material.encode("utf-8", "ignore")).digest()
