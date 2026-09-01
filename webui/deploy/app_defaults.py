# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""Curated PA App-ID → default service ports.

Cross-vendor resolution of `application-default` for non-PA targets. PA
resolves application-default natively against its App-ID content DB; Forti/CP
have no equivalent, so a rule that says "allow web-browsing on its default
port" would otherwise migrate as "allow ALL". This table maps the common
App-IDs to their standard (proto, port) so the deploy loader can synthesise
real service objects (QA finding, "hybrid" approach).

Scope is deliberately the frequent App-IDs - PA ships thousands via content
updates; unmapped App-IDs fall through to a drop-warn rather than silent ALL.
Only tcp/udp resolve to synthetic service objects; icmp-only apps (ping) carry
("icmp", None) and are treated as unresolved (vendor builtins differ).
"""
from __future__ import annotations

# app-id (lowercase) → list of (proto, port). Multi-entry apps list several.
APP_DEFAULT_PORTS: dict[str, list[tuple[str, str | None]]] = {
    "web-browsing":  [("tcp", "80")],
    "http-proxy":    [("tcp", "8080")],
    "ssl":           [("tcp", "443")],
    "ssh":           [("tcp", "22")],
    "telnet":        [("tcp", "23")],
    "ftp":           [("tcp", "21")],
    "smtp":          [("tcp", "25")],
    "pop3":          [("tcp", "110")],
    "imap":          [("tcp", "143")],
    "ldap":          [("tcp", "389")],
    "ms-rdp":        [("tcp", "3389")],
    "ms-ds-smb":     [("tcp", "445")],
    "rpc":           [("tcp", "135")],
    "ntp":           [("udp", "123")],
    "snmp":          [("udp", "161")],
    "syslog":        [("udp", "514")],
    "tftp":          [("udp", "69")],
    "dns":           [("udp", "53"), ("tcp", "53")],
    "dhcp":          [("udp", "67"), ("udp", "68")],
    "kerberos":      [("tcp", "88"), ("udp", "88")],
    "ldaps":         [("tcp", "636")],
    "mysql":         [("tcp", "3306")],
    "ms-sql-db":     [("tcp", "1433")],
    "postgres":      [("tcp", "5432")],
    "ping":          [("icmp", None)],
}


def resolve_app_default(apps: list[str]) -> tuple[list[tuple[str, str]], list[str]]:
    """Split a rule's App-IDs into resolvable (proto, port) tcp/udp specs and
    an unresolved remainder (unmapped apps + icmp-only). Returns
    (specs, unresolved_app_names). De-dups specs preserving order.
    """
    specs: list[tuple[str, str]] = []
    unresolved: list[str] = []
    for app in apps:
        key = (app or "").strip().lower()
        if not key or key == "any":
            continue
        entries = APP_DEFAULT_PORTS.get(key)
        if not entries:
            unresolved.append(app)
            continue
        usable = [(p, port) for (p, port) in entries if p in ("tcp", "udp") and port]
        if not usable:
            unresolved.append(app)
            continue
        for spec in usable:
            if spec not in specs:
                specs.append(spec)
    return specs, unresolved
