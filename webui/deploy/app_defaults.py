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

import json

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


def _as_list(value) -> list:
    """A JSON-encoded list column as a list, anything else as what it is."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except Exception:
            return []
    return [x for x in (value or []) if x]


def apply_app_default(rules: list[dict], platform: str, forti_ngfw_mode: str | None,
                      service_objects: list[dict]) -> list[tuple[str, str]]:
    """Resolve ``application-default`` to concrete service objects for a
    target without App-ID (the deploy loader's "Schicht 2"), in place.

    PA resolves the token natively and a FortiGate in policy-based NGFW mode
    carries the applications on its security policy with
    enforce-default-app-port, so both are
    left alone. Everywhere else a rule whose service is application-default
    gets ``services`` = the default ports of its App-IDs, synthesised as
    ``app-<proto>-<port>`` objects appended to ``service_objects``; the
    App-IDs the table does not know land in ``_appdef_unresolved`` for the
    drivers to declare. Returns the synthesised (service, rule) pairs for the
    Review's services row.

    The per-rule service MODE (``service_override``, the PA switch) is honoured
    for every target: ``any`` means the
    operator accepts every service, so the rule is left to the drivers' Any
    path untouched and undeclared; ``application-default`` forces this
    resolution even where the source named services.
    """
    synth: list[tuple[str, str]] = []
    if platform == "panw" or (platform == "fortigate" and forti_ngfw_mode == "policy-based"):
        return synth
    seen = {o["name"] for o in service_objects}
    for rule in rules:
        mode = str(rule.get("service_override") or "").strip().lower()
        if mode == "any":
            continue
        forced = mode == "application-default"
        if rule.get("services") and not forced:
            continue
        if not forced and "application-default" not in _as_list(rule.get("import_services")):
            continue
        specs, unresolved = resolve_app_default(_as_list(rule.get("import_applications")))
        names: list[str] = []
        for proto, port in specs:
            sname = f"app-{proto}-{port}"
            if sname not in seen:
                service_objects.append({"name": sname, "value": {"protocol": proto, "port": port}})
                seen.add(sname)
                synth.append((sname, str(rule.get("rule_name") or "")))
            if sname not in names:
                names.append(sname)
        if names:
            rule["services"] = names
            if unresolved:
                rule["_appdef_unresolved"] = unresolved   # narrower: these App-IDs are left out
        else:
            if forced:
                rule.pop("services", None)   # the mode replaces the source's services
            # wider: nothing resolved, the drivers' Any path runs and
            # deploy.base.appdef_result declares it (blocks on an allow rule).
            # The scalar (proto, port_from, port_to) is the pipeline's artifact
            # of a consolidated flow, not the source's service: left in place it
            # sends the Check Point renderer down its port lookup and the rule
            # out as one port while the declaration says every service
            # (measured 2026-11-03: s_8000-tcp for a rule declared as Any).
            for scalar in ("proto", "protocol", "port_from", "port_to"):
                rule.pop(scalar, None)
            rule["_appdef_widened"] = unresolved
    return synth

