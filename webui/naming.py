# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
"""The naming workbench:
a scheme over a selection of named entities, planned as a set before anything
is written. Pure functions over plain dicts: the caller (main.py) loads the
entities of a kind and writes the plan's changes, this module renders the
pattern, checks the batch for collisions and reports what the target's
renderer would truncate.

An item is a dict: `key` (the source name, or the rule's hash), `shown` (the
name the project shows today), `source` (the source's name) and `vars` (the
pattern's variables). The namespace is every entity of the kind on the source
as `{key: shown}`, the batch's items included; a collision is two entities
that would end up shown under one name.
"""
from __future__ import annotations

import re
import string
from typing import Any

# What the renderers cap a name at (D4): the renderers' own constants, read as
# they stand on 2026-11-20 (fortinet.py _LIM_POLICY, _LIM_OBJ, _LIM_ZONE;
# panw.py _PA_NAME_MAX_LEN and the schedule cap, zones by the vendor's limit,
# the renderer applies none; checkpoint.py _NAME_MAX_LEN). None: no cap known.
LIMITS: dict[str, dict[str, int]] = {
    "fortigate":  {"rule": 35, "object": 79, "service": 79, "zone": 35, "nat_rule": 79},
    "panw":       {"rule": 63, "object": 63, "service": 63, "zone": 31, "nat_rule": 63},
    "checkpoint": {"rule": 100, "object": 100, "service": 100, "zone": 100, "nat_rule": 100},
}
# the renderers prefix every rule, or the unnamed ones, with the project's
# rule prefix before the cap: the workbench counts it for the FortiGate, which
# prefixes every rule
PREFIX_COUNTS = {"fortigate"}

KINDS = ("object", "service", "interface", "zone", "vrf", "nat_rule", "rule")
CASES = ("keep", "lower", "upper")
CAP_ITEMS = 500
CAP_RULES = 200
SHOWN_ROWS = 50          # rows an answer carries per table, beside the counts

_FORMATTER = string.Formatter()
_VAR_RE = re.compile(r"\{([a-z_]+)(?::[^}]*)?\}")


def limit_for(platform: str | None, kind: str) -> int | None:
    return (LIMITS.get(str(platform or "")) or {}).get(kind)


def variables_of(pattern: str) -> list[str]:
    """The variable names a pattern uses, in order."""
    return list(dict.fromkeys(_VAR_RE.findall(pattern or "")))


def render(pattern: str, variables: dict[str, Any]) -> str:
    """The pattern with its variables filled: `{name}`, `{source}`, `{n}`,
    `{n:03}`, `{device}`, `{kind}`, for rules `{action}`, `{src_zone}`,
    `{dst_zone}`. An unknown variable raises ValueError with its name."""
    out: list[str] = []
    for literal, field, spec, conv in _FORMATTER.parse(pattern or ""):
        out.append(literal)
        if field is None:
            continue
        if field not in variables:
            raise ValueError(f"unknown variable {{{field}}}: the pattern knows "
                             + ", ".join("{" + k + "}" for k in sorted(variables)))
        val = variables[field]
        if conv:
            val = _FORMATTER.convert_field(val, conv)
        out.append(format(val, spec or ""))
    return "".join(out)


def transform(name: str, replace: list[dict] | None, case: str) -> str:
    """`replace` (from, to pairs in order) and `case` act on the shown name
    alone, the pattern's literals stay as written (D7)."""
    s = str(name or "")
    for pair in replace or []:
        frm = str((pair or {}).get("from") or "")
        if frm:
            s = s.replace(frm, str((pair or {}).get("to") or ""))
    if case == "lower":
        s = s.lower()
    elif case == "upper":
        s = s.upper()
    return s


def plan(kind: str, items: list[dict], namespace: dict[str, str], *, pattern: str | None = None,
         mapping: dict[str, str] | None = None, replace: list[dict] | None = None, case: str = "keep",
         limit: int | None = None, prefix_len: int = 0, label_of=None) -> dict:
    """The batch as a set (D7). `items` are the selection in order (the ordinal
    `{n}` counts them from 1), `namespace` every entity of the kind on the
    source as key -> shown name today (the items included). Either `pattern` or
    `mapping` (key -> name). Returns changes, refused, unchanged, inverse and
    the counts; a refused item refuses the batch, the caller writes nothing
    then. `label_of(key)` names an entity in a sentence (the source name for
    rules, the key otherwise)."""
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {', '.join(KINDS)}")
    if case not in CASES:
        raise ValueError(f"case must be one of {', '.join(CASES)}")
    if (pattern is None) == (mapping is None):
        raise ValueError("give pattern (with select) or mapping, one of the two")
    label_of = label_of or (lambda k: str(k))

    wanted: dict[str, str] = {}          # key -> new shown name
    changes: list[dict] = []
    refused: list[dict] = []
    unchanged: list[str] = []
    for i, it in enumerate(items, start=1):
        key = str(it["key"])
        shown = str(it.get("shown") or "")
        if mapping is not None:
            if key not in mapping:
                continue
            new = str(mapping[key] or "").strip()
        else:
            vars_ = dict(it.get("vars") or {})
            vars_.setdefault("name", transform(shown, replace, case))
            vars_.setdefault("source", str(it.get("source") or ""))
            vars_.setdefault("n", i)
            vars_.setdefault("kind", kind)
            try:
                new = render(pattern or "", vars_).strip()
            except ValueError as exc:
                refused.append({"key": key, "from": shown, "to": None, "sentence": str(exc)})
                continue
        if kind != "rule" and not new:
            refused.append({"key": key, "from": shown, "to": "", "sentence": "the name cannot be empty"})
            continue
        if new == shown:
            unchanged.append(key)
            continue
        wanted[key] = new
        row = {"key": key, "from": shown, "to": new, "source": str(it.get("source") or "")}
        if limit is not None and new and len(new) + prefix_len > limit:
            row["over_limit"] = limit
        changes.append(row)

    # the set check: every entity's final shown name, the batch laid over
    final: dict[str, str] = dict(namespace)
    final.update(wanted)
    owners: dict[str, list[str]] = {}
    for key, name in final.items():
        if name:                           # unnamed rules do not collide
            owners.setdefault(name, []).append(key)
    for row in changes:
        others = [k for k in owners.get(row["to"], []) if k != row["key"]]
        if others:
            other = others[0]
            if other in wanted:
                sentence = f"{row['to']!r} is also the new name of {label_of(other)}"
            elif namespace.get(other) == other or kind == "rule":
                sentence = f"a {_word(kind)} named {row['to']!r} already exists in the source ({label_of(other)})"
            else:
                sentence = f"{row['to']!r} is already the name {label_of(other)} is shown under"
            refused.append({"key": row["key"], "from": row["from"], "to": row["to"], "sentence": sentence})
    refused_keys = {r["key"] for r in refused}
    changes = [c for c in changes if c["key"] not in refused_keys]
    inverse = {c["to"]: c["from"] for c in changes} if kind != "rule" else {c["key"]: c["from"] for c in changes}
    return {
        "kind": kind,
        "changes": changes[:SHOWN_ROWS], "changes_total": len(changes),
        "refused": refused[:SHOWN_ROWS], "refused_total": len(refused),
        "unchanged_total": len(unchanged),
        "over_limit_total": sum(1 for c in changes if c.get("over_limit")),
        "inverse": inverse,
        "_all_changes": changes,           # the writer's list, stripped before the answer leaves
    }


_WORDS = {"object": "object", "service": "service", "interface": "interface", "zone": "zone",
          "vrf": "virtual router", "nat_rule": "NAT rule", "rule": "rule"}


def _word(kind: str) -> str:
    return _WORDS.get(kind, kind)


def answer_of(p: dict) -> dict:
    """The plan without the writer's private list."""
    return {k: v for k, v in p.items() if not k.startswith("_")}
