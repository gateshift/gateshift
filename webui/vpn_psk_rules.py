# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
"""Pre-shared key rules per target platform (backlog 30).

The VPN key store took any key and a key the target refuses failed in the
push. Each target has its own rule, from the vendors' documentation:

  FortiOS       6 to 128 printable characters. That is the default, an IPsec
                password policy on the box can ask for 8 to 128, FIPS-CC mode
                asks for 14 since 7.6.1. The push reports those.
  PAN-OS        up to 255 characters, ASCII or not.
  Check Point   6 to 64 characters with at least four different ones.

The check runs when the key is saved and names the target's rule in one
sentence. A target without a rule here, or no target given, stores the key
unchecked.
"""
from __future__ import annotations

RULES = {
    "fortigate": {"label": "FortiOS", "min": 6, "max": 128, "printable": True, "distinct": 0},
    "panw": {"label": "PAN-OS", "min": 1, "max": 255, "printable": False, "distinct": 0},
    "checkpoint": {"label": "Check Point", "min": 6, "max": 64, "printable": False, "distinct": 4},
}


def _span(rule: dict) -> str:
    kind = "printable characters" if rule["printable"] else "characters"
    if rule["min"] > 1:
        return f"{rule['min']} to {rule['max']} {kind}"
    return f"up to {rule['max']} {kind}"


def rule_sentence(platform: str) -> str | None:
    """What the target takes, for a hint beside the input, or None."""
    rule = RULES.get((platform or "").strip().lower())
    if not rule:
        return None
    tail = f" with at least {rule['distinct']} different ones" if rule["distinct"] else ""
    return f"{rule['label']} takes a pre-shared key of {_span(rule)}{tail}."


def check(platform: str, psk: str) -> str | None:
    """One sentence when the target would refuse this key, else None."""
    rule = RULES.get((platform or "").strip().lower())
    if not rule or psk is None:
        return None
    n = len(psk)
    if n < rule["min"] or n > rule["max"]:
        return f"{rule['label']} takes a pre-shared key of {_span(rule)}, this one has {n}."
    if rule["printable"] and any(not (32 <= ord(c) <= 126) for c in psk):
        return f"{rule['label']} takes a pre-shared key of printable characters only."
    if rule["distinct"] and len(set(psk)) < rule["distinct"]:
        return (f"{rule['label']} takes a pre-shared key with at least {rule['distinct']} "
                f"different characters, this one has {len(set(psk))}.")
    return None


def findings(platform: str, keys: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """The (tunnel name, sentence) pairs of the stored keys a target refuses
    (CE backlog 42): the push checks them before its first write, the
    Review names them as findings. A platform without a rule finds nothing."""
    out: list[tuple[str, str]] = []
    for name, psk in keys:
        problem = check(platform, psk or "")
        if problem:
            out.append((str(name), problem))
    return out
