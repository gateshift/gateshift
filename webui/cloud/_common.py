# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""Shared by the cloud parsers: how a container's resolved members become
address objects a target can hold.

A group member must be a named object, not a literal: FortiGate rejects a
group member that is not an address object and the other targets are no
friendlier (the build reported every cloud group as "all members
unresolved" before this, 2026-10-08). So each resolved address becomes an
address object with a stable literal-derived name, the same convention the
OPNsense parser uses for raw alias entries, and the group references it.
"""
from __future__ import annotations


def port_literal(proto: str, text: str) -> str | None:
    """'tcp' + '0-65535' -> 'tcp/1-65535', '443' -> 'tcp/443', '8000-8100'
    stays. Port 0 is not a port on any target (Check Point refuses it), so
    a range starting there starts at 1 and a lone 0 is dropped (None)."""
    t = str(text or "").strip()
    if not t or t == "*":
        return f"{proto}/1-65535"
    lo, _, hi = t.partition("-")
    try:
        lo_i = int(lo)
        hi_i = int(hi) if hi else lo_i
    except ValueError:
        return None
    lo_i = max(lo_i, 1)
    hi_i = min(max(hi_i, lo_i), 65535)
    if lo_i > 65535:
        return None
    if lo_i == 1 and hi_i == 65535:
        return f"{proto}/1-65535"
    return f"{proto}/{lo_i}" if lo_i == hi_i else f"{proto}/{lo_i}-{hi_i}"


def literal_name(value: str) -> str:
    """A stable object name for a raw address: '10.1.2.4/32' -> 'h-10_1_2_4-32'."""
    return "h-" + value.replace("/", "-").replace(".", "_").replace(":", "_")


def member_objects(cidrs: list[str], owner: str, synth: dict[str, dict], what: str = "member of") -> list[str]:
    """Register one address object per CIDR in `synth` (keyed by name, so a
    member shared by two containers is emitted once) and return the member
    names in order."""
    names: list[str] = []
    for c in cidrs:
        name = literal_name(c)
        synth.setdefault(name, {"obj_type": "address", "name": name,
                                "value": {"type": "ip-netmask", "value": c,
                                          "description": f"{what} {owner}"}})
        names.append(name)
    return names


def service_ref(literal: str, synth: dict[str, dict]) -> str:
    """A service a rule names as protocol and port ('tcp/443', 'udp/53',
    'tcp/8000-8100', 'icmp', 'esp') as the service object the rule
    references instead ('svc-tcp-443'). The FortiGate renderer hands rule
    services to the box by name, so a literal arrives as an unknown
    service and the policy push fails (found on the first real push of a
    cloud leg, 2026-10-09). 'any' stays 'any'."""
    lit = (literal or "").strip().lower()
    if not lit or lit == "any":
        return "any"
    proto, _, port = lit.partition("/")
    name = f"svc-{proto}-{port}" if port else f"svc-{proto}"
    synth.setdefault(name, {"obj_type": "service", "name": name,
                            "value": {"protocol": proto, "port": port or "any",
                                      "description": "service named by a rule"}})
    return name


def literal_ref(cidr: str, owner: str, synth: dict[str, dict]) -> str:
    """An address a rule names directly, as the address object the rule
    references instead. A rule side must hold names, not literals: the
    generate's auto-object pass reads the pipeline's bare addresses and
    loses the prefix length, so a subnet literal became a host object and
    the renderers, unable to match the literal, replaced the side by any
    (found on the first bundle-upload leg, 2026-10-09)."""
    return member_objects([cidr], owner, synth, what="address named by")[0]
