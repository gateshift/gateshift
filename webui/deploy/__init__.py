# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

from .base import DeployDriver, StepResult, DRIVERS

# Platforms whose driver EXISTS and is tested, but which are not offered as a
# push target yet. Same approach the Optimize page and the Org tab take: close
# the entry point, keep the code. Deleting a verified driver to express a
# scoping decision would throw away the expensive part - the measurements
# behind it - and would make the decision hard to reverse.
#
# opnsense: decision 2026-10-01. It ships as a configuration SOURCE and stays
# a log source; whether the target role is ever published is open. That role
# is complete and was verified end to end - 181 rules pushed, all ten
# verifier checks green - but it carries a prerequisite no other target has:
# a VLAN or a tunnel has to be ASSIGNED an interface by hand before a rule or
# an interface group may name it, and that step has no API.
#
# Read by the target-eligibility checks in main.py. The driver stays
# registered in DRIVERS so its code, its tests and the QA verifier keep
# working - and so a device registered from automation can still be imported.
TARGET_NOT_OFFERED = frozenset({"opnsense"})


def target_platforms() -> set[str]:
    """Platforms a device may be selected as a push target for."""
    return set(DRIVERS) - TARGET_NOT_OFFERED


__all__ = ["DeployDriver", "StepResult", "DRIVERS",
           "TARGET_NOT_OFFERED", "target_platforms"]
