# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

from . import opnsense
from . import kv


def parse(header: str, payload: str):
    prog = header.split("[")[0] if header else ""
    if prog == "filterlog":
        return opnsense.parse(payload)
    return kv.parse(payload)