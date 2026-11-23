# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
"""`python -m gateshift_mcp`: the development server on stdio;
the installation offers the same server at /mcp.
Logs go to stderr only, stdout is the protocol channel."""
from __future__ import annotations

import logging
import sys

from . import api as apimod


def main() -> int:
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING,
                        format="gateshift-mcp %(levelname)s %(message)s")
    from .server import build, env_state
    try:
        state = env_state()
    except apimod.ConfigError as exc:
        print(f"gateshift-mcp: {exc}", file=sys.stderr)
        return 2
    srv = build(lambda ctx: state)
    srv.run(transport="stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())
