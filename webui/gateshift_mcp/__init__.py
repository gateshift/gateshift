# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
"""gateshift-mcp: the MCP server beside Gateshift.

A small program that speaks MCP on stdio to the operator's client and talks
to the product through its automation API at /api/v1 with a token. It holds
no database, no driver and no copy of a table: every tool is a call of the
API, and what the API refuses the tool refuses with the same sentence.

The package splits into `api` (the client of /api/v1), `tools` (the tools as
plain functions, testable without the SDK) and `server` (the SDK wiring)."""

import os


def _shipped_version() -> str:
    """Line 1 of webui/VERSION, the file the web application reads its own
    version from. The release export stamps it, so a server shipped with an
    installation reports the installation's version."""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "VERSION")
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.readline().strip() or "dev"
    except OSError:
        return "dev"


# The product version this server was shipped with. The server compares it
# with the installation's API version on its first call and says so when
# they differ.
SERVER_VERSION = _shipped_version()
