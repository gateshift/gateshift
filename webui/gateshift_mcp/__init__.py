# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
"""gateshift-mcp: the MCP server beside Gateshift.

A small program that speaks MCP on stdio to the operator's client and talks
to the product through its automation API at /api/v1 with a token. It holds
no database, no driver and no copy of a table: every tool is a call of the
API, and what the API refuses the tool refuses with the same sentence.

The package splits into `api` (the client of /api/v1), `tools` (the tools as
plain functions, testable without the SDK) and `server` (the SDK wiring)."""

# The product version this server was shipped with (webui/VERSION at the
# release). The server compares it with the installation's API version on
# its first call and says so when they differ.
SERVER_VERSION = "0.9.6-dev"
