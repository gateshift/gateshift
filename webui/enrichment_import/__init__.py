# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""Phase-B promoters - lift vendor-specific raw_extras from
fw_imported_rules into the per-rule enrichment override tables with
source='auto'.

Each vendor's promoter is a self-contained module exposing one entry:

    def promote_imported_to_overrides(conn, device_id: int) -> dict:
        ...

The dispatch table maps fw_devices.platform → callable. Pipeline-runner
(_do_run generate-stage) iterates all source devices post-generate and
calls the promoter for the device's vendor. Targets are skipped.

Promoters must be idempotent: each run starts by deleting
source='auto' rows for the device's content_hashes and rewrites them
fresh. source='manual' rows are never touched.
"""

from . import checkpoint, fortigate, panw

IMPORT_PROMOTERS = {
    "fortigate":  fortigate.promote_imported_to_overrides,
    "panw":       panw.promote_imported_to_overrides,
    "checkpoint": checkpoint.promote_imported_to_overrides,
}
