# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

import glob
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from modules.ingest import make_engines, ingest_logfiles, scan_senders
from modules.db_bootstrap import bootstrap_schema_from_sql
from modules.db_jobs import run_sql_jobs


def _parse_env_dt(key: str):
    val = os.getenv(key, "").strip()
    if not val:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(val, fmt)
        except ValueError:
            continue
    return None


def _version() -> str:
    """The version this image was built from: webui/VERSION, baked in as
    /app/VERSION (and mounted there by the dev compose). The webapp compares
    it with its own and refuses to run two halves of different versions,
    because both write the identity columns of the rule pipeline."""
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION")) as f:
            return (f.readline().strip() or "unknown")
    except OSError:
        return "unknown"


def _identity_migration(engine) -> str | None:
    """The identity-migration marker in fw_meta, or None. The table is the
    webapp's; on a fresh install it may not exist yet, which is 'no marker',
    not an error."""
    from sqlalchemy import text
    with engine.connect() as conn:
        has = conn.execute(text(
            "SELECT 1 FROM information_schema.TABLES "
            "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'fw_meta'")).scalar()
        if not has:
            return None
        return conn.execute(text(
            "SELECT v FROM fw_meta WHERE k = 'identity_migration'")).scalar()


def main():
    db_name = "gateshift"
    log_pattern = "/logs/*.log"
    schema_dir = "/sql/init"
    jobs_dir = "/sql/jobs"

    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    print(f"[collector] version={_version()}", flush=True)

    # Time window: env vars take priority, fall back to days_back=7
    since_dt = _parse_env_dt("SINCE_TS")
    until_dt = _parse_env_dt("UNTIL_TS")
    if since_dt is None:
        days_back = int(os.getenv("DAYS_BACK", "7"))
        since_dt = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days_back)

    engine0, engine = make_engines(db_name)
    bootstrap_schema_from_sql(engine0, db_name, schema_dir)

    # Both halves of the product write the rule pipeline's identity columns.
    # While a migration of those columns is marked in progress, a run here
    # would write them under the old formula and the drift cleanup would then
    # delete every override keyed on the new one. Refuse, in clear text.
    marker = _identity_migration(engine)
    if marker:
        print(f"ERROR: identity migration in progress ({marker}): "
              f"the collector does not run until it completes", flush=True)
        raise SystemExit(2)

    if mode == "discover":
        # The senders the receiver has heard, written to fw_log_senders for
        # the webapp's candidate list. No Device is created here, ever
        # (docs/DEVICE_IDENTITY_PLAN.md, phase 4): a sender string may point
        # at a Device, the operator makes that mapping.
        files = sorted(glob.glob(log_pattern))
        senders = scan_senders(engine, files)
        print(json.dumps({"senders": senders}, default=str))
        return

    # The run page's filter: the Device's row id (docs/DEVICE_IDENTITY_PLAN.md, D5)
    _df = os.getenv("DEVICE_ID", "").strip()
    device_filter = int(_df) if _df.isdigit() else None

    if mode == "ingest":
        files = sorted(glob.glob(log_pattern))
        inserted = ingest_logfiles(engine, files, since_dt=since_dt, until_dt=until_dt,
                                   device_filter=device_filter)
        print(f"inserted={inserted}")
        return

    if mode == "generate":
        executed = run_sql_jobs(engine0, db_name, jobs_dir, since_dt=since_dt, until_dt=until_dt)
        print(f"executed={executed}")
        return

    if mode == "all":
        files = sorted(glob.glob(log_pattern))
        inserted = ingest_logfiles(engine, files, since_dt=since_dt, until_dt=until_dt,
                                   device_filter=device_filter)
        print(f"inserted={inserted}")
        executed = run_sql_jobs(engine0, db_name, jobs_dir, since_dt=since_dt, until_dt=until_dt)
        print(f"executed={executed}")
        return

    raise SystemExit("mode must be one of: discover | ingest | generate | all")


if __name__ == "__main__":
    main()
