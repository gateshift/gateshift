# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

import glob
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from modules.ingest import make_engines, ingest_logfiles, discover_devices_from_logs
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


def main():
    db_name = "gateshift"
    log_pattern = "/logs/*.log"
    schema_dir = "/sql/init"
    jobs_dir = "/sql/jobs"

    mode = sys.argv[1] if len(sys.argv) > 1 else "all"

    # Time window: env vars take priority, fall back to days_back=7
    since_dt = _parse_env_dt("SINCE_TS")
    until_dt = _parse_env_dt("UNTIL_TS")
    if since_dt is None:
        days_back = int(os.getenv("DAYS_BACK", "7"))
        since_dt = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days_back)

    engine0, engine = make_engines(db_name)
    bootstrap_schema_from_sql(engine0, db_name, schema_dir)

    if mode == "discover":
        files = sorted(glob.glob(log_pattern))
        hosts = discover_devices_from_logs(files)
        print(json.dumps({"devices": [{"host": h, "vendor": v} for h, v in hosts.items()]}))
        return

    device_filter = os.getenv("DEVICE_HOST", "").strip() or None

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
