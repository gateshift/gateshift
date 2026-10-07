# Copyright (c) 2026 Timo Duttine - SPDX-License-Identifier: BUSL-1.1
"""Set a new password for the UI's admin account (docs/ACCESS_DESIGN.md, D6).

A forgotten password is never a data loss: run this inside the webapp
container, then log in with the new password.

    docker compose exec webapp python reset_admin.py            # prompts twice
    docker compose exec webapp python reset_admin.py --password 'new one'

Creates the account when none exists (the setup page then no longer
appears). Uses the same database settings as the application.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys

from sqlalchemy import create_engine, text

import auth


def _engine():
    host = os.getenv("DB_HOST", "mariadb")
    port = os.getenv("DB_PORT", "3306")
    user = os.getenv("DB_USER") or "root"
    pw = (os.getenv("DB_PASSWORD") if os.getenv("DB_USER") else None) or os.getenv("MARIADB_ROOT_PASSWORD", "")
    name = os.getenv("DB_NAME", "gateshift")
    return create_engine(f"mysql+pymysql://{user}:{pw}@{host}:{port}/{name}")


def main() -> int:
    ap = argparse.ArgumentParser(description="set the admin password of the Gateshift UI")
    ap.add_argument("--password", help="the new password (prompted when omitted)")
    args = ap.parse_args()
    pw = args.password
    if pw is None:
        pw = getpass.getpass("New admin password: ")
        if pw != getpass.getpass("Again: "):
            print("the two entries differ", file=sys.stderr)
            return 2
    if len(pw) < auth.MIN_PASSWORD_LEN:
        print(f"the password needs at least {auth.MIN_PASSWORD_LEN} characters", file=sys.stderr)
        return 2
    h = auth.hash_password(pw)
    with _engine().begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS fw_users (
              id            INT AUTO_INCREMENT PRIMARY KEY,
              username      VARCHAR(64)  NOT NULL UNIQUE,
              pw_hash       VARCHAR(255) NOT NULL,
              disabled      TINYINT(1)   NOT NULL DEFAULT 0,
              created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
              last_login_at DATETIME     NULL
            )"""))
        n = conn.execute(text("UPDATE fw_users SET pw_hash = :h, disabled = 0 WHERE username = 'admin'"),
                         {"h": h}).rowcount
        if not n:
            conn.execute(text("INSERT INTO fw_users (username, pw_hash) VALUES ('admin', :h)"), {"h": h})
    print("admin password set" if n else "admin account created with the given password")
    return 0


if __name__ == "__main__":
    sys.exit(main())
