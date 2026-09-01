# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

import os
import urllib.parse

from sqlalchemy.engine import URL, make_url


def _credentials() -> tuple[str, str]:
    """Application database account.

    Prefers the unprivileged DB_USER/DB_PASSWORD pair; falls back to root for
    installations that predate the dedicated user.
    """
    user = os.getenv("DB_USER") or "root"
    if os.getenv("DB_USER"):
        pw = os.getenv("DB_PASSWORD") or ""
    else:
        pw = os.getenv("MARIADB_ROOT_PASSWORD", "")
    return user, pw


def build_server_url() -> str:
    user, pw = _credentials()
    return (
        f"mysql+pymysql://{urllib.parse.quote_plus(user)}:"
        f"{urllib.parse.quote_plus(pw)}@"
        f"{os.getenv('DB_HOST','mariadb')}:"
        f"{os.getenv('DB_PORT','3306')}/"
    )


def build_db_url(server_url: str, db_name: str) -> URL:
    return make_url(server_url).set(database=db_name)
