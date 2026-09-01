# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

import os
from pathlib import Path
from time import sleep

from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url


def ensure_database_and_load_schema(server_url: str, db_name: str) -> tuple[str, URL]:
    schema_path = (Path(__file__).resolve().parent / "../../sql/fw_flows.sql").resolve()
    sql = schema_path.read_text(encoding="utf-8")

    url_server = make_url(server_url).set(database=None)
    engine_server = create_engine(url_server, pool_pre_ping=True, isolation_level="AUTOCOMMIT")

    last = None
    exists = None
    for _ in range(60):
        try:
            with engine_server.connect() as conn:
                exists = conn.execute(
                    text("SELECT 1 FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = :db LIMIT 1"),
                    {"db": db_name},
                ).first()

                if not exists:
                    conn.execute(
                        text(
                            f"CREATE DATABASE `{db_name}` "
                            f"CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
                        )
                    )
                break
        except Exception as e:
            last = e
            sleep(1)
    else:
        raise last

    url_db = make_url(server_url).set(database=db_name)
    engine_db = create_engine(url_db, pool_pre_ping=True)

    if not exists:
        with engine_db.begin() as conn:
            for stmt in sql.split(";"):
                stmt = stmt.strip()
                if stmt:
                    conn.exec_driver_sql(stmt)

    return db_name, url_db


def _read_sql(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def _split_sql(sql: str):
    parts = []
    buf = []
    in_squote = False
    in_dquote = False
    in_bquote = False
    in_line_comment = False   # '-- …\n' or '# …\n'
    in_block_comment = False  # '/* … */'
    escape = False

    i = 0
    n = len(sql)
    while i < n:
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""

        if in_line_comment:
            buf.append(ch)
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue

        if in_block_comment:
            buf.append(ch)
            if ch == "*" and nxt == "/":
                buf.append(nxt)
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue

        if escape:
            buf.append(ch)
            escape = False
            i += 1
            continue

        if ch == "\\" and (in_squote or in_dquote):
            buf.append(ch)
            escape = True
            i += 1
            continue

        if not (in_squote or in_dquote or in_bquote):
            if ch == "-" and nxt == "-":
                buf.append(ch)
                buf.append(nxt)
                in_line_comment = True
                i += 2
                continue
            if ch == "#":
                buf.append(ch)
                in_line_comment = True
                i += 1
                continue
            if ch == "/" and nxt == "*":
                buf.append(ch)
                buf.append(nxt)
                in_block_comment = True
                i += 2
                continue

        if ch == "'" and not in_dquote and not in_bquote:
            in_squote = not in_squote
            buf.append(ch)
            i += 1
            continue

        if ch == '"' and not in_squote and not in_bquote:
            in_dquote = not in_dquote
            buf.append(ch)
            i += 1
            continue

        if ch == "`" and not in_squote and not in_dquote:
            in_bquote = not in_bquote
            buf.append(ch)
            i += 1
            continue

        if ch == ";" and not in_squote and not in_dquote and not in_bquote:
            stmt = "".join(buf).strip()
            if stmt:
                parts.append(stmt)
            buf = []
            i += 1
            continue

        buf.append(ch)
        i += 1

    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)

    return parts


def _exec_sql_file(conn, sql_path: str):
    sql = _read_sql(sql_path)
    for stmt in _split_sql(sql):
        conn.execute(text(stmt))


def bootstrap_schema_from_sql(engine0, db_name: str, schema_dir: str):
    if not schema_dir:
        return

    with engine0.begin() as conn:
        conn.execute(
            text(
                f"CREATE DATABASE IF NOT EXISTS `{db_name}` "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
        )
        conn.execute(text(f"USE `{db_name}`"))

        if os.path.isdir(schema_dir):
            for name in sorted(os.listdir(schema_dir)):
                if name.endswith(".sql"):
                    _exec_sql_file(conn, os.path.join(schema_dir, name))