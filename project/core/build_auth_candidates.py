"""
build_auth_candidates.py
=========================
Runs logic/auth_detection.py's login-route + seeded-credential detection
against every docker-successful sample and persists the result, so ZAP's
authenticated-scan wiring (project/dast.py) has something to read instead of
re-parsing code/sql_script on every scan.

Pure detection over already-stored columns -- no Docker, no ZAP, no network.
Additive only: creates one new table, auth_candidates. Never writes to
code_cwe or any other existing table.

Coverage measured against the real corpus before trusting this: 5,126/13,634
(37.6%) samples have a login-shaped route (reads both a username-like and a
password-like form field), but only 1,999/13,634 (14.7%) also have an
extractable *plaintext* seeded credential -- most of the gap is samples that
store a real password hash (pbkdf2/bcrypt/etc.) instead, which cannot be
reversed into a login-usable plaintext.

Usage:
    python build_auth_candidates.py                # compute + persist
    python build_auth_candidates.py --limit 200     # smoke test
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(__file__))
from db_handler import DBManager  # noqa: E402

_PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
from logic.auth_detection import detect_auth_candidate  # noqa: E402


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS auth_candidates (
            code_id         INTEGER PRIMARY KEY,
            login_path      TEXT NOT NULL,
            username_field  TEXT NOT NULL,
            password_field  TEXT NOT NULL,
            username        TEXT NOT NULL,
            password        TEXT NOT NULL,
            computed_at     TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    conn.commit()


def build_auth_candidates(db_path: str | None = None, limit: int | None = None) -> int:
    """Compute and persist auth candidates. Returns the count found.

    `db_path=None` uses the real project/core/code_cwe.db; pass a scratch
    path to test safely first.
    """
    db_path = db_path or DBManager().db_path
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    ensure_schema(conn)

    query = "SELECT id, code, sql_script FROM code_cwe WHERE docker = 'tested-successful'"
    if limit:
        query += f" LIMIT {int(limit)}"
    rows = conn.execute(query).fetchall()

    found = 0
    for row in rows:
        candidate = detect_auth_candidate(row["code"] or "", row["sql_script"] or "")
        if candidate is None:
            continue
        conn.execute(
            """
            INSERT INTO auth_candidates
                (code_id, login_path, username_field, password_field, username, password)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(code_id) DO UPDATE SET
                login_path = excluded.login_path,
                username_field = excluded.username_field,
                password_field = excluded.password_field,
                username = excluded.username,
                password = excluded.password,
                computed_at = datetime('now')
            """,
            (row["id"], candidate.login_path, candidate.username_field,
             candidate.password_field, candidate.username, candidate.password),
        )
        found += 1
    conn.commit()
    conn.close()
    return found


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", default=None)
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    n = build_auth_candidates(args.db, limit=args.limit)
    print(f"auth_candidates: {n} samples with a usable login flow detected and persisted.")


if __name__ == "__main__":
    main()
