"""
export_raw_tool_outputs.py

Purpose
-------
Dump the RAW (unparsed) tool output columns for every docker-runnable code
sample, for manual false-positive review — e.g. "secure + CWE-605 flagged"
rows: read the actual bandit text and check whether the finding is real or
boilerplate noise (see the CWE-605 / CWE-668 / CWE-352 pattern discussed
earlier).

This does NOT extract/parse CWE tokens — it exports the tool columns as-is,
so you can eyeball exactly what bandit/semgrep/sonarqube/zap/burpsuite said.

Usage
-----
    python export_raw_tool_outputs.py
    python export_raw_tool_outputs.py --docker_status tested-successful --out raw_tools.csv
    python export_raw_tool_outputs.py --limit 200          # quick sample for a first look
"""

import os
import csv
import sqlite3
import argparse

from core.db_handler import DBManager

COLUMNS = ["id", "CWE", "secure", "bandit", "owasp_zap", "burpsuite", "semgrep", "sonarqube"]


def export_raw_tool_outputs(out_path, docker_status="tested-successful", limit=None):
    db = DBManager()
    conn = sqlite3.connect(db.db_path)
    cur = conn.cursor()

    query = f"SELECT {', '.join(COLUMNS)} FROM code_cwe"
    params = ()
    if docker_status:
        query += " WHERE docker = ?"
        params = (docker_status,)
    query += " ORDER BY id"
    if limit:
        query += " LIMIT ?"
        params = params + (limit,)

    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(COLUMNS)
        for row in rows:
            writer.writerow(row)

    print(f"Written {len(rows)} rows -> {out_path}")
    return out_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Export CWE/secure/bandit/owasp_zap/burpsuite/semgrep/sonarqube "
                     "columns as-is (raw, unparsed) for docker-runnable rows."
    )
    parser.add_argument("--docker_status", default="tested-successful",
                         help="Pass an empty string to disable the docker filter entirely.")
    parser.add_argument("--out", default=None, help="Output CSV path")
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    BASE_DIR = os.path.dirname(__file__)
    out_path = args.out or os.path.join(BASE_DIR, "exports", "raw_tool_outputs.csv")

    export_raw_tool_outputs(
        out_path=out_path,
        docker_status=args.docker_status or None,
        limit=args.limit,
    )