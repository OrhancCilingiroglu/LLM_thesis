"""
cwe_hierarchy_matching.py
==========================
Wires src/core/cwe.py's hierarchy-aware classification into the real
code_cwe.db, per methodology-plan.md Section 1.3.

For every docker-successful sample and every tool, classifies how that tool's
reported CWE(s) relate to the sample's target CWE: exact / ancestor /
descendant / sibling / unrelated / none / no_report. Reuses the CWE
extraction already used by cwe_correlations.py (parse_sast_cwes,
parse_zap_cwes, burp_cwes_for_ids) rather than re-parsing tool output, and
reads codeql/snyk_code findings via DBManager.load_findings.

Additive only: creates one new table, cwe_hierarchy_matches. Never writes to
code_cwe or any other existing table -- this module only reads code_cwe.

Usage:
    python cwe_hierarchy_matching.py                       # compute + persist
    python cwe_hierarchy_matching.py --report-only          # just print the table
    python cwe_hierarchy_matching.py --limit 200            # smoke test
"""

from __future__ import annotations

import argparse
import io
import os
import sqlite3
import sys
from collections import defaultdict
from contextlib import redirect_stdout
from pathlib import Path
from typing import Iterable

sys.path.insert(0, os.path.dirname(__file__))  # allow `from cwe_correlations import ...`
from cwe_correlations import (  # noqa: E402
    burp_cwes_for_ids,
    is_secure_value,
    parse_sast_cwes,
    parse_sonarqube_cwes,
    parse_zap_cwes,
)

_SRC_CORE = Path(__file__).resolve().parents[2] / "src" / "core"
if str(_SRC_CORE) not in sys.path:
    sys.path.insert(0, str(_SRC_CORE))
from cwe import load_hierarchy  # noqa: E402

_UTILS = Path(__file__).resolve().parents[1] / "utils"
if str(_UTILS) not in sys.path:
    sys.path.insert(0, str(_UTILS))
with redirect_stdout(io.StringIO()):  # OWASP.py prints a debug count on import
    import OWASP  # noqa: E402

DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "code_cwe.db")
# "bandit"/"semgrep" here read the OLD text-column extraction (regex CWE
# string / no ruleset attribution). sonarqube has no fixed/structured version
# yet, so it stays here permanently until it does.
LEGACY_SAST_TOOLS = ("bandit", "semgrep", "sonarqube")

# The 2026-08-30 structured re-scan (see changes_summary.md) added
# bandit_cwes/_raw/_version and semgrep_cwes/_raw/_version columns -- these
# are read via DBManager.load_findings(), same as codeql/snyk_code. Tracked
# under "_new" tool names so both the old and new extraction for the same
# tool coexist as separate rows in cwe_hierarchy_matches, which is exactly
# the strict/old-config vs strict/new-config comparison methodology-plan.md
# §1.3's acceptance artifact asks for.
STRUCTURED_TOOLS = ("codeql", "snyk_code", "bandit_new", "semgrep_new")
_STRUCTURED_TOOL_DB_NAME = {"bandit_new": "bandit", "semgrep_new": "semgrep"}

# Best-relationship priority: lower wins when a tool reports several CWEs
# and only some of them relate meaningfully to the target.
_RELATIONSHIP_RANK = {
    "exact": 0, "ancestor": 1, "descendant": 2, "sibling": 3, "unrelated": 4, "none": 5,
}

_OWASP_LOOKUP: dict[int, str] | None = None


def _owasp_category_for_cwe(cwe: int) -> str | None:
    global _OWASP_LOOKUP
    if _OWASP_LOOKUP is None:
        _OWASP_LOOKUP = {}
        for name in dir(OWASP):
            if name.endswith("_list"):
                category = name.split("_", 2)[0]  # "A05_2025_Injection_list" -> "A05"
                for cwe_id in getattr(OWASP, name):
                    _OWASP_LOOKUP[cwe_id] = category
    return _OWASP_LOOKUP.get(cwe)


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create cwe_hierarchy_matches if absent. Never touches any other table."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS cwe_hierarchy_matches (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            code_id             INTEGER NOT NULL,
            tool                TEXT NOT NULL,
            target_cwe          INTEGER,
            reported_cwes       TEXT,
            relationship        TEXT NOT NULL,
            cwe_catalog_version TEXT,
            computed_at         TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(code_id, tool)
        )
        """
    )
    conn.commit()


def _best_relationship(hierarchy, target_cwe: int, reported: set[int]) -> str:
    if not reported:
        return "no_report"
    classifications = (hierarchy.classify(cwe, target_cwe) for cwe in reported)
    return min(classifications, key=lambda r: _RELATIONSHIP_RANK[r])


def _reported_cwes_by_tool(
    row: sqlite3.Row, burp_map: dict[int, set[str]], code_id: int, db_manager,
) -> dict[str, set[int]]:
    def as_ints(cwe_strings: Iterable[str]) -> set[int]:
        return {int(c.replace("CWE-", "")) for c in cwe_strings}

    reported: dict[str, set[int]] = {}
    for tool in LEGACY_SAST_TOOLS:
        if tool == "sonarqube":
            # sonarqube's column is a compound descriptive string, not a
            # plain comma list -- parse_sast_cwes silently returns nothing
            # for it (see parse_sonarqube_cwes's docstring for the numbers).
            reported[tool] = as_ints(parse_sonarqube_cwes(row[tool]))
        else:
            reported[tool] = as_ints(parse_sast_cwes(row[tool]))
    reported["owasp_zap"] = as_ints(parse_zap_cwes(row["owasp_zap"]))
    reported["burpsuite"] = as_ints(burp_map.get(code_id, set()))
    for tool in STRUCTURED_TOOLS:
        db_tool_name = _STRUCTURED_TOOL_DB_NAME.get(tool, tool)
        findings = db_manager.load_findings(code_id, db_tool_name)
        reported[tool] = {cwe for f in findings for cwe in f.cwe_ids}
    return reported


def compute_hierarchy_matches(
    db_path: str | None = None,
    docker_status: str = "tested-successful",
    limit: int | None = None,
    id_list: list[int] | None = None,
) -> int:
    """Classify every (sample, tool) pair and upsert into cwe_hierarchy_matches.

    Read-only against code_cwe and every other existing table; the only write
    is an upsert (by the (code_id, tool) unique key) into the new table this
    module owns, so re-running only refreshes rows it created itself.

    `db_path=None` uses the real project/core/code_cwe.db; pass an explicit
    scratch path to test safely (see changes_summary.md's 2026-08-29 entry on
    why this parameter exists on every DB-touching function now).
    """
    db_path = db_path or DEFAULT_DB_PATH
    sys.path.insert(0, os.path.dirname(__file__))
    from db_handler import DBManager

    db_manager = DBManager(db_path=db_path)
    hierarchy = load_hierarchy()

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    ensure_schema(conn)

    query = f"SELECT * FROM code_cwe WHERE docker = ?"
    params: list = [docker_status]
    if id_list is not None:
        placeholders = ",".join("?" * len(id_list))
        query += f" AND id IN ({placeholders})"
        params.extend(id_list)
    if limit is not None:
        query += " LIMIT ?"
        params.append(limit)

    rows = conn.execute(query, params).fetchall()
    burp_map = burp_cwes_for_ids(conn, (r["id"] for r in rows))

    written = 0
    for row in rows:
        target_raw = row["CWE"]
        if target_raw is None:
            continue
        target_cwe = int(str(target_raw).replace("CWE-", ""))
        code_id = row["id"]

        reported_by_tool = _reported_cwes_by_tool(row, burp_map, code_id, db_manager)
        for tool, reported in reported_by_tool.items():
            relationship = _best_relationship(hierarchy, target_cwe, reported)
            conn.execute(
                """
                INSERT INTO cwe_hierarchy_matches
                    (code_id, tool, target_cwe, reported_cwes, relationship, cwe_catalog_version)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(code_id, tool) DO UPDATE SET
                    target_cwe = excluded.target_cwe,
                    reported_cwes = excluded.reported_cwes,
                    relationship = excluded.relationship,
                    cwe_catalog_version = excluded.cwe_catalog_version,
                    computed_at = datetime('now')
                """,
                (
                    code_id, tool, target_cwe,
                    ",".join(str(c) for c in sorted(reported)) if reported else None,
                    relationship,
                    hierarchy.catalog.version,
                ),
            )
            written += 1
        # Commit per sample, not once at the end: load_findings() (called from
        # _reported_cwes_by_tool on the *next* row) opens its own connection,
        # and a long-lived open write transaction here would lock it out with
        # "database is locked" the moment it tries to read.
        conn.commit()
    conn.close()
    return written


# --------------------------------------------------------------------------- #
# Reporting: strict vs relaxed detection rate, per tool and per OWASP category
# --------------------------------------------------------------------------- #

RELAXED_MATCH = frozenset({"exact", "ancestor", "descendant"})
# "sibling" (reported CWE shares the target's direct parent but is neither
# its ancestor nor descendant, e.g. reporting CWE-79 XSS when the target is
# CWE-89 SQLi -- both children of CWE-74) was excluded on user review: a
# sibling report names a genuinely different weakness that merely happens to
# live in the same family. Crediting it as "relaxed match" would count a
# wrong answer as partial credit; only classifications that actually
# subsume or specialize the target CWE count.


def strict_vs_relaxed_report(db_path: str | None = None, docker_status: str = "tested-successful") -> str:
    """Read cwe_hierarchy_matches + code_cwe (read-only) and render the
    Phase-1 acceptance-artifact table: strict vs. hierarchy-aware ("relaxed")
    detection rate, broken down per tool and per OWASP category.
    """
    db_path = db_path or DEFAULT_DB_PATH
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    rows = conn.execute(
        """
        SELECT m.tool, m.target_cwe, m.relationship, c.secure
        FROM cwe_hierarchy_matches m
        JOIN code_cwe c ON c.id = m.code_id
        WHERE c.docker = ?
        """,
        (docker_status,),
    ).fetchall()
    conn.close()

    # (tool, owasp_category) -> counts
    totals: dict[tuple[str, str], int] = defaultdict(int)
    strict_hits: dict[tuple[str, str], int] = defaultdict(int)
    relaxed_hits: dict[tuple[str, str], int] = defaultdict(int)

    for row in rows:
        if is_secure_value(row["secure"]):
            continue  # detection rate is only meaningful on vulnerable samples
        category = _owasp_category_for_cwe(row["target_cwe"]) or "UNMAPPED"
        key = (row["tool"], category)
        totals[key] += 1
        if row["relationship"] == "exact":
            strict_hits[key] += 1
        if row["relationship"] in RELAXED_MATCH:
            relaxed_hits[key] += 1

    lines = [
        "=" * 88,
        "STRICT VS. HIERARCHY-AWARE (RELAXED) DETECTION RATE, PER TOOL / OWASP CATEGORY",
        "=" * 88,
        "Relaxed = exact | ancestor | descendant | sibling (see src/core/cwe.py)",
        f"{'tool':<12}{'category':<10}{'N':>6}{'strict%':>10}{'relaxed%':>10}{'gap(pp)':>10}",
        "-" * 88,
    ]
    for key in sorted(totals, key=lambda k: (k[0], k[1])):
        tool, category = key
        n = totals[key]
        strict_pct = strict_hits[key] / n * 100 if n else 0.0
        relaxed_pct = relaxed_hits[key] / n * 100 if n else 0.0
        lines.append(
            f"{tool:<12}{category:<10}{n:>6}{strict_pct:>9.1f}%{relaxed_pct:>9.1f}%{relaxed_pct - strict_pct:>9.1f}"
        )
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", default=DEFAULT_DB_PATH)
    ap.add_argument("--docker-status", default="tested-successful")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--report-only", action="store_true",
                     help="Skip (re)computing; just print the report from existing rows.")
    args = ap.parse_args()

    if not args.report_only:
        n = compute_hierarchy_matches(args.db, args.docker_status, limit=args.limit)
        print(f"Wrote/updated {n} (sample, tool) classifications into cwe_hierarchy_matches.")

    print(strict_vs_relaxed_report(args.db, args.docker_status))


if __name__ == "__main__":
    main()
