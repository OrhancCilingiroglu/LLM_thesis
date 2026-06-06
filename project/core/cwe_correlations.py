"""
cross_cwe_analysis.py
=====================

Cross-CWE Detection Analysis
----------------------------
For every "targeted CWE" group of code samples in the ``code_cwe`` table,
this script computes the empirical distribution of CWEs that SAST/DAST
tools actually reported across those samples.

The result tells us how *clean* (specific) a generated code example is
with respect to the CWE it was supposed to demonstrate.

Output (per group, e.g. CWE-89 vulnerable):
    CWE-89  (N=42):  CWE-89  45.2%  |  CWE-20  23.8%  |  CWE-90  15.3% ...

Two groups are reported separately for every targeted CWE:
    * <CWE-XX>            -> vulnerable samples (secure = 0)
    * <CWE-XX>-secure     -> secure samples     (secure = 1)

This is the analysis required as the last step before selecting
"true secure" candidates: a secure sample is *truly* secure when its
group shows no detected CWEs (or only a low background rate).

Inputs  : code_cwe.db  (schema as in /mnt/project/schema.sql)
Outputs :
    - cross_cwe_report.txt     human-readable, sorted by detection share
    - cross_cwe_long.csv       long-form table (one row per target/detected pair)
    - cross_cwe_matrix.csv     wide matrix (rows = targets, columns = detected CWEs)

Usage:
    python cross_cwe_analysis.py [--db PATH] [--out-dir DIR] [--min-share 0.0]

Only rows whose docker status is "tested-successful" are considered, in
order to match the population used by ``cwe_summary.py``.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sqlite3
from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Set, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Values that some tool columns may contain instead of real JSON / CWE strings.
# They must be treated as "no detection information" rather than as data.
PLACEHOLDERS: Set[str] = {
    "not-tested", "not_tested", "not tested",
    "na", "n/a", "none", "null", "nan", "-", "",
}

# String values that map to "this row is a secure sample".
SECURE_TRUE: Set[str] = {"SECURE", "TRUE", "1", "YES", "Y"}


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def normalize_cwe(raw) -> str | None:
    """Return ``CWE-<int>`` canonical form, or ``None`` if not parseable."""
    if raw is None:
        return None
    s = str(raw).strip().upper()
    if not s or s in PLACEHOLDERS:
        return None
    if not s.startswith("CWE-"):
        s = f"CWE-{s}"
    try:
        num = int(s.replace("CWE-", "").strip())
    except ValueError:
        return None
    return f"CWE-{num}"


def is_secure_value(val) -> bool:
    """Normalize the heterogeneous ``secure`` column to a boolean."""
    if val is None:
        return False
    if isinstance(val, bool):
        return val
    if isinstance(val, int):
        return val == 1
    return str(val).strip().upper() in SECURE_TRUE


def safe_json(raw):
    """Parse a JSON blob coming from a database TEXT column, robustly."""
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="replace")
    s = str(raw).strip()
    if not s or s.lower() in PLACEHOLDERS or s[0] not in "{[":
        return None
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# Per-tool CWE extractors
# ---------------------------------------------------------------------------

def parse_sast_cwes(raw) -> Set[str]:
    """
    SAST tools (bandit / semgrep / sonarqube) are stored as comma-separated
    ``CWE-XX`` strings. Extract every distinct CWE id.
    """
    found: Set[str] = set()
    if not raw:
        return found
    for item in str(raw).split(","):
        c = normalize_cwe(item)
        if c is not None:
            found.add(c)
    return found


def parse_zap_cwes(zap_raw) -> Set[str]:
    """
    OWASP ZAP output is JSON. CWEs may appear either in the ``cweid`` field
    of an alert or as ``CWE-<n>`` keys in the ``tags`` object.
    """
    found: Set[str] = set()
    alerts = safe_json(zap_raw)
    if alerts is None:
        return found

    # Flatten the two known ZAP shapes ("alerts": [...]) and ("site": [{"alerts": [...]}, ...]).
    if isinstance(alerts, dict):
        if isinstance(alerts.get("alerts"), list):
            alerts = alerts["alerts"]
        elif isinstance(alerts.get("site"), list):
            merged: List[dict] = []
            for s in alerts["site"]:
                if isinstance(s, dict) and isinstance(s.get("alerts"), list):
                    merged.extend(s["alerts"])
            alerts = merged
        else:
            alerts = []

    if not isinstance(alerts, list):
        return found

    for alert in alerts:
        if not isinstance(alert, dict):
            continue

        # 1) explicit cweid
        c = normalize_cwe(alert.get("cweid"))
        # ZAP uses 0 / -1 as "no CWE assigned"
        if c is not None and c not in ("CWE-0", "CWE--1"):
            found.add(c)

        # 2) tags carrying "CWE-<n>" keys
        tags = alert.get("tags")
        if isinstance(tags, dict):
            for tag_key in tags:
                c = normalize_cwe(tag_key)
                if c is not None:
                    found.add(c)
    return found


def burp_cwes_for_ids(conn: sqlite3.Connection, ids: Iterable[int]) -> Dict[int, Set[str]]:
    """
    Burp Suite detections are not stored in ``code_cwe.burpsuite`` (which is
    just "found"/"not-found") but in the auxiliary ``burp_scan_result`` table,
    one row per finding, with the column ``mapped_cwe``.

    Returns ``{code_id: {CWE-XX, ...}}``. Missing ids simply have empty sets.
    """
    result: Dict[int, Set[str]] = {cid: set() for cid in ids}
    if not result:
        return result

    cur = conn.cursor()
    # Check if the burp_scan_result table actually exists in this database
    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='burp_scan_result'"
    )
    if cur.fetchone() is None:
        return result

    # Use chunked IN-queries to avoid SQLite's parameter limit (~999).
    id_list = list(result.keys())
    CHUNK = 500
    for i in range(0, len(id_list), CHUNK):
        chunk = id_list[i : i + CHUNK]
        placeholders = ",".join("?" * len(chunk))
        cur.execute(
            f"SELECT code_id, mapped_cwe FROM burp_scan_result "
            f"WHERE code_id IN ({placeholders})",
            chunk,
        )
        for code_id, mapped_cwe in cur.fetchall():
            c = normalize_cwe(mapped_cwe)
            if c is not None:
                result[code_id].add(c)
    return result


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def collect_detections(
    db_path: str,
    docker_status: str = "tested-successful",
) -> Tuple[Dict[Tuple[str, bool], int], Dict[Tuple[str, bool], Counter]]:
    """
    Walk the ``code_cwe`` table and aggregate cross-CWE detections.

    Returns
    -------
    sample_counts : {(target_cwe, is_secure): N}
        Number of samples in each (target CWE, security status) group.
    detection_counts : {(target_cwe, is_secure): Counter({detected_cwe: rows_in_which_detected})}
        For every group, how many rows triggered each detected CWE
        (a row is counted once per detected CWE, not per tool).
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # We only consider docker-success rows so that every sample really ran
    # and was scannable by DAST tools.
    cur.execute(
        """
        SELECT id, CWE, secure, bandit, semgrep, sonarqube, owasp_zap
        FROM code_cwe
        WHERE docker = ?
        """,
        (docker_status,),
    )
    rows = cur.fetchall()

    # Pre-fetch Burp findings in one batch — far cheaper than per-row queries.
    burp_map = burp_cwes_for_ids(conn, (r["id"] for r in rows))

    sample_counts: Dict[Tuple[str, bool], int] = defaultdict(int)
    detection_counts: Dict[Tuple[str, bool], Counter] = defaultdict(Counter)

    for row in rows:
        target = normalize_cwe(row["CWE"])
        if target is None:
            # Skip rows whose target CWE is missing / unparseable.
            continue

        secure = is_secure_value(row["secure"])
        key = (target, secure)
        sample_counts[key] += 1

        # Union of CWEs detected by any tool for this sample.
        # Using a union (not a sum) means a sample is counted once per
        # distinct CWE regardless of how many tools flagged it.
        detected: Set[str] = set()
        detected |= parse_sast_cwes(row["bandit"])
        detected |= parse_sast_cwes(row["semgrep"])
        detected |= parse_sast_cwes(row["sonarqube"])
        detected |= parse_zap_cwes(row["owasp_zap"])
        detected |= burp_map.get(row["id"], set())

        for cwe in detected:
            detection_counts[key][cwe] += 1

    conn.close()
    return sample_counts, detection_counts


# ---------------------------------------------------------------------------
# Report writers
# ---------------------------------------------------------------------------

def _group_label(target_cwe: str, secure: bool) -> str:
    """Format the row label as used in the human-readable report."""
    return f"{target_cwe}-secure" if secure else target_cwe


def _sort_key_numeric_cwe(cwe: str) -> int:
    """Sort CWE strings numerically (CWE-2 before CWE-10)."""
    try:
        return int(cwe.replace("CWE-", ""))
    except ValueError:
        return 10**9


def write_text_report(
    out_path: str,
    sample_counts: Dict[Tuple[str, bool], int],
    detection_counts: Dict[Tuple[str, bool], Counter],
    min_share: float = 0.0,
) -> None:
    """
    Write a human-readable report. Each line shows one targeted CWE group
    followed by the most frequently detected CWEs, sorted by share.

    ``min_share`` filters out detected CWEs below the given fraction (0..1).
    """
    lines: List[str] = []
    lines.append("=" * 78)
    lines.append("CROSS-CWE DETECTION ANALYSIS")
    lines.append("=" * 78)
    lines.append("Each line:  <targeted CWE>  (N=<samples>):  "
                 "<detected CWE> <share%>, ...")
    lines.append("Share = (rows in which the tool stack reported the detected CWE)")
    lines.append("        / (total rows in the targeted group)")
    lines.append("Burp findings come from burp_scan_result.mapped_cwe, "
                 "not from the 'found'/'not-found' flag.")
    lines.append("")

    # Split into vulnerable / secure sections for readability.
    for section_title, want_secure in [("VULNERABLE SAMPLES", False),
                                       ("SECURE SAMPLES",     True)]:
        lines.append("-" * 78)
        lines.append(section_title)
        lines.append("-" * 78)

        # Sort groups by numeric CWE id.
        group_keys = sorted(
            [k for k in sample_counts if k[1] == want_secure],
            key=lambda k: _sort_key_numeric_cwe(k[0]),
        )

        if not group_keys:
            lines.append("(no samples)")
            lines.append("")
            continue

        for key in group_keys:
            target_cwe, secure = key
            n = sample_counts[key]
            counter = detection_counts.get(key, Counter())

            # Rank detected CWEs by share, descending; ties broken by numeric id.
            ranked = sorted(
                counter.items(),
                key=lambda kv: (-kv[1] / n if n else 0,
                                _sort_key_numeric_cwe(kv[0])),
            )

            parts: List[str] = []
            for det_cwe, cnt in ranked:
                share = cnt / n if n else 0.0
                if share < min_share:
                    continue
                parts.append(f"{det_cwe} {share * 100:5.1f}%")

            label = _group_label(target_cwe, secure)
            if parts:
                lines.append(f"{label:<18}  (N={n:>4}):  " + "  |  ".join(parts))
            else:
                lines.append(f"{label:<18}  (N={n:>4}):  (no detections above "
                             f"{min_share * 100:.1f}% threshold)")
        lines.append("")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def write_long_csv(
    out_path: str,
    sample_counts: Dict[Tuple[str, bool], int],
    detection_counts: Dict[Tuple[str, bool], Counter],
) -> None:
    """
    Long-form CSV — one row per (target group, detected CWE).
    Convenient for further analysis in pandas / R.
    """
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "target_cwe",
            "security_status",      # 'secure' | 'vulnerable'
            "group_label",          # e.g. CWE-89 or CWE-89-secure
            "sample_size",          # N
            "detected_cwe",
            "detected_count",
            "detected_percent",     # 0..100
        ])
        for key in sorted(sample_counts.keys(),
                          key=lambda k: (k[1], _sort_key_numeric_cwe(k[0]))):
            target_cwe, secure = key
            n = sample_counts[key]
            counter = detection_counts.get(key, Counter())
            sec_str = "secure" if secure else "vulnerable"
            label = _group_label(target_cwe, secure)

            if not counter:
                # Emit a placeholder row so groups with zero detections are
                # still visible in the output.
                w.writerow([target_cwe, sec_str, label, n, "", 0, 0.0])
                continue

            for det_cwe, cnt in sorted(
                counter.items(),
                key=lambda kv: (-kv[1], _sort_key_numeric_cwe(kv[0])),
            ):
                share = (cnt / n * 100) if n else 0.0
                w.writerow([target_cwe, sec_str, label, n,
                            det_cwe, cnt, round(share, 2)])


def write_matrix_csv(
    out_path: str,
    sample_counts: Dict[Tuple[str, bool], int],
    detection_counts: Dict[Tuple[str, bool], Counter],
) -> None:
    """
    Wide matrix CSV — rows = group labels, columns = detected CWEs.
    Cell value is the detection percentage (0..100). Useful for heatmaps.
    """
    # Build the column universe = every detected CWE that appeared anywhere.
    all_detected: Set[str] = set()
    for counter in detection_counts.values():
        all_detected.update(counter.keys())
    columns = sorted(all_detected, key=_sort_key_numeric_cwe)

    with open(out_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["group_label", "sample_size", *columns])

        for key in sorted(sample_counts.keys(),
                          key=lambda k: (k[1], _sort_key_numeric_cwe(k[0]))):
            target_cwe, secure = key
            n = sample_counts[key]
            counter = detection_counts.get(key, Counter())
            row = [_group_label(target_cwe, secure), n]
            for col in columns:
                share = (counter.get(col, 0) / n * 100) if n else 0.0
                row.append(round(share, 2))
            w.writerow(row)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Cross-CWE detection analysis on the code_cwe SQLite DB."
    )
    ap.add_argument(
        "--db",
        default=os.path.join(os.path.dirname(__file__), "code_cwe.db"),
        help="Path to the SQLite database (default: ./code_cwe.db).",
    )
    ap.add_argument(
        "--out-dir",
        default=os.path.dirname(__file__) or ".",
        help="Directory where the reports will be written.",
    )
    ap.add_argument(
        "--docker-status",
        default="tested-successful",
        help='Only rows with this docker status are analyzed '
             '(default: "tested-successful").',
    )
    ap.add_argument(
        "--min-share",
        type=float,
        default=0.0,
        help="Hide detected CWEs whose share is below this fraction in the "
             "text report (e.g. 0.05 = 5%%). Default 0.0 (show all).",
    )
    args = ap.parse_args()

    if not os.path.exists(args.db):
        raise SystemExit(f"Database not found: {args.db}")
    os.makedirs(args.out_dir, exist_ok=True)

    print(f"[1/4] Reading {args.db} (docker = {args.docker_status!r}) ...")
    sample_counts, detection_counts = collect_detections(
        args.db, docker_status=args.docker_status
    )

    total_samples = sum(sample_counts.values())
    n_groups = len(sample_counts)
    print(f"      analyzed {total_samples} samples across {n_groups} groups")

    txt_path    = os.path.join(args.out_dir, "cross_cwe_report.txt")
    long_path   = os.path.join(args.out_dir, "cross_cwe_long.csv")
    matrix_path = os.path.join(args.out_dir, "cross_cwe_matrix.csv")

    print(f"[2/4] Writing text report -> {txt_path}")
    write_text_report(txt_path, sample_counts, detection_counts,
                      min_share=args.min_share)

    print(f"[3/4] Writing long CSV    -> {long_path}")
    write_long_csv(long_path, sample_counts, detection_counts)

    print(f"[4/4] Writing matrix CSV  -> {matrix_path}")
    write_matrix_csv(matrix_path, sample_counts, detection_counts)

    print("Done.")


if __name__ == "__main__":
    main()