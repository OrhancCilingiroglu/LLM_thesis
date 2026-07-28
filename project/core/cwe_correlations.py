"""
cwe_correlations.py
===================
Cross-CWE detection analysis on the code_cwe SQLite database.

For each (target_cwe, security_status) group, computes the empirical
distribution of CWEs actually reported by SAST/DAST tools across those
samples. Only rows with docker = "tested-successful" are considered.

Outputs:
    cross_cwe_report.txt   — human-readable, sorted by detection share
    cross_cwe_long.csv     — long-form table (one row per target/detected pair)
    cross_cwe_matrix.csv   — wide matrix suitable for heatmap visualisation

Usage:
    python cwe_correlations.py [--db PATH] [--out-dir DIR] [--min-share 0.05]
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

PLACEHOLDERS: Set[str] = {
    "not-tested", "not_tested", "not tested",
    "na", "n/a", "none", "null", "nan", "-", "",
}

SECURE_TRUE: Set[str] = {"SECURE", "TRUE", "1", "YES", "Y"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalize_cwe(raw) -> str | None:
    """Return canonical CWE-<n> form, or None if unparseable."""
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
    """Normalise the heterogeneous secure column to a boolean."""
    if val is None:
        return False
    if isinstance(val, bool):
        return val
    if isinstance(val, int):
        return val == 1
    return str(val).strip().upper() in SECURE_TRUE


def safe_json(raw):
    """Parse a TEXT column that may contain JSON, returning None on failure."""
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
    """Extract CWE ids from comma-separated SAST output (bandit/semgrep/sonarqube)."""
    found: Set[str] = set()
    if not raw:
        return found
    for item in str(raw).split(","):
        c = normalize_cwe(item)
        if c is not None:
            found.add(c)
    return found


def parse_zap_cwes(zap_raw) -> Set[str]:
    """Extract CWE ids from ZAP JSON output (cweid field and CWE-* tag keys)."""
    found: Set[str] = set()
    alerts = safe_json(zap_raw)
    if alerts is None:
        return found

    # Normalise both known ZAP shapes: {"alerts": [...]} and {"site": [{"alerts": [...]}]}
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
        c = normalize_cwe(alert.get("cweid"))
        if c is not None and c not in ("CWE-0", "CWE--1"):
            found.add(c)
        tags = alert.get("tags")
        if isinstance(tags, dict):
            for tag_key in tags:
                c = normalize_cwe(tag_key)
                if c is not None:
                    found.add(c)
    return found


def burp_cwes_for_ids(conn: sqlite3.Connection, ids: Iterable[int]) -> Dict[int, Set[str]]:
    """
    Fetch Burp Suite CWEs from burp_scan_result.mapped_cwe in batched IN-queries.
    Returns {code_id: {CWE-XX, ...}}; absent ids map to empty sets.
    """
    result: Dict[int, Set[str]] = {cid: set() for cid in ids}
    if not result:
        return result

    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='burp_scan_result'")
    if cur.fetchone() is None:
        return result

    id_list = list(result.keys())
    CHUNK = 500
    for i in range(0, len(id_list), CHUNK):
        chunk = id_list[i : i + CHUNK]
        placeholders = ",".join("?" * len(chunk))
        cur.execute(
            f"SELECT code_id, mapped_cwe FROM burp_scan_result WHERE code_id IN ({placeholders})",
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
    Aggregate cross-CWE detections from the code_cwe table.

    Returns
    -------
    sample_counts    : {(target_cwe, is_secure): N}
    detection_counts : {(target_cwe, is_secure): Counter({detected_cwe: n_rows})}
        A sample is counted once per distinct detected CWE regardless of
        how many tools flagged it (union, not sum).
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute(
        "SELECT id, CWE, secure, bandit, semgrep, sonarqube, owasp_zap "
        "FROM code_cwe WHERE docker = ?",
        (docker_status,),
    )
    rows = cur.fetchall()

    # Batch-fetch Burp results to avoid N per-row queries
    burp_map = burp_cwes_for_ids(conn, (r["id"] for r in rows))

    sample_counts: Dict[Tuple[str, bool], int] = defaultdict(int)
    detection_counts: Dict[Tuple[str, bool], Counter] = defaultdict(Counter)

    for row in rows:
        target = normalize_cwe(row["CWE"])
        if target is None:
            continue

        secure = is_secure_value(row["secure"])
        key = (target, secure)
        sample_counts[key] += 1

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
    return f"{target_cwe}-secure" if secure else target_cwe


def _sort_key_numeric_cwe(cwe: str) -> int:
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
    """Write human-readable report sorted by detection share."""
    lines: List[str] = [
        "=" * 78,
        "CROSS-CWE DETECTION ANALYSIS",
        "=" * 78,
        "Each line:  <targeted CWE>  (N=<samples>):  <detected CWE> <share%>, ...",
        "Share = rows where the tool stack reported the detected CWE / total group rows",
        "Burp findings sourced from burp_scan_result.mapped_cwe.",
        "",
    ]

    for section_title, want_secure in [("VULNERABLE SAMPLES", False), ("SECURE SAMPLES", True)]:
        lines += ["-" * 78, section_title, "-" * 78]

        group_keys = sorted(
            [k for k in sample_counts if k[1] == want_secure],
            key=lambda k: _sort_key_numeric_cwe(k[0]),
        )

        if not group_keys:
            lines += ["(no samples)", ""]
            continue

        for key in group_keys:
            target_cwe, secure = key
            n = sample_counts[key]
            counter = detection_counts.get(key, Counter())

            ranked = sorted(
                counter.items(),
                key=lambda kv: (-kv[1] / n if n else 0, _sort_key_numeric_cwe(kv[0])),
            )

            parts = [
                f"{det_cwe} {cnt / n * 100:5.1f}%"
                for det_cwe, cnt in ranked
                if (cnt / n if n else 0) >= min_share
            ]

            label = _group_label(target_cwe, secure)
            if parts:
                lines.append(f"{label:<18}  (N={n:>4}):  " + "  |  ".join(parts))
            else:
                lines.append(f"{label:<18}  (N={n:>4}):  "
                             f"(no detections above {min_share * 100:.1f}% threshold)")
        lines.append("")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def write_long_csv(
    out_path: str,
    sample_counts: Dict[Tuple[str, bool], int],
    detection_counts: Dict[Tuple[str, bool], Counter],
) -> None:
    """Long-form CSV: one row per (target group, detected CWE). Suitable for pandas/R."""
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "target_cwe", "security_status", "group_label",
            "sample_size", "detected_cwe", "detected_count", "detected_percent",
        ])
        for key in sorted(sample_counts, key=lambda k: (k[1], _sort_key_numeric_cwe(k[0]))):
            target_cwe, secure = key
            n = sample_counts[key]
            counter = detection_counts.get(key, Counter())
            sec_str = "secure" if secure else "vulnerable"
            label = _group_label(target_cwe, secure)

            if not counter:
                w.writerow([target_cwe, sec_str, label, n, "", 0, 0.0])
                continue

            for det_cwe, cnt in sorted(counter.items(),
                                       key=lambda kv: (-kv[1], _sort_key_numeric_cwe(kv[0]))):
                w.writerow([target_cwe, sec_str, label, n,
                            det_cwe, cnt, round(cnt / n * 100 if n else 0, 2)])


def write_matrix_csv(
    out_path: str,
    sample_counts: Dict[Tuple[str, bool], int],
    detection_counts: Dict[Tuple[str, bool], Counter],
) -> None:
    """Wide matrix CSV: rows = groups, columns = detected CWEs. Useful for heatmaps."""
    all_detected: Set[str] = set()
    for counter in detection_counts.values():
        all_detected.update(counter.keys())
    columns = sorted(all_detected, key=_sort_key_numeric_cwe)

    with open(out_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["group_label", "sample_size", *columns])
        for key in sorted(sample_counts, key=lambda k: (k[1], _sort_key_numeric_cwe(k[0]))):
            target_cwe, secure = key
            n = sample_counts[key]
            counter = detection_counts.get(key, Counter())
            row = [_group_label(target_cwe, secure), n]
            row += [round(counter.get(col, 0) / n * 100 if n else 0, 2) for col in columns]
            w.writerow(row)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Cross-CWE detection analysis on the code_cwe SQLite DB."
    )
    ap.add_argument("--db", default=os.path.join(os.path.dirname(__file__), "code_cwe.db"))
    ap.add_argument("--out-dir", default=os.path.dirname(__file__) or ".")
    ap.add_argument("--docker-status", default="tested-successful")
    ap.add_argument("--min-share", type=float, default=0.0,
                    help="Hide detected CWEs below this share in text report (e.g. 0.05 = 5%%).")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        raise SystemExit(f"Database not found: {args.db}")
    os.makedirs(args.out_dir, exist_ok=True)

    print(f"[1/4] Reading {args.db} (docker={args.docker_status!r}) ...")
    sample_counts, detection_counts = collect_detections(args.db, args.docker_status)
    print(f"      {sum(sample_counts.values())} samples, {len(sample_counts)} groups")

    txt_path    = os.path.join(args.out_dir, "cross_cwe_report.txt")
    long_path   = os.path.join(args.out_dir, "cross_cwe_long.csv")
    matrix_path = os.path.join(args.out_dir, "cross_cwe_matrix.csv")

    print(f"[2/4] Writing text report  -> {txt_path}")
    write_text_report(txt_path, sample_counts, detection_counts, min_share=args.min_share)

    print(f"[3/4] Writing long CSV     -> {long_path}")
    write_long_csv(long_path, sample_counts, detection_counts)

    print(f"[4/4] Writing matrix CSV   -> {matrix_path}")
    write_matrix_csv(matrix_path, sample_counts, detection_counts)

    print("Done.")


if __name__ == "__main__":
    main()