"""
token_analysis.py
=================
Analyzes the token length distribution of code samples stored in the
code_cwe SQLite database and reports the percentage of samples that
exceed a configurable token threshold (default: 4096 tokens).
Usage:
    python token_analysis.py
    python token_analysis.py --threshold 2048
    python token_analysis.py --threshold 8192 --db path/to/custom.db
    python token_analysis.py --breakdown          # per-CWE breakdown
    python token_analysis.py --export results.csv # save per-row data
"""

import argparse
import csv
import os
import sqlite3
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

# ── Token counting ────────────────────────────────────────────────────────────

def _build_counter():
    """
    Return a callable that counts tokens in a code string.
    Prefers tiktoken (exact); falls back to a word-based heuristic.
    """
    try:
        import tiktoken
        enc = tiktoken.get_encoding("cl100k_base")
        def count(text: str) -> int:
            return len(enc.encode(text))
        print("[INFO] Using tiktoken (cl100k_base) for token counting.")
        return count
    except ImportError:
        print("[WARN] tiktoken not found. Falling back to heuristic counter "
              "(words × 1.3). Install tiktoken for exact counts: "
              "pip install tiktoken")
        def count(text: str) -> int:
            # Heuristic: average English token ≈ 0.75 words → words / 0.75
            return int(len(text.split()) * 1.3)
        return count


count_tokens = _build_counter()


# ── Database helpers ──────────────────────────────────────────────────────────

DB_PATH = os.path.join(os.path.dirname(__file__), "code_cwe.db")

@dataclass
class CodeRecord:
    """Represents a single row fetched from code_cwe."""
    id:        int
    cwe:       str
    secure:    str
    producer:  str
    token_count: int = field(default=0, init=False)


def fetch_records(db_path: str) -> list[CodeRecord]:
    """
    Fetch all rows with non-empty code from the code_cwe table and
    compute their token counts.

    Parameters
    ----------
    db_path : str
        Path to the SQLite database file.

    Returns
    -------
    list[CodeRecord]
        One record per row, with token_count pre-populated.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id, CWE, secure, producer, code FROM code_cwe WHERE code IS NOT NULL AND code != ''"
    )
    rows = cursor.fetchall()
    conn.close()

    records: list[CodeRecord] = []
    for row_id, cwe, secure, producer, code in rows:
        rec = CodeRecord(
            id=row_id,
            cwe=str(cwe) if cwe else "UNKNOWN",
            secure=str(secure) if secure else "UNKNOWN",
            producer=str(producer) if producer else "UNKNOWN",
        )
        rec.token_count = count_tokens(code)
        records.append(rec)

    return records


# ── Statistical helpers ───────────────────────────────────────────────────────

def compute_percentile(values: list[int], p: float) -> float:
    """Return the p-th percentile of a sorted list (linear interpolation)."""
    if not values:
        return 0.0
    sorted_v = sorted(values)
    n = len(sorted_v)
    idx = (p / 100) * (n - 1)
    lo, hi = int(idx), min(int(idx) + 1, n - 1)
    frac = idx - lo
    return sorted_v[lo] + frac * (sorted_v[hi] - sorted_v[lo])


def bucket_distribution(values: list[int]) -> dict[str, int]:
    """
    Group token counts into human-readable buckets for thesis reporting.

    Buckets (tokens):
        ≤512 | 513–1024 | 1025–2048 | 2049–4096 | 4097–8192 | >8192
    """
    buckets = {
        "≤512":      0,
        "513–1024":  0,
        "1025–2048": 0,
        "2049–4096": 0,
        "4097–8192": 0,
        ">8192":     0,
    }
    for v in values:
        if v <= 512:
            buckets["≤512"] += 1
        elif v <= 1024:
            buckets["513–1024"] += 1
        elif v <= 2048:
            buckets["1025–2048"] += 1
        elif v <= 4096:
            buckets["2049–4096"] += 1
        elif v <= 8192:
            buckets["4097–8192"] += 1
        else:
            buckets[">8192"] += 1
    return buckets


# ── Reporting ─────────────────────────────────────────────────────────────────

def print_overall_summary(records: list[CodeRecord], threshold: int) -> None:
    """Print a formatted summary table to stdout."""
    token_counts = [r.token_count for r in records]
    total        = len(token_counts)
    above        = sum(1 for t in token_counts if t > threshold)
    below        = total - above
    pct_above    = (above / total * 100) if total > 0 else 0.0

    print("\n" + "=" * 60)
    print("TOKEN DISTRIBUTION ANALYSIS")
    print("=" * 60)
    print(f"  Database               : {DB_PATH}")
    print(f"  Total code samples     : {total:>8,}")
    print(f"  Threshold              : {threshold:>8,} tokens")
    print(f"  Above threshold        : {above:>8,}  ({pct_above:.2f}%)")
    print(f"  Below/equal threshold  : {below:>8,}  ({100 - pct_above:.2f}%)")
    print()
    print("  --- Descriptive Statistics ---")
    print(f"  Min tokens             : {min(token_counts):>8,}")
    print(f"  Max tokens             : {max(token_counts):>8,}")
    print(f"  Mean tokens            : {sum(token_counts)/total:>8,.1f}")
    print(f"  Median (P50)           : {compute_percentile(token_counts, 50):>8,.1f}")
    print(f"  P75                    : {compute_percentile(token_counts, 75):>8,.1f}")
    print(f"  P90                    : {compute_percentile(token_counts, 90):>8,.1f}")
    print(f"  P95                    : {compute_percentile(token_counts, 95):>8,.1f}")
    print(f"  P99                    : {compute_percentile(token_counts, 99):>8,.1f}")
    print()
    print("  --- Token Bucket Distribution ---")
    buckets = bucket_distribution(token_counts)
    for label, count in buckets.items():
        bar = "█" * min(count // max(total // 50, 1) + 1, 40)
        pct = count / total * 100 if total else 0
        print(f"  {label:<12} {bar:<42} {count:>6}  ({pct:.1f}%)")
    print("=" * 60)


def print_breakdown(records: list[CodeRecord], threshold: int) -> None:
    """Print per-CWE breakdown: how many samples exceed the threshold."""
    # Group by CWE
    cwe_groups: dict[str, list[int]] = defaultdict(list)
    for rec in records:
        cwe_groups[rec.cwe].append(rec.token_count)

    print("\n" + "=" * 60)
    print("PER-CWE BREAKDOWN  (threshold = {:,} tokens)".format(threshold))
    print("=" * 60)
    print(f"  {'CWE':<12} {'Total':>7} {'Above':>7} {'Pct':>8} {'Mean':>8}")
    print(f"  {'-'*12} {'-'*7} {'-'*7} {'-'*8} {'-'*8}")

    for cwe in sorted(cwe_groups.keys()):
        counts = cwe_groups[cwe]
        n      = len(counts)
        above  = sum(1 for c in counts if c > threshold)
        pct    = above / n * 100 if n else 0
        mean   = sum(counts) / n if n else 0
        print(f"  {cwe:<12} {n:>7,} {above:>7,} {pct:>7.1f}% {mean:>8,.0f}")

    print("=" * 60)


def export_csv(records: list[CodeRecord], path: str, threshold: int) -> None:
    """
    Export per-sample token data to a CSV file for statistical analysis
    in tools such as R, SPSS, or Excel.
    """
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "cwe", "secure", "producer",
                         "token_count", f"above_{threshold}"])
        for rec in records:
            writer.writerow([
                rec.id,
                rec.cwe,
                rec.secure,
                rec.producer,
                rec.token_count,
                1 if rec.token_count > threshold else 0,
            ])
    print(f"\n[INFO] Per-sample token data exported → {path}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze token length distribution of code samples in code_cwe.db"
    )
    parser.add_argument(
        "--threshold", type=int, default=4096,
        help="Token count threshold to report (default: 4096)"
    )
    parser.add_argument(
        "--db", type=str, default=DB_PATH,
        help="Path to the SQLite database (default: code_cwe.db next to this script)"
    )
    parser.add_argument(
        "--breakdown", action="store_true",
        help="Also print per-CWE breakdown table"
    )
    parser.add_argument(
        "--export", type=str, default=None, metavar="CSV_PATH",
        help="Export per-sample results to a CSV file for external analysis"
    )
    args = parser.parse_args()

    if not os.path.exists(args.db):
        print(f"[ERROR] Database not found: {args.db}", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] Loading records from: {args.db}")
    records = fetch_records(args.db)

    if not records:
        print("[WARN] No records with non-empty code found.", file=sys.stderr)
        sys.exit(0)

    print_overall_summary(records, args.threshold)

    if args.breakdown:
        print_breakdown(records, args.threshold)

    if args.export:
        export_csv(records, args.export, args.threshold)


if __name__ == "__main__":
    main()