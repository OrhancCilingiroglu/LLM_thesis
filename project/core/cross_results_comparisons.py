"""
CWE Co-occurrence Analysis
==========================
Investigates which CWEs systematically appear together in fine-tuned LLM
predictions and whether that pattern is explained by data imbalance.

Two inputs are supported (use either or both):
  --jsonl   : one or more JSONL evaluation files produced by data_transformer.py
              Each line must contain `target`, `local_llm_response`, and `meta`.
  --summary : the code_cwe.dbxcwe_summary.csv exported from the DB

Outputs (all written to --out_dir, default: cooccurrence_out/):
  cooccurrence_matrix.csv      – symmetric NxN matrix of pair frequencies
  cooccurrence_pairs.csv       – sorted list of (cwe_a, cwe_b, count, support)
  imbalance_report.csv         – per-CWE dataset size vs prediction frequency
  confusion_summary.csv        – per ground-truth CWE: top predicted CWEs
  cooccurrence_report.txt      – human-readable narrative report
"""

import os
import re
import json
import argparse
import csv
from collections import defaultdict, Counter
from itertools import combinations


# ---------------------------------------------------------------------------
# Regex: matches CWE-89, CWE 89, cwe-89, CWE:89 — case-insensitive
# ---------------------------------------------------------------------------
CWE_RE = re.compile(r"CWE[-:\s_]?(\d+)", re.IGNORECASE)


def parse_cwe_list(text: str) -> list[str]:
    """Extract all CWE IDs from a free-form LLM response string."""
    if not text:
        return []
    matches = CWE_RE.findall(str(text))
    seen, result = set(), []
    for m in matches:
        tag = f"CWE-{m}"
        if tag not in seen:
            seen.add(tag)
            result.append(tag)
    return result


def normalise_target(target: str) -> str | None:
    """Normalise the ground-truth target field to 'CWE-xx' or None."""
    t = str(target).strip().upper()
    if t in ("NONE", "", "NULL", "N/A"):
        return None
    if not t.startswith("CWE-"):
        t = f"CWE-{t}"
    return t


# ---------------------------------------------------------------------------
# Load JSONL evaluation files
# ---------------------------------------------------------------------------

def load_jsonl_files(paths: list[str]) -> list[dict]:
    """
    Parse one or more JSONL files.
    Each record must have `target` (ground-truth) and `local_llm_response`.
    `meta.db_secure` and `meta.db_cwe` are used as fallbacks when available.
    """
    records = []
    for path in paths:
        if not os.path.isfile(path):
            print(f"[WARN] JSONL file not found: {path}")
            continue
        with open(path, encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError as e:
                    print(f"[WARN] {path}:{i} JSON parse error: {e}")
                    continue

                meta       = obj.get("meta", {})
                target_raw = obj.get("target", meta.get("db_cwe", ""))
                llm_raw    = obj.get("local_llm_response", "")
                is_secure  = meta.get("db_secure", False)

                records.append({
                    "id":         obj.get("id"),
                    "target":     normalise_target(target_raw),
                    "predicted":  parse_cwe_list(llm_raw),
                    "is_secure":  is_secure,
                    "model":      obj.get("local_llm_model", ""),
                    "raw_response": llm_raw,
                })
    print(f"[INFO] Loaded {len(records)} records from {len(paths)} JSONL file(s).")
    return records


# ---------------------------------------------------------------------------
# Load the CSV summary (exported from cwe_summary table)
# ---------------------------------------------------------------------------

def load_summary_csv(path: str) -> list[dict]:
    """Load code_cwe.dbxcwe_summary.csv for dataset distribution analysis."""
    rows = []
    with open(path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Safely cast integer columns
            for col in ["full_match_count", "partial_match_count",
                        "bandit_detections", "semgrep_detections",
                        "sonarqube_detections", "zap_detections",
                        "burpsuite_detections", "total_detections",
                        "total_docker_ok", "secure_docker_ok", "vuln_docker_ok"]:
                try:
                    row[col] = int(row[col])
                except (ValueError, KeyError):
                    row[col] = 0
            rows.append(row)
    print(f"[INFO] Loaded {len(rows)} CWEs from summary CSV.")
    return rows


# ---------------------------------------------------------------------------
# Core analysis helpers
# ---------------------------------------------------------------------------

def build_cooccurrence(records: list[dict]) -> Counter:
    """
    Count how many samples have both cwe_a and cwe_b in the LLM prediction.
    Only considers samples where the model predicted at least 2 CWEs.
    """
    pair_counts: Counter = Counter()
    for rec in records:
        preds = rec["predicted"]
        if len(preds) < 2:
            continue
        for a, b in combinations(sorted(preds), 2):
            pair_counts[(a, b)] += 1
    return pair_counts


def build_prediction_frequency(records: list[dict]) -> Counter:
    """Count how often each CWE appears in ANY prediction (multi-CWE or not)."""
    freq: Counter = Counter()
    for rec in records:
        for cwe in rec["predicted"]:
            freq[cwe] += 1
    return freq


def build_confusion(records: list[dict]) -> dict[str, Counter]:
    """
    For each ground-truth CWE, count which CWEs the model predicted.
    Used to spot systematic mis-predictions.
    """
    confusion: dict[str, Counter] = defaultdict(Counter)
    for rec in records:
        gt = rec["target"]  # can be None for secure samples
        label = gt if gt else "NONE"
        for pred in rec["predicted"]:
            confusion[label][pred] += 1
        if not rec["predicted"]:
            confusion[label]["NONE"] += 1
    return dict(confusion)


def dataset_vs_prediction(
    summary_rows: list[dict],
    pred_freq: Counter,
    total_records: int,
) -> list[dict]:
    """
    Join per-CWE dataset population (from CSV) with per-CWE prediction frequency.
    Returns rows sorted by prediction over-representation ratio.
    """
    result = []
    all_cwes = {row["cwe"] for row in summary_rows} | set(pred_freq.keys())
    summary_lookup = {row["cwe"]: row for row in summary_rows}

    for cwe in sorted(all_cwes):
        s = summary_lookup.get(cwe, {})
        vuln_count   = s.get("vuln_docker_ok", 0)
        total_dataset = s.get("total_docker_ok", 0)
        pred_count   = pred_freq.get(cwe, 0)

        # Expected prediction rate if model were perfectly calibrated to dataset size
        expected_rate = vuln_count / total_records if total_records > 0 else 0
        actual_rate   = pred_count / total_records if total_records > 0 else 0

        # Ratio > 1 → model over-predicts this CWE relative to dataset frequency
        ratio = (actual_rate / expected_rate) if expected_rate > 0 else float("inf")

        result.append({
            "cwe":            cwe,
            "owasp_category": s.get("owasp_category", "UNKNOWN"),
            "vuln_in_dataset": vuln_count,
            "total_in_dataset": total_dataset,
            "predicted_count": pred_count,
            "expected_rate":  round(expected_rate, 4),
            "actual_rate":    round(actual_rate, 4),
            "over_rep_ratio": round(ratio, 3) if ratio != float("inf") else "inf",
        })

    # Sort by over-representation ratio (descending)
    result.sort(key=lambda r: (
        float(r["over_rep_ratio"]) if r["over_rep_ratio"] != "inf" else 9999
    ), reverse=True)
    return result


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------

def write_cooccurrence_matrix(
    pairs: Counter,
    out_dir: str,
    min_count: int = 2,
) -> None:
    """Write a symmetric co-occurrence matrix to CSV."""
    # Collect all CWEs that appear in any pair above threshold
    cwes = sorted({cwe for pair, cnt in pairs.items() if cnt >= min_count
                   for cwe in pair})
    if not cwes:
        print("[INFO] No co-occurring CWE pairs above threshold — skipping matrix.")
        return

    path = os.path.join(out_dir, "cooccurrence_matrix.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([""] + cwes)
        for row_cwe in cwes:
            row = [row_cwe]
            for col_cwe in cwes:
                if row_cwe == col_cwe:
                    row.append("")
                else:
                    key = tuple(sorted([row_cwe, col_cwe]))
                    row.append(pairs.get(key, 0) or "")
            writer.writerow(row)
    print(f"[OUT] {path}")


def write_cooccurrence_pairs(pairs: Counter, out_dir: str) -> None:
    """Write all co-occurrence pairs sorted by frequency."""
    path = os.path.join(out_dir, "cooccurrence_pairs.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["cwe_a", "cwe_b", "co_occur_count"])
        for (a, b), cnt in pairs.most_common():
            writer.writerow([a, b, cnt])
    print(f"[OUT] {path}")


def write_imbalance_report(rows: list[dict], out_dir: str) -> None:
    """Write the dataset-vs-prediction imbalance table."""
    path = os.path.join(out_dir, "imbalance_report.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        if not rows:
            return
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"[OUT] {path}")


def write_confusion_summary(confusion: dict[str, Counter], out_dir: str) -> None:
    """Write per-ground-truth-CWE top predicted CWEs."""
    path = os.path.join(out_dir, "confusion_summary.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ground_truth_cwe", "predicted_cwe", "count", "rank"])
        for gt_cwe, pred_counter in sorted(confusion.items()):
            for rank, (pred, cnt) in enumerate(pred_counter.most_common(10), 1):
                writer.writerow([gt_cwe, pred, cnt, rank])
    print(f"[OUT] {path}")


def write_narrative_report(
    records:       list[dict],
    pairs:         Counter,
    pred_freq:     Counter,
    imbalance:     list[dict],
    confusion:     dict[str, Counter],
    out_dir:       str,
    top_n:         int = 20,
) -> None:
    """Write a human-readable narrative report for thesis use."""

    path = os.path.join(out_dir, "cooccurrence_report.txt")
    total = len(records)

    # Basic prediction stats
    single_pred  = sum(1 for r in records if len(r["predicted"]) == 1)
    multi_pred   = sum(1 for r in records if len(r["predicted"]) > 1)
    no_pred      = sum(1 for r in records if len(r["predicted"]) == 0)
    secure_recs  = sum(1 for r in records if r["is_secure"])
    vuln_recs    = total - secure_recs

    # Exact-match accuracy
    correct = sum(
        1 for r in records
        if r["target"] and r["target"] in r["predicted"]
        and len(r["predicted"]) == 1
    )

    with open(path, "w", encoding="utf-8") as f:

        f.write("=" * 72 + "\n")
        f.write("CWE CO-OCCURRENCE ANALYSIS REPORT\n")
        f.write("=" * 72 + "\n\n")

        # ── 1. Dataset overview ──────────────────────────────────────────────
        f.write("1. DATASET OVERVIEW\n")
        f.write("-" * 40 + "\n")
        f.write(f"  Total evaluation records  : {total}\n")
        f.write(f"  Secure samples            : {secure_recs}\n")
        f.write(f"  Vulnerable samples        : {vuln_recs}\n\n")

        # ── 2. Prediction statistics ─────────────────────────────────────────
        f.write("2. PREDICTION STATISTICS\n")
        f.write("-" * 40 + "\n")
        f.write(f"  No prediction (NONE)      : {no_pred}  ({no_pred/total*100:.1f}%)\n")
        f.write(f"  Exactly 1 CWE predicted   : {single_pred}  ({single_pred/total*100:.1f}%)\n")
        f.write(f"  2+ CWEs predicted         : {multi_pred}  ({multi_pred/total*100:.1f}%)\n")
        f.write(f"\n  Exact-match accuracy (single correct CWE): "
                f"{correct}/{vuln_recs} = {correct/vuln_recs*100:.1f}%\n\n")

        # ── 3. Most frequently predicted CWEs ────────────────────────────────
        f.write("3. MOST FREQUENTLY PREDICTED CWEs (top 15)\n")
        f.write("-" * 40 + "\n")
        for rank, (cwe, cnt) in enumerate(pred_freq.most_common(15), 1):
            f.write(f"  {rank:>2}. {cwe:<12}  predicted {cnt}x "
                    f"({cnt/total*100:.1f}% of samples)\n")
        f.write("\n")

        # ── 4. Top co-occurring pairs ─────────────────────────────────────────
        f.write("4. TOP CO-OCCURRING CWE PAIRS IN LLM PREDICTIONS\n")
        f.write("-" * 40 + "\n")
        if not pairs:
            f.write("  No multi-CWE predictions found.\n\n")
        else:
            f.write("  These pairs appear together in the same LLM response:\n\n")
            for rank, ((a, b), cnt) in enumerate(pairs.most_common(top_n), 1):
                f.write(f"  {rank:>2}. {a} + {b}  →  {cnt} co-occurrences\n")
            f.write("\n")

        # ── 5. Imbalance analysis ─────────────────────────────────────────────
        f.write("5. DATASET SIZE vs PREDICTION FREQUENCY (imbalance check)\n")
        f.write("-" * 40 + "\n")
        f.write("  over_rep_ratio = (actual prediction rate) / (dataset share)\n")
        f.write("  ratio > 1 → model over-predicts this CWE relative to its\n")
        f.write("              frequency in the training data\n\n")

        # Top over-represented
        over_rep = [r for r in imbalance
                    if r["over_rep_ratio"] != "inf"
                    and float(r["over_rep_ratio"]) > 1.5
                    and r["predicted_count"] > 0]
        under_rep = [r for r in sorted(imbalance,
                     key=lambda x: float(x["over_rep_ratio"])
                     if x["over_rep_ratio"] != "inf" else 9999)
                     if r["predicted_count"] > 0]

        f.write(f"  Most over-represented CWEs (ratio > 1.5, top {top_n}):\n")
        for r in over_rep[:top_n]:
            f.write(
                f"    {r['cwe']:<12}  dataset={r['vuln_in_dataset']:>4}  "
                f"predicted={r['predicted_count']:>4}  "
                f"ratio={r['over_rep_ratio']}\n"
            )
        f.write(f"\n  Most under-represented CWEs (predicted rarely or never):\n")
        for r in under_rep[:10]:
            f.write(
                f"    {r['cwe']:<12}  dataset={r['vuln_in_dataset']:>4}  "
                f"predicted={r['predicted_count']:>4}  "
                f"ratio={r['over_rep_ratio']}\n"
            )
        f.write("\n")

        # ── 6. Confusion analysis ──────────────────────────────────────────────
        f.write("6. CONFUSION ANALYSIS: ground-truth vs top predictions\n")
        f.write("-" * 40 + "\n")
        for gt, pred_counter in sorted(confusion.items()):
            gt_total = sum(pred_counter.values())
            top = pred_counter.most_common(5)
            f.write(f"\n  GT={gt}  (n={gt_total})\n")
            for pred, cnt in top:
                bar = "█" * min(20, int(cnt / gt_total * 20))
                f.write(f"    pred={pred:<12}  {cnt:>4}x  {cnt/gt_total*100:>5.1f}%  {bar}\n")

        f.write("\n" + "=" * 72 + "\n")
        f.write("END OF REPORT\n")
        f.write("=" * 72 + "\n")

    print(f"[OUT] {path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Analyse CWE co-occurrence patterns in LLM evaluation outputs."
    )
    ap.add_argument(
        "--jsonl", nargs="+", default=[],
        metavar="PATH",
        help="One or more JSONL evaluation files (from data_transformer.py).",
    )
    ap.add_argument(
        "--summary", default=None,
        metavar="CSV_PATH",
        help="Path to code_cwe.dbxcwe_summary.csv for imbalance analysis.",
    )
    ap.add_argument(
        "--out_dir", default="cooccurrence_out",
        help="Directory to write all output files (default: cooccurrence_out/).",
    )
    ap.add_argument(
        "--min_pair_count", type=int, default=2,
        help="Minimum co-occurrence count to include a pair in the matrix (default: 2).",
    )
    args = ap.parse_args()

    if not args.jsonl and not args.summary:
        ap.error("Provide at least one of --jsonl or --summary.")

    os.makedirs(args.out_dir, exist_ok=True)

    # ── Load data ──────────────────────────────────────────────────────────
    records: list[dict] = []
    if args.jsonl:
        records = load_jsonl_files(args.jsonl)

    summary_rows: list[dict] = []
    if args.summary:
        summary_rows = load_summary_csv(args.summary)

    # ── Run analyses ───────────────────────────────────────────────────────
    pairs      = build_cooccurrence(records)
    pred_freq  = build_prediction_frequency(records)
    confusion  = build_confusion(records) if records else {}

    imbalance: list[dict] = []
    if summary_rows:
        imbalance = dataset_vs_prediction(summary_rows, pred_freq, len(records))

    # ── Write outputs ──────────────────────────────────────────────────────
    if pairs:
        write_cooccurrence_matrix(pairs, args.out_dir, min_count=args.min_pair_count)
        write_cooccurrence_pairs(pairs, args.out_dir)

    if imbalance:
        write_imbalance_report(imbalance, args.out_dir)

    if confusion:
        write_confusion_summary(confusion, args.out_dir)

    if records:
        write_narrative_report(
            records, pairs, pred_freq, imbalance, confusion, args.out_dir
        )

    # ── Quick console summary ──────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("QUICK SUMMARY")
    print("=" * 60)
    if records:
        total    = len(records)
        multi    = sum(1 for r in records if len(r["predicted"]) > 1)
        no_pred  = sum(1 for r in records if not r["predicted"])
        print(f"  Records loaded       : {total}")
        print(f"  Multi-CWE predictions: {multi} ({multi/total*100:.1f}%)")
        print(f"  No prediction (NONE) : {no_pred} ({no_pred/total*100:.1f}%)")
        if pairs:
            top_pair, top_cnt = pairs.most_common(1)[0]
            print(f"  Top co-occurring pair: {top_pair[0]} + {top_pair[1]} ({top_cnt}x)")
        if pred_freq:
            top_cwe, top_cwe_cnt = pred_freq.most_common(1)[0]
            print(f"  Most predicted CWE   : {top_cwe} ({top_cwe_cnt}x, "
                  f"{top_cwe_cnt/total*100:.1f}%)")
    if imbalance:
        over = [r for r in imbalance
                if r["over_rep_ratio"] not in ("inf", 0)
                and float(r["over_rep_ratio"]) > 2.0]
        print(f"  Over-represented CWEs (ratio>2): {len(over)}")
        for r in over[:5]:
            print(f"    {r['cwe']}  ratio={r['over_rep_ratio']}")
    print("=" * 60)
    print(f"\nAll outputs written to: {os.path.abspath(args.out_dir)}/\n")


if __name__ == "__main__":
    main()