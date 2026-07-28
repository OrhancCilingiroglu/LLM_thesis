"""
sast_findings_figures.py
=========================
Generates publication-quality figures for the "SAST Findings" subsection of
a thesis, from the outputs of three upstream pipeline scripts:

    1. cwe_summary.py        -> cwe_summary table (export it yourself, see below)
    2. analyser.py            -> cwe_correlation_results.txt
    3. cwe_correlations.py    -> cross_cwe_matrix.csv (optional, for the heatmap)

--------------------------------------------------------------------------
HOW TO GET THE INPUT FILES (run these once, on the same DB snapshot)
--------------------------------------------------------------------------
    python cwe_summary.py
    sqlite3 code_cwe.db -header -csv "SELECT * FROM cwe_summary;" > code_cwe_summary_export.csv
    python analyser.py                              # -> cwe_correlation_results.txt
    python cwe_correlations.py --db code_cwe.db --out-dir ./cwe_corr_out --min-share 0.05

--------------------------------------------------------------------------
USAGE
--------------------------------------------------------------------------
    python sast_findings_figures.py \
        --summary-csv code_cwe_summary_export.csv \
        --correlation-txt cwe_correlation_results.txt \
        --matrix-csv cwe_corr_out/cross_cwe_matrix.csv \
        --out-dir figures/

--matrix-csv is optional; if omitted, only figures 1-4 are produced.

--------------------------------------------------------------------------
DESIGN NOTES (read before changing thresholds/labels)
--------------------------------------------------------------------------
- Terminology is intentionally simplified to a binary outcome per sample:
  "Detected" (the tool stack identified the target CWE, whether via a single
  tool or several) vs. "Not Detected". The underlying analyser.py labels
  (FULL MATCH / PARTIAL MATCH / TOOL MATCH BUT NOT DB / NO MATCH) are
  collapsed as follows, since the FULL/PARTIAL distinction was not used
  downstream in the thesis narrative:
      Detected     = FULL MATCH + PARTIAL MATCH   (target CWE was found)
      Not Detected = NO MATCH + TOOL MATCH BUT NOT DB
                     (target CWE was NOT found, regardless of whether the
                      tool stack flagged some other, unrelated CWE)
- The "UNMAPPED" pseudo-category (CWEs that don't fall under any OWASP 2025
  Top 10 entry) is excluded from category-level figures, since it is not a
  real OWASP category and would clutter the comparison.
- SonarQube is always shown explicitly in the tool-contribution figure even
  when its detection count is zero. analyser.py's Counter.most_common() only
  prints tools with at least one hit, so a silent SonarQube==0 would
  otherwise disappear from the chart instead of being visible as a finding.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

# ---------------------------------------------------------------------------
# Shared plotting style - consistent, thesis-appropriate look
# ---------------------------------------------------------------------------
sns.set_theme(style="whitegrid", context="paper", font_scale=1.05)
FIGSIZE_WIDE = (10, 5.5)
FIGSIZE_TALL = (8, 9)
DPI = 300

# Canonical tool list. Kept explicit (rather than inferred from the report)
# so that a tool with zero detections is still rendered, not silently
# dropped by analyser.py's Counter.most_common() output.
CANONICAL_TOOLS = ["bandit", "semgrep", "sonarqube", "owasp_zap", "burpsuite"]
TOOL_DISPLAY_NAMES = {
    "bandit": "Bandit",
    "semgrep": "Semgrep",
    "sonarqube": "SonarQube",
    "owasp_zap": "OWASP ZAP",
    "burpsuite": "Burp Suite",
}

# Binary detection outcome used throughout the figures (see DESIGN NOTES).
DETECTED = "Detected"
NOT_DETECTED = "Not Detected"


def prettify_owasp_category(raw_category: str) -> str:
    """
    Convert a raw OWASP 2025 category key into a short display label.

    Example: "A05_2025_Injection" -> "A05 Injection"
             "A09_2025_Security_Logging_and_Alerting_Failures"
                 -> "A09 Security Logging and Alerting Failures"
    """
    match = re.match(r"^(A\d{2})_\d{4}_(.+)$", raw_category)
    if not match:
        return raw_category.replace("_", " ")
    code, name = match.groups()
    return f"{code} {name.replace('_', ' ')}"


# ---------------------------------------------------------------------------
# Parsers for cwe_correlation_results.txt (analyser.py output)
# ---------------------------------------------------------------------------

def parse_tool_contribution(text: str) -> pd.DataFrame:
    """
    Extract the 'TOOL DETECTION CONTRIBUTION' block into a tidy DataFrame,
    guaranteeing every tool in CANONICAL_TOOLS appears even if it recorded
    zero detections (see module docstring).
    """
    block_match = re.search(
        r"TOOL DETECTION CONTRIBUTION.*?\n(.*?)\n\s*Total tool hits",
        text,
        re.S,
    )
    if not block_match:
        raise ValueError("Could not find 'TOOL DETECTION CONTRIBUTION' section in the report.")

    parsed = re.findall(
        r"-\s*(\w+)\s*:\s*(\d+) detections\s*\(([\d.]+)% of all tool hits\)",
        block_match.group(1),
    )
    if not parsed:
        raise ValueError("No per-tool detection lines matched inside the contribution block.")

    found = {tool: (int(count), float(pct)) for tool, count, pct in parsed}

    rows = []
    for tool in CANONICAL_TOOLS:
        count, pct = found.get(tool, (0, 0.0))
        rows.append({"tool": TOOL_DISPLAY_NAMES.get(tool, tool), "detections": count, "share_pct": pct})

    df = pd.DataFrame(rows)
    return df.sort_values("detections", ascending=False).reset_index(drop=True)


def parse_overall_detection(text: str) -> pd.DataFrame:
    """
    Extract secure vs. vulnerable sample counts, collapsed into the binary
    Detected / Not Detected outcome (see module docstring for the mapping).
    """
    result = []
    for sample_type, heading in [("Secure", "Secure correlation distribution:"),
                                  ("Vulnerable", "Vulnerable correlation distribution:")]:
        block_match = re.search(rf"{re.escape(heading)}\n((?:\s*-.*\n)+)", text)
        if not block_match:
            continue

        detected = not_detected = 0
        for outcome, count in re.findall(r"-\s*(.+?):\s*(\d+)\s*\(", block_match.group(1)):
            count = int(count)
            if outcome.strip() in ("FULL MATCH", "PARTIAL MATCH"):
                detected += count
            else:  # NO MATCH, TOOL MATCH BUT NOT DB
                not_detected += count

        result.append({"sample_type": sample_type, "outcome": DETECTED, "count": detected})
        result.append({"sample_type": sample_type, "outcome": NOT_DETECTED, "count": not_detected})

    if not result:
        raise ValueError("Could not find secure/vulnerable correlation distribution blocks.")
    return pd.DataFrame(result)


def parse_owasp_category_detection(text: str) -> pd.DataFrame:
    """
    Extract, per OWASP 2025 category, the vulnerable-sample Detected /
    Not Detected counts. The "UNMAPPED" pseudo-category is dropped since it
    is not a genuine OWASP category.
    """
    category_pattern = re.compile(r"^\[(?P<cat>[\w]+)\]\n(?P<body>.*?)(?=\n\[\w+\]\n|\Z)", re.S | re.M)
    rows = []
    for m in category_pattern.finditer(text):
        cat = m.group("cat")
        if cat == "UNMAPPED":
            continue

        body = m.group("body")
        vuln_block = re.search(r"Vulnerable Codes:\n(.*?)\n {2}Secure Codes:", body, re.S)
        if not vuln_block:
            continue

        detected = not_detected = 0
        for outcome, count in re.findall(
            r"\*\s*(FULL MATCH|PARTIAL MATCH|TOOL MATCH BUT NOT DB|NO MATCH):\s*(\d+)",
            vuln_block.group(1),
        ):
            count = int(count)
            if outcome in ("FULL MATCH", "PARTIAL MATCH"):
                detected += count
            else:
                not_detected += count

        total = detected + not_detected
        if total == 0:
            continue

        rows.append({
            "owasp_category": prettify_owasp_category(cat),
            "total_vulnerable_valid": total,
            DETECTED: detected,
            NOT_DETECTED: not_detected,
        })

    if not rows:
        raise ValueError("Could not find any OWASP category blocks in the report.")
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Figure builders
# ---------------------------------------------------------------------------

def fig1_tool_contribution(df: pd.DataFrame, out_path: Path) -> None:
    """Horizontal bar chart: which tool contributes what share of detections."""
    fig, ax = plt.subplots(figsize=(8, 4.5))
    colors = ["#4C72B0" if d > 0 else "#B0B0B0" for d in df["detections"]]
    bars = ax.barh(df["tool"], df["detections"], color=colors)
    ax.invert_yaxis()  # highest contributor on top
    ax.set_xlabel("Independent detections of the target CWE")
    ax.set_title("Per-tool contribution to correct CWE detection\n(vulnerable samples only)")

    max_val = max(df["detections"].max(), 1)
    for bar, count, pct in zip(bars, df["detections"], df["share_pct"]):
        label = f"{count}  ({pct:.1f}%)" if count > 0 else "0 (no detections)"
        ax.text(bar.get_width() + max_val * 0.01, bar.get_y() + bar.get_height() / 2,
                label, va="center", fontsize=9)

    fig.tight_layout()
    fig.savefig(out_path, dpi=DPI)
    plt.close(fig)
    print(f"[fig1] wrote {out_path}")


def fig2_overall_detection(df: pd.DataFrame, out_path: Path) -> None:
    """
    Grouped bar chart comparing secure vs. vulnerable detection outcomes.

    Each bar is annotated with its raw sample count, since a bare visual
    comparison of bar heights is not sufficient to cite in a thesis --
    the underlying number must always be readable directly on the figure.
    """
    pivot = df.pivot(index="outcome", columns="sample_type", values="count").reindex([DETECTED, NOT_DETECTED])

    fig, ax = plt.subplots(figsize=FIGSIZE_WIDE)
    pivot.plot(kind="bar", ax=ax, color=["#4C72B0", "#DD8452"])
    ax.set_ylabel("Number of samples")
    ax.set_xlabel("")
    ax.set_title("Detection outcome: secure vs. vulnerable samples")
    ax.legend(title="Sample type")
    plt.setp(ax.get_xticklabels(), rotation=0)

    # Annotate every bar with its exact count (data label requirement).
    for container in ax.containers:
        ax.bar_label(container, fmt="%d", padding=2, fontsize=9)
    ax.margins(y=0.12)  # room for the labels above the tallest bar

    fig.tight_layout()
    fig.savefig(out_path, dpi=DPI)
    plt.close(fig)
    print(f"[fig2] wrote {out_path}")


def fig3_owasp_category(df: pd.DataFrame, out_path: Path) -> None:
    """
    100%-stacked horizontal bar chart of Detected / Not Detected shares per
    OWASP category.

    Each segment is labelled with both its percentage share and the raw
    sample count behind it (e.g. "19.1% (n=393)"), since a percentage alone
    cannot be traced back to the underlying evidence in the thesis text.
    """
    counts = df.set_index("owasp_category")[[DETECTED, NOT_DETECTED]]
    totals = df.set_index("owasp_category")["total_vulnerable_valid"]
    shares = counts.div(totals, axis=0) * 100
    shares = shares.sort_values(DETECTED, ascending=True)
    counts = counts.loc[shares.index]  # keep counts aligned with the sorted shares

    fig, ax = plt.subplots(figsize=FIGSIZE_TALL)
    colors = {DETECTED: "#2ca02c", NOT_DETECTED: "#d62728"}
    left = pd.Series(0.0, index=shares.index)

    for outcome in [DETECTED, NOT_DETECTED]:
        bars = ax.barh(shares.index, shares[outcome], left=left, color=colors[outcome], label=outcome)
        for bar, pct, count in zip(bars, shares[outcome], counts[outcome]):
            if pct < 3:  # skip labels on slivers too thin to render legibly
                continue
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_y() + bar.get_height() / 2,
                     f"{pct:.1f}%\n(n={count})", ha="center", va="center", fontsize=7.5, color="white")
        left += shares[outcome]

    ax.set_xlabel("Share of vulnerable samples (%)")
    ax.set_ylabel("")
    ax.set_xlim(0, 100)
    ax.set_title("Detection rate by OWASP 2025 category (vulnerable samples)")
    ax.legend(title="Outcome", bbox_to_anchor=(1.02, 1), loc="upper left")

    fig.tight_layout()
    fig.savefig(out_path, dpi=DPI)
    plt.close(fig)
    print(f"[fig3] wrote {out_path}")


def fig4_cwe_recall_extremes(summary_csv: pd.DataFrame, out_path: Path,
                               min_population: int = 10, top_n: int = 15) -> None:
    """
    Bar chart of the best- and worst-detected CWEs by recall, restricted to
    CWEs with at least `min_population` vulnerable samples (to avoid noisy
    ratios from tiny groups).
    """
    df = summary_csv.copy()
    df["detected"] = df["full_match_count"] + df["partial_match_count"]
    df = df[df["vuln_docker_ok"] >= min_population].copy()
    df["recall_pct"] = df["detected"] / df["vuln_docker_ok"] * 100

    best = df.sort_values("recall_pct", ascending=False).head(top_n)
    worst = df.sort_values("recall_pct", ascending=True).head(top_n)

    fig, axes = plt.subplots(1, 2, figsize=(12, 6), sharex=True)

    axes[0].barh(best["cwe"], best["recall_pct"], color="#2ca02c")
    axes[0].invert_yaxis()
    axes[0].set_title(f"Best-detected CWEs (n>={min_population})")
    axes[0].set_xlabel("Detection rate (%)")

    axes[1].barh(worst["cwe"], worst["recall_pct"], color="#d62728")
    axes[1].invert_yaxis()
    axes[1].set_title(f"Worst-detected CWEs (n>={min_population})")
    axes[1].set_xlabel("Detection rate (%)")

    fig.suptitle("Detection-rate extremes across target CWEs")
    fig.tight_layout()
    fig.savefig(out_path, dpi=DPI)
    plt.close(fig)
    print(f"[fig4] wrote {out_path}")


def fig5_cross_cwe_heatmap(
    matrix_csv: pd.DataFrame,
    out_path: Path,
    top_n_rows: int = 25,
    top_n_cols: int = 20,
    include_secure_rows: bool = False,
    annotate_min_pct: float = 1.0,
) -> None:
    """
    Heatmap of cross_cwe_matrix.csv: rows = target CWE groups, columns =
    CWEs actually reported by the tool stack, values = detection share (%).

    cross_cwe_matrix.csv typically has one row per *target* CWE (plus a
    "-secure" variant row per CWE) and one column per *every* CWE ever
    reported by any tool -- easily 200+ columns and 100+ rows, which makes
    the raw matrix unreadable as a single figure. This function makes it
    presentable by:
      1. Dropping "-secure" rows by default (a thesis "SAST findings"
         figure is about vulnerable-sample detection, not false positives;
         set include_secure_rows=True to keep them).
      2. Keeping only the `top_n_rows` target CWEs with the largest sample
         size (statistically the most reliable rows).
      3. Keeping only the `top_n_cols` most frequently reported CWEs
         *within that reduced row set* (not the full matrix), so the
         columns shown are the ones actually relevant to the rows plotted.
      4. Masking (leaving blank) any cell below `annotate_min_pct`, so the
         figure highlights genuine cross-detection patterns instead of
         being covered in near-zero noise.
    """
    matrix_csv = matrix_csv.copy()

    if not include_secure_rows:
        matrix_csv = matrix_csv[~matrix_csv["group_label"].str.endswith("-secure")]

    matrix_csv = matrix_csv.set_index("group_label")
    value_cols = [c for c in matrix_csv.columns if c != "sample_size"]

    # Row selection: the CWEs with the largest, most statistically reliable sample sizes.
    row_selection = matrix_csv["sample_size"].sort_values(ascending=False).head(top_n_rows).index
    reduced = matrix_csv.loc[row_selection, value_cols]

    # Column selection: most frequently reported CWEs, computed only within the selected rows.
    col_selection = reduced.sum(axis=0).sort_values(ascending=False).head(top_n_cols).index
    reduced = reduced[col_selection]

    # Hide near-zero cells instead of cluttering the figure with them.
    mask = reduced < annotate_min_pct

    fig, ax = plt.subplots(figsize=(max(10, 0.55 * len(col_selection)), max(8, 0.4 * len(row_selection))))
    sns.heatmap(
        reduced, mask=mask, cmap="rocket_r", ax=ax, annot=True, fmt=".0f",
        annot_kws={"fontsize": 7}, linewidths=0.3, linecolor="#EEEEEE",
        cbar_kws={"label": "Detection share (%)"},
    )
    ax.set_xlabel("CWE actually reported by the tool stack")
    ax.set_ylabel("Target CWE (top {} by sample size)".format(len(row_selection)))
    ax.set_title(
        f"Cross-CWE detection matrix\n"
        f"(top {len(row_selection)} target CWEs x top {len(col_selection)} reported CWEs, "
        f"cells < {annotate_min_pct:.0f}% hidden)"
    )
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right")

    fig.tight_layout()
    fig.savefig(out_path, dpi=DPI)
    plt.close(fig)
    print(f"[fig5] wrote {out_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("---")[0])
    ap.add_argument("--summary-csv", required=True,
                     help="Exported cwe_summary table (from cwe_summary.py).")
    ap.add_argument("--correlation-txt", required=True,
                     help="cwe_correlation_results.txt (from analyser.py).")
    ap.add_argument("--matrix-csv", default=None,
                     help="cross_cwe_matrix.csv (from cwe_correlations.py). Optional.")
    ap.add_argument("--out-dir", default="figures",
                     help="Directory to write PNG figures into (default: figures/).")
    ap.add_argument("--min-population", type=int, default=10,
                     help="Minimum vulnerable-sample count for a CWE to appear "
                          "in the recall-extremes figure (default: 10).")
    ap.add_argument("--heatmap-top-rows", type=int, default=25,
                     help="Number of target CWE rows to keep in the fig5 heatmap "
                          "(default: 25, chosen by largest sample size).")
    ap.add_argument("--heatmap-top-cols", type=int, default=20,
                     help="Number of reported-CWE columns to keep in the fig5 heatmap "
                          "(default: 20, chosen within the selected rows).")
    ap.add_argument("--heatmap-include-secure-rows", action="store_true",
                     help="Include '-secure' rows in the fig5 heatmap (default: off, "
                          "since SAST findings figures focus on vulnerable samples).")
    ap.add_argument("--heatmap-annotate-min-pct", type=float, default=1.0,
                     help="Hide fig5 heatmap cells below this percentage to reduce "
                          "visual noise (default: 1.0).")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    correlation_text = Path(args.correlation_txt).read_text(encoding="utf-8")
    summary_df = pd.read_csv(args.summary_csv)

    print("[1/4] Parsing tool contribution ...")
    tool_df = parse_tool_contribution(correlation_text)
    fig1_tool_contribution(tool_df, out_dir / "fig1_tool_contribution.png")

    print("[2/4] Parsing overall detection outcome ...")
    overall_df = parse_overall_detection(correlation_text)
    fig2_overall_detection(overall_df, out_dir / "fig2_overall_detection.png")

    print("[3/4] Parsing OWASP category blocks ...")
    owasp_df = parse_owasp_category_detection(correlation_text)
    fig3_owasp_category(owasp_df, out_dir / "fig3_owasp_category.png")

    print("[4/4] Building CWE detection-rate extremes chart ...")
    fig4_cwe_recall_extremes(summary_df, out_dir / "fig4_cwe_recall_extremes.png",
                              min_population=args.min_population)

    if args.matrix_csv:
        print("[optional] Building cross-CWE heatmap ...")
        matrix_df = pd.read_csv(args.matrix_csv)
        fig5_cross_cwe_heatmap(
            matrix_df, out_dir / "fig5_cross_cwe_heatmap.png",
            top_n_rows=args.heatmap_top_rows,
            top_n_cols=args.heatmap_top_cols,
            include_secure_rows=args.heatmap_include_secure_rows,
            annotate_min_pct=args.heatmap_annotate_min_pct,
        )
    else:
        print("[optional] --matrix-csv not provided, skipping fig5 (heatmap).")

    print(f"\nAll figures written to: {out_dir.resolve()}/")


if __name__ == "__main__":
    main()