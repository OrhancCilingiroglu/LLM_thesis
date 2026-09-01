"""
cwe_cooccurrence.py
===================

Co-occurrence and marginal-bias analysis of CWEs from two sources:

    1. DATASET side  : CWE sets extracted from SAST/DAST tool outputs
                       (bandit, semgrep, sonarqube, owasp_zap, burpsuite)
                       per row in the ``code_cwe`` table.

    2. LLM side      : CWE sets extracted from ``local_llm_response`` fields
                       of JSONL files produced by ``data_transformer.py``.

For each source the script produces:

    * a marginal-frequency table  : how often each CWE appears in any document
    * a co-occurrence table       : every observed pair (a, b) with joint
                                    count, marginals, lift and PMI
    * a heatmap of the top-N CWEs (lift-based, capped to most frequent CWEs)

It also produces a marginal-bias comparison:

    * how often each CWE appears in the dataset vs in LLM responses,
      expressed as proportion, log-ratio and a chi-square test

Why PMI / lift instead of raw counts?
-------------------------------------
Two CWEs can appear together simply because both are very frequent on their
own. PMI and lift normalise for marginal frequency: if lift > 1 the pair
co-occurs more than independence would predict, and PMI = log(lift). This
distinguishes structural correlation (e.g. CWE-89 + CWE-20, both involving
input handling) from spurious co-occurrence driven by a skewed dataset.

Usage
-----
    python cwe_cooccurrence.py dataset
    python cwe_cooccurrence.py llm exports/local_llm_*.jsonl
    python cwe_cooccurrence.py compare
    python cwe_cooccurrence.py all  exports/local_llm_*.jsonl
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
import math
import os
import re
import sqlite3
import sys

from collections import Counter, defaultdict
from itertools import combinations
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

# ---------------------------------------------------------------------------
# Project imports — kept minimal to allow the script to be run from the
# project root without extra setup.
# ---------------------------------------------------------------------------
try:
    from core.db_handler import DBManager
    from core.cwe_correlations import parse_sonarqube_cwes
except ImportError:                                    # pragma: no cover
    # Fallback for running outside the project (e.g. unit tests). The
    # dataset-side analysis simply will not work in that case.
    DBManager = None                                   # type: ignore
    parse_sonarqube_cwes = None                         # type: ignore


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PLACEHOLDERS = {
    "not-tested", "not_tested", "not tested",
    "na", "n/a", "none", "null", "nan", "-", "",
}

# ZAP CWE token regex (used both for ZAP's "tags" keys and as a sanity check)
CWE_RE = re.compile(r"CWE-\d+", flags=re.IGNORECASE)


# ===========================================================================
# Generic helpers
# ===========================================================================

def _normalise_cwe(token: str) -> Optional[str]:
    """Return ``CWE-<n>`` (uppercase) if ``token`` is a valid CWE id, else None."""
    if token is None:
        return None
    s = str(token).strip().upper()
    if not s:
        return None
    if not s.startswith("CWE-"):
        # accept bare numbers like "89"
        if s.isdigit():
            s = f"CWE-{s}"
        else:
            return None
    try:
        n = int(s.replace("CWE-", "").strip())
    except ValueError:
        return None
    if n <= 0:
        return None
    return f"CWE-{n}"


def parse_sast_cwes(raw: Optional[str]) -> Set[str]:
    """Parse a comma-separated SAST tool output into a set of CWE ids."""
    out: Set[str] = set()
    if not raw:
        return out
    s = str(raw).strip()
    if s.lower() in PLACEHOLDERS:
        return out
    for tok in s.split(","):
        cwe = _normalise_cwe(tok)
        if cwe is not None:
            out.add(cwe)
    # also catch CWE-xx tokens embedded in free-text fields (e.g. semgrep
    # sometimes emits "tags=[CWE-79]")
    for tok in CWE_RE.findall(s):
        cwe = _normalise_cwe(tok)
        if cwe is not None:
            out.add(cwe)
    return out


def _safe_json(raw) -> Optional[object]:
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


def parse_zap_cwes(zap_raw) -> Set[str]:
    """Extract CWE ids from a raw OWASP ZAP JSON blob."""
    found: Set[str] = set()
    alerts = _safe_json(zap_raw)
    if alerts is None:
        return found

    # ZAP reports come in a few shapes ("alerts" list, "site"->[{"alerts":[...]}],
    # plain list). Normalise to a list of alert dicts.
    if isinstance(alerts, dict):
        if isinstance(alerts.get("alerts"), list):
            alerts = alerts["alerts"]
        elif isinstance(alerts.get("site"), list):
            merged: List = []
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
        cweid = str(alert.get("cweid", "")).strip()
        if cweid and cweid not in ("0", "-1"):
            cwe = _normalise_cwe(f"CWE-{cweid}")
            if cwe is not None:
                found.add(cwe)
        tags = alert.get("tags", {})
        if isinstance(tags, dict):
            for tag_key in tags:
                cwe = _normalise_cwe(tag_key)
                if cwe is not None:
                    found.add(cwe)
    return found


def parse_llm_cwes(text: Optional[str]) -> Set[str]:
    """Extract every CWE id mentioned in a free-text LLM response."""
    if not text:
        return set()
    out: Set[str] = set()
    for tok in CWE_RE.findall(str(text)):
        cwe = _normalise_cwe(tok)
        if cwe is not None:
            out.add(cwe)
    return out


# ===========================================================================
# Dataset-side extraction
# ===========================================================================

def extract_dataset_cwe_sets(
    db_path: Optional[str] = None,
    docker_status: str = "tested-successful",
    include_target: bool = False,
    secure_filter: Optional[str] = None,
) -> List[Tuple[int, Set[str]]]:
    """
    Read the ``code_cwe`` table and return a list of ``(row_id, cwe_set)``
    tuples where ``cwe_set`` is the union of CWE ids reported by the
    SAST/DAST tools for that row.

    Parameters
    ----------
    db_path : str, optional
        Override path to the SQLite database. Defaults to ``DBManager``'s
        configured path.
    docker_status : str
        Restrict to rows whose ``docker`` column equals this value. Use ""
        to disable the filter.
    include_target : bool
        If True, the row's labelled ``CWE`` is added to the set as well.
        Default False — the dataset side then represents "what tools
        observed", which is the cleanest analogue of the LLM side.
    secure_filter : str, optional
        ``"secure"``, ``"vulnerable"`` or None (no filter).
    """
    if DBManager is None:
        raise RuntimeError(
            "DBManager unavailable — run this script from the project root "
            "so that `core.db_handler` is importable."
        )

    db = DBManager(db_path) if db_path else DBManager()

    # Pull all needed columns in a single query for speed. The schema names
    # follow the existing project (column "CWE", lower-case tool columns).
    where_parts: List[str] = []
    params: List = []
    if docker_status:
        where_parts.append("docker = ?")
        params.append(docker_status)
    where_clause = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""

    sql = (
        "SELECT id, CWE, secure, "
        "       bandit, semgrep, sonarqube, owasp_zap, burpsuite "
        f"FROM code_cwe {where_clause}"
    )

    conn = sqlite3.connect(db.db_path)
    try:
        rows = conn.execute(sql, tuple(params)).fetchall()
    finally:
        conn.close()

    out: List[Tuple[int, Set[str]]] = []
    for row in rows:
        rid, db_cwe_raw, secure_raw, bandit, semgrep, sonarqube, zap, burp = row

        if secure_filter is not None:
            is_sec = _is_secure(secure_raw)
            if secure_filter == "secure" and not is_sec:
                continue
            if secure_filter == "vulnerable" and is_sec:
                continue

        cwe_set: Set[str] = set()
        cwe_set |= parse_sast_cwes(bandit)
        cwe_set |= parse_sast_cwes(semgrep)
        cwe_set |= parse_sonarqube_cwes(sonarqube)
        cwe_set |= parse_zap_cwes(zap)

        # BurpSuite stores only "found"/"not-found" relative to the
        # *targeted* CWE. We do not learn a new CWE from it, but if the
        # caller asked for the target to be included and burp confirmed it,
        # the target is already present anyway via SAST/ZAP in most cases.
        if include_target:
            target = _normalise_cwe(db_cwe_raw)
            if target is not None:
                cwe_set.add(target)
        else:
            # Even when not including the target, an empty set is useless
            # for co-occurrence; we keep it to compute totals correctly
            # but the document contributes 0 pairs.
            pass

        # Suppress burp variable warning when target not included
        _ = burp

        out.append((int(rid), cwe_set))

    return out


def _is_secure(raw) -> bool:
    if raw is None:
        return False
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, int):
        return raw == 1
    s = str(raw).strip().upper()
    return s in {"SECURE", "TRUE", "1", "YES", "Y"}


# ===========================================================================
# LLM-side extraction
# ===========================================================================

def extract_llm_cwe_sets(
    jsonl_paths: Sequence[str],
    require_response: bool = True,
) -> List[Tuple[int, Set[str]]]:
    """
    Read one or more JSONL files produced by ``data_transformer.py`` and
    return ``(record_id, cwe_set)`` tuples parsed from
    ``local_llm_response``.

    Records with an empty response are skipped if ``require_response`` is
    True (default) — they have not been scored by the model yet.
    """
    out: List[Tuple[int, Set[str]]] = []
    seen_ids: Set[int] = set()        # de-duplicate across files
    n_files = 0

    for path in jsonl_paths:
        if not os.path.isfile(path):
            print(f"[llm] WARN: not a file, skipping: {path}", file=sys.stderr)
            continue
        n_files += 1
        with open(path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError as e:
                    print(
                        f"[llm] WARN: bad JSON {path}:{line_no} ({e})",
                        file=sys.stderr,
                    )
                    continue

                rid = rec.get("id")
                resp = rec.get("local_llm_response", "") or ""
                if require_response and not resp.strip():
                    continue

                if rid in seen_ids:
                    continue
                if isinstance(rid, int):
                    seen_ids.add(rid)

                cwe_set = parse_llm_cwes(resp)
                out.append((rid if isinstance(rid, int) else -1, cwe_set))

    print(f"[llm] read {len(out)} responses from {n_files} file(s)")
    return out


# ===========================================================================
# Co-occurrence and PMI / lift
# ===========================================================================

def compute_marginals_and_pairs(
    documents: Iterable[Tuple[int, Set[str]]],
) -> Tuple[Counter, Counter, int, int]:
    """
    Walk a sequence of (id, cwe_set) pairs and return:

        marginals : Counter[cwe] = number of documents containing cwe
        pairs     : Counter[(cwe_a, cwe_b)] = number of documents
                    containing both, with cwe_a < cwe_b lexicographically
        n_total   : total documents inspected
        n_with_any: documents that contributed at least one CWE
    """
    marginals: Counter = Counter()
    pairs: Counter = Counter()
    n_total = 0
    n_with_any = 0

    for _rid, cwe_set in documents:
        n_total += 1
        if not cwe_set:
            continue
        n_with_any += 1

        for cwe in cwe_set:
            marginals[cwe] += 1

        # Single-CWE documents contribute no pairs but still count toward
        # marginals. For >=2 CWEs, enumerate unordered pairs.
        if len(cwe_set) >= 2:
            for a, b in combinations(sorted(cwe_set), 2):
                pairs[(a, b)] += 1

    return marginals, pairs, n_total, n_with_any


def cooccurrence_table(
    marginals: Counter,
    pairs: Counter,
    n_total: int,
    min_support: int = 10,
) -> List[Dict[str, object]]:
    """
    Build a list of dicts, one per pair, with PMI and lift.

    PMI uses base-2 logarithm so values map to a bits-of-information scale
    that is easy to reason about (PMI = 1 bit -> co-occurrence is twice
    as likely as independence predicts).

    Pairs whose joint count is below ``min_support`` are dropped to avoid
    PMI noise on rare pairs.
    """
    if n_total <= 0:
        return []

    rows: List[Dict[str, object]] = []
    for (a, b), joint in pairs.items():
        if joint < min_support:
            continue
        ma = marginals[a]
        mb = marginals[b]
        if ma == 0 or mb == 0:
            continue
        p_a = ma / n_total
        p_b = mb / n_total
        p_ab = joint / n_total
        expected = p_a * p_b
        if expected <= 0:
            continue
        lift = p_ab / expected
        # joint > 0 here (joint >= min_support >= 1)
        pmi = math.log2(lift) if lift > 0 else 0.0
        # Conditional probabilities help interpretation
        p_b_given_a = joint / ma
        p_a_given_b = joint / mb
        rows.append({
            "cwe_a":           a,
            "cwe_b":           b,
            "joint":           joint,
            "marginal_a":      ma,
            "marginal_b":      mb,
            "p_ab":            p_ab,
            "p_a":             p_a,
            "p_b":             p_b,
            "lift":            lift,
            "pmi_bits":        pmi,
            "p_b_given_a":     p_b_given_a,
            "p_a_given_b":     p_a_given_b,
        })

    rows.sort(key=lambda r: (-r["lift"], -r["joint"]))      # type: ignore[index]
    return rows


# ===========================================================================
# CSV writers
# ===========================================================================

def write_marginals_csv(marginals: Counter, n_total: int, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    rows = sorted(marginals.items(), key=lambda kv: (-kv[1], kv[0]))
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["cwe", "count", "n_total", "proportion"])
        for cwe, c in rows:
            w.writerow([cwe, c, n_total, f"{c / n_total:.6f}" if n_total else "0"])
    print(f"[out] wrote marginals -> {path}  ({len(rows)} CWEs)")


def write_pairs_csv(rows: List[Dict[str, object]], path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if not rows:
        print(f"[out] no pairs to write -> {path}")
        return
    fields = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"[out] wrote pairs     -> {path}  ({len(rows)} rows)")


# ===========================================================================
# Heatmap (PMI / lift) for top-N CWEs
# ===========================================================================

def plot_lift_heatmap(
    marginals: Counter,
    pairs: Counter,
    n_total: int,
    out_path: str,
    top_n: int = 20,
    title: str = "CWE co-occurrence lift",
) -> None:
    """Square heatmap of lift between the top-N most frequent CWEs."""
    try:
        import numpy as np
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as e:
        print(f"[plot] matplotlib/numpy not available ({e}); skipping {out_path}")
        return

    if n_total <= 0 or not marginals:
        print(f"[plot] no data; skipping {out_path}")
        return

    top = [c for c, _ in marginals.most_common(top_n)]
    # Sort by CWE numeric for a tidy axis
    top.sort(key=lambda c: int(c.replace("CWE-", "")))
    idx = {c: i for i, c in enumerate(top)}
    k = len(top)
    mat = np.full((k, k), np.nan, dtype=float)

    for a in top:
        for b in top:
            if a == b:
                # Diagonal: self-lift = 1 / P(a) -> not meaningful, leave NaN
                continue
            key = (a, b) if a < b else (b, a)
            joint = pairs.get(key, 0)
            ma = marginals[a]
            mb = marginals[b]
            if ma == 0 or mb == 0:
                continue
            expected = (ma / n_total) * (mb / n_total)
            if joint == 0 or expected <= 0:
                mat[idx[a], idx[b]] = 0.0
            else:
                p_ab = joint / n_total
                mat[idx[a], idx[b]] = p_ab / expected

    fig, ax = plt.subplots(figsize=(max(8, 0.45 * k + 4),
                                    max(7, 0.45 * k + 3)))
    # Mask the diagonal
    masked = np.ma.masked_invalid(mat)
    cmap = plt.get_cmap("viridis").copy()
    cmap.set_bad(color="#dddddd")

    im = ax.imshow(masked, cmap=cmap, aspect="auto",
                   vmin=0.0, vmax=max(2.0, float(np.nanmax(masked) or 2.0)))
    ax.set_xticks(range(k))
    ax.set_yticks(range(k))
    ax.set_xticklabels(top, rotation=90, fontsize=8)
    ax.set_yticklabels(top, fontsize=8)
    ax.set_title(f"{title}\n(top {k} CWEs by frequency, N={n_total})")
    cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    cbar.set_label("lift = P(a,b) / [P(a) P(b)]")
    fig.tight_layout()
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    fig.savefig(out_path, dpi=160)
    plt.close(fig)
    print(f"[plot] wrote heatmap  -> {out_path}")


# ===========================================================================
# Marginal-bias comparison (dataset vs LLM)
# ===========================================================================

def compare_marginals(
    dataset_marg: Counter, n_dataset: int,
    llm_marg: Counter,     n_llm: int,
    out_csv: str,
    out_png: Optional[str] = None,
    min_either: int = 5,
) -> None:
    """
    Compare per-CWE marginal frequencies between dataset and LLM.

    For every CWE that appears in either source we record:

        count_dataset, p_dataset, count_llm, p_llm,
        log2_ratio_llm_over_dataset, chi2, p_value

    Where the chi-square test uses a 2x2 contingency table::

           dataset_yes  dataset_no
        llm_yes ...        ...
        llm_no  ...        ...

    A small ``min_either`` filter avoids reporting on CWEs seen only once
    or twice in either source.
    """
    try:
        from scipy.stats import chi2_contingency
        have_scipy = True
    except ImportError:
        have_scipy = False
        print("[bias] scipy not available — chi-square columns will be blank.")

    cwes = sorted(set(dataset_marg) | set(llm_marg),
                  key=lambda c: int(c.replace("CWE-", "")))
    rows: List[Dict[str, object]] = []
    for cwe in cwes:
        d = dataset_marg.get(cwe, 0)
        l = llm_marg.get(cwe, 0)
        if d + l < min_either:
            continue
        p_d = d / n_dataset if n_dataset else 0.0
        p_l = l / n_llm     if n_llm     else 0.0

        # Add 0.5 (Haldane) only for the log-ratio so it never blows up;
        # keep raw counts in their own columns.
        d_smooth = d + 0.5
        l_smooth = l + 0.5
        n_d_smooth = n_dataset + 1
        n_l_smooth = n_llm + 1
        pd_s = d_smooth / n_d_smooth
        pl_s = l_smooth / n_l_smooth
        log2_ratio = math.log2(pl_s / pd_s) if pd_s > 0 else 0.0

        chi2_v: object = ""
        p_val: object = ""
        if have_scipy and n_dataset > 0 and n_llm > 0:
            table = [
                [d,                  n_dataset - d],
                [l,                  n_llm - l],
            ]
            try:
                chi2_v_, p_val_, _, _ = chi2_contingency(table, correction=True)
                chi2_v = f"{chi2_v_:.4f}"
                p_val  = f"{p_val_:.6g}"
            except Exception:
                pass

        rows.append({
            "cwe":                       cwe,
            "count_dataset":             d,
            "count_llm":                 l,
            "p_dataset":                 round(p_d, 6),
            "p_llm":                     round(p_l, 6),
            "log2_ratio_llm_over_dataset": round(log2_ratio, 4),
            "chi2":                      chi2_v,
            "p_value":                   p_val,
        })

    # Sort by absolute log-ratio descending: most divergent CWEs at the top
    rows.sort(key=lambda r: -abs(float(r["log2_ratio_llm_over_dataset"])))   # type: ignore[arg-type]

    os.makedirs(os.path.dirname(out_csv) or ".", exist_ok=True)
    if rows:
        fields = list(rows[0].keys())
        with open(out_csv, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            for r in rows:
                w.writerow(r)
    print(f"[bias] wrote marginal comparison -> {out_csv}  ({len(rows)} CWEs)")

    if out_png and rows:
        try:
            import numpy as np
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
        except ImportError:
            print("[bias] matplotlib not available; skipping plot")
            return

        # Top-K most divergent for readability
        top_k = min(30, len(rows))
        sub = rows[:top_k]
        labels = [r["cwe"] for r in sub]
        ratios = [float(r["log2_ratio_llm_over_dataset"]) for r in sub]
        colors = ["#d62728" if v > 0 else "#1f77b4" for v in ratios]

        fig, ax = plt.subplots(figsize=(8, max(5, 0.30 * top_k + 1.5)))
        y = np.arange(top_k)
        ax.barh(y, ratios, color=colors)
        ax.set_yticks(y)
        ax.set_yticklabels(labels, fontsize=8)
        ax.invert_yaxis()
        ax.axvline(0, color="black", linewidth=0.8)
        ax.set_xlabel("log2( P_LLM(cwe) / P_dataset(cwe) )")
        ax.set_title(
            "Marginal bias: red = LLM over-produces, blue = under-produces\n"
            f"(top {top_k} most divergent CWEs;  "
            f"N_dataset={n_dataset}, N_llm={n_llm})"
        )
        fig.tight_layout()
        fig.savefig(out_png, dpi=160)
        plt.close(fig)
        print(f"[bias] wrote bias plot           -> {out_png}")


# ===========================================================================
# End-to-end runners
# ===========================================================================

def run_dataset(
    out_dir: str,
    db_path: Optional[str] = None,
    docker_status: str = "tested-successful",
    include_target: bool = False,
    secure_filter: Optional[str] = None,
    min_support: int = 10,
    top_n: int = 20,
) -> Tuple[Counter, int]:
    print("\n=== DATASET ANALYSIS ===")
    docs = extract_dataset_cwe_sets(
        db_path=db_path,
        docker_status=docker_status,
        include_target=include_target,
        secure_filter=secure_filter,
    )
    marg, pairs, n_total, n_with_any = compute_marginals_and_pairs(docs)
    print(f"[dataset] documents inspected     : {n_total}")
    print(f"[dataset] documents with >=1 CWE  : {n_with_any}")
    print(f"[dataset] unique CWEs             : {len(marg)}")
    print(f"[dataset] pair candidates         : {len(pairs)}")

    write_marginals_csv(marg, n_total, os.path.join(out_dir, "marginals_dataset.csv"))
    rows = cooccurrence_table(marg, pairs, n_total, min_support=min_support)
    write_pairs_csv(rows, os.path.join(out_dir, "cooccurrence_dataset.csv"))
    plot_lift_heatmap(
        marg, pairs, n_total,
        out_path=os.path.join(out_dir, "heatmap_dataset.png"),
        top_n=top_n,
        title="Dataset (SAST/DAST tool detections) — CWE co-occurrence lift",
    )
    return marg, n_total


def run_llm(
    jsonl_paths: Sequence[str],
    out_dir: str,
    min_support: int = 10,
    top_n: int = 20,
) -> Tuple[Counter, int]:
    print("\n=== LLM ANALYSIS ===")
    docs = extract_llm_cwe_sets(jsonl_paths)
    marg, pairs, n_total, n_with_any = compute_marginals_and_pairs(docs)
    print(f"[llm] responses inspected     : {n_total}")
    print(f"[llm] responses with >=1 CWE  : {n_with_any}")
    print(f"[llm] unique CWEs             : {len(marg)}")
    print(f"[llm] pair candidates         : {len(pairs)}")

    write_marginals_csv(marg, n_total, os.path.join(out_dir, "marginals_llm.csv"))
    rows = cooccurrence_table(marg, pairs, n_total, min_support=min_support)
    write_pairs_csv(rows, os.path.join(out_dir, "cooccurrence_llm.csv"))
    plot_lift_heatmap(
        marg, pairs, n_total,
        out_path=os.path.join(out_dir, "heatmap_llm.png"),
        top_n=top_n,
        title="LLM responses — CWE co-occurrence lift",
    )
    return marg, n_total


def run_compare(
    out_dir: str,
    dataset_marg: Counter, n_dataset: int,
    llm_marg: Counter,     n_llm: int,
) -> None:
    print("\n=== MARGINAL BIAS COMPARISON ===")
    compare_marginals(
        dataset_marg, n_dataset,
        llm_marg,     n_llm,
        out_csv=os.path.join(out_dir, "marginal_bias.csv"),
        out_png=os.path.join(out_dir, "marginal_bias.png"),
    )


# ===========================================================================
# CLI
# ===========================================================================

def _expand_globs(patterns: Sequence[str]) -> List[str]:
    out: List[str] = []
    for p in patterns:
        matches = sorted(glob.glob(p))
        if matches:
            out.extend(matches)
        elif os.path.isfile(p):
            out.append(p)
        else:
            print(f"[cli] WARN: no match for {p}", file=sys.stderr)
    return out


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out-dir", default="analysis",
                        help="Output directory (default: analysis/)")
    parser.add_argument("--min-support", type=int, default=10,
                        help="Drop pairs whose joint count is below this "
                             "value when reporting PMI / lift (default: 10)")
    parser.add_argument("--top-n", type=int, default=20,
                        help="Number of CWEs shown in the heatmap "
                             "(default: 20)")
    parser.add_argument("--db-path", default=None,
                        help="Override DB path (default: DBManager default)")
    parser.add_argument("--docker-status", default="tested-successful",
                        help="Filter dataset rows by docker status "
                             "(default: tested-successful, '' to disable)")
    parser.add_argument("--include-target", action="store_true",
                        help="Add the row's labelled CWE to its CWE set on "
                             "the dataset side (default: off)")
    parser.add_argument("--secure-filter", default=None,
                        choices=[None, "secure", "vulnerable"],
                        help="Restrict dataset rows to one secure label")

    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("dataset", help="Run dataset-side analysis only")
    p_llm = sub.add_parser("llm", help="Run LLM-side analysis only")
    p_llm.add_argument("jsonl", nargs="+",
                       help="JSONL paths (globs allowed)")
    sub.add_parser("compare", help="Compare existing marginal CSVs "
                                   "(must run dataset & llm first)")
    p_all = sub.add_parser("all", help="Run dataset + llm + compare")
    p_all.add_argument("jsonl", nargs="+",
                       help="JSONL paths (globs allowed)")

    args = parser.parse_args(argv)
    os.makedirs(args.out_dir, exist_ok=True)

    if args.cmd == "dataset":
        run_dataset(
            out_dir=args.out_dir,
            db_path=args.db_path,
            docker_status=args.docker_status,
            include_target=args.include_target,
            secure_filter=args.secure_filter,
            min_support=args.min_support,
            top_n=args.top_n,
        )
        return 0

    if args.cmd == "llm":
        paths = _expand_globs(args.jsonl)
        if not paths:
            print("[cli] no JSONL files matched", file=sys.stderr)
            return 2
        run_llm(
            jsonl_paths=paths,
            out_dir=args.out_dir,
            min_support=args.min_support,
            top_n=args.top_n,
        )
        return 0

    if args.cmd == "compare":
        # Read existing marginals_*.csv
        d_marg, n_d = _read_marginals_csv(
            os.path.join(args.out_dir, "marginals_dataset.csv"))
        l_marg, n_l = _read_marginals_csv(
            os.path.join(args.out_dir, "marginals_llm.csv"))
        run_compare(args.out_dir, d_marg, n_d, l_marg, n_l)
        return 0

    if args.cmd == "all":
        paths = _expand_globs(args.jsonl)
        if not paths:
            print("[cli] no JSONL files matched", file=sys.stderr)
            return 2
        d_marg, n_d = run_dataset(
            out_dir=args.out_dir,
            db_path=args.db_path,
            docker_status=args.docker_status,
            include_target=args.include_target,
            secure_filter=args.secure_filter,
            min_support=args.min_support,
            top_n=args.top_n,
        )
        l_marg, n_l = run_llm(
            jsonl_paths=paths,
            out_dir=args.out_dir,
            min_support=args.min_support,
            top_n=args.top_n,
        )
        run_compare(args.out_dir, d_marg, n_d, l_marg, n_l)
        return 0

    return 1


def _read_marginals_csv(path: str) -> Tuple[Counter, int]:
    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"Expected {path} — run the 'dataset' / 'llm' subcommands first.")
    marg: Counter = Counter()
    n_total = 0
    with open(path, "r", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            cwe = row["cwe"]
            cnt = int(row["count"])
            marg[cwe] = cnt
            n_total = max(n_total, int(row["n_total"]))
    return marg, n_total


if __name__ == "__main__":
    sys.exit(main())