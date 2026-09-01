"""
fusion_model.py
================
Dawid-Skene label fusion over every SAST/DAST source (methodology-plan.md
Section 1.5 / E1). Combines each source's per-sample vote --
VULNERABLE / SECURE / ABSTAIN, for "does this source's output support the
sample's target CWE being present" -- into one probabilistic label,
estimating each source's sensitivity/specificity purely from inter-source
agreement, with no ground truth (there is none in this project).

Implements the three fusion methods the plan's Phase 1 acceptance artifact
asks to compare:
    F0  1-of-n union            (the pipeline's original behaviour)
    F1  majority vote
    F2  Dawid-Skene EM          (this module's actual contribution)

Reference: Dawid & Skene (1979), "Maximum Likelihood Estimation of Observer
Error-Rates Using the EM Algorithm". No gold labels are used to fit the
model; the generation-time target CWE is used only afterwards, as a noisy,
independent sanity check (RQ6', see methodology-plan.md Section 0.1) --
never to train the fusion weights themselves.

Scope of this pass: vulnerable-labelled, docker-successful samples only
(8,544) -- these are the samples with a meaningful "does source X detect
the target CWE" question. Secure-labelled samples are a natural extension
(here a VULNERABLE vote would mean "tool disagrees with the DB label") but
are not run in this pass.

Sources (8): bandit_new, semgrep_new, sonarqube, codeql, snyk_code,
owasp_zap, owasp_zap_authenticated, burpsuite. The *legacy* bandit/semgrep
columns are deliberately excluded -- bandit_new/semgrep_new supersede them
(see the earlier changes_summary.md entries on why the legacy columns were
contaminated/lossy), and including both would double-count what is really
the same two tools.

Usage:
    python fusion_model.py                  # compute + persist + print tables
    python fusion_model.py --report-only    # just print tables from what's stored
"""

from __future__ import annotations

import argparse
import os
import re
import sqlite3
import sys
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(__file__))
from cwe_correlations import parse_zap_cwes  # noqa: E402

_SRC_CORE = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "src", "core"))
if _SRC_CORE not in sys.path:
    sys.path.insert(0, _SRC_CORE)
from cwe import load_hierarchy  # noqa: E402

DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "code_cwe.db")

# Sources already classified by cwe_hierarchy_matching.py -- read from that
# table rather than re-parsing tool output a second way.
HIERARCHY_SOURCES = ("bandit_new", "semgrep_new", "sonarqube", "codeql", "snyk_code", "owasp_zap", "burpsuite")
# Computed fresh here: too new to be in cwe_hierarchy_matches yet.
FRESH_SOURCES = ("owasp_zap_authenticated",)
ALL_SOURCES = HIERARCHY_SOURCES + FRESH_SOURCES

RELAXED_MATCH = frozenset({"exact", "ancestor", "descendant"})
# "sibling" excluded: it names a genuinely different weakness that only
# happens to share the target's direct parent (e.g. CWE-79 reported when the
# target is CWE-89, both children of CWE-74) -- not a relaxed match, a wrong
# answer. See the identical note in cwe_hierarchy_matching.py.

VULN, SEC, ABSTAIN = 1, 0, -1


def _scanned_predicate(source: str) -> str:
    """SQL boolean expression: has `source` actually produced a result for
    this row (as opposed to never having run)? Column semantics differ per
    tool -- structured tools (bandit_new etc.) use a *_version column that's
    only set once save_findings() runs; legacy-style columns use sentinel
    strings instead.
    """
    return {
        "bandit_new": "bandit_version IS NOT NULL",
        "semgrep_new": "semgrep_version IS NOT NULL",
        "codeql": "codeql_version IS NOT NULL",
        "snyk_code": "snyk_code_version IS NOT NULL",
        "sonarqube": "sonarqube NOT IN ('not-tested', 'error') AND sonarqube IS NOT NULL",
        "owasp_zap": "owasp_zap != 'not-tested' AND owasp_zap IS NOT NULL",
        "burpsuite": "burpsuite != 'not-tested' AND burpsuite IS NOT NULL",
        "owasp_zap_authenticated": "owasp_zap_authenticated IS NOT NULL",
    }[source]


def build_vote_matrix(
    db_path: str, docker_status: str = "tested-successful", unrelated_as_abstain: bool = False,
) -> tuple[list[int], dict[str, dict[int, int]]]:
    """Returns (sample_ids, {source: {sample_id: vote}}), vote in {VULN, SEC, ABSTAIN}.

    `unrelated_as_abstain` toggles how a source's "found a different,
    unrelated CWE" result is treated -- see _vote()'s docstring-comment
    below for the reasoning. Compare both by calling this twice; see
    compare_unrelated_treatment().
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    scanned_cols = ", ".join(f"({_scanned_predicate(s)}) AS scanned_{s}" for s in ALL_SOURCES)
    rows = conn.execute(
        f"""
        SELECT id, CWE, owasp_zap_authenticated, {scanned_cols}
        FROM code_cwe
        WHERE docker = ? AND secure IN ('VULNERABLE', 0)
        """,
        (docker_status,),
    ).fetchall()
    sample_ids = [r["id"] for r in rows]
    target_cwe = {r["id"]: int(str(r["CWE"]).replace("CWE-", "")) for r in rows}
    scanned = {s: {r["id"]: bool(r[f"scanned_{s}"]) for r in rows} for s in ALL_SOURCES}

    # --- hierarchy-classified sources: read straight from cwe_hierarchy_matches ---
    placeholders = ",".join("?" * len(HIERARCHY_SOURCES))
    hm_rows = conn.execute(
        f"SELECT code_id, tool, relationship FROM cwe_hierarchy_matches WHERE tool IN ({placeholders})",
        HIERARCHY_SOURCES,
    ).fetchall()
    relationship = {(r["code_id"], r["tool"]): r["relationship"] for r in hm_rows}

    # --- fresh source: owasp_zap_authenticated, classified here ---
    hierarchy = load_hierarchy()
    auth_zap_relationship: dict[int, str] = {}
    for r in rows:
        if not scanned["owasp_zap_authenticated"][r["id"]]:
            continue
        reported = {int(c.replace("CWE-", "")) for c in parse_zap_cwes(r["owasp_zap_authenticated"])}
        if not reported:
            auth_zap_relationship[r["id"]] = "no_report"
            continue
        best = min(
            (hierarchy.classify(cwe, target_cwe[r["id"]]) for cwe in reported),
            key=lambda rel: {"exact": 0, "ancestor": 1, "descendant": 2, "sibling": 3, "unrelated": 4, "none": 5}[rel],
        )
        auth_zap_relationship[r["id"]] = best

    conn.close()

    def _vote(rel: str) -> int:
        if rel in RELAXED_MATCH:
            return VULN
        if rel == "unrelated" and unrelated_as_abstain:
            # A source reporting some *other*, genuinely unrelated CWE is not
            # obviously evidence of "target absent" -- it may just mean the
            # tool was looking elsewhere. Treated as SEC by default (the
            # tool made a claim, and that claim wasn't the target); this flag
            # tests the alternative reading: no claim about the target at
            # all, i.e. ABSTAIN. "no_report" (scanned, found literally
            # nothing) is unaffected either way -- that is a real clean
            # signal, not a claim about something else.
            return ABSTAIN
        return SEC

    votes: dict[str, dict[int, int]] = {s: {} for s in ALL_SOURCES}
    for sid in sample_ids:
        for s in HIERARCHY_SOURCES:
            if not scanned[s][sid]:
                votes[s][sid] = ABSTAIN
                continue
            rel = relationship.get((sid, s), "no_report")
            votes[s][sid] = _vote(rel)
        for s in FRESH_SOURCES:
            if not scanned[s][sid]:
                votes[s][sid] = ABSTAIN
                continue
            rel = auth_zap_relationship.get(sid, "no_report")
            votes[s][sid] = _vote(rel)

    return sample_ids, votes


# --------------------------------------------------------------------------- #
# F0 / F1: union and majority vote
# --------------------------------------------------------------------------- #


def union_label(sample_ids: list[int], votes: dict[str, dict[int, int]]) -> dict[int, int]:
    return {sid: (VULN if any(votes[s][sid] == VULN for s in votes) else SEC) for sid in sample_ids}


def majority_label(sample_ids: list[int], votes: dict[str, dict[int, int]]) -> dict[int, int]:
    out = {}
    for sid in sample_ids:
        v = sum(1 for s in votes if votes[s][sid] == VULN)
        n = sum(1 for s in votes if votes[s][sid] != ABSTAIN)
        out[sid] = VULN if n and v / n > 0.5 else SEC
    return out


# --------------------------------------------------------------------------- #
# F2: Dawid-Skene EM (binary, per-source sensitivity/specificity)
# --------------------------------------------------------------------------- #


@dataclass
class DawidSkeneResult:
    prevalence: float
    sensitivity: dict[str, float]  # P(vote=VULN | true=VULN)
    specificity: dict[str, float]  # P(vote=SEC  | true=SEC)
    p_vulnerable: dict[int, float]  # posterior per sample
    iterations: int


def fit_dawid_skene(
    sample_ids: list[int], votes: dict[str, dict[int, int]],
    max_iter: int = 100, tol: float = 1e-6,
) -> DawidSkeneResult:
    """EM fit. Abstains contribute no likelihood term for that (sample,
    source) pair -- standard treatment in the weak-supervision literature,
    since an abstaining source is making no claim either way.
    """
    sources = list(votes.keys())

    # Init: majority vote (ignoring abstains) as the starting posterior.
    p = {}
    for sid in sample_ids:
        vs = [votes[s][sid] for s in sources if votes[s][sid] != ABSTAIN]
        p[sid] = (sum(1 for v in vs if v == VULN) / len(vs)) if vs else 0.5

    sens = {s: 0.7 for s in sources}
    spec = {s: 0.9 for s in sources}
    prevalence = sum(p.values()) / len(p)

    prev_ll = None
    for it in range(1, max_iter + 1):
        # M-step
        for s in sources:
            num_sens = sum(p[sid] for sid in sample_ids if votes[s][sid] == VULN)
            den_sens = sum(p[sid] for sid in sample_ids if votes[s][sid] != ABSTAIN)
            num_spec = sum((1 - p[sid]) for sid in sample_ids if votes[s][sid] == SEC)
            den_spec = sum((1 - p[sid]) for sid in sample_ids if votes[s][sid] != ABSTAIN)
            sens[s] = min(max(num_sens / den_sens, 1e-6), 1 - 1e-6) if den_sens > 0 else sens[s]
            spec[s] = min(max(num_spec / den_spec, 1e-6), 1 - 1e-6) if den_spec > 0 else spec[s]
        prevalence = min(max(sum(p.values()) / len(p), 1e-6), 1 - 1e-6)

        # E-step
        log_lik = 0.0
        for sid in sample_ids:
            log_v = 0.0
            log_s = 0.0
            import math
            lv = math.log(prevalence)
            ls = math.log(1 - prevalence)
            for s in sources:
                vote = votes[s][sid]
                if vote == ABSTAIN:
                    continue
                lv += math.log(sens[s]) if vote == VULN else math.log(1 - sens[s])
                ls += math.log(spec[s]) if vote == SEC else math.log(1 - spec[s])
            m = max(lv, ls)
            pv = math.exp(lv - m)
            ps = math.exp(ls - m)
            p[sid] = pv / (pv + ps)
            log_lik += m + math.log(pv + ps)

        if prev_ll is not None and abs(log_lik - prev_ll) < tol:
            break
        prev_ll = log_lik

    return DawidSkeneResult(prevalence, sens, spec, p, it)


# --------------------------------------------------------------------------- #
# Persistence + reporting
# --------------------------------------------------------------------------- #


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS fusion_labels (
            code_id       INTEGER PRIMARY KEY,
            p_vulnerable  REAL NOT NULL,
            f0_union      INTEGER NOT NULL,
            f1_majority   INTEGER NOT NULL,
            f2_dawid_skene INTEGER NOT NULL,
            computed_at   TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    conn.commit()


def run_fusion(
    db_path: str | None = None, unrelated_as_abstain: bool = False, table_name: str = "fusion_labels",
) -> tuple[DawidSkeneResult, list[int], dict[str, dict[int, int]]]:
    """Fit + persist. `table_name` lets the two "unrelated" treatments coexist
    as separate tables (fusion_labels = official/default = SECURE treatment;
    fusion_labels_unrelated_abstain = the alternative) rather than one
    overwriting the other -- same reasoning as bandit_new/docker_recheck
    elsewhere in this project: both are legitimate results worth keeping.
    """
    db_path = db_path or DEFAULT_DB_PATH
    sample_ids, votes = build_vote_matrix(db_path, unrelated_as_abstain=unrelated_as_abstain)
    f0 = union_label(sample_ids, votes)
    f1 = majority_label(sample_ids, votes)
    ds = fit_dawid_skene(sample_ids, votes)

    conn = sqlite3.connect(db_path)
    conn.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            code_id       INTEGER PRIMARY KEY,
            p_vulnerable  REAL NOT NULL,
            f0_union      INTEGER NOT NULL,
            f1_majority   INTEGER NOT NULL,
            f2_dawid_skene INTEGER NOT NULL,
            computed_at   TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    conn.commit()
    for sid in sample_ids:
        p = ds.p_vulnerable[sid]
        conn.execute(
            f"""
            INSERT INTO {table_name} (code_id, p_vulnerable, f0_union, f1_majority, f2_dawid_skene)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(code_id) DO UPDATE SET
                p_vulnerable = excluded.p_vulnerable,
                f0_union = excluded.f0_union,
                f1_majority = excluded.f1_majority,
                f2_dawid_skene = excluded.f2_dawid_skene,
                computed_at = datetime('now')
            """,
            (sid, p, f0[sid], f1[sid], 1 if p > 0.5 else 0),
        )
    conn.commit()
    conn.close()
    return ds, sample_ids, votes


def compare_unrelated_treatment(db_path: str | None = None) -> None:
    """Run both readings of an 'unrelated' vote side by side: SECURE (the
    default -- a claim that isn't the target still counts as evidence
    against it) vs ABSTAIN (the alternative -- a claim about something else
    is no claim about the target at all). Persists both
    (fusion_labels / fusion_labels_unrelated_abstain).
    """
    db_path = db_path or DEFAULT_DB_PATH
    results = {}
    for label, flag, table in [
        ("unrelated = SECURE (mevcut/varsayilan)", False, "fusion_labels"),
        ("unrelated = ABSTAIN (alternatif)", True, "fusion_labels_unrelated_abstain"),
    ]:
        ds, sample_ids, votes = run_fusion(db_path, unrelated_as_abstain=flag, table_name=table)
        results[label] = (ds, sample_ids, votes)
        print("\n" + "#" * 78)
        print(f"# {label}  ->  tablo: {table}")
        print("#" * 78)
        print_report(ds, sample_ids, votes)

    print("\n" + "=" * 78)
    print("KARSILASTIRMA")
    print("=" * 78)
    print(f"{'':<42}{'SECURE (varsayilan)':>18}{'ABSTAIN (alternatif)':>20}")
    (ds_a, ids_a, _), (ds_b, ids_b, _) = results.values()
    n = len(ids_a)
    print(f"{'tahmini gercek prevalence (pi)':<42}{ds_a.prevalence*100:>17.1f}%{ds_b.prevalence*100:>19.1f}%")
    n_a = sum(1 for i in ids_a if ds_a.p_vulnerable[i] > 0.5)
    n_b = sum(1 for i in ids_b if ds_b.p_vulnerable[i] > 0.5)
    print(f"{'F2 Dawid-Skene P>0.5 (adet)':<42}{n_a:>18}{n_b:>20}")
    print(f"{'F2 Dawid-Skene P>0.5 (oran)':<42}{n_a/n*100:>17.1f}%{n_b/n*100:>19.1f}%")
    for s in ds_a.sensitivity:
        print(f"  {s:<38} sens {ds_a.sensitivity[s]*100:>5.1f}% -> {ds_b.sensitivity[s]*100:>5.1f}%"
              f"   spec {ds_a.specificity[s]*100:>5.1f}% -> {ds_b.specificity[s]*100:>5.1f}%")


def print_report(ds: DawidSkeneResult, sample_ids: list[int], votes: dict[str, dict[int, int]]) -> None:
    f0 = union_label(sample_ids, votes)
    f1 = majority_label(sample_ids, votes)
    n = len(sample_ids)

    print("=" * 78)
    print("SOURCE RELIABILITY (Dawid-Skene EM estimates, no ground truth used)")
    print("=" * 78)
    print(f"{'source':<26}{'coverage':>10}{'sensitivity':>14}{'specificity':>14}")
    for s in votes:
        coverage = sum(1 for sid in sample_ids if votes[s][sid] != ABSTAIN)
        print(f"{s:<26}{coverage:>9}/{n}{ds.sensitivity[s]:>13.1%}{ds.specificity[s]:>14.1%}")

    print()
    print("=" * 78)
    print("FUSION METHOD COMPARISON (F0 union / F1 majority / F2 Dawid-Skene)")
    print("=" * 78)
    n_f0 = sum(f0.values())
    n_f1 = sum(f1.values())
    n_f2_50 = sum(1 for sid in sample_ids if ds.p_vulnerable[sid] > 0.5)
    n_f2_80 = sum(1 for sid in sample_ids if ds.p_vulnerable[sid] > 0.8)
    n_f2_95 = sum(1 for sid in sample_ids if ds.p_vulnerable[sid] > 0.95)
    print(f"total vulnerable-labelled samples: {n}")
    print(f"F0 union            : {n_f0} ({n_f0/n*100:.1f}%)")
    print(f"F1 majority vote     : {n_f1} ({n_f1/n*100:.1f}%)")
    print(f"F2 Dawid-Skene P>0.5 : {n_f2_50} ({n_f2_50/n*100:.1f}%)")
    print(f"F2 Dawid-Skene P>0.8 : {n_f2_80} ({n_f2_80/n*100:.1f}%)")
    print(f"F2 Dawid-Skene P>0.95: {n_f2_95} ({n_f2_95/n*100:.1f}%)")
    print(f"estimated true prevalence (pi): {ds.prevalence:.1%}")
    print(f"EM converged in {ds.iterations} iterations")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", default=DEFAULT_DB_PATH)
    ap.add_argument("--report-only", action="store_true")
    ap.add_argument("--compare-unrelated", action="store_true",
                     help="Run both readings of an 'unrelated' vote (SECURE vs ABSTAIN) side by side.")
    args = ap.parse_args()

    if args.compare_unrelated:
        compare_unrelated_treatment(args.db)
        return

    sample_ids, votes = build_vote_matrix(args.db)
    if args.report_only:
        ds = fit_dawid_skene(sample_ids, votes)
    else:
        ds, sample_ids, votes = run_fusion(args.db)
    print_report(ds, sample_ids, votes)


if __name__ == "__main__":
    main()
