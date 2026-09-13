"""
Build a balanced, stratified JSONL dataset from code_cwe.db for LLM fine-tuning.

Selection rules (all configurable):
  * only rows where docker == 'tested-successful'
  * vulnerable rows must clear an acceptance gate (--corr_filter):
        - FUSION_F0         → fusion_model.py's persisted, hierarchy-aware
                               F0 union label across all 8 SAST/DAST sources
                               (default since 2026-09-08 -- see
                               changes_summary.md's 2026-09-08 (2)/(7))
        - FULL              → SAST hit AND DAST hit (strict, exact-match only)
        - PARTIAL           → SAST hit XOR DAST hit (single-source, exact-match only)
        - FULL_OR_PARTIAL   → either of the above (legacy default pre-2026-09-08)
    Burpsuite is folded into DAST hits via the per-finding `burp_scan_result`
    table (see Burpsuite contribution below); FULL/PARTIAL now also read
    bandit_new/semgrep_new/codeql/snyk_code/owasp_zap_authenticated instead
    of the legacy pre-Phase-1 columns (see row_correlation()'s docstring).
  * secure rows must be correlation-NONE (no tool flagged the DB CWE → clean,
    checked against the same widened tool set as FULL/PARTIAL above)
  * per-CWE cap: at most MAX_PER_BUCKET per (cwe, secure_flag) bucket
  * per-CWE floor: CWEs with < MIN_PER_CWE vulnerable samples are dropped
  * code-level dedup via sha1 of stripped source
  * stratified split by (owasp_category, secure_flag) so every split
    preserves both distributions

Multi-label targets
-------------------
The default target is the *sorted union* of every CWE id reported across
every product output for a given row:

      target = sorted(  bandit   ∪  semgrep    ∪  sonarqube
                      ∪ zap      ∪  burpsuite  ∪  {DB CWE} )

Burpsuite contribution
~~~~~~~~~~~~~~~~~~~~~~
The `code_cwe.burpsuite` column only stores a coarse 'found' / 'not-found'
status against the DB-labelled CWE — which throws away every other CWE
Burp actually detected. The detailed per-finding rows live in the
`burp_scan_result` table, each with a `mapped_cwe` column produced by
`dast_pipeline.py` via `message_parsers.BURP_TYPE_TO_CWE`. We read that
table directly so Burp contributes the full set of CWEs it flagged.

The legacy 'found' status is functionally equivalent to
`db_cwe ∈ burp_mapped_cwes` (see `DBManager.save_scan_results`,
burpsuite branch), so the FULL / PARTIAL / NONE filter behaves the same
on the DB CWE — we just gain richer multi-label targets.

Optional confidence floor (`--burp_min_confidence`) discards 'tentative'
or 'firm' Burp findings — useful for an ablation against noisier DAST.

For secure rows the target stays "NONE" — these rows have already been
filtered to mean "no tool raised any alarm for the DB CWE", so we want
the model to learn the clean label for them.

Legacy / single-label mode
--------------------------
`--multi_label False` falls back to the original target = single DB CWE.
Useful for the classical single-label baseline experiment.

`--include_db_cwe_in_target False` builds the union strictly from tool
outputs (without injecting the DB ground-truth label).

`--corr_filter` lets the user pick FUSION_F0 / FULL / PARTIAL / FULL_OR_PARTIAL / ALL.

Raw tool-consensus mode
-----------------------
    --corr_filter ALL --secure_target tool_union \
    --min_per_cwe 0 --max_per_bucket 0

keeps every docker-runnable row and labels it purely by what the products
reported — no correlation gate, no forced "NONE" for secure rows, no per-CWE
caps. This answers a different research question from the default pipeline:
instead of "can a model learn verified vulnerabilities?", it asks "can a model
reproduce the aggregate output of five scanners?".

Two caveats that must be reported alongside any result from this mode:

  1. The labels inherit every false positive the tools produce. Scanner rules
     that fire on framework boilerplate (host binding, missing security
     headers, absent CSRF tokens) attach to nearly every row, so a constant
     predictor that ignores the code entirely scores a high micro-F1. Always
     report that constant-predictor floor as a control.
  2. A DB-secure row can carry a non-empty target. "Secure" then means only
     "no tool confirmed the DB-labelled CWE", not "no vulnerability present".

Code scrubbing (`--scrub_mode`) and post-scrub dedup still apply in this mode
and should not be disabled: without them, 50%+ of rows leak a literal CWE-xx
token into the prompt, letting the model copy the answer out of a comment.

Outputs
-------
  - dataset_train.jsonl, dataset_val.jsonl, dataset_test.jsonl
  - dataset_stats.json  (counts per CWE / OWASP / split, plus target-level
                         CWE frequency and per-tool CWE coverage)
"""
import os, re, json, sqlite3, hashlib, random, argparse
from collections import defaultdict, Counter
from core.db_handler import DBManager
from core.cwe_summary import cwe_to_owasp, parse_sast_cwes, parse_zap_cwes  # reuse
from core.cwe_correlations import parse_sonarqube_cwes  # reuse

RNG = random.Random(42)

# Burp REST API confidence levels, weakest → strongest. Used by the
# `--burp_min_confidence` flag for noise control.
BURP_CONFIDENCE_LEVELS = ("tentative", "firm", "certain")

# Correlation filter choices for vulnerable rows.
#
# FUSION_F0 is the default (changed 2026-09-08, see changes_summary.md).
# Gates vulnerable-row acceptance on `fusion_labels.f0_union` --
# fusion_model.py's already-computed, hierarchy-aware union across all 8
# SAST/DAST sources (bandit_new, semgrep_new, sonarqube, codeql, snyk_code,
# owasp_zap, owasp_zap_authenticated, burpsuite). Read-only: build_dataset.py
# never recomputes fusion itself, it only reads the persisted artifact
# (`python fusion_model.py` must be re-run first if the DB has changed since
# fusion_labels was last written) -- "scoring must not live inside scanning"
# per CLAUDE.md, and re-scoring here would just duplicate a computation that
# already exists and is independently tested.
#
# FULL / PARTIAL / FULL_OR_PARTIAL are the legacy correlation-based gates
# (SAST hit AND/OR/XOR DAST hit on the DB CWE, exact-match only, no
# hierarchy). Still available for ablations that specifically want that
# narrower definition, but no longer the default -- they were silently
# running on stale pre-Phase-1 tool columns until this fix (see
# changes_summary.md's 2026-09-08 (2) entry for the diagnosis) and even
# corrected to read the fixed columns, they lack hierarchy-aware matching
# and CodeQL/Snyk, which FUSION_F0 has.
#
# ALL disables correlation-based acceptance entirely: every docker-runnable
# row is kept, secure and vulnerable alike, regardless of whether any tool
# confirmed the DB CWE. Use it together with --secure_target tool_union to
# build the "raw tool consensus" dataset, where the label is defined purely
# by what the products reported rather than by the DB ground truth. Note that
# this deliberately removes the quality gate — the resulting labels contain
# whatever noise the tools produce, which is the point when the research
# question is about tool reliability itself.
CORR_FILTER_CHOICES = ("FUSION_F0", "FULL", "PARTIAL", "FULL_OR_PARTIAL", "ALL")

# What to write as `target` for rows the DB marks secure.
#   none       — legacy: always "NONE" (the model should find nothing)
#   tool_union — the same multi-label union used for vulnerable rows, so a
#                secure-flagged row that tools still flagged carries those
#                CWEs. Only meaningful with --corr_filter ALL, because the
#                default filter already guarantees secure rows are alarm-free.
SECURE_TARGET_CHOICES = ("none", "tool_union")

# ─────────────────────────────────────────────────────────────────────────────
# Multi-label blacklist — manually curated noise filter
# ─────────────────────────────────────────────────────────────────────────────
# CWEs listed here are dropped from the multi-label `target` (and from the
# `all_cwes` field) WHEN they come from a tool output **and** they are not
# the DB ground-truth CWE for the row. The DB CWE itself is never filtered:
# if a blacklisted CWE happens to be a row's ground truth, it stays. The
# rule targets tool *noise*, not the human label.
#
# The raw per-tool sets remain untouched in `meta.tool_cwes` so the thesis
# can run "with vs. without blacklist" ablations on the same JSONL files.
#
# Use canonical "CWE-NN" strings, no spaces. Examples to consider once you
# inspect `dataset_stats.json -> by_target_cwe`:
#
#   "CWE-200",   # Information Exposure — Semgrep flags many benign logs
#   "CWE-754",   # Improper Check for Unusual Conditions — very generic
#   "CWE-693",   # Protection Mechanism Failure — abstract umbrella CWE
#
# Empty by default; the user is expected to fill this set by hand.
BLACKLIST_MULTILABEL: set[str] = {
    # "CWE-200",
    # "CWE-754",
}

PROMPT_TEMPLATE = (
    "You are a Static Application Security Testing (SAST) tool.\n"
    "List the CWE IDs present in the following code.\n"
    "Output ONLY a comma-separated list like: CWE-xx, CWE-yy.\n"
    "If none, output: NONE.\n\n"
    "### code\n<CODE>\n{code}\n</CODE>\n"
)


# ─────────────────────────────────────────────────────────────
# Prompt-leak scrubbing
# ─────────────────────────────────────────────────────────────
# Matches "CWE-89", "CWE 89", "CWE_89", "cwe89" — case-insensitive, numeric boundary.
# Also catches common phrasings like "CWE-89:", "CWE 89 vulnerability".
CWE_LITERAL_RE = re.compile(r"CWE[-_\s]?\d+", re.IGNORECASE)


def scrub_code_for_leaks(code: str, mode: str = "line") -> tuple[str, int]:
    """
    Remove any literal CWE reference from code so the model can't just copy it.
    Returns (cleaned_code, num_matches_removed).

    mode="line"  → delete the ENTIRE line that contains any CWE-xx token
                   (safer: also drops nearby hints like '# SQL injection - CWE-89')
    mode="token" → delete just the CWE-xx token, keep the line
    mode="none"  → no scrubbing at all (debug / ablation only)
    """
    if not CWE_LITERAL_RE.search(code):
        return code, 0

    if mode == "line":
        kept, removed = [], 0
        for line in code.splitlines():
            if CWE_LITERAL_RE.search(line):
                removed += 1
                continue
            kept.append(line)
        return "\n".join(kept), removed

    if mode == "none":
        return code, 0

    # token mode
    cleaned, n = CWE_LITERAL_RE.subn("", code)
    # collapse the double spaces that result from token removal
    cleaned = re.sub(r"[ \t]{2,}", " ", cleaned)
    return cleaned, n


# ─────────────────────────────────────────────────────────────
# Per-row CWE extraction
# ─────────────────────────────────────────────────────────────
def _cwe_sort_key(c: str) -> int:
    """
    Numeric sort key for CWE strings. Unparseable values (very rare —
    e.g. malformed tool output) fall into a single bucket at the end so
    the overall order stays deterministic.
    """
    try:
        return int(str(c).upper().replace("CWE-", "").strip())
    except (ValueError, AttributeError):
        return 10 ** 9


def _normalise_cwe(raw) -> str | None:
    """
    Turn whatever a tool wrote ('89', '-1', 'CWE-89', 'CWE_89', ' CWE-89 ')
    into a canonical 'CWE-89' string, or return None for junk values.
    """
    if raw is None:
        return None
    s = str(raw).strip().upper()
    if not s:
        return None
    if not s.startswith("CWE-"):
        s = f"CWE-{s}"
    try:
        n = int(s.replace("CWE-", "").strip())
    except ValueError:
        return None
    if n <= 0:                       # CWE-0 / CWE--1 are placeholder noise
        return None
    return f"CWE-{n}"


def fetch_burp_cwes_from_db(db_path: str, code_id: int,
                            min_confidence: str | None = None) -> set:
    """
    Pull every CWE id Burp emitted for this code_id from the
    `burp_scan_result` detail table. Returns a deduplicated set such as
    {'CWE-79', 'CWE-89'}.

    The on-disk `code_cwe.burpsuite` column only stores a coarse
    'found'/'not-found' status against the DB-labelled CWE and discards
    every other CWE Burp detected — we sidestep it by reading the
    per-finding detail table directly.

    `min_confidence`, if given, drops findings below the threshold
    (Burp's order is tentative < firm < certain). Default = keep all
    confidence levels so the multi-label target is maximally rich.

    The function fails open: if the `burp_scan_result` table is missing
    (older DBs) or empty, we simply return an empty set.
    """
    # Resolve the confidence threshold once
    if min_confidence:
        try:
            threshold_idx = BURP_CONFIDENCE_LEVELS.index(min_confidence.lower())
            allowed = set(BURP_CONFIDENCE_LEVELS[threshold_idx:])
        except ValueError:
            allowed = None
    else:
        allowed = None

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT mapped_cwe, confidence FROM burp_scan_result WHERE code_id = ?",
            (code_id,),
        )
        rows = cursor.fetchall()
    except sqlite3.OperationalError:
        # Table absent (older schema) — degrade gracefully to empty set.
        return set()
    finally:
        conn.close()

    found = set()
    for mapped, conf in rows:
        cwe = _normalise_cwe(mapped)
        if cwe is None:
            continue
        if allowed is not None:
            c = (str(conf).strip().lower() if conf else "")
            # Findings with missing/unknown confidence are dropped only when
            # an explicit confidence floor is requested; otherwise everything
            # is kept (default = maximum recall).
            if not c or c not in allowed:
                continue
        found.add(cwe)
    return found


def _fetch_new_tool_cwes(db_path: str, code_id: int) -> dict:
    """bandit/semgrep/codeql/snyk_code's *structured* `<tool>_cwes` columns
    (fixed CWE extraction, distinct from the legacy free-text `code_cwe.
    bandit`/`code_cwe.semgrep` columns `sast_row` reads) plus
    owasp_zap_authenticated -- the Phase 1 fixes/additions that
    `per_tool_cwes()` didn't read before 2026-09-08 (changes_summary.md's
    2026-09-08 (2) entry). NOTE: despite "bandit_new"/"semgrep_new" being
    the names used in prose/fusion_model.py's source labels, the actual DB
    columns are `bandit_cwes`/`semgrep_cwes` (see cwe_hierarchy_matching.py's
    `_STRUCTURED_TOOL_DB_NAME` mapping) -- fixed here 2026-09-11 after this
    function silently queried the nonexistent `bandit_new_cwes`/
    `semgrep_new_cwes` and got dropped by the `present` filter below,
    meaning bandit/semgrep contributed nothing via this path (codeql/
    snyk_code/zap_authenticated were unaffected, those names are correct).
    Structured columns are already comma-separated "CWE-xx" strings
    (`sarif_scanners.findings_to_columns`), same format `parse_sast_cwes`
    already parses, so no new parser is needed.
    """
    conn = sqlite3.connect(db_path)
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(code_cwe)").fetchall()}
        wanted = ["bandit_cwes", "semgrep_cwes", "codeql_cwes",
                  "snyk_code_cwes", "owasp_zap_authenticated"]
        present = [c for c in wanted if c in cols]
        if not present:
            return {}
        row = conn.execute(
            f"SELECT {', '.join(present)} FROM code_cwe WHERE id = ?", (code_id,)
        ).fetchone()
        if row is None:
            return {}
        values = dict(zip(present, row))
    finally:
        conn.close()
    return {
        "bandit_new":  parse_sast_cwes(values.get("bandit_cwes") or ""),
        "semgrep_new": parse_sast_cwes(values.get("semgrep_cwes") or ""),
        "codeql":      parse_sast_cwes(values.get("codeql_cwes") or ""),
        "snyk_code":   parse_sast_cwes(values.get("snyk_code_cwes") or ""),
        "zap_authenticated": parse_zap_cwes(values.get("owasp_zap_authenticated")),
    }


def per_tool_cwes(db: DBManager, code_id: int, sast_row, dast_row,
                  burp_min_confidence: str | None = None) -> dict:
    """
    Return a dict {tool_name: set_of_CWE_strings} for every CWE-emitting
    tool on a single row. Burpsuite is included by reading the
    `burp_scan_result` detail table (see `fetch_burp_cwes_from_db`).

    "bandit"/"semgrep" here are the legacy pre-Phase-1 columns, kept for
    provenance/comparison; "bandit_new"/"semgrep_new"/"codeql"/"snyk_code"/
    "zap_authenticated" are the fixed/added Phase 1 sources -- both sets
    feed `row_correlation()`/`merged_cwes()` so nothing regresses, but
    `row_correlation()` was widened (see its docstring) to read the new set.
    """
    tool_cwes = {
        "bandit":    parse_sast_cwes(sast_row[1] if sast_row and len(sast_row) > 1 else ""),
        "semgrep":   parse_sast_cwes(sast_row[2] if sast_row and len(sast_row) > 2 else ""),
        "sonarqube": parse_sonarqube_cwes(sast_row[3] if sast_row and len(sast_row) > 3 else ""),
        "zap":       parse_zap_cwes(dast_row[1] if dast_row and len(dast_row) > 1 else None),
        "burpsuite": fetch_burp_cwes_from_db(db.db_path, code_id,
                                             min_confidence=burp_min_confidence),
    }
    tool_cwes.update(_fetch_new_tool_cwes(db.db_path, code_id))
    return tool_cwes


def merged_cwes(db_cwe: str, tool_cwes: dict, include_db_cwe: bool = True,
                blacklist: set[str] | None = None) -> tuple[list, int]:
    """
    Union of every CWE id reported across all product outputs, returned as
    a tuple `(sorted_list, n_ignored_by_blacklist)`.

    Blacklist semantics
    -------------------
    If `blacklist` is given, any CWE produced by a tool that is in the
    blacklist *and is not equal to the DB ground-truth CWE for this row*
    is dropped from the union. The DB CWE itself is never filtered — a
    blacklisted entry that happens to also be the row's ground truth is
    preserved (the rule targets tool *noise*, not the human label).

    `include_db_cwe`
    ----------------
    When True the DB ground-truth CWE is also added to the union. This
    is the recommended default: a row reaches this point only after
    passing the correlation filter, so the DB CWE is empirically present
    in the code even if one particular tool happens to miss it. The DB
    CWE is added AFTER blacklist filtering, so its inclusion never
    depends on the blacklist contents.
    """
    blacklist = blacklist or set()
    db_cwe_norm = str(db_cwe).strip().upper() if db_cwe else ""

    # Flatten all tool detections first so we can count blacklist hits
    # against the raw union (before any filtering / DB-CWE injection).
    raw_union: set = set()
    for cwes in tool_cwes.values():
        raw_union |= cwes

    kept = {c for c in raw_union
            if not (c in blacklist and c != db_cwe_norm)}
    ignored = len(raw_union) - len(kept)

    if include_db_cwe and db_cwe_norm:
        kept.add(db_cwe_norm)
    return sorted(kept, key=_cwe_sort_key), ignored


def row_correlation(db_cwe: str, tool_cwes: dict) -> str:
    """
    FULL / PARTIAL / NONE classification for the DB-labelled CWE on a
    single row. Exact-match only (no hierarchy) -- for that, use the
    `FUSION_F0` corr_filter instead, which reads fusion_model.py's already
    hierarchy-aware label rather than reimplementing that matching here.

    SAST hit ⇔ db_cwe in (bandit_new ∪ semgrep_new ∪ sonarqube ∪ codeql ∪ snyk_code)
    DAST hit ⇔ db_cwe in (zap ∪ zap_authenticated ∪ burpsuite)

    Widened 2026-09-08 (changes_summary.md 2026-09-08 (2)) from the legacy
    bandit/semgrep-only, no-CodeQL/Snyk version -- that version silently
    reproduced the pre-Phase-1 "Old" 14.6%-strict detection rate. `bandit`/
    `semgrep` (the legacy, known-buggy columns -- see Phase 1's bandit
    comment-contamination fix) are deliberately excluded from this
    computation now; they're still in `tool_cwes` for `merged_cwes()`'s
    multi-label union and provenance, just not trusted for the correlation
    gate anymore.
    """
    in_sast = db_cwe in (tool_cwes["bandit_new"]
                         | tool_cwes["semgrep_new"]
                         | tool_cwes["sonarqube"]
                         | tool_cwes["codeql"]
                         | tool_cwes["snyk_code"])
    in_dast = db_cwe in (tool_cwes["zap"]
                         | tool_cwes["zap_authenticated"]
                         | tool_cwes["burpsuite"])

    if in_sast and in_dast:
        return "FULL"
    if in_sast or in_dast:
        return "PARTIAL"
    return "NONE"


def _accept_vuln(corr: str, corr_filter: str, f0: bool | None = None) -> bool:
    """Apply the user-selected correlation filter to a vulnerable row.

    `f0` is this row's `fusion_labels.f0_union` value (None if the row
    wasn't in fusion's scope, e.g. not yet scanned by any source) --
    only consulted when corr_filter == "FUSION_F0".
    """
    if corr_filter == "ALL":
        return True                      # no correlation gate at all
    if corr_filter == "FUSION_F0":
        return bool(f0)                  # None (not in fusion's scope) -> reject
    if corr_filter == "FULL":
        return corr == "FULL"
    if corr_filter == "PARTIAL":
        return corr == "PARTIAL"
    # FULL_OR_PARTIAL — legacy behaviour
    return corr in ("FULL", "PARTIAL")


# ─────────────────────────────────────────────────────────────
# Row collection
# ─────────────────────────────────────────────────────────────
def _load_f0_union(db_path: str) -> dict[int, bool]:
    """Reads fusion_model.py's already-persisted, hierarchy-aware F0 union
    label. Read-only -- run `python fusion_model.py` first if the DB has
    changed since fusion_labels was last written; this function does not
    recompute it (scoring stays a separate pass from this dataset-building
    pass, same as it stays separate from scanning).
    """
    conn = sqlite3.connect(db_path)
    try:
        exists = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='fusion_labels'"
        ).fetchone()
        if not exists:
            return {}
        return {
            r[0]: bool(r[1])
            for r in conn.execute("SELECT code_id, f0_union FROM fusion_labels").fetchall()
        }
    finally:
        conn.close()


def collect_rows(db, min_per_cwe, max_per_bucket, scrub_mode="line",
                 include_db_cwe_in_target=True,
                 burp_min_confidence: str | None = None,
                 corr_filter: str = "FUSION_F0",
                 min_full_per_cwe: int = 0,
                 min_partial_per_cwe: int = 0,
                 exact_per_bucket: int | None = None,
                 stats: dict | None = None):
    """`stats`, when passed, is filled in place with a per-stage row count
    (docker pool -> too-short -> empty-after-scrub -> dedup -> accepted
    pre-floor -> kept after per-CWE floor -> final after bucket cap/quota).
    Purely additive and optional -- existing callers that don't pass it see
    no behavior change. Added to answer phase1-acceptance-artifacts.md's
    open item 3 (the ~3,700-sample "available for training" vs "actually
    reaches fine-tuning" gap) without guessing which stage causes it.
    """
    ids = db.get_ids_by_docker_status("tested-successful")
    f0_union = _load_f0_union(db.db_path) if corr_filter == "FUSION_F0" else {}
    if stats is not None:
        stats["docker_successful_pool"] = len(ids)
        stats["dropped_too_short"] = 0
        stats["dropped_empty_after_scrub"] = 0
        stats["dropped_dedup"] = 0
        stats["dropped_no_db_cwe"] = 0
        stats["dropped_secure_tool_alarm"] = 0
        stats["dropped_vuln_correlation"] = 0
        stats["accepted_pre_floor"] = 0
    # bucket[(cwe, is_secure)] = [record, ...]
    buckets = defaultdict(list)
    seen_hashes = set()

    # Per-CWE correlation histogram, tracked BEFORE the corr_filter is
    # applied. Used to enforce `min_full_per_cwe` / `min_partial_per_cwe`
    # independently of which rows actually make it into the buckets —
    # this lets you say "train on FULL rows only, but keep a CWE only if
    # it has at least N PARTIAL examples as supporting evidence", which
    # `len(buckets[cwe])` cannot express on its own.
    cwe_corr_counts: dict[str, Counter] = defaultdict(Counter)

    # leak-stats
    scrubbed_rows = 0
    total_removals = 0
    empty_after_scrub = 0

    for cid in ids:
        try:
            code_row = db.get_code(cid)
            code = (code_row[0] if code_row else "") or ""
            code = code.strip()
            if len(code) < 40:
                if stats is not None:
                    stats["dropped_too_short"] += 1
                continue

            # ── prompt-leak scrub ────────────────────────────────
            # remove any literal "CWE-xx" reference (or the whole line) from code
            # so models can't just copy the label out of the source
            code, removed = scrub_code_for_leaks(code, mode=scrub_mode)
            if removed:
                scrubbed_rows  += 1
                total_removals += removed
            code = code.strip()
            if len(code) < 40:
                empty_after_scrub += 1
                if stats is not None:
                    stats["dropped_empty_after_scrub"] += 1
                continue
            # ──────────────────────────────────────────────────────

            # dedup is done AFTER scrubbing so that two rows which only
            # differed by their CWE comment collapse into one
            h = hashlib.sha1(code.encode("utf-8", errors="replace")).hexdigest()
            if h in seen_hashes:
                if stats is not None:
                    stats["dropped_dedup"] += 1
                continue

            db_cwe_raw = db.get_CWE_by_id(cid)
            if not db_cwe_raw:
                if stats is not None:
                    stats["dropped_no_db_cwe"] += 1
                continue
            cwe = str(db_cwe_raw).strip().upper()
            if not cwe.startswith("CWE-"):
                cwe = f"CWE-{cwe}"
            owasp = cwe_to_owasp(cwe)

            is_secure = db.is_secure_by_id(cid)
            sast_row  = db.fetch_sast_data_by_id(cid)
            dast_row  = db.fetch_dast_data_by_id(cid)   # (id, zap, burp_status)

            # all per-tool CWE sets — fetched ONCE per row and reused for
            # both correlation filtering and the multi-label target
            tool_cwes = per_tool_cwes(db, cid, sast_row, dast_row,
                                      burp_min_confidence=burp_min_confidence)
            corr      = row_correlation(cwe, tool_cwes)

            # legacy 'found'/'not-found' status — still kept in meta for
            # provenance / debugging even though correlation no longer
            # depends on it directly
            burp_status = dast_row[2] if dast_row and len(dast_row) > 2 else None

            # acceptance rules
            if is_secure:
                # corr_filter=ALL keeps secure rows even when a tool raised an
                # alarm. That is intentional in "raw tool consensus" mode: the
                # alarm itself is the label we want to study, not a reason to
                # discard the row.
                if corr_filter != "ALL" and corr != "NONE":
                    if stats is not None:
                        stats["dropped_secure_tool_alarm"] += 1
                    continue             # any tool alarm → skip (not clean)
            else:
                # Track the per-CWE correlation breakdown for *every*
                # vulnerable row (post-dedup) — even ones we are about
                # to drop via `corr_filter`. The CWE-level floors below
                # consult this histogram.
                cwe_corr_counts[cwe][corr] += 1
                if not _accept_vuln(corr, corr_filter, f0=f0_union.get(cid)):
                    if stats is not None:
                        stats["dropped_vuln_correlation"] += 1
                    continue

            # multi-label target: union of every CWE any tool flagged
            # (bandit + semgrep + sonarqube + zap + burpsuite) plus the DB
            # CWE, after the blacklist filter has removed manually-curated
            # tool-noise CWEs (the DB CWE itself is exempt — see
            # `merged_cwes` docstring).
            all_cwes, ignored_by_blacklist = merged_cwes(
                cwe, tool_cwes,
                include_db_cwe=include_db_cwe_in_target,
                blacklist=BLACKLIST_MULTILABEL,
            )

            seen_hashes.add(h)
            if stats is not None:
                stats["accepted_pre_floor"] += 1
            buckets[(cwe, bool(is_secure))].append({
                "id":          cid,
                "code":        code,
                "cwe":         cwe,                       # DB ground-truth CWE
                "owasp":       owasp,
                "is_secure":   bool(is_secure),
                "correlation": corr,                      # FULL / PARTIAL / NONE for DB CWE
                "tool_cwes":   {k: sorted(v, key=_cwe_sort_key)
                                for k, v in tool_cwes.items()},
                "burp_status": (str(burp_status).strip().lower()
                                if burp_status else ""),
                "all_cwes":    all_cwes,                  # sorted union, used as target
                "blacklist_ignored_count": ignored_by_blacklist,
            })
        except Exception as e:
            print(f"[warn] id={cid}: {e}")

    print(f"[scrub] mode={scrub_mode} | rows touched={scrubbed_rows} | "
          f"total tokens/lines removed={total_removals} | "
          f"dropped (empty after scrub)={empty_after_scrub}")

    # Blacklist provenance — how many tool-flagged CWE *instances* were
    # dropped, across how many rows. Reads from the per-row counter we
    # stored above. Useful as a sanity check after editing the constant.
    total_blacklist_ignored = sum(r["blacklist_ignored_count"]
                                  for rows in buckets.values() for r in rows)
    rows_with_ignored = sum(1
                            for rows in buckets.values() for r in rows
                            if r["blacklist_ignored_count"] > 0)
    print(f"[blacklist] entries={len(BLACKLIST_MULTILABEL)} | "
          f"ignored instances={total_blacklist_ignored} | "
          f"rows affected={rows_with_ignored} | "
          f"set={sorted(BLACKLIST_MULTILABEL, key=_cwe_sort_key)}")

    # ── Per-CWE floor enforcement ────────────────────────────────────
    # A CWE is kept iff all three thresholds are simultaneously cleared:
    #   1. total vulnerable rows in the bucket  ≥ min_per_cwe
    #   2. FULL    rows for this CWE in the DB  ≥ min_full_per_cwe
    #   3. PARTIAL rows for this CWE in the DB  ≥ min_partial_per_cwe
    # Counts (2) and (3) are taken from `cwe_corr_counts`, which records
    # every vulnerable row *before* the corr_filter dropped any of them,
    # so the floors are evidence-based and independent of `--corr_filter`.
    kept_cwes = set()
    for (c, sec), rows in buckets.items():
        if sec:
            continue
        full_n    = cwe_corr_counts[c]["FULL"]
        partial_n = cwe_corr_counts[c]["PARTIAL"]
        if (len(rows) >= min_per_cwe
                and full_n    >= min_full_per_cwe
                and partial_n >= min_partial_per_cwe):
            kept_cwes.add(c)
    buckets = {k: v for k, v in buckets.items() if k[0] in kept_cwes}
    if stats is not None:
        stats["kept_after_cwe_floor"] = sum(len(v) for v in buckets.values())

    # ── Per-bucket sampling ───────────────────────────────────────────────
    # Shuffle first (fixed seed → reproducible across runs) then apply the
    # requested size constraint.
    #
    # exact_per_bucket (new):
    #   When set, every (cwe, secure_flag) bucket must contain *exactly* N
    #   rows after sampling.  Buckets with fewer than N rows are discarded so
    #   the dataset stays perfectly balanced.  This is the recommended setting
    #   for controlled ablation experiments cited in the thesis (§ Dataset
    #   Construction) because it eliminates CWE-level class-size variance as
    #   a confound.  CWEs whose *vulnerable* bucket cannot reach the quota are
    #   dropped entirely (secure buckets of surviving CWEs may still be below
    #   quota when the DB simply does not have enough clean examples — those
    #   CWEs are also dropped so every surviving CWE contributes the same
    #   volume on both sides of the secure/vulnerable axis).
    #
    # max_per_bucket (legacy):
    #   Upper-bound only; buckets with fewer rows are kept as-is.  Useful
    #   when dataset coverage matters more than perfect balance.
    for k in buckets:
        RNG.shuffle(buckets[k])

    if exact_per_bucket is not None:
        # First pass: enforce the exact quota per bucket.
        sized: dict = {}
        for k, rows in buckets.items():
            if len(rows) >= exact_per_bucket:
                sized[k] = rows[:exact_per_bucket]
            # Buckets below quota are intentionally excluded.

        # Second pass: a CWE is kept only when *both* its vulnerable bucket
        # (is_secure=False) AND its secure bucket (is_secure=True) met quota.
        # This guarantees a perfectly balanced secure/vuln split per CWE.
        cwes_with_full_quota = {
            cwe for (cwe, is_sec) in sized if not is_sec
        } & {
            cwe for (cwe, is_sec) in sized if is_sec
        }

        dropped = {cwe for (cwe, _) in buckets
                   if cwe not in cwes_with_full_quota}
        if dropped:
            print(f"[exact_per_bucket={exact_per_bucket}] dropped "
                  f"{len(dropped)} CWE(s) that could not fill both buckets: "
                  f"{sorted(dropped)}")

        buckets = {k: v for k, v in sized.items()
                   if k[0] in cwes_with_full_quota}
    elif max_per_bucket and max_per_bucket > 0:
        # Legacy behaviour: cap without requiring exact count.
        for k in buckets:
            buckets[k] = buckets[k][:max_per_bucket]
    # max_per_bucket <= 0 → no cap at all (keep every accepted row)

    if stats is not None:
        stats["final_after_bucket_cap"] = sum(len(v) for v in buckets.values())

    return buckets


def stratified_split(rows, test_frac=0.2, val_frac=0.1):
    """Stratify by (owasp, is_secure). CWE'ye göre değil — çok az sınıf boşluğu oluşur."""
    groups = defaultdict(list)
    for r in rows:
        groups[(r["owasp"], r["is_secure"])].append(r)

    train, val, test = [], [], []
    for _, grp in groups.items():
        RNG.shuffle(grp)
        n = len(grp)
        n_test = max(1, int(round(n * test_frac))) if n >= 5 else 0
        n_val  = max(1, int(round(n * val_frac)))  if n >= 10 else 0
        test  += grp[:n_test]
        val   += grp[n_test:n_test + n_val]
        train += grp[n_test + n_val:]
    return train, val, test


# ─────────────────────────────────────────────────────────────
# JSONL emission
# ─────────────────────────────────────────────────────────────
def to_jsonl_record(r, multi_label: bool = True,
                    secure_target: str = "none") -> dict:
    """
    Build the JSONL record for a single example.

    target
    ------
      * secure row, secure_target="none"       → "NONE"  (legacy)
      * secure row, secure_target="tool_union" → same union rule as a
                                                 vulnerable row; "NONE" when
                                                 no tool flagged anything
      * vulnerable, multi_label → comma-separated sorted union of every
                                  CWE any tool flagged (+ DB CWE)
      * vulnerable, legacy      → single DB CWE (old behaviour)

    Note on secure_target="tool_union": `all_cwes` may include the DB CWE when
    --include_db_cwe_in_target is on. For a secure row that would assert the
    very vulnerability the row is supposed to lack, so the DB CWE is stripped
    here and only genuine tool detections survive.

    meta carries provenance so thesis-side analysis can drill into where
    each label came from (which tool detected what).
    """
    if r["is_secure"]:
        if secure_target == "tool_union":
            tool_union = sorted(
                {c for cwes in (r.get("tool_cwes") or {}).values() for c in cwes
                 if c not in BLACKLIST_MULTILABEL},
                key=_cwe_sort_key,
            )
            target = ", ".join(tool_union) if tool_union else "NONE"
        else:
            target = "NONE"
    elif multi_label and r.get("all_cwes"):
        target = ", ".join(r["all_cwes"])
    else:
        target = r["cwe"]

    return {
        "id":     r["id"],
        "prompt": PROMPT_TEMPLATE.format(code=r["code"]),
        "target": target,
        "code":   r["code"],
        "meta": {
            "db_cwe":      r["cwe"],
            "db_secure":   r["is_secure"],
            "owasp":       r["owasp"],
            "correlation": r["correlation"],
            "all_cwes":    r.get("all_cwes", []),
            "tool_cwes":   r.get("tool_cwes", {}),
            "burp_status": r.get("burp_status", ""),
            # How many CWE instances this row had filtered out by
            # BLACKLIST_MULTILABEL. 0 means either the blacklist is
            # empty or none of the tool detections were on the list.
            "blacklist_ignored_count": r.get("blacklist_ignored_count", 0),
        },
    }


def write_jsonl(path: str, rows: list, multi_label: bool = True,
                secure_target: str = "none") -> None:
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(to_jsonl_record(r, multi_label=multi_label,
                                               secure_target=secure_target),
                               ensure_ascii=False) + "\n")


# ─────────────────────────────────────────────────────────────
# Stats
# ─────────────────────────────────────────────────────────────
def stats(rows: list, secure_target: str = "none") -> dict:
    """
    Per-split aggregate stats. In addition to the legacy `by_cwe` count
    (which buckets each row by its DB CWE) and `by_owasp`, we also emit:

      * by_target_cwe          — histogram over every CWE appearing in
                                 any row's *target* list (right metric
                                 for label imbalance in multi-label)
      * by_tool_cwe[tool]      — per-tool histogram of CWEs that tool
                                 detected across the split (useful for
                                 thesis figures like 'CWE coverage by
                                 product')
      * by_correlation         — counts of FULL / PARTIAL / NONE rows
      * avg_targets_per_vuln_row — average label cardinality for the
                                   vulnerable subset
    """
    target_counter = Counter()
    tool_counters: dict[str, Counter] = defaultdict(Counter)
    corr_counter = Counter()

    for r in rows:
        corr_counter[r.get("correlation", "NONE")] += 1
        if r.get("is_secure"):
            # Under secure_target="tool_union" a secure row can still carry
            # labels, so count its actual tool detections rather than assuming
            # "NONE". With the legacy secure_target the tool sets are empty by
            # construction (corr==NONE was required), so this reduces to the
            # old behaviour automatically.
            sec_union = {c for cwes in (r.get("tool_cwes") or {}).values()
                         for c in cwes if c not in BLACKLIST_MULTILABEL}
            if secure_target == "tool_union" and sec_union:
                for c in sec_union:
                    target_counter[c] += 1
            else:
                target_counter["NONE"] += 1
        else:
            # fall back to the DB CWE if all_cwes is somehow empty
            for c in (r.get("all_cwes") or [r["cwe"]]):
                target_counter[c] += 1
        # Per-tool coverage is provenance, not label — track it for every row
        # regardless of secure flag, otherwise the "CWE coverage by product"
        # figure silently omits half the dataset in ALL mode.
        for tool, cwes in (r.get("tool_cwes") or {}).items():
            for c in cwes:
                tool_counters[tool][c] += 1

    n_vuln = sum(1 for r in rows if not r["is_secure"])

    return {
        "total":          len(rows),
        "by_cwe":         dict(Counter(r["cwe"]   for r in rows)),
        "by_owasp":       dict(Counter(r["owasp"] for r in rows)),
        "by_target_cwe":  dict(target_counter),
        "by_tool_cwe":    {tool: dict(c) for tool, c in tool_counters.items()},
        "by_correlation": dict(corr_counter),
        "secure":         sum(1 for r in rows if r["is_secure"]),
        "vulnerable":     n_vuln,
        "avg_targets_per_vuln_row": (
            sum(len(r.get("all_cwes", [])) for r in rows if not r["is_secure"])
            / max(1, n_vuln)
        ),
        # Blacklist provenance: total instances filtered out across this
        # split and how many rows were touched. Useful for the thesis
        # methodology section and for "with vs. without blacklist" deltas.
        "blacklist_total_ignored": sum(r.get("blacklist_ignored_count", 0)
                                       for r in rows),
        "blacklist_rows_affected": sum(1 for r in rows
                                       if r.get("blacklist_ignored_count", 0) > 0),
    }


def _str2bool(v) -> bool:
    """argparse-friendly bool parser so --multi_label False actually works."""
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "y", "t")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out_dir",        default="dataset_out")
    ap.add_argument("--min_per_cwe",    type=int, default=15,
                    help="Skip CWEs with fewer than this many *accepted* vulnerable "
                         "samples (i.e. rows that survived --corr_filter).")
    ap.add_argument("--min_full_per_cwe", type=int, default=0,
                    help="Independent floor: only keep CWEs that have at least this "
                         "many FULL-match vulnerable rows in the DB. Counted BEFORE "
                         "--corr_filter is applied, so you can e.g. train on FULL rows "
                         "while requiring strong PARTIAL evidence. Default 0 (off).")
    ap.add_argument("--min_partial_per_cwe", type=int, default=0,
                    help="Independent floor: only keep CWEs that have at least this "
                         "many PARTIAL-match vulnerable rows in the DB. Counted BEFORE "
                         "--corr_filter is applied. Default 0 (off).")
    ap.add_argument("--max_per_bucket", type=int, default=60,
                    help="Cap per (cwe, secure_flag) to keep the set balanced")
    ap.add_argument("--exact_per_bucket", type=int, default=None,
                    help="If set, sample *exactly* this many rows per (cwe, secure_flag) "
                         "bucket.  CWEs that cannot fill both their secure and vulnerable "
                         "buckets to the requested size are dropped entirely, producing a "
                         "perfectly class-balanced dataset at the cost of CWE coverage. "
                         "Overrides --max_per_bucket when provided. "
                         "Example: --exact_per_bucket 5 gives 5 secure + 5 vulnerable per CWE.")
    ap.add_argument("--scrub_mode",     default="line", choices=["line", "token", "none"],
                    help="How to remove CWE-xx leaks from code: "
                         "'line' drops the whole line (recommended), "
                         "'token' only removes the CWE-xx token")
    ap.add_argument("--test_frac",      type=float, default=0.2)
    ap.add_argument("--val_frac",       type=float, default=0.1)
    ap.add_argument("--multi_label",    type=_str2bool, default=True,
                    help="If True (default), target = sorted union of every CWE reported "
                         "by any tool (bandit/semgrep/sonarqube/zap/burpsuite) plus the "
                         "DB CWE. If False, target = single DB CWE (legacy single-label).")
    ap.add_argument("--include_db_cwe_in_target", type=_str2bool, default=True,
                    help="When multi_label is True, whether to also include the DB "
                         "ground-truth CWE in the target list (default True).")
    ap.add_argument("--corr_filter", choices=list(CORR_FILTER_CHOICES),
                    default="FUSION_F0",
                    help="Which acceptance gate to apply to vulnerable rows: "
                         "FUSION_F0 (default — reads fusion_model.py's persisted, "
                         "hierarchy-aware F0 union label; re-run `python fusion_model.py` "
                         "first if the DB changed since), "
                         "FULL (SAST and DAST both detected the DB CWE, exact-match only), "
                         "PARTIAL (only one of SAST/DAST detected it, exact-match only), "
                         "FULL_OR_PARTIAL (legacy default before 2026-09-08), "
                         "ALL (no correlation gate at all — keeps every "
                         "docker-runnable row including secure rows that tools "
                         "flagged; pair with --secure_target tool_union).")
    ap.add_argument("--secure_target", choices=list(SECURE_TARGET_CHOICES),
                    default="none",
                    help="Target for DB-secure rows: 'none' (default, legacy — "
                         "always NONE) or 'tool_union' (the CWEs tools actually "
                         "reported for that row, DB CWE excluded). "
                         "'tool_union' only makes sense with --corr_filter ALL.")
    ap.add_argument("--burp_min_confidence",
                    choices=list(BURP_CONFIDENCE_LEVELS),
                    default=None,
                    help="Drop Burp findings below this confidence level "
                         "(Burp order: tentative < firm < certain). "
                         "Default: keep all confidences.")
    args = ap.parse_args()

    if args.secure_target == "tool_union" and args.corr_filter != "ALL":
        print("[warn] --secure_target tool_union with --corr_filter "
              f"{args.corr_filter}: secure rows are already required to be "
              "alarm-free (correlation NONE), so their tool union is empty and "
              "every secure target will still be NONE. Use --corr_filter ALL "
              "to get the intended behaviour.")

    os.makedirs(args.out_dir, exist_ok=True)
    db = DBManager()
    buckets = collect_rows(db, args.min_per_cwe, args.max_per_bucket,
                           scrub_mode=args.scrub_mode,
                           include_db_cwe_in_target=args.include_db_cwe_in_target,
                           burp_min_confidence=args.burp_min_confidence,
                           corr_filter=args.corr_filter,
                           min_full_per_cwe=args.min_full_per_cwe,
                           min_partial_per_cwe=args.min_partial_per_cwe,
                           exact_per_bucket=args.exact_per_bucket)
    all_rows = [r for rows in buckets.values() for r in rows]
    print(f"[info] collected {len(all_rows)} rows across "
          f"{len({r['cwe'] for r in all_rows})} CWEs "
          f"(multi_label={args.multi_label}, "
          f"corr_filter={args.corr_filter}, "
          f"secure_target={args.secure_target}, "
          f"min_per_cwe={args.min_per_cwe}, "
          f"exact_per_bucket={args.exact_per_bucket}, "
          f"min_full_per_cwe={args.min_full_per_cwe}, "
          f"min_partial_per_cwe={args.min_partial_per_cwe}, "
          f"include_db_cwe_in_target={args.include_db_cwe_in_target}, "
          f"burp_min_confidence={args.burp_min_confidence})")

    train, val, test = stratified_split(all_rows, args.test_frac, args.val_frac)
    for name, rows in (("train", train), ("val", val), ("test", test)):
        write_jsonl(os.path.join(args.out_dir, f"dataset_{name}.jsonl"), rows,
                    multi_label=args.multi_label,
                    secure_target=args.secure_target)

    report = {name: stats(rows, secure_target=args.secure_target)
              for name, rows in (("train", train), ("val", val), ("test", test))}
    with open(os.path.join(args.out_dir, "dataset_stats.json"), "w") as f:
        json.dump(report, f, indent=2)
    print(json.dumps({k: v["total"] for k, v in report.items()}, indent=2))


if __name__ == "__main__":
    main()