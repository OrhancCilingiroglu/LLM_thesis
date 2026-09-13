"""LLM judge panel (methodology-plan.md Phase 2, section 2.2/2.3).

Scores whether a sample actually contains its generation-time target CWE,
using frontier API models as judges (never the student/fine-tuned models --
methodology-plan.md's own rule). Output is structured JSON with mandatory
verbatim evidence, checked mechanically before a VULNERABLE verdict is
allowed to carry CWE credit -- an unsupported verdict is downgraded to
UNCERTAIN rather than discarded outright, so the evidence-check-pass-rate
metric (§2.3) can still see it happened.

Persistence follows the same additive pattern as CodeQL/Snyk
(src/tools/sarif_scanners.py + DBManager.save_findings/load_findings/
has_scanned): each judge is a "tool" writing to its own <judge>_cwes/_raw/
_version columns via a JudgeVerdict -> Finding mapping. Nothing here
duplicates that persistence layer.

Two new tables, both additive, neither touches code_cwe directly:
    judge_cache  -- hash(code + prompt_version + model) -> raw response, so
                    iterating on the prompt never re-pays for an unchanged call.
    judge_subset -- the frozen stratified cohort every judge scores, so the
                    Phase 2 source-agreement matrix compares judges on the
                    exact same samples even as code_cwe.db keeps growing.

Usage:
    python llm_judge.py --select-subset-only          # just print the cohort
    python llm_judge.py --judge claude_judge --limit 5 # smoke test
    python llm_judge.py --judge claude_judge           # full 3,000-sample run
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import sqlite3
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from api_handler import ClaudeClient, OpenAIClient  # noqa: E402
from cwe_hierarchy_matching import OWASP, _owasp_category_for_cwe  # noqa: E402
from db_handler import DBManager  # noqa: E402

_SRC_TOOLS = Path(__file__).resolve().parents[2] / "src" / "tools"
if str(_SRC_TOOLS) not in sys.path:
    sys.path.insert(0, str(_SRC_TOOLS))
from sarif_scanners import Finding  # noqa: E402

_SRC_CORE = Path(__file__).resolve().parents[2] / "src" / "core"
if str(_SRC_CORE) not in sys.path:
    sys.path.insert(0, str(_SRC_CORE))
from cwe import load_hierarchy  # noqa: E402

DB_PATH = os.path.join(os.path.dirname(__file__), "code_cwe.db")

# Bump this whenever _JUDGE_PROMPT_TEMPLATE or JUDGE_SYSTEM_PROMPT changes --
# it is part of the cache key, so a bump means "re-ask every sample".
PROMPT_VERSION = "judge_v1"

DEFAULT_SUBSET_NAME = "phase2_3000"
DEFAULT_SUBSET_N = 3000
# Frozen, not tunable per-run -- methodology-plan.md's reproducibility rule.
# Change only by picking a new subset_name (old cohorts stay reproducible).
DEFAULT_SEED = 20260902

JUDGE_SYSTEM_PROMPT = (
    "You are a senior application security engineer reviewing a single-file "
    "Python/Flask application for one specific weakness. Respond with STRICT "
    "JSON only -- no markdown fences, no prose before or after the object."
)

_JUDGE_PROMPT_TEMPLATE = """Target weakness: CWE-{target_cwe}.

Review the code below and decide whether it contains an instance of
CWE-{target_cwe} that is actually reachable/exploitable in this file (not a
generic code-quality issue, and not a different CWE).

### Code (Python/Flask)
```python
{code}
```

Respond with exactly this JSON shape, nothing else:
{{
  "verdict": "VULNERABLE" | "SECURE" | "UNCERTAIN",
  "cwe": {target_cwe},
  "evidence_line": "<verbatim line copied from the code above, or empty string if verdict is not VULNERABLE>",
  "line_number": <int or null>,
  "sink": "<short name of the vulnerable function/call, or empty string>",
  "exploit_sketch": "<one sentence, or empty string>",
  "confidence": <float 0.0-1.0>
}}

If verdict is VULNERABLE, evidence_line MUST be copied verbatim (identical
whitespace and characters) from the code above -- do not paraphrase or
reconstruct it. An evidence_line that cannot be found verbatim in the code
will cause this verdict to be discarded.
"""

# Bump on any change to _BLIND_PROMPT_TEMPLATE/JUDGE_SYSTEM_PROMPT_BLIND.
# Separate from PROMPT_VERSION because the two prompts ask fundamentally
# different questions (confirm a given CWE vs. independently find one) and
# must never share a cache key or a DB column.
PROMPT_VERSION_BLIND = "judge_v2_blind"

JUDGE_SYSTEM_PROMPT_BLIND = (
    "You are a senior application security engineer reviewing a single-file "
    "Python/Flask application for security weaknesses. Respond with STRICT "
    "JSON only -- no markdown fences, no prose before or after the object."
)

# Deliberately never mentions the sample's target CWE -- this is the "blind
# recovery" pass methodology-plan.md §2.1 asks for ("independent of both
# parties"). See the caveat in changes_summary.md 2026-09-02 (1)/(2): the
# anchored prompt above (_JUDGE_PROMPT_TEMPLATE) reveals the target, which
# makes its "cwe" field trivially match it and its votes near-useless for
# Dawid-Skene (specificity 8.0%/30.5%). This template is what that caveat
# said still needed to be built.
_BLIND_PROMPT_TEMPLATE = """Review the code below for security vulnerabilities. Identify the single most
significant one, if any -- do not list multiple issues.

### Code (Python/Flask)
```python
{code}
```

Respond with exactly this JSON shape, nothing else:
{{
  "verdict": "VULNERABLE" | "SECURE" | "UNCERTAIN",
  "cwe": <int or null -- the CWE id you believe applies, your own independent judgment>,
  "evidence_line": "<verbatim line copied from the code above, or empty string>",
  "line_number": <int or null>,
  "sink": "<short name of the vulnerable function/call, or empty string>",
  "exploit_sketch": "<one sentence, or empty string>",
  "confidence": <float 0.0-1.0>
}}

If verdict is VULNERABLE, evidence_line MUST be copied verbatim (identical
whitespace and characters) from the code above.
"""


def build_judge_prompt(code: str, target_cwe: int) -> str:
    return _JUDGE_PROMPT_TEMPLATE.format(code=code, target_cwe=target_cwe)


def build_blind_judge_prompt(code: str) -> str:
    return _BLIND_PROMPT_TEMPLATE.format(code=code)


# Bump on any change to _GUIDED_PROMPT_TEMPLATE/JUDGE_SYSTEM_PROMPT_GUIDED.
PROMPT_VERSION_GUIDED = "judge_v3_guided"

JUDGE_SYSTEM_PROMPT_GUIDED = JUDGE_SYSTEM_PROMPT_BLIND

# The blind pass (judge_v2_blind) recovers ~23% of target CWEs, but the
# failure is not random: recovery is ~50-96% on "canonical" pattern-matched
# CWEs (SQLi, XSS, path traversal, deserialization...) and 0% on ~15 rarer/
# architectural ones (LDAP injection, SSI/PHP inclusion, replay attacks,
# certificate validation...) that a model apparently never spontaneously
# considers -- confirmed both in this project's own data (changes_summary.md
# 2026-09-03) and in the literature (data-imbalance bias toward frequent CWE
# categories; VSP-style candidate-list prompting reported a 553% F1 gain on
# vulnerability-*type* identification specifically, arXiv:2402.17230).
#
# This prompt sits between anchored (reveals the exact target -> collapses
# specificity) and blind (reveals nothing -> misses the long tail): it shows
# the OWASP-category candidate CWEs the sample's target belongs to -- e.g.
# all ~34 A05-Injection CWEs -- explicitly as a checklist to consider, not as
# the answer, and lets the judge escape the list if something else applies.
# The category is still statistically informative (it is derived from the
# true target), so this is NOT a substitute for the blind pass on RQ6' --
# it is a separate ablation testing whether a scoped vocabulary alone closes
# the long-tail gap.
_GUIDED_PROMPT_TEMPLATE = """Review the code below for security vulnerabilities.

Consider whether it contains an instance of any of the following weakness
types. This is a candidate checklist, not a hint at the answer -- most of
these will NOT apply, and you should not force-fit one just because it is
listed:

{candidates}

If the code's primary vulnerability is not well described by any entry
above, report the CWE you believe actually applies instead -- do not pick
from the list just because a list was given.

### Code (Python/Flask)
```python
{code}
```

Respond with exactly this JSON shape, nothing else:
{{
  "verdict": "VULNERABLE" | "SECURE" | "UNCERTAIN",
  "cwe": <int or null -- the CWE id you believe applies, your own independent judgment>,
  "evidence_line": "<verbatim line copied from the code above, or empty string>",
  "line_number": <int or null>,
  "sink": "<short name of the vulnerable function/call, or empty string>",
  "exploit_sketch": "<one sentence, or empty string>",
  "confidence": <float 0.0-1.0>
}}

If verdict is VULNERABLE, evidence_line MUST be copied verbatim (identical
whitespace and characters) from the code above.
"""


def _candidate_cwes_for_target(target_cwe: int) -> list[int]:
    """CWEs in the same OWASP 2025 category as `target_cwe` -- the checklist
    shown to the guided judge. Uses the category only, never the target
    itself, so the true answer is not identifiable from the list alone.
    """
    category = _owasp_category_for_cwe(target_cwe)
    if category is None:
        return []
    for name in dir(OWASP):
        if name.endswith("_list") and name.split("_", 2)[0] == category:
            return list(getattr(OWASP, name))
    return []


def _format_candidates(code: str, candidates: list[int]) -> str:
    hierarchy = load_hierarchy()
    lines = [
        f"CWE-{c}: {hierarchy.catalog.names[c]}"
        for c in sorted(candidates) if c in hierarchy.catalog.names
    ]
    return _GUIDED_PROMPT_TEMPLATE.format(code=code, candidates="\n".join(lines))


def build_guided_judge_prompt(code: str, target_cwe: int) -> str:
    return _format_candidates(code, _candidate_cwes_for_target(target_cwe))


# --------------------------------------------------------------------------- #
# Negative control -- phase2-acceptance-artifacts.md open item 7. Same guided
# checklist prompt, but the candidate list is drawn from a category that does
# NOT contain the sample's own target CWE, run against code the fusion model
# already scores confidently SECURE for its real target (p_vulnerable < 0.1).
# Tests whether the checklist itself induces false VULNERABLE verdicts --
# "kandirma" (the advisor's question) independent of whether the listed CWE
# is even plausible for the code shown. Never anchored/scored against the
# real target; the only thing measured is the false-VULNERABLE rate against
# a checklist that structurally should not apply.
# --------------------------------------------------------------------------- #

PROMPT_VERSION_NEGCTRL = "judge_v4_negctrl"

_OWASP_CATEGORIES = sorted(
    name.split("_", 2)[0] for name in dir(OWASP) if name.endswith("_list")
)


def mismatched_category_for(target_cwe: int) -> str:
    """Deterministic (seeded, reproducible) choice of an OWASP category that
    does NOT contain target_cwe -- e.g. an A05/Injection sample gets an A04
    candidate list, never its own. Picked by a fixed rotation off the
    target's own category rather than `random`, so re-running this on the
    same corpus always assigns the same decoy category to the same sample.
    """
    own = _owasp_category_for_cwe(target_cwe)
    others = [c for c in _OWASP_CATEGORIES if c != own]
    if not others:
        raise ValueError(f"no other OWASP category available to mismatch against {own!r}")
    idx = target_cwe % len(others)
    return others[idx]


def _candidates_for_category(category: str) -> set[int]:
    for name in dir(OWASP):
        if name.endswith("_list") and name.split("_", 2)[0] == category:
            return set(getattr(OWASP, name))
    return set()


def build_negctrl_judge_prompt(code: str, target_cwe: int) -> tuple[str, str]:
    """Returns (prompt, decoy_category) -- caller persists decoy_category
    alongside the verdict so the false-VULNERABLE rate can be reported
    per-decoy-category, not just in aggregate.
    """
    decoy_category = mismatched_category_for(target_cwe)
    candidates = _candidates_for_category(decoy_category)
    if not candidates:
        raise ValueError(f"no CWE list found for decoy category {decoy_category!r}")
    return _format_candidates(code, list(candidates)), decoy_category


# --------------------------------------------------------------------------- #
# Evidence check -- mechanical hallucination filter (methodology-plan.md §2.2)
# --------------------------------------------------------------------------- #

_WS_RE = re.compile(r"\s+")


def _normalize_ws(text: str) -> str:
    return _WS_RE.sub(" ", text).strip()


def evidence_check(code: str, evidence_line: str) -> bool:
    """True if `evidence_line` appears verbatim (whitespace-normalized) in `code`."""
    if not evidence_line or not evidence_line.strip():
        return False
    return _normalize_ws(evidence_line) in _normalize_ws(code)


# --------------------------------------------------------------------------- #
# Verdict parsing
# --------------------------------------------------------------------------- #

_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)


class VerdictParseError(ValueError):
    pass


_BAD_ESCAPE_RE = re.compile(r'\\(?!["\\/bfnrtu])')


def parse_verdict_json(raw_text: str) -> dict:
    """Extract and parse the judge's JSON object, tolerating markdown fences.

    Judges routinely paste multi-line `evidence_line` snippets (HTML/JS with
    quotes and backslash escapes of their own) straight into the JSON string
    without re-escaping for JSON -- raw newlines and stray backslashes like
    `\\'` are common (e.g. sample ids 16664, 20137, 6266, 11408, 27224 across
    every blind/guided judge, all deterministic -- same code, same failure,
    every retry). Neither is a one-off glitch a plain retry fixes, so this
    tries three JSON readings, strictest first, before giving up:
      1. strict json.loads -- the common case, unchanged.
      2. strict=False -- tolerates raw control characters (literal newlines/
         tabs) inside strings; Python's json module supports this directly.
      3. (2) plus backslash-escaping any `\\` not already a valid JSON escape
         -- fixes stray escapes like `\\'` that came from HTML/JS source, not
         a JSON encoder.
    """
    text = raw_text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text.split("\n", 1)[1] if "\n" in text else text
    match = _JSON_BLOCK_RE.search(text)
    if not match:
        raise VerdictParseError(f"no JSON object found in judge output: {raw_text[:200]!r}")
    body = match.group(0)
    repaired = _BAD_ESCAPE_RE.sub(r"\\\\", body)
    last_exc: json.JSONDecodeError | None = None
    for candidate, strict in ((body, True), (body, False), (repaired, False)):
        try:
            return json.loads(candidate, strict=strict)
        except json.JSONDecodeError as exc:
            last_exc = exc
    raise VerdictParseError(f"malformed JSON from judge: {last_exc}") from last_exc


@dataclass(frozen=True)
class JudgeVerdict:
    sample_id: int
    judge: str
    judge_version: str
    verdict: str          # "VULNERABLE" | "SECURE" | "UNCERTAIN"
    cwe: int | None
    evidence_line: str
    line_number: int | None
    sink: str
    exploit_sketch: str
    confidence: float | None
    evidence_pass: bool   # False only when a VULNERABLE verdict failed the check
    raw_text: str          # judge's raw response, pre-parse, kept for audit


def verdict_from_json(sample_id: int, judge: str, judge_version: str, code: str,
                       payload: dict, raw_text: str) -> JudgeVerdict:
    verdict = str(payload.get("verdict", "UNCERTAIN")).upper()
    evidence_line = str(payload.get("evidence_line") or "")
    evidence_pass = evidence_check(code, evidence_line) if verdict == "VULNERABLE" else True
    if verdict == "VULNERABLE" and not evidence_pass:
        # Downgrade, don't discard: keeps the sample visible to the
        # evidence-check-pass-rate metric instead of vanishing silently.
        verdict = "UNCERTAIN"

    cwe = payload.get("cwe")
    try:
        cwe = int(cwe) if cwe is not None else None
    except (TypeError, ValueError):
        cwe = None

    confidence = payload.get("confidence")
    try:
        confidence = float(confidence) if confidence is not None else None
    except (TypeError, ValueError):
        confidence = None

    line_number = payload.get("line_number")
    try:
        line_number = int(line_number) if line_number is not None else None
    except (TypeError, ValueError):
        line_number = None

    return JudgeVerdict(
        sample_id=sample_id, judge=judge, judge_version=judge_version,
        verdict=verdict, cwe=cwe, evidence_line=evidence_line,
        line_number=line_number, sink=str(payload.get("sink") or ""),
        exploit_sketch=str(payload.get("exploit_sketch") or ""),
        confidence=confidence, evidence_pass=evidence_pass, raw_text=raw_text,
    )


def verdict_to_finding(v: JudgeVerdict) -> Finding:
    """CWE credit only for a supported VULNERABLE verdict; SECURE/UNCERTAIN
    verdicts still produce a Finding (cwe_ids=()) so `raw` -- confidence,
    exploit_sketch, the evidence-check outcome -- is never dropped just
    because the sample "passed". findings_to_columns() only nulls out `raw`
    for an *empty* findings list, so one Finding per judged sample keeps it.
    """
    cwe_ids = (v.cwe,) if (v.verdict == "VULNERABLE" and v.cwe is not None) else ()
    return Finding(
        sample_id=str(v.sample_id),
        tool=v.judge,
        tool_version=v.judge_version,
        cwe_ids=cwe_ids,
        rule_id=v.sink,
        message=v.exploit_sketch,
        line=v.line_number,
        severity=None,
        provenance="llm-judge",
        raw={
            "verdict": v.verdict,
            "cwe": v.cwe,
            "evidence_line": v.evidence_line,
            "evidence_pass": v.evidence_pass,
            "confidence": v.confidence,
            "raw_text": v.raw_text,
        },
    )


# --------------------------------------------------------------------------- #
# Cache -- hash(code + prompt_version + model) -> raw response
# --------------------------------------------------------------------------- #

def _cache_key(code: str, model: str, prompt_version: str | None = None) -> str:
    # `prompt_version or PROMPT_VERSION` (not a default-arg value) so a test
    # can monkeypatch the module-level PROMPT_VERSION and still see it here.
    prompt_version = prompt_version or PROMPT_VERSION
    h = hashlib.sha256()
    h.update(code.encode("utf-8"))
    h.update(b"\x00")
    h.update(prompt_version.encode("utf-8"))
    h.update(b"\x00")
    h.update(model.encode("utf-8"))
    return h.hexdigest()


def _ensure_cache_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS judge_cache (
            cache_key TEXT PRIMARY KEY,
            model     TEXT NOT NULL,
            raw_text  TEXT NOT NULL
        )
        """
    )


def _cache_get(db_path: str, cache_key: str) -> str | None:
    conn = sqlite3.connect(db_path)
    try:
        _ensure_cache_table(conn)
        row = conn.execute(
            "SELECT raw_text FROM judge_cache WHERE cache_key = ?", (cache_key,)
        ).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def _cache_put(db_path: str, cache_key: str, model: str, raw_text: str) -> None:
    conn = sqlite3.connect(db_path)
    try:
        _ensure_cache_table(conn)
        conn.execute(
            "INSERT OR REPLACE INTO judge_cache (cache_key, model, raw_text) VALUES (?, ?, ?)",
            (cache_key, model, raw_text),
        )
        conn.commit()
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Judge registry -- one client + one (prompt->raw_text) callable per judge name
# --------------------------------------------------------------------------- #

_JUDGE_CLIENTS: dict[str, tuple] = {}

# One row per (provider, prompt mode). Adding a new prompt mode or provider
# is "add a row", not "add a branch" -- see the pre-refactor history in git
# if the old if/elif chain is ever useful as a reference.
_PROVIDERS = {
    "claude": lambda: ("claude", ClaudeClient()),
    "gpt4": lambda: ("gpt4", OpenAIClient()),
}
_MODES = {
    "": (PROMPT_VERSION, JUDGE_SYSTEM_PROMPT),
    "_blind": (PROMPT_VERSION_BLIND, JUDGE_SYSTEM_PROMPT_BLIND),
    "_guided": (PROMPT_VERSION_GUIDED, JUDGE_SYSTEM_PROMPT_GUIDED),
    "_negctrl": (PROMPT_VERSION_NEGCTRL, JUDGE_SYSTEM_PROMPT_GUIDED),
}


def _prompt_mode(judge_name: str) -> str:
    for suffix in ("_blind", "_guided", "_negctrl"):
        if judge_name.endswith(suffix):
            return suffix
    return ""


def _get_client(judge_name: str) -> tuple:
    """Returns (call(prompt) -> raw_text, judge_version). Lazily constructed
    so a missing API key only fails the judge actually being used.

    judge_name is "<provider>_judge[<mode>]" e.g. "claude_judge",
    "gpt4_judge_blind", "claude_judge_guided".
    """
    if judge_name not in _JUDGE_CLIENTS:
        mode = _prompt_mode(judge_name)
        provider_key = judge_name[: -len("_judge" + mode)] if mode else judge_name[: -len("_judge")]
        if provider_key not in _PROVIDERS or mode not in _MODES:
            raise ValueError(
                f"unknown judge: {judge_name!r}; expected '<claude|gpt4>_judge[_blind|_guided]'"
            )
        prompt_version, system_prompt = _MODES[mode]
        _, client = _PROVIDERS[provider_key]()

        if provider_key == "claude":
            version = f"{client.model_in}@{prompt_version}"

            def call(prompt: str, _client=client, _system=system_prompt) -> str:
                return _client.send_prompt(prompt, temperature=0, system=_system)

        else:  # gpt4
            model = "gpt-4.1-2025-04-14"
            version = f"{model}@{prompt_version}"

            def call(prompt: str, _client=client, _model=model, _system=system_prompt) -> str:
                return _client.send_prompt(
                    prompt, model_temp=_model, temperature=0, system=_system,
                    response_format={"type": "json_object"},
                )

        _JUDGE_CLIENTS[judge_name] = (call, version)
    return _JUDGE_CLIENTS[judge_name]


def _build_prompt(judge_name: str, code: str, target_cwe: int) -> str:
    mode = _prompt_mode(judge_name)
    if mode == "_blind":
        return build_blind_judge_prompt(code)
    if mode == "_guided":
        return build_guided_judge_prompt(code, target_cwe)
    if mode == "_negctrl":
        return build_negctrl_judge_prompt(code, target_cwe)[0]
    return build_judge_prompt(code, target_cwe)


def _call_and_cache(judge_name: str, code: str, target_cwe: int, db_path: str,
                     strict: bool = False) -> str:
    call, model_for_cache = _get_client(judge_name)
    prompt_version, _ = _MODES[_prompt_mode(judge_name)]
    key = _cache_key(code, model_for_cache, prompt_version)
    if not strict:
        cached = _cache_get(db_path, key)
        if cached is not None:
            return cached
    prompt = _build_prompt(judge_name, code, target_cwe)
    if strict:
        prompt += "\n\nReply with ONLY the JSON object, nothing else."
    raw_text = call(prompt)
    _cache_put(db_path, key, model_for_cache, raw_text)  # overwrites a bad cached retry, too
    return raw_text


# --------------------------------------------------------------------------- #
# Stratified subset selection (frozen, reproducible)
# --------------------------------------------------------------------------- #

def _vulnerable_docker_successful_ids_and_cwe(db_path: str) -> list[tuple[int, int]]:
    """Same pool fusion_model.build_vote_matrix scores: vulnerable, docker-successful."""
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT id, CWE FROM code_cwe WHERE docker = 'tested-successful' "
            "AND secure IN ('VULNERABLE', 0)"
        ).fetchall()
    finally:
        conn.close()
    return [(r[0], r[1]) for r in rows if r[1] is not None]


def _ensure_subset_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS judge_subset (
            subset_name TEXT NOT NULL,
            code_id     INTEGER NOT NULL,
            PRIMARY KEY (subset_name, code_id)
        )
        """
    )


def select_stratified_subset(db_path: str = DB_PATH, subset_name: str = DEFAULT_SUBSET_NAME,
                              n: int = DEFAULT_SUBSET_N, seed: int = DEFAULT_SEED) -> list[int]:
    """Frozen, reproducible stratified sample of vulnerable docker-successful ids.

    Stratified by OWASP 2025 category, proportional to each category's share of
    the pool. Persisted under `subset_name` in judge_subset the first time it is
    computed, and returned unchanged on every later call -- every judge must
    score the exact same cohort for the Phase 2 source-agreement matrix to be
    meaningful, and code_cwe.db keeps growing as other pipeline stages run.
    """
    conn = sqlite3.connect(db_path)
    try:
        _ensure_subset_table(conn)
        existing = [
            r[0] for r in conn.execute(
                "SELECT code_id FROM judge_subset WHERE subset_name = ?", (subset_name,)
            ).fetchall()
        ]
        if existing:
            return sorted(existing)

        pool = _vulnerable_docker_successful_ids_and_cwe(db_path)
        if not pool:
            return []
        by_category: dict[str, list[int]] = defaultdict(list)
        for code_id, cwe in pool:
            category = _owasp_category_for_cwe(cwe) or "UNMAPPED"
            by_category[category].append(code_id)

        total = len(pool)
        n = min(n, total)
        raw_shares = {cat: n * len(ids) / total for cat, ids in by_category.items()}
        target = {cat: int(share) for cat, share in raw_shares.items()}
        remainder = n - sum(target.values())
        # largest-remainder method: exact per-category counts summing to n
        order = sorted(by_category, key=lambda c: raw_shares[c] - target[c], reverse=True)
        for cat in order[:remainder]:
            target[cat] += 1

        rng = random.Random(seed)
        selected: list[int] = []
        for cat, ids in by_category.items():
            k = min(target[cat], len(ids))
            selected.extend(rng.sample(ids, k))

        conn.executemany(
            "INSERT OR IGNORE INTO judge_subset (subset_name, code_id) VALUES (?, ?)",
            [(subset_name, i) for i in selected],
        )
        conn.commit()
        return sorted(selected)
    finally:
        conn.close()


DEFAULT_NEGCTRL_SUBSET_NAME = "negctrl_120"
DEFAULT_NEGCTRL_N = 120
DEFAULT_NEGCTRL_SEED = 20260908


def select_negctrl_subset(db_path: str = DB_PATH, subset_name: str = DEFAULT_NEGCTRL_SUBSET_NAME,
                           n: int = DEFAULT_NEGCTRL_N, seed: int = DEFAULT_NEGCTRL_SEED) -> list[int]:
    """Frozen, reproducible stratified sample of the negative-control pool:
    vulnerable/docker-successful samples the F2 (no-judges) fusion already
    scores confidently SECURE for their real target (p_vulnerable < 0.1,
    from the `fusion_labels` table `fusion_model.py` persists). Stratified
    by OWASP 2025 category, same method as `select_stratified_subset`, and
    persisted under `subset_name` in `judge_subset` so a re-run always
    scores the same cohort.
    """
    conn = sqlite3.connect(db_path)
    try:
        _ensure_subset_table(conn)
        existing = [
            r[0] for r in conn.execute(
                "SELECT code_id FROM judge_subset WHERE subset_name = ?", (subset_name,)
            ).fetchall()
        ]
        if existing:
            return sorted(existing)

        pool = conn.execute(
            "SELECT c.id, c.CWE FROM code_cwe c JOIN fusion_labels f ON f.code_id = c.id "
            "WHERE f.p_vulnerable < 0.1 AND c.CWE IS NOT NULL"
        ).fetchall()
        if not pool:
            return []
        by_category: dict[str, list[int]] = defaultdict(list)
        for code_id, cwe in pool:
            category = _owasp_category_for_cwe(int(str(cwe).replace("CWE-", ""))) or "UNMAPPED"
            by_category[category].append(code_id)

        total = len(pool)
        n = min(n, total)
        raw_shares = {cat: n * len(ids) / total for cat, ids in by_category.items()}
        target = {cat: int(share) for cat, share in raw_shares.items()}
        remainder = n - sum(target.values())
        order = sorted(by_category, key=lambda c: raw_shares[c] - target[c], reverse=True)
        for cat in order[:remainder]:
            target[cat] += 1

        rng = random.Random(seed)
        selected: list[int] = []
        for cat, ids in by_category.items():
            k = min(target[cat], len(ids))
            selected.extend(rng.sample(ids, k))

        conn.executemany(
            "INSERT OR IGNORE INTO judge_subset (subset_name, code_id) VALUES (?, ?)",
            [(subset_name, i) for i in selected],
        )
        conn.commit()
        return sorted(selected)
    finally:
        conn.close()


def negctrl_report(db_path: str = DB_PATH, subset_name: str = DEFAULT_NEGCTRL_SUBSET_NAME) -> dict:
    """Two readings for the negative-control cross-check, overall and per
    decoy OWASP category. Reads back whatever's saved under
    claude_judge_negctrl / gpt4_judge_negctrl -- run judge_batch() first.

    `false_vulnerable_rate` -- verdict == VULNERABLE at all. The loose
    reading: the prompt explicitly allows the judge to name a CWE outside
    the given checklist ("if the code's primary vulnerability is not well
    described by any entry above, report the CWE you believe actually
    applies instead"), so a VULNERABLE verdict alone doesn't prove the
    checklist caused it -- it may be a real, independent issue the judge
    would have found unprompted.

    `decoy_checklist_match_rate` -- stricter and closer to the advisor's
    actual question: VULNERABLE *and* the reported `cwe` is literally a
    member of the mismatched candidate list shown to the judge. This is
    the "took the bait" signal -- harder to explain as an unrelated real
    finding, though still not proof of hallucination (evidence_pass, also
    reported, is the existing mechanical check for that).
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        ids = [
            r[0] for r in conn.execute(
                "SELECT code_id FROM judge_subset WHERE subset_name = ?", (subset_name,)
            ).fetchall()
        ]
        cwe_by_id = {
            r["id"]: int(str(r["CWE"]).replace("CWE-", ""))
            for r in conn.execute(
                f"SELECT id, CWE FROM code_cwe WHERE id IN ({','.join('?' * len(ids))})", ids
            ).fetchall()
        } if ids else {}

        report: dict = {"n": len(ids), "judges": {}}
        for judge_name in ("claude_judge_negctrl", "gpt4_judge_negctrl"):
            rows = conn.execute(
                f"SELECT id, {judge_name}_raw FROM code_cwe "
                f"WHERE id IN ({','.join('?' * len(ids))}) AND {judge_name}_version IS NOT NULL",
                ids,
            ).fetchall() if ids else []

            per_category: dict[str, list[tuple[bool, bool]]] = defaultdict(list)
            n_scored = 0
            n_false_vuln = 0
            n_checklist_match = 0
            n_evidence_pass_given_vuln = 0
            for r in rows:
                if not r[f"{judge_name}_raw"]:
                    continue
                n_scored += 1
                verdict_raw = json.loads(r[f"{judge_name}_raw"])[0]["raw"]
                is_false_vuln = verdict_raw["verdict"] == "VULNERABLE"
                decoy = mismatched_category_for(cwe_by_id[r["id"]])
                reported_cwe = verdict_raw["cwe"]
                is_checklist_match = (
                    is_false_vuln and reported_cwe is not None
                    and reported_cwe in _candidates_for_category(decoy)
                )
                per_category[decoy].append((is_false_vuln, is_checklist_match))
                if is_false_vuln:
                    n_false_vuln += 1
                    if verdict_raw["evidence_pass"]:
                        n_evidence_pass_given_vuln += 1
                if is_checklist_match:
                    n_checklist_match += 1

            report["judges"][judge_name] = {
                "n_scored": n_scored,
                "n_false_vulnerable": n_false_vuln,
                "false_vulnerable_rate": (n_false_vuln / n_scored) if n_scored else None,
                "n_decoy_checklist_match": n_checklist_match,
                "decoy_checklist_match_rate": (n_checklist_match / n_scored) if n_scored else None,
                "evidence_pass_rate_given_vulnerable": (
                    n_evidence_pass_given_vuln / n_false_vuln if n_false_vuln else None
                ),
                "by_decoy_category": {
                    cat: {
                        "n": len(flags),
                        "false_vulnerable_rate": sum(f for f, _ in flags) / len(flags),
                        "decoy_checklist_match_rate": sum(m for _, m in flags) / len(flags),
                    }
                    for cat, flags in sorted(per_category.items())
                },
            }
        return report
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #

def judge_batch(judge_name: str, sample_ids: list[int], db_path: str = DB_PATH,
                 max_retries: int = 1, max_consecutive_errors: int = 8,
                 progress_every: int = 25) -> dict:
    """Judge every id in sample_ids with `judge_name`. Resumable via
    DBManager.has_scanned -- a re-run only pays for ids not yet scanned.

    Aborts early if `max_consecutive_errors` failures happen in a row --
    a long run failing on every sample is almost always systemic (bad API
    key, insufficient balance, rate limit), not per-sample noise. Stopping
    early avoids burning through the rest of the subset on a call that is
    guaranteed to keep failing.

    Returns {"scanned", "skipped", "errors": [(id, str), ...], "aborted": bool}.
    """
    db = DBManager(db_path=db_path)
    _, judge_version = _get_client(judge_name)
    summary = {"scanned": 0, "skipped": 0, "errors": [], "aborted": False}
    consecutive_errors = 0
    total = len(sample_ids)

    for i, sample_id in enumerate(sample_ids, start=1):
        if db.has_scanned(sample_id, judge_name):
            summary["skipped"] += 1
            continue
        try:
            code, *_ = db.get_files_by_id(sample_id)
            target_cwe = db.get_CWE_by_id(sample_id)
            raw_text = _call_and_cache(judge_name, code, target_cwe, db_path)

            payload = None
            for attempt in range(max_retries + 1):
                try:
                    payload = parse_verdict_json(raw_text)
                    break
                except VerdictParseError:
                    if attempt >= max_retries:
                        raise
                    raw_text = _call_and_cache(
                        judge_name, code, target_cwe, db_path, strict=True
                    )

            verdict = verdict_from_json(sample_id, judge_name, judge_version, code, payload, raw_text)
            finding = verdict_to_finding(verdict)
            db.save_findings(sample_id, judge_name, [finding], judge_version)
            summary["scanned"] += 1
            consecutive_errors = 0
        except Exception as exc:  # noqa: BLE001 -- log and keep going, one bad sample shouldn't kill the batch
            summary["errors"].append((sample_id, str(exc)))
            consecutive_errors += 1
            if consecutive_errors >= max_consecutive_errors:
                print(
                    f"[{judge_name}] aborting after {consecutive_errors} consecutive errors "
                    f"-- likely a systemic issue (API key / balance / rate limit), not per-sample "
                    f"noise. Last error: {exc}",
                    flush=True,
                )
                summary["aborted"] = True
                break

        if progress_every and i % progress_every == 0:
            print(
                f"[{judge_name}] {i}/{total} processed "
                f"(scanned={summary['scanned']} skipped={summary['skipped']} "
                f"errors={len(summary['errors'])})",
                flush=True,
            )

    return summary


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", default=DB_PATH)
    ap.add_argument("--judge", choices=[
        "claude_judge", "gpt4_judge",
        "claude_judge_blind", "gpt4_judge_blind",
        "claude_judge_guided", "gpt4_judge_guided",
    ])
    ap.add_argument("--subset-name", default=DEFAULT_SUBSET_NAME)
    ap.add_argument("--n", type=int, default=DEFAULT_SUBSET_N)
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--limit", type=int, default=None,
                     help="Only judge the first N ids of the subset (smoke testing).")
    ap.add_argument("--select-subset-only", action="store_true",
                     help="Compute/print the stratified subset, no API calls.")
    args = ap.parse_args()

    subset = select_stratified_subset(args.db, args.subset_name, args.n, args.seed)
    print(f"subset '{args.subset_name}': {len(subset)} ids")

    if args.select_subset_only:
        return
    if not args.judge:
        ap.error("--judge is required unless --select-subset-only is set")

    ids = subset[: args.limit] if args.limit else subset
    summary = judge_batch(args.judge, ids, db_path=args.db)
    print(
        f"{args.judge}: scanned={summary['scanned']} skipped={summary['skipped']} "
        f"errors={len(summary['errors'])}"
    )
    for sample_id, err in summary["errors"][:20]:
        print(f"  id={sample_id}: {err}")


if __name__ == "__main__":
    main()
