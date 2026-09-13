import sqlite3

import pytest

import llm_judge
from db_handler import DBManager


# --------------------------------------------------------------------------- #
# Evidence check
# --------------------------------------------------------------------------- #

def test_evidence_check_finds_exact_line():
    code = "def f():\n    cursor.execute(query)\n"
    assert llm_judge.evidence_check(code, "cursor.execute(query)")


def test_evidence_check_tolerates_whitespace_differences():
    code = "def f():\n    cursor.execute(  query  )\n"
    assert llm_judge.evidence_check(code, "cursor.execute( query )")


def test_evidence_check_rejects_paraphrased_line():
    code = "def f():\n    cursor.execute(query)\n"
    assert not llm_judge.evidence_check(code, "runs a SQL query without sanitizing input")


def test_evidence_check_rejects_empty_line():
    assert not llm_judge.evidence_check("some code", "")
    assert not llm_judge.evidence_check("some code", "   ")


# --------------------------------------------------------------------------- #
# Verdict JSON parsing
# --------------------------------------------------------------------------- #

def test_parses_plain_json():
    payload = llm_judge.parse_verdict_json('{"verdict": "SECURE", "cwe": 89}')
    assert payload == {"verdict": "SECURE", "cwe": 89}


def test_parses_json_wrapped_in_markdown_fence():
    raw = '```json\n{"verdict": "VULNERABLE", "cwe": 89}\n```'
    payload = llm_judge.parse_verdict_json(raw)
    assert payload["verdict"] == "VULNERABLE"


def test_raises_on_non_json_output():
    with pytest.raises(llm_judge.VerdictParseError):
        llm_judge.parse_verdict_json("I cannot analyze this code.")


# --------------------------------------------------------------------------- #
# JudgeVerdict construction -- the evidence-check gate
# --------------------------------------------------------------------------- #

def test_vulnerable_verdict_with_supported_evidence_stays_vulnerable():
    code = "cursor.execute(query)"
    payload = {"verdict": "VULNERABLE", "cwe": 89, "evidence_line": "cursor.execute(query)",
               "confidence": 0.9}
    v = llm_judge.verdict_from_json(1, "claude_judge", "v@1", code, payload, "raw")
    assert v.verdict == "VULNERABLE"
    assert v.evidence_pass is True
    assert v.cwe == 89


def test_vulnerable_verdict_with_unsupported_evidence_is_downgraded():
    code = "cursor.execute(query)"
    payload = {"verdict": "VULNERABLE", "cwe": 89, "evidence_line": "this line does not exist"}
    v = llm_judge.verdict_from_json(1, "claude_judge", "v@1", code, payload, "raw")
    assert v.verdict == "UNCERTAIN"
    assert v.evidence_pass is False
    assert v.cwe == 89  # kept for audit even though the verdict was downgraded


def test_secure_verdict_does_not_require_evidence():
    payload = {"verdict": "SECURE", "cwe": 89, "evidence_line": ""}
    v = llm_judge.verdict_from_json(1, "claude_judge", "v@1", "any code", payload, "raw")
    assert v.verdict == "SECURE"
    assert v.evidence_pass is True


def test_malformed_confidence_and_line_number_fall_back_to_none():
    payload = {"verdict": "SECURE", "cwe": 89, "confidence": "high", "line_number": "n/a"}
    v = llm_judge.verdict_from_json(1, "claude_judge", "v@1", "code", payload, "raw")
    assert v.confidence is None
    assert v.line_number is None


# --------------------------------------------------------------------------- #
# JudgeVerdict -> Finding -> DB round trip (real save_findings/load_findings,
# on a scratch DB copy -- never the real code_cwe.db)
# --------------------------------------------------------------------------- #

def _make_scratch_db(tmp_path) -> str:
    db_path = str(tmp_path / "scratch.db")
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE code_cwe (
            id INTEGER PRIMARY KEY,
            CWE INTEGER,
            code TEXT,
            dockerfile TEXT,
            sql_script TEXT,
            requirements TEXT,
            port INTEGER,
            docker TEXT,
            secure TEXT
        )
        """
    )
    conn.commit()
    conn.close()
    return db_path


def test_vulnerable_finding_carries_cwe_credit(tmp_path):
    v = llm_judge.JudgeVerdict(
        sample_id=1, judge="claude_judge", judge_version="v@1", verdict="VULNERABLE",
        cwe=89, evidence_line="cursor.execute(q)", line_number=12, sink="cursor.execute",
        exploit_sketch="SQL injection via unsanitized input", confidence=0.9,
        evidence_pass=True, raw_text="{...}",
    )
    finding = llm_judge.verdict_to_finding(v)
    assert finding.cwe_ids == (89,)
    assert finding.raw["confidence"] == 0.9


def test_secure_finding_keeps_no_cwe_credit_but_preserves_raw(tmp_path):
    db_path = _make_scratch_db(tmp_path)
    db = DBManager(db_path=db_path)
    db.get_files_by_id  # sanity: DBManager wired to the scratch db

    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO code_cwe (id, CWE, code, docker, secure) VALUES (1, 89, 'x=1', 'tested-successful', 'VULNERABLE')")
    conn.commit()
    conn.close()

    v = llm_judge.JudgeVerdict(
        sample_id=1, judge="claude_judge", judge_version="v@1", verdict="SECURE",
        cwe=89, evidence_line="", line_number=None, sink="", exploit_sketch="",
        confidence=0.7, evidence_pass=True, raw_text="{...}",
    )
    finding = llm_judge.verdict_to_finding(v)
    assert finding.cwe_ids == ()

    db.save_findings(1, "claude_judge", [finding], "v@1")
    assert db.has_scanned(1, "claude_judge")
    loaded = db.load_findings(1, "claude_judge")
    assert len(loaded) == 1
    assert loaded[0].raw["verdict"] == "SECURE"
    assert loaded[0].raw["confidence"] == 0.7


# --------------------------------------------------------------------------- #
# Cache round trip
# --------------------------------------------------------------------------- #

def test_cache_put_then_get_round_trips(tmp_path):
    db_path = _make_scratch_db(tmp_path)
    key = llm_judge._cache_key("some code", "claude-haiku-4-5")
    assert llm_judge._cache_get(db_path, key) is None
    llm_judge._cache_put(db_path, key, "claude-haiku-4-5", '{"verdict": "SECURE"}')
    assert llm_judge._cache_get(db_path, key) == '{"verdict": "SECURE"}'


def test_cache_key_changes_with_prompt_version(monkeypatch):
    key_v1 = llm_judge._cache_key("code", "model")
    monkeypatch.setattr(llm_judge, "PROMPT_VERSION", "judge_v2")
    key_v2 = llm_judge._cache_key("code", "model")
    assert key_v1 != key_v2


# --------------------------------------------------------------------------- #
# Stratified subset selection
# --------------------------------------------------------------------------- #

def _seed_stratification_pool(db_path: str):
    conn = sqlite3.connect(db_path)
    rows = []
    rid = 1
    # A05 (e.g. CWE-89) x6, A01 (CWE-22) x3, unmapped CWE x1 -- proportional split
    for _ in range(6):
        rows.append((rid, 89, "tested-successful", "VULNERABLE")); rid += 1
    for _ in range(3):
        rows.append((rid, 22, "tested-successful", "VULNERABLE")); rid += 1
    rows.append((rid, 999999, "tested-successful", "VULNERABLE")); rid += 1
    conn.executemany(
        "INSERT INTO code_cwe (id, CWE, docker, secure) VALUES (?, ?, ?, ?)", rows
    )
    conn.commit()
    conn.close()


def test_stratified_subset_is_deterministic_and_sums_to_n(tmp_path):
    db_path = _make_scratch_db(tmp_path)
    _seed_stratification_pool(db_path)

    subset_a = llm_judge.select_stratified_subset(db_path, subset_name="s1", n=5, seed=1)
    assert len(subset_a) == 5

    # second call returns the frozen cohort unchanged, not a fresh sample
    subset_b = llm_judge.select_stratified_subset(db_path, subset_name="s1", n=5, seed=1)
    assert subset_a == subset_b


def test_stratified_subset_caps_at_pool_size(tmp_path):
    db_path = _make_scratch_db(tmp_path)
    _seed_stratification_pool(db_path)
    subset = llm_judge.select_stratified_subset(db_path, subset_name="s2", n=10_000, seed=1)
    assert len(subset) == 10  # pool only has 10 vulnerable/docker-successful rows


def test_stratified_subset_different_names_are_independent_cohorts(tmp_path):
    db_path = _make_scratch_db(tmp_path)
    _seed_stratification_pool(db_path)
    a = llm_judge.select_stratified_subset(db_path, subset_name="s1", n=5, seed=1)
    b = llm_judge.select_stratified_subset(db_path, subset_name="s2", n=5, seed=2)
    conn = sqlite3.connect(db_path)
    total_rows = conn.execute("SELECT COUNT(*) FROM judge_subset").fetchone()[0]
    conn.close()
    assert total_rows == len(a) + len(b)


# --------------------------------------------------------------------------- #
# Guided (judge_v3) prompt -- candidate checklist, target still hidden
# --------------------------------------------------------------------------- #

def test_guided_candidates_are_the_target_owasp_category():
    candidates = llm_judge._candidate_cwes_for_target(89)  # CWE-89 = A05 Injection
    assert 89 in candidates  # the target is a member of its own category's list
    assert 79 in candidates  # XSS, another A05 member
    assert 502 not in candidates  # CWE-502 is A08, not A05


def test_guided_prompt_lists_candidates_but_never_names_the_target_as_answer():
    prompt = llm_judge.build_guided_judge_prompt("cursor.execute(q)", 89)
    assert "CWE-89:" in prompt  # present as one line of the checklist
    assert "Target weakness" not in prompt  # never singled out as the anchored prompt does
    assert "most of\nthese will NOT apply" in prompt or "most of these will NOT apply" in prompt.replace("\n", " ")


def test_guided_prompt_mode_uses_its_own_prompt_version():
    assert llm_judge._prompt_mode("claude_judge_guided") == "_guided"
    key_guided = llm_judge._cache_key("code", "model", llm_judge.PROMPT_VERSION_GUIDED)
    key_blind = llm_judge._cache_key("code", "model", llm_judge.PROMPT_VERSION_BLIND)
    key_anchored = llm_judge._cache_key("code", "model", llm_judge.PROMPT_VERSION)
    assert len({key_guided, key_blind, key_anchored}) == 3  # three distinct cache namespaces


def test_call_and_cache_uses_guided_prompt_for_guided_judge_names(monkeypatch, tmp_path):
    db_path = _make_scratch_db(tmp_path)
    seen_prompts = []

    def fake_call(prompt):
        seen_prompts.append(prompt)
        return '{"verdict": "SECURE"}'

    monkeypatch.setattr(llm_judge, "_get_client", lambda name: (fake_call, "fake-model"))
    llm_judge._call_and_cache("claude_judge_guided", "cursor.execute(q)", 89, db_path)
    assert "CWE-89:" in seen_prompts[0]
    assert "Target weakness" not in seen_prompts[0]


# --------------------------------------------------------------------------- #
# judge_batch orchestration, with a fake client (no real API calls)
# --------------------------------------------------------------------------- #

def test_judge_batch_skips_already_scanned_samples(tmp_path, monkeypatch):
    db_path = _make_scratch_db(tmp_path)
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO code_cwe (id, CWE, code, docker, secure) VALUES "
        "(1, 89, 'cursor.execute(q)', 'tested-successful', 'VULNERABLE')"
    )
    conn.commit()
    conn.close()

    calls = []

    def fake_call(prompt, _client=None):
        calls.append(prompt)
        return '{"verdict": "VULNERABLE", "cwe": 89, "evidence_line": "cursor.execute(q)", "confidence": 0.8}'

    monkeypatch.setattr(llm_judge, "_get_client", lambda name: (fake_call, "fake-model@judge_v1"))

    summary = llm_judge.judge_batch("claude_judge", [1], db_path=db_path)
    assert summary["scanned"] == 1
    assert len(calls) == 1

    # second run: already scanned, must not call the fake client again
    summary2 = llm_judge.judge_batch("claude_judge", [1], db_path=db_path)
    assert summary2["skipped"] == 1
    assert len(calls) == 1

    db = DBManager(db_path=db_path)
    loaded = db.load_findings(1, "claude_judge")
    assert loaded[0].cwe_ids == (89,)


def test_blind_prompt_never_mentions_target_cwe():
    prompt = llm_judge.build_blind_judge_prompt("cursor.execute(q)")
    assert "89" not in prompt
    assert "Target weakness" not in prompt


def test_cache_key_differs_between_anchored_and_blind_prompt_versions():
    anchored = llm_judge._cache_key("code", "model", llm_judge.PROMPT_VERSION)
    blind = llm_judge._cache_key("code", "model", llm_judge.PROMPT_VERSION_BLIND)
    assert anchored != blind


def test_call_and_cache_uses_blind_prompt_for_blind_judge_names(tmp_path, monkeypatch):
    db_path = _make_scratch_db(tmp_path)
    seen_prompts = []

    def fake_call(prompt):
        seen_prompts.append(prompt)
        return '{"verdict": "SECURE"}'

    monkeypatch.setattr(llm_judge, "_get_client", lambda name: (fake_call, "fake-model"))
    llm_judge._call_and_cache("claude_judge_blind", "cursor.execute(q)", 89, db_path)
    assert "89" not in seen_prompts[0]
    assert "Target weakness" not in seen_prompts[0]


def test_judge_batch_records_errors_without_stopping_the_batch(tmp_path, monkeypatch):
    db_path = _make_scratch_db(tmp_path)
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO code_cwe (id, CWE, code, docker, secure) VALUES "
        "(1, 89, 'x=1', 'tested-successful', 'VULNERABLE')"
    )
    conn.commit()
    conn.close()

    def broken_call(prompt):
        raise RuntimeError("simulated API error (e.g. insufficient balance)")

    monkeypatch.setattr(llm_judge, "_get_client", lambda name: (broken_call, "fake-model@judge_v1"))

    summary = llm_judge.judge_batch("claude_judge", [1], db_path=db_path)
    assert summary["scanned"] == 0
    assert len(summary["errors"]) == 1
    assert summary["errors"][0][0] == 1
