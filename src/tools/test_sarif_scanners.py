"""Tests for the batch SAST adapters.

The CodeQL tests run the real binary against real samples; the Snyk tests use a
synthetic SARIF document in Snyk's documented shape, because the Snyk CLI needs
authentication and network access.
"""

import json
import shutil
from pathlib import Path

import pytest

from sarif_scanners import (
    CodeQLBatchAdapter,
    Finding,
    ScanError,
    extract_cwe_ids,
    parse_sarif,
    sample_id_from_staged_name,
    scan_corpus,
    stage_batch,
)

HERE = Path(__file__).parent
CODEQL_BIN = HERE / "codeql" / "codeql"

VULNERABLE_APP = '''
import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/search")
def search():
    term = request.args.get("q", "")
    conn = sqlite3.connect("app_db.sqlite")
    cur = conn.cursor()
    cur.execute("SELECT id FROM products WHERE name LIKE '%" + term + "%'")
    return str(cur.fetchall())


@app.route("/greet")
def greet():
    return "<h1>Hello " + request.args.get("name", "") + "</h1>"
'''

SECURE_APP = '''
import sqlite3
from flask import Flask, request, escape

app = Flask(__name__)


@app.route("/search")
def search():
    term = request.args.get("q", "")
    conn = sqlite3.connect("app_db.sqlite")
    cur = conn.cursor()
    cur.execute("SELECT id FROM products WHERE name LIKE ?", ("%" + term + "%",))
    return str(cur.fetchall())
'''


# --------------------------------------------------------------------------- #
# CWE extraction
# --------------------------------------------------------------------------- #


def test_extracts_codeql_style_tags_and_strips_zero_padding():
    rule = {"properties": {"tags": ["security", "external/cwe/cwe-089"]}}
    assert extract_cwe_ids(rule) == (89,)


def test_extracts_multiple_cwes_sorted():
    rule = {
        "properties": {
            "tags": [
                "correctness",
                "security",
                "external/cwe/cwe-022",
                "external/cwe/cwe-099",
                "external/cwe/cwe-073",
            ]
        }
    }
    assert extract_cwe_ids(rule) == (22, 73, 99)


def test_extracts_snyk_style_cwe_property():
    rule = {"properties": {"cwe": ["CWE-89", "CWE-943"], "tags": ["security"]}}
    assert extract_cwe_ids(rule) == (89, 943)


def test_extracts_from_taxonomy_relationships():
    rule = {"relationships": [{"target": {"id": "CWE-79"}}]}
    assert extract_cwe_ids(rule) == (79,)


def test_ignores_non_cwe_tags():
    rule = {"properties": {"tags": ["security", "maintainability", "owasp-top-10"]}}
    assert extract_cwe_ids(rule) == ()


def test_handles_rule_with_no_properties():
    assert extract_cwe_ids({}) == ()


# --------------------------------------------------------------------------- #
# Staging and attribution
# --------------------------------------------------------------------------- #


def test_staged_filenames_round_trip_sample_ids():
    for sample_id in ["1", "00042", "a1b2c3", "run_3-sample_7"]:
        name = f"sample_{sample_id}.py"
        assert sample_id_from_staged_name(name) == sample_id


def test_foreign_files_are_not_attributed():
    assert sample_id_from_staged_name("conftest.py") is None
    assert sample_id_from_staged_name("site-packages/flask/app.py") is None


def test_stage_batch_rejects_unsafe_sample_ids(tmp_path):
    with pytest.raises(ValueError):
        stage_batch([("../../etc/passwd", "x = 1")], tmp_path)


def test_stage_batch_writes_one_module_per_sample(tmp_path):
    stage_batch([("a1", "x = 1"), ("a2", "y = 2")], tmp_path)
    assert sorted(p.name for p in tmp_path.glob("*.py")) == [
        "sample_a1.py",
        "sample_a2.py",
    ]


# --------------------------------------------------------------------------- #
# SARIF parsing
# --------------------------------------------------------------------------- #


SNYK_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "SnykCode",
                    "semanticVersion": "1.0.0",
                    "rules": [
                        {
                            "id": "python/SqlInjection",
                            "properties": {
                                "cwe": ["CWE-89"],
                                "tags": ["python", "security"],
                                "categories": ["Security"],
                            },
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "python/SqlInjection",
                    "level": "error",
                    "message": {"text": "Unsanitized input flows into execute."},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "sample_0007.py"},
                                "region": {"startLine": 13},
                            }
                        }
                    ],
                }
            ],
        }
    ],
}


def test_parses_snyk_sarif_shape():
    findings = parse_sarif(SNYK_SARIF, tool="snyk_code", tool_version="1.1307.0")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.sample_id == "0007"
    assert finding.cwe_ids == (89,)
    assert finding.line == 13
    assert finding.rule_id == "python/SqlInjection"
    assert finding.tool == "snyk_code"


def test_parses_results_that_reference_rules_by_index():
    sarif = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {"id": "r0", "properties": {"tags": ["external/cwe/cwe-078"]}}
                        ]
                    }
                },
                "results": [
                    {
                        "ruleIndex": 0,
                        "message": {"text": "cmd injection"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "sample_9.py"},
                                    "region": {"startLine": 3},
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    }
    findings = parse_sarif(sarif, tool="t", tool_version="v")
    assert findings[0].cwe_ids == (78,)


def test_results_without_locations_are_dropped_not_crashed():
    sarif = {
        "runs": [
            {
                "tool": {"driver": {"rules": []}},
                "results": [{"ruleId": "x", "message": {"text": "no location"}}],
            }
        ]
    }
    assert parse_sarif(sarif, tool="t", tool_version="v") == []


def test_empty_sarif_yields_no_findings():
    assert parse_sarif({"runs": []}, tool="t", tool_version="v") == []


# --------------------------------------------------------------------------- #
# CodeQL end-to-end (real binary)
# --------------------------------------------------------------------------- #

requires_codeql = pytest.mark.skipif(
    not CODEQL_BIN.exists(), reason="CodeQL bundle not present"
)


@pytest.fixture(scope="module")
def codeql():
    return CodeQLBatchAdapter(codeql_bin=CODEQL_BIN)


@requires_codeql
def test_codeql_reports_its_version(codeql):
    assert codeql.version.startswith("2.")


@requires_codeql
def test_codeql_empty_batch_short_circuits(codeql):
    assert codeql.scan_batch([]) == []


@requires_codeql
def test_codeql_separates_vulnerable_from_patched_samples(codeql):
    """The load-bearing test: attribution must survive batching."""
    samples = [("vuln1", VULNERABLE_APP), ("safe1", SECURE_APP), ("vuln2", VULNERABLE_APP)]
    findings = codeql.scan_batch(samples)

    by_sample: dict[str, set[int]] = {}
    for finding in findings:
        by_sample.setdefault(finding.sample_id, set()).update(finding.cwe_ids)

    assert 89 in by_sample.get("vuln1", set()), "SQL injection missed in vuln1"
    assert 89 in by_sample.get("vuln2", set()), "SQL injection missed in vuln2"
    assert 89 not in by_sample.get("safe1", set()), "false positive on the patched sample"
    assert 79 in by_sample.get("vuln1", set()), "reflected XSS missed in vuln1"


@requires_codeql
def test_codeql_findings_carry_line_numbers(codeql):
    """Line numbers feed the localisation experiment; they must survive parsing."""
    findings = codeql.scan_batch([("loc1", VULNERABLE_APP)])
    sqli = [f for f in findings if 89 in f.cwe_ids]
    assert sqli, "no SQL injection finding to check"
    assert sqli[0].line is not None and sqli[0].line > 0
    assert sqli[0].tool_version.startswith("2.")


@requires_codeql
def test_codeql_bad_binary_raises_rather_than_reporting_clean(codeql):
    """A crashed scan must never look like a clean scan."""
    broken = CodeQLBatchAdapter(codeql_bin="/nonexistent/codeql")
    with pytest.raises((ScanError, FileNotFoundError)):
        broken.scan_batch([("x", VULNERABLE_APP)])


@requires_codeql
def test_scan_corpus_batches_and_attributes_across_batches(codeql):
    samples = [(f"s{i}", VULNERABLE_APP if i % 2 else SECURE_APP) for i in range(6)]
    findings = list(scan_corpus(codeql, samples, batch_size=2))
    with_sqli = {f.sample_id for f in findings if 89 in f.cwe_ids}
    assert with_sqli == {"s1", "s3", "s5"}


# --------------------------------------------------------------------------- #
# Migration provenance
# --------------------------------------------------------------------------- #


def test_scanned_findings_default_to_full_fidelity():
    findings = parse_sarif(SNYK_SARIF, tool="snyk_code", tool_version="1.1307.0")
    assert findings[0].provenance == "scan"
    assert findings[0].has_full_fidelity


def test_backfilled_findings_are_marked_lower_fidelity():
    """A row recovered from the old comma-separated CWE column has no raw output."""
    backfilled = Finding(
        sample_id="00042",
        tool="bandit",
        tool_version="unknown",
        cwe_ids=(89,),
        rule_id="",
        message="",
        provenance="backfill",
    )
    assert not backfilled.has_full_fidelity
    assert backfilled.cwe_ids == (89,)  # still usable for detection scoring


def test_backfilled_and_scanned_findings_coexist():
    """Scoring reads both; only line-level experiments filter on fidelity."""
    scanned = parse_sarif(SNYK_SARIF, tool="snyk_code", tool_version="1.1307.0")[0]
    backfilled = Finding("0007", "zap", "2.14", (79,), "", "", provenance="backfill")
    pool = [scanned, backfilled]
    assert {f.sample_id for f in pool} == {"0007"}
    assert [f.has_full_fidelity for f in pool] == [True, False]


# --------------------------------------------------------------------------- #
# Persistence mapping (per-tool columns, existing schema)
# --------------------------------------------------------------------------- #

from sarif_scanners import findings_from_columns, findings_to_columns, parse_cwe_string


def test_parses_the_legacy_cwe_column_format():
    assert parse_cwe_string("CWE-78,CWE-89") == (78, 89)
    assert parse_cwe_string("cwe-22; CWE-089") == (22, 89)
    assert parse_cwe_string(None) == ()
    assert parse_cwe_string("") == ()


def test_columns_round_trip_without_loss():
    original = parse_sarif(SNYK_SARIF, tool="snyk_code", tool_version="1.1307.0")
    cols = findings_to_columns(original)
    assert cols["cwes"] == "CWE-89"
    restored = findings_from_columns("0007", "snyk_code", **{
        k: cols[k] for k in ("cwes", "raw", "version")
    })
    assert len(restored) == 1
    assert restored[0].cwe_ids == original[0].cwe_ids
    assert restored[0].line == original[0].line
    assert restored[0].rule_id == original[0].rule_id
    assert restored[0].provenance == "scan"


def test_cwes_column_keeps_the_existing_comma_format():
    findings = [
        Finding("s1", "codeql", "2.20.3", (22, 73), "py/path-injection", "m"),
        Finding("s1", "codeql", "2.20.3", (89,), "py/sql-injection", "m"),
    ]
    assert findings_to_columns(findings)["cwes"] == "CWE-22,CWE-73,CWE-89"


def test_legacy_row_without_raw_backfills_as_degraded():
    """Old bandit/semgrep rows kept only the CWE string."""
    restored = findings_from_columns("42", "bandit", "CWE-78,CWE-89", None, None)
    assert len(restored) == 1
    assert restored[0].cwe_ids == (78, 89)
    assert restored[0].provenance == "backfill"
    assert not restored[0].has_full_fidelity
    assert restored[0].line is None


def test_empty_findings_write_nulls_not_empty_strings():
    """A clean scan and a missing scan must stay distinguishable in the DB."""
    assert findings_to_columns([]) == {"cwes": None, "raw": None, "version": None}


def test_columns_reject_findings_from_mixed_tools():
    mixed = [
        Finding("s1", "codeql", "2.20.3", (89,), "r", "m"),
        Finding("s1", "snyk_code", "1.0", (79,), "r", "m"),
    ]
    with pytest.raises(ValueError):
        findings_to_columns(mixed)
