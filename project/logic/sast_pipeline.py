# logic/static_pipeline.py
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import uuid
import utils.message_parsers
from pathlib import Path
from typing import Callable, Optional, Sequence, Tuple
from dotenv import load_dotenv
import requests
import time

load_dotenv()
sonar_token = os.getenv("usertoken")

# SAST Commands
def run_bandit_on_code(code):
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as tmp:
        tmp.write(code)
        fname = tmp.name
    try:
        result = subprocess.run(["bandit", "-r", fname], capture_output=True, text=True)
        #print(result)
        bandit_result = utils.message_parsers.analyze_static_output(result.stdout)
        #print(bandit_result)
    except Exception:
        bandit_result = "error"
    #    result ="error"
    os.remove(fname)
    return bandit_result
    #return result

def run_semgrep_on_code(code: str, rulesets: default_semgrep_rules) -> str:
    rulesets = [r.strip() for r in (rulesets or []) if r and r.strip()]
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as tmp:
        tmp.write(code)
        fname = tmp.name

    cwes_found: set[str] = set()
    try:
        for ruleset in rulesets:
            try:
                proc = subprocess.run(
                    ["semgrep", "--quiet", "--config", ruleset, "--json", fname],
                    capture_output=True, text=True
                )
                # 0: no findings, 1: findings 
                if proc.returncode not in (0, 1):
                    continue
                data = json.loads(proc.stdout or "{}")  
                for finding in data.get("results", []):
                    meta = finding.get("extra", {}).get("metadata", {})
                    cwe_list = meta.get("cwe", []) or []
                    for c in cwe_list:
                        cwes_found.add(str(c).split(":")[0].strip())
            except Exception:
                continue
        return ",".join(sorted(cwes_found)) if cwes_found else "None"
    except Exception as e:
        return f"error: {e}"
    finally:
        try: os.remove(fname)  # type: ignore[name-defined]
        except Exception: pass

def default_semgrep_rules() -> list[str]:
    # Old config (32/238 project target-CWEs covered, verified against the
    # actual rule definitions from semgrep.dev/c/p/<name>, not just names).
    # p/injection 404s -- semgrep.dev/c/p/injection returns HTTP 404 and the
    # CLI exits 7, which the old error handling below silently `continue`d
    # past. It has contributed zero rules to every scan ever run with this
    # list. Left here, commented, as a record rather than deleted.
    # return [
    #     "p/owasp-top-ten",
    #     "p/cwe-top-25",
    #     "p/python",
    #     "p/injection",
    #     "p/sql-injection",
    # ]

    # New config: 41/238 target CWEs covered, a strict superset of the old
    # config's coverage (loses nothing, adds CWE-73/94/96/322/523/676/706/
    # 776/915). p/default alone already subsumes p/python, p/security-audit,
    # p/cwe-top-25 and p/sql-injection for this project's target CWE list --
    # verified via greedy set-cover over all 14 plausible candidate packs, so
    # they add no further ruleset here. p/flask and p/secrets are kept
    # despite small raw CWE-tag overlap with p/default: Flask-specific rules
    # catch framework-specific instances a generic rule misses, and hardcoded
    # credentials are a plausible real issue in LLM-generated demo apps.
    #
    # Ceiling to state in the thesis, not chase further: no combination of
    # public Semgrep packs exceeds ~41/238 (17%) of this project's target CWE
    # list. Most of A03 (Software Supply Chain) and A10 (Mishandling of
    # Exceptional Conditions) have zero Python-rule coverage in the registry
    # under any pack -- a structural SAST blind spot, not a config gap.
    return [
        "p/default",
        "p/owasp-top-ten",
        "p/flask",
        "p/secrets",
    ]


# --------------------------------------------------------------------------- #
# Structured re-scan: bandit's issue_cwe.id + semgrep's ruleset-tagged findings
# --------------------------------------------------------------------------- #
#
# The functions above (run_bandit_on_code, run_semgrep_on_code) regex/metadata
# -parse straight to a comma-separated CWE string and throw away everything
# else -- no raw output survives, so the old code_cwe.bandit/.semgrep columns
# can never be re-scored, only re-scanned. These new functions fix that: they
# return structured Finding objects (same dataclass sarif_scanners.py uses for
# CodeQL/Snyk) so save_findings() can persist raw output + version, exactly
# like the CodeQL/Snyk path, into NEW columns -- the old two are untouched.

_REPO_ROOT = Path(__file__).resolve().parents[2]
_VENV_BANDIT = _REPO_ROOT / ".venv" / "bin" / "bandit"


def _load_finding_class():
    import sys
    src_tools = _REPO_ROOT / "src" / "tools"
    if str(src_tools) not in sys.path:
        sys.path.insert(0, str(src_tools))
    from sarif_scanners import Finding
    return Finding


_VENV_SEMGREP = _REPO_ROOT / ".venv" / "bin" / "semgrep"


def _bandit_binary() -> str:
    # The system-wide `bandit` on PATH is 1.6.2, too old for issue_cwe.id
    # (needs >=1.7.3). The project's own .venv has 1.8.6 -- use it explicitly
    # rather than relying on PATH order, which silently picks the old one.
    return str(_VENV_BANDIT) if _VENV_BANDIT.exists() else "bandit"


def _semgrep_binary() -> str:
    # The system-wide `semgrep` (a snap package) is 1.56.0, which rejects
    # p/default outright: modern registry rules use `severity: CRITICAL`,
    # a value 1.56.0's schema validator doesn't recognize, so the *entire*
    # config is refused (exit 7) rather than just that one rule -- confirmed
    # by reproducing it directly. The venv has 1.142.0, which handles it fine.
    return str(_VENV_SEMGREP) if _VENV_SEMGREP.exists() else "semgrep"


def run_bandit_structured(code: str, sample_id: str):
    """Run bandit -f json and return (findings, tool_version).

    Reads results[].issue_cwe.id directly (bandit >=1.7.3) instead of
    regex-matching text output, and keeps test_id/line/severity/confidence
    per finding -- all of which the old text-based path discarded.
    """
    Finding = _load_finding_class()
    bandit_bin = _bandit_binary()

    version_out = subprocess.run([bandit_bin, "--version"], capture_output=True, text=True)
    version = (version_out.stdout or version_out.stderr or "unknown").splitlines()[0].strip()
    version = version.replace("bandit ", "").strip()

    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as tmp:
        tmp.write(code)
        fname = tmp.name

    findings: list = []
    try:
        proc = subprocess.run([bandit_bin, "-f", "json", "-r", fname],
                               capture_output=True, text=True)
        # bandit exits 1 when issues are found, 0 when clean; only a crash
        # (missing binary, bad AST) produces no parseable JSON at all.
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            data = {}
        for result in data.get("results", []):
            cwe = result.get("issue_cwe") or {}
            cwe_id = cwe.get("id")
            findings.append(Finding(
                sample_id=sample_id,
                tool="bandit",
                tool_version=version,
                cwe_ids=(cwe_id,) if cwe_id else (),
                rule_id=result.get("test_id", ""),
                message=result.get("issue_text", ""),
                line=result.get("line_number"),
                severity=result.get("issue_severity"),
                raw=result,
            ))
    finally:
        try:
            os.remove(fname)
        except OSError:
            pass
    return findings, version


_CWE_TAG_RE = re.compile(r"CWE-(\d+)")


def run_semgrep_structured(code: str, sample_id: str, rulesets: list[str] | None = None):
    """Run each semgrep ruleset and return (findings, version, failed_rulesets).

    Each Finding.raw carries which ruleset produced it (the plan's ask:
    "record which ruleset produced each finding so marginal contribution is
    reportable"), which the old comma-separated-CWE-string path couldn't.
    A ruleset that fails to run (bad config, network, exit code outside
    {0,1}) is returned in `failed_rulesets` instead of being silently
    dropped -- the caller decides how to record that.
    """
    Finding = _load_finding_class()
    rulesets = [r.strip() for r in (rulesets or default_semgrep_rules()) if r and r.strip()]
    semgrep_bin = _semgrep_binary()

    version_out = subprocess.run([semgrep_bin, "--version"], capture_output=True, text=True)
    version = (version_out.stdout or "unknown").strip().splitlines()[-1].strip()

    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as tmp:
        tmp.write(code)
        fname = tmp.name

    findings: list = []
    failed_rulesets: list[str] = []
    try:
        for ruleset in rulesets:
            proc = subprocess.run(
                [semgrep_bin, "--quiet", "--config", ruleset, "--json", fname],
                capture_output=True, text=True,
            )
            if proc.returncode not in (0, 1):
                failed_rulesets.append(f"{ruleset}: exit {proc.returncode}")
                continue
            try:
                data = json.loads(proc.stdout or "{}")
            except json.JSONDecodeError:
                failed_rulesets.append(f"{ruleset}: invalid JSON output")
                continue
            if data.get("errors"):
                # exit 0/1 with a non-empty errors array = partial failure
                # (some rules didn't run), not "clean" or "no findings".
                failed_rulesets.append(f"{ruleset}: {len(data['errors'])} rule error(s)")

            for result in data.get("results", []):
                meta = result.get("extra", {}).get("metadata", {}) or {}
                cwe_ids = tuple(sorted({
                    int(m.group(1))
                    for c in (meta.get("cwe", []) or [])
                    for m in [_CWE_TAG_RE.search(str(c))] if m
                }))
                findings.append(Finding(
                    sample_id=sample_id,
                    tool="semgrep",
                    tool_version=version,
                    cwe_ids=cwe_ids,
                    rule_id=result.get("check_id", ""),
                    message=result.get("extra", {}).get("message", ""),
                    line=(result.get("start", {}) or {}).get("line"),
                    severity=meta.get("severity") or result.get("extra", {}).get("severity"),
                    raw={"ruleset": ruleset, **result},
                ))
    finally:
        try:
            os.remove(fname)
        except OSError:
            pass
    return findings, version, failed_rulesets


def _load_sarif_scanners():
    import sys
    src_tools = _REPO_ROOT / "src" / "tools"
    if str(src_tools) not in sys.path:
        sys.path.insert(0, str(src_tools))
    import sarif_scanners
    return sarif_scanners


def run_bandit_batch(samples: list[tuple[str, str]]):
    """Run bandit once over a whole staged batch directory instead of once
    per file. The per-sample run_bandit_structured() above measured ~1
    sample/several-seconds when run one file at a time across 13,634 samples
    -- the same fixed-per-invocation-overhead problem CodeQL had, just from
    process startup rather than query compilation. Batching cuts 13,634
    invocations down to ~28 (batch_size=500).

    Returns ({sample_id: [Finding, ...]}, tool_version, syntax_error_ids).

    `syntax_error_ids` lists samples bandit's own `errors` array reported as
    unparseable (real, confirmed against Python's own compile() on a sample --
    genuinely malformed generated code, e.g. a missing paren around a
    triple-quoted string argument). The caller must NOT call save_findings()
    for these: an empty finding list would misreport "bandit ran and found
    nothing" when what actually happened is "bandit couldn't parse this file
    at all" -- leaving them unscanned (has_scanned() stays False) keeps that
    distinction rather than silently recording a false negative.
    """
    sarif_scanners = _load_sarif_scanners()
    Finding = _load_finding_class()
    bandit_bin = _bandit_binary()

    version_out = subprocess.run([bandit_bin, "--version"], capture_output=True, text=True)
    version = (version_out.stdout or version_out.stderr or "unknown").splitlines()[0]
    version = version.replace("bandit ", "").strip()

    findings_by_sample: dict[str, list] = {sid: [] for sid, _ in samples}
    with tempfile.TemporaryDirectory(prefix="bandit_batch_") as tmp:
        batch_dir = Path(tmp) / "src"
        sarif_scanners.stage_batch(samples, batch_dir)
        # -q suppresses the progress bar bandit prints on stdout for batches
        # large enough to take a couple of seconds -- without it, "Working...
        # <bar> 100% 0:00:02\n" is prepended before the JSON, so json.loads()
        # fails and every finding in the batch is silently lost. Confirmed by
        # reproducing directly: identical run without -q produced 0 results
        # over 500 real samples that in fact had 908.
        proc = subprocess.run([bandit_bin, "-q", "-f", "json", "-r", str(batch_dir)],
                               capture_output=True, text=True)
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            data = {}

    syntax_error_ids = {
        sarif_scanners.sample_id_from_staged_name(e.get("filename", ""))
        for e in data.get("errors", [])
    }
    syntax_error_ids.discard(None)

    for result in data.get("results", []):
        sample_id = sarif_scanners.sample_id_from_staged_name(result.get("filename", ""))
        if sample_id is None or sample_id not in findings_by_sample:
            continue
        cwe = result.get("issue_cwe") or {}
        cwe_id = cwe.get("id")
        findings_by_sample[sample_id].append(Finding(
            sample_id=sample_id,
            tool="bandit",
            tool_version=version,
            cwe_ids=(cwe_id,) if cwe_id else (),
            rule_id=result.get("test_id", ""),
            message=result.get("issue_text", ""),
            line=result.get("line_number"),
            severity=result.get("issue_severity"),
            raw=result,
        ))
    return findings_by_sample, version, syntax_error_ids


def run_semgrep_batch(samples: list[tuple[str, str]], rulesets: list[str] | None = None):
    """Batched counterpart to run_semgrep_structured -- one invocation per
    (batch, ruleset) instead of per (sample, ruleset), attributing results
    back by the staged filename in each result's `path` field.

    Returns ({sample_id: [Finding, ...]}, tool_version, failed_rulesets).
    """
    sarif_scanners = _load_sarif_scanners()
    Finding = _load_finding_class()
    semgrep_bin = _semgrep_binary()
    rulesets = [r.strip() for r in (rulesets or default_semgrep_rules()) if r and r.strip()]

    version_out = subprocess.run([semgrep_bin, "--version"], capture_output=True, text=True)
    version = (version_out.stdout or "unknown").strip().splitlines()[-1].strip()

    findings_by_sample: dict[str, list] = {sid: [] for sid, _ in samples}
    failed_rulesets: list[str] = []

    with tempfile.TemporaryDirectory(prefix="semgrep_batch_") as tmp:
        batch_dir = Path(tmp) / "src"
        sarif_scanners.stage_batch(samples, batch_dir)

        for ruleset in rulesets:
            proc = subprocess.run(
                [semgrep_bin, "--quiet", "--config", ruleset, "--json", str(batch_dir)],
                capture_output=True, text=True,
            )
            if proc.returncode not in (0, 1):
                failed_rulesets.append(f"{ruleset}: exit {proc.returncode}")
                continue
            try:
                data = json.loads(proc.stdout or "{}")
            except json.JSONDecodeError:
                failed_rulesets.append(f"{ruleset}: invalid JSON output")
                continue
            if data.get("errors"):
                failed_rulesets.append(f"{ruleset}: {len(data['errors'])} rule error(s)")

            for result in data.get("results", []):
                sample_id = sarif_scanners.sample_id_from_staged_name(result.get("path", ""))
                if sample_id is None or sample_id not in findings_by_sample:
                    continue
                meta = result.get("extra", {}).get("metadata", {}) or {}
                cwe_ids = tuple(sorted({
                    int(m.group(1))
                    for c in (meta.get("cwe", []) or [])
                    for m in [_CWE_TAG_RE.search(str(c))] if m
                }))
                findings_by_sample[sample_id].append(Finding(
                    sample_id=sample_id,
                    tool="semgrep",
                    tool_version=version,
                    cwe_ids=cwe_ids,
                    rule_id=result.get("check_id", ""),
                    message=result.get("extra", {}).get("message", ""),
                    line=(result.get("start", {}) or {}).get("line"),
                    severity=meta.get("severity") or result.get("extra", {}).get("severity"),
                    raw={"ruleset": ruleset, **result},
                ))
    return findings_by_sample, version, failed_rulesets


def _fetch_code_samples(db, code_ids: list[int]) -> list[tuple[str, str]]:
    samples = []
    for code_id in code_ids:
        code = db.get_code(code_id)
        code = code[0] if isinstance(code, tuple) else code
        if code:
            samples.append((str(code_id), code))
        else:
            print(f"SKIP id={code_id}: no code")
    return samples


def rescan_bandit_semgrep(
    *,
    id_list: list[int] | None = None,
    docker_status: str = "tested-successful",
    batch_size: int = 500,
    run_bandit: bool = True,
    run_semgrep: bool = True,
    db=None,
) -> None:
    """Re-scan stored source with the fixed bandit/semgrep extraction, batched.

    Resumable via DBManager.has_scanned(); persists into the new
    bandit_cwes/_raw/_version and semgrep_cwes/_raw/_version columns via
    save_findings(). Never touches the legacy code_cwe.bandit/.semgrep TEXT
    columns -- those stay exactly as they are.

    `db=None` uses the real project/core/code_cwe.db; pass a scratch
    DBManager to test safely first.
    """
    if db is None:
        from core import db_handler
        db = db_handler.DBManager()
    sarif_scanners = _load_sarif_scanners()

    code_ids = sorted(id_list) if id_list is not None else db.get_ids_by_docker_status(docker_status)

    if run_bandit:
        pending = [cid for cid in code_ids if not db.has_scanned(cid, "bandit")]
        samples = _fetch_code_samples(db, pending)
        all_syntax_errors: set[str] = set()
        for batch in sarif_scanners.batched(samples, batch_size):
            findings_by_sample, version, syntax_error_ids = run_bandit_batch(batch)
            for sample_id, findings in findings_by_sample.items():
                if sample_id in syntax_error_ids:
                    continue  # leave unscanned -- see run_bandit_batch's docstring
                db.save_findings(int(sample_id), "bandit", findings, tool_version=version)
            all_syntax_errors |= syntax_error_ids
            print(f"bandit: batch of {len(batch)} -> "
                  f"{sum(len(f) for f in findings_by_sample.values())} findings, "
                  f"{len(syntax_error_ids)} unparseable")
        if all_syntax_errors:
            print(f"bandit: {len(all_syntax_errors)} samples had genuinely invalid Python "
                  f"syntax (confirmed against Python's own compile()), left unscanned: "
                  f"{sorted(all_syntax_errors, key=int)[:20]}"
                  f"{' ...' if len(all_syntax_errors) > 20 else ''}")

    if run_semgrep:
        pending = [cid for cid in code_ids if not db.has_scanned(cid, "semgrep")]
        samples = _fetch_code_samples(db, pending)
        semgrep_rulesets = default_semgrep_rules()
        all_failed_rulesets: dict[str, int] = {}
        for batch in sarif_scanners.batched(samples, batch_size):
            findings_by_sample, version, failed = run_semgrep_batch(batch, semgrep_rulesets)
            for sample_id, findings in findings_by_sample.items():
                db.save_findings(int(sample_id), "semgrep", findings, tool_version=version)
            for f in failed:
                ruleset_name = f.split(":")[0]
                all_failed_rulesets[ruleset_name] = all_failed_rulesets.get(ruleset_name, 0) + 1
            print(f"semgrep: batch of {len(batch)} -> "
                  f"{sum(len(f) for f in findings_by_sample.values())} findings")
        if all_failed_rulesets:
            print("Semgrep ruleset failures during this run (recorded, not silently dropped):")
            for ruleset, count in sorted(all_failed_rulesets.items(), key=lambda kv: -kv[1]):
                print(f"  {ruleset}: failed on {count} batch(es)")

    print(f"rescan_bandit_semgrep: {len(code_ids)} samples in scope.")


##! Part for Sonarqube and necessary functions

def _extract_ce_task_id(scanner_stdout: str) -> str | None:
        """
        Sonar Scanner generally contains a line at the output like
        "More about the report processing at http://.../api/ce/task?id=AX..."
        Take id from that
        """
        if not scanner_stdout:
            return None
        for line in scanner_stdout.splitlines():
            if "/api/ce/task?id=" in line:
                try:
                    return line.split("/api/ce/task?id=", 1)[1].strip()
                except Exception:
                    pass
        for line in scanner_stdout.splitlines():
            if "ceTaskId" in line and "=" in line:
                # kaba yakalama
                parts = line.split("=", 1)
                if len(parts) == 2:
                    candidate = parts[1].strip()
                    if candidate:
                        return candidate
        return None
def _wait_for_ce_task(base_url: str, ce_task_id: str, headers: dict, timeout_s: int = 120, poll_s: float = 1.0) -> dict:
    """
    Wait until SonarQube CE task is done, return the final payload.
    """
    deadline = time.time() + timeout_s
    url = f"{base_url}/api/ce/task?id={ce_task_id}"

    last_payload = None
    while time.time() < deadline:
        r = requests.get(url, headers=headers, timeout=30)
        if r.status_code != 200:
            raise RuntimeError(f"CE task API error: {r.status_code} {r.text}")

        payload = r.json()
        last_payload = payload
        status = (payload.get("task") or {}).get("status")
        if status == "SUCCESS":
            return payload
        if status in ("FAILED", "CANCELED"):
            raise RuntimeError(f"CE task ended with status={status}: {payload}")

        time.sleep(poll_s)

    raise TimeoutError(f"CE task did not finish within {timeout_s}s. Last payload: {last_payload}")

def _paginate(endpoint_url: str, headers: dict, page_size: int = 500, list_key: str = "issues") -> list[dict]:
    """
    SonarQube API paging:
      - p: page number (1..n)
      - ps: page size
    response -> paging.total learn the total page.
    list_key: issues/hotspots key of list
    To make sure we get everything
    """
    out: list[dict] = []
    p = 1
    total = None

    while True:
        url = f"{endpoint_url}&p={p}&ps={page_size}"
        r = requests.get(url, headers=headers, timeout=30)
        if r.status_code != 200:
            raise RuntimeError(f"Pagination API error: {r.status_code} {r.text}")
        payload = r.json()
        paging = payload.get("paging") or {}
        if total is None:
            total = paging.get("total")
        items = payload.get(list_key, []) or []
        out.extend(items)
        # total bilinmiyorsa en azından boş gelince dur
        if total is None:
            if not items:
                break
        else:
            if len(out) >= total:
                break
        if not items:
            break
        p += 1
    return out

    
def run_sonarqube_on_code(code):
    """"
     - Run scanner on temp python file
     - Wait until task is done
     - take issues and hotspots via API
     - for futher analysis use utils.parsers
    """
    base_url = "http://localhost:9000"
    sonar_token = os.getenv("sonar_user_token")
    if not sonar_token:
        print("SonarQube token not found in env: sonar_user_token")
        return "error"
    

    with tempfile.TemporaryDirectory() as tmpdir:
        code_path = os.path.join(tmpdir, "app.py")
        # to prevent any name collision
        project_key = f"project_{os.getpid()}_{uuid.uuid4().hex[:8]}"

        with open(code_path, "w") as f:
            f.write(code)

        with open(os.path.join(tmpdir, "sonar-project.properties"), "w") as f:
            f.write(f"""
sonar.projectKey={project_key}
sonar.sources=.
sonar.language=py
sonar.python.version=3
sonar.sourceEncoding=UTF-8
sonar.log.level=INFO
sonar.host.url={base_url}
sonar.token={sonar_token}
""".strip() + "\n")
#sonar-scanner is built on a docker host
        try:
            # 1. Run scanner
            result = subprocess.run(["/opt/sonar-scanner/bin/sonar-scanner"],
                                     cwd=tmpdir,
                                     capture_output=True,
                                     text=True)
            scanner_stdout = result.stdout or ""
            scanner_stderr = result.stderr or ""

            if result.returncode != 0:
                print("SonarQube Scanner Error (stderr):", scanner_stderr)
                print("SonarQube Scanner Output (stdout):", scanner_stdout)
                return "error"
            headers = {"Authorization": f"Bearer {sonar_token}"}
            # 2. Wait for the scanner to finish its task
            ce_task_id = _extract_ce_task_id(scanner_stdout)
            ce_payload = None
            if ce_task_id:
                ce_payload = _wait_for_ce_task(base_url, ce_task_id, headers=headers, timeout_s=180, poll_s=1.0)
            else:
                # if dont catch ceTaskId, wait (opsiyonel)
                # Delete if it waits for eternity
                time.sleep(2)

            cwe_list = set()

            # 3. Issues API, for all pages (ALL ISSUES NOT ONLY SEC)
            issues_url = f"http://localhost:9000/api/issues/search?componentKeys={project_key}"
            all_issues = _paginate(issues_url, headers=headers, page_size=500, list_key="issues")
            
            # 3.2. SEC Issues
            security_issues = []

            # gerçek vulnerability'ler
            vuln_url = f"{base_url}/api/issues/search?componentKeys={project_key}&types=VULNERABILITY"
            security_issues.extend(
                 _paginate(vuln_url, headers=headers, page_size=500, list_key="issues")
                                )
            # security tags
            tag_sec_url = f"{base_url}/api/issues/search?componentKeys={project_key}&tags=security"
            security_issues.extend(
            _paginate(tag_sec_url, headers=headers, page_size=500, list_key="issues")
                                )
            #clean duplicates
            security_issues = {i["key"]: i for i in security_issues}.values()
            security_issues = list(security_issues)

            # 4. Hotspots API, for all pages
            hotspots_url = f"{base_url}/api/hotspots/search?projectKey={project_key}"
            all_hotspots = _paginate(hotspots_url, headers=headers, page_size=500, list_key="hotspots")

            # format the outputs
            issues_data = {"issues": all_issues}
            hotspot_data = {"hotspots": all_hotspots}
            security_issue_data = {"issues": security_issues}
            security_hotspot_data = {"hotspots": all_hotspots}

            # 5. Collect Tag/CWE
            cwe_list = set()
            for issue in all_issues:
                cwe_list.update(utils.message_parsers.extract_security_tags(issue))
            for hs in all_hotspots:
                cwe_list.update(utils.message_parsers.extract_security_tags(hs))

            filtered_issues = utils.message_parsers.filter_issues(issues_data)
            filtered_hotspots = utils.message_parsers.filter_hotspots(hotspot_data)
            filtered_security_issues = utils.message_parsers.filter_issues(security_issue_data)
            filtered_security_hotspots = utils.message_parsers.filter_hotspots(security_hotspot_data)

            tags = (",".join(sorted(cwe_list)) if cwe_list else "None")

            # RAW DATA is ready here
            raw_bundle = {
                "project_key": project_key,
                "scanner_stdout": scanner_stdout,
                "scanner_stderr": scanner_stderr,
                "ce_task_id": ce_task_id,
                "ce_payload": ce_payload,
                "issues": all_issues,
                "hotspots": all_hotspots,
            }
            results = (
            f"security: tags={tags}; "
            f"issues={filtered_security_issues}; "
            f"hotspots={filtered_security_hotspots}; "
            f"all_issues={filtered_issues}; "
            f"all_hotspots={filtered_hotspots}"
                    )   
            return results
        
        except Exception as e:
            print("SonarQube Exception:", e)
            return "error"
        

GetCodeFn = Callable[[int], str | Tuple[str, ...]]
SaveFn    = Callable[[int, str, str], None]   # (id, tool, results)

def sast_scan(
    *,
    start_id: int = None,
    end_id: int = None,
    id_list: list = None,
    get_code: GetCodeFn,
    save_result: SaveFn,
    run_bandit: bool = True,
    run_semgrep: bool = True,
    run_sonar: bool = True,
    rulesets: Optional[Sequence[str]] = None,
) -> None:
    from core import db_handler
    db = db_handler.DBManager()
    rules = list(rulesets) if rulesets else default_semgrep_rules()

    # pull not-tested ids once, no need to hit db on every iteration
    not_tested_map  = db.get_not_tested_tools()
    bandit_pending  = set(not_tested_map.get("bandit", []))
    semgrep_pending = set(not_tested_map.get("semgrep", []))
    sonar_pending   = set(not_tested_map.get("sonarqube", []))

 # if id list exist use that
    if id_list is not None:
        code_ids = sorted(id_list)
    else:
        code_ids = range(start_id, end_id + 1)
        
    for code_id in code_ids:
        # skip if none of the tools need to run for this id
        needs_any = (
            (run_bandit  and code_id in bandit_pending)  or
            (run_semgrep and code_id in semgrep_pending) or
            (run_sonar   and code_id in sonar_pending)
        )
        if not needs_any:
            print(f"SKIP SAST: code_id={code_id} already scanned")
            continue

        try:
            got = get_code(code_id)
        except Exception:
            continue

        code = got[0] if isinstance(got, tuple) else got

        b = run_bandit_on_code(code)  if (run_bandit  and code_id in bandit_pending)  else None
        s = run_semgrep_on_code(code, rules) if (run_semgrep and code_id in semgrep_pending) else None
        q = run_sonarqube_on_code(code) if (run_sonar   and code_id in sonar_pending)   else None

        if b is not None: save_result(code_id, "bandit",    b)
        if s is not None: save_result(code_id, "semgrep",   s)
        if q is not None: save_result(code_id, "sonarqube", q)

        print(f"id={code_id} bandit={b} semgrep={s} sonar={q}")
    print("SAST analysis completed.")


def _load_sarif_scanners():
    """sarif_scanners.py lives under src/tools/, outside the project/ tree."""
    import sys
    src_tools = Path(__file__).resolve().parents[2] / "src" / "tools"
    if str(src_tools) not in sys.path:
        sys.path.insert(0, str(src_tools))
    import sarif_scanners
    return sarif_scanners


def batch_sast_scan(
    *,
    id_list: list[int] | None = None,
    docker_status: str = "tested-successful",
    batch_size: int = 500,
    run_codeql: bool = True,
    run_snyk: bool = True,
    codeql_bin: str = "codeql",
    snyk_bin: str = "snyk",
    db=None,
) -> None:
    """Batch-scan docker-successful samples with CodeQL and/or Snyk Code.

    Both tools amortize a large fixed per-invocation cost across many samples
    (see src/tools/sarif_scanners.py) so, unlike bandit/semgrep, samples are
    staged and scanned in batches rather than one at a time -- running this
    corpus through CodeQL one sample at a time would take ~75h instead of well
    under one.

    Resumable via DBManager.has_scanned(): a sample already recorded for a tool
    (clean or not) is left out of that tool's next batch, so results and raw
    output stay in code_cwe.db and re-running only picks up what's left.

    `db` takes an existing DBManager (e.g. pointed at a scratch DB for testing);
    defaults to the real project/core/code_cwe.db only when omitted.
    """
    sarif_scanners = _load_sarif_scanners()
    if db is None:
        from core import db_handler
        db = db_handler.DBManager()

    code_ids = sorted(id_list) if id_list is not None else db.get_ids_by_docker_status(docker_status)

    adapters = []
    if run_codeql:
        adapters.append(("codeql", sarif_scanners.CodeQLBatchAdapter(codeql_bin=codeql_bin)))
    if run_snyk:
        adapters.append(("snyk_code", sarif_scanners.SnykCodeBatchAdapter(snyk_bin=snyk_bin)))

    for tool, adapter in adapters:
        pending_ids = [cid for cid in code_ids if not db.has_scanned(cid, tool)]
        if not pending_ids:
            print(f"SKIP {tool}: nothing pending")
            continue

        samples: list[tuple[str, str]] = []
        for code_id in pending_ids:
            code = db.get_code(code_id)
            code = code[0] if isinstance(code, tuple) else code
            if not code:
                print(f"SKIP {tool}: id={code_id} has no code")
                continue
            samples.append((str(code_id), code))

        by_sample: dict[str, list] = {sample_id: [] for sample_id, _ in samples}
        scanned_ids: set[str] = set()
        for batch in sarif_scanners.batched(samples, batch_size):
            try:
                findings = adapter.scan_batch(batch)
            except sarif_scanners.ScanError as e:
                print(f"{tool}: batch of {len(batch)} FAILED, left as not-scanned: {e}")
                continue
            for f in findings:
                by_sample.setdefault(f.sample_id, []).append(f)
            scanned_ids.update(sample_id for sample_id, _ in batch)
            print(f"{tool}: batch of {len(batch)} -> {len(findings)} findings")

        version = adapter.version
        for sample_id in scanned_ids:
            db.save_findings(int(sample_id), tool, by_sample[sample_id], tool_version=version)

        print(f"{tool}: {len(scanned_ids)}/{len(samples)} samples scanned and saved")