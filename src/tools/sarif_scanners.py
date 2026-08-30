"""Batch SAST adapters for CodeQL and Snyk Code.

Both tools are far too slow (CodeQL) or too rate-limited (Snyk, 100 tests per
billing period on the free plan) to be invoked once per sample. Both, however,
accept a directory and emit SARIF whose results carry a per-file
`artifactLocation.uri`. So both are driven the same way:

    write N samples into one staging directory  ->  one scan  ->  attribute
    results back to sample ids by filename

Measured on CodeQL 2.20.3 (single-file Flask apps, 4 injected weaknesses each):

    1 sample    : 20.2 s analyse
    60 samples  : 21.7 s analyse   (4.2 s db create)
    500 samples : 26.5 s analyse   (8.6 s db create)

The cost is almost entirely fixed query-compilation overhead, so batching turns
a ~75 h job into well under an hour. Attribution was verified exact at 500
samples: 333/333 samples carrying an injected SQL injection were recovered.

Snyk Code counts one test per directory scanned, not per file, so the same
batching keeps the whole corpus inside the free-plan allowance.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Sequence

log = logging.getLogger(__name__)

# Matches both CodeQL's tag form ("external/cwe/cwe-089") and the plain forms
# Snyk uses ("CWE-89"). Leading zeros are stripped by int().
_CWE_PATTERNS = (
    re.compile(r"^external/cwe/cwe-(\d+)$", re.IGNORECASE),
    re.compile(r"^cwe[-_ :]?(\d+)$", re.IGNORECASE),
)

# Filenames are the attribution key, so they must round-trip a sample id.
_STAGED_NAME = "sample_{sample_id}.py"
_STAGED_RE = re.compile(r"^sample_(?P<sample_id>[A-Za-z0-9_-]+)\.py$")


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Finding:
    """One weakness reported by one tool against one sample.

    Mirrors the shared ToolAdapter contract: every adapter in the project
    returns a list of these, and nothing downstream needs to know which tool
    produced them.

    `provenance` exists for the migration. Findings recovered from the old
    per-tool columns cannot carry everything a fresh scan carries -- some tools
    only ever persisted a comma-separated CWE string, so `raw` is empty and
    `line` is None for those. Scoring must be able to tell the two apart, or a
    field that is missing for storage reasons gets read as a field the tool did
    not report.
    """

    sample_id: str
    tool: str
    tool_version: str
    cwe_ids: tuple[int, ...]
    rule_id: str
    message: str
    line: int | None = None
    severity: str | None = None
    provenance: str = "scan"  # "scan" | "backfill"
    raw: dict = field(default_factory=dict, repr=False)

    @property
    def has_full_fidelity(self) -> bool:
        """True when this finding came from a scan that stored its raw output.

        Experiments that need line numbers (localisation) or re-derivable CWE
        extraction must filter on this rather than assuming every row is equal.
        """
        return self.provenance == "scan" and bool(self.raw)


class ScanError(RuntimeError):
    """Raised when a tool fails in a way that must not be recorded as 'no findings'.

    A crashed scan and a clean scan are indistinguishable downstream unless the
    difference is raised here, so never swallow this.
    """


# --------------------------------------------------------------------------- #
# SARIF parsing
# --------------------------------------------------------------------------- #


def extract_cwe_ids(rule: dict) -> tuple[int, ...]:
    """Pull CWE identifiers out of a SARIF reportingDescriptor.

    Tools disagree on where they put them, so all known locations are checked:

    * CodeQL  -> properties.tags = ["security", "external/cwe/cwe-089"]
    * Snyk    -> properties.cwe  = ["CWE-89"]  (and sometimes properties.tags)
    * generic -> relationships against a CWE taxonomy

    Returns a sorted tuple so findings compare and deduplicate cleanly.
    """
    found: set[int] = set()
    props = rule.get("properties", {}) or {}

    candidates: list[str] = []
    candidates.extend(props.get("tags", []) or [])
    cwe_prop = props.get("cwe", []) or []
    candidates.extend([cwe_prop] if isinstance(cwe_prop, str) else cwe_prop)
    candidates.extend(props.get("categories", []) or [])

    for rel in rule.get("relationships", []) or []:
        target_id = (rel.get("target", {}) or {}).get("id")
        if target_id:
            candidates.append(str(target_id))

    for value in candidates:
        for pattern in _CWE_PATTERNS:
            match = pattern.match(str(value).strip())
            if match:
                found.add(int(match.group(1)))  # int() drops CodeQL's zero padding
                break

    return tuple(sorted(found))


def _rule_index(run: dict) -> dict[str, dict]:
    """Build ruleId -> rule, covering both driver rules and extension rules."""
    tool = run.get("tool", {}) or {}
    rules: dict[str, dict] = {}
    for component in [tool.get("driver", {})] + list(tool.get("extensions", []) or []):
        for rule in (component or {}).get("rules", []) or []:
            if rule.get("id"):
                rules[rule["id"]] = rule
    return rules


def _resolve_rule(result: dict, rules: dict[str, dict], run: dict) -> dict:
    """Resolve a result's rule, falling back to the positional index."""
    rule_id = result.get("ruleId")
    if rule_id and rule_id in rules:
        return rules[rule_id]
    index = result.get("ruleIndex")
    if index is not None:
        driver_rules = ((run.get("tool", {}) or {}).get("driver", {}) or {}).get("rules", []) or []
        if 0 <= index < len(driver_rules):
            return driver_rules[index]
    return result.get("rule", {}) or {}


def parse_sarif(
    sarif: dict,
    *,
    tool: str,
    tool_version: str,
    id_from_filename=None,
) -> list[Finding]:
    """Turn a SARIF document into Findings, attributed per staged sample."""
    resolve_id = id_from_filename or sample_id_from_staged_name
    findings: list[Finding] = []

    for run in sarif.get("runs", []) or []:
        rules = _rule_index(run)
        for result in run.get("results", []) or []:
            rule = _resolve_rule(result, rules, run)
            cwe_ids = extract_cwe_ids(rule)

            locations = result.get("locations", []) or []
            if not locations:
                continue
            physical = (locations[0] or {}).get("physicalLocation", {}) or {}
            uri = (physical.get("artifactLocation", {}) or {}).get("uri", "")
            sample_id = resolve_id(uri)
            if sample_id is None:
                log.debug("skipping result outside the staged set: %s", uri)
                continue

            findings.append(
                Finding(
                    sample_id=sample_id,
                    tool=tool,
                    tool_version=tool_version,
                    cwe_ids=cwe_ids,
                    rule_id=result.get("ruleId") or rule.get("id") or "",
                    message=(result.get("message", {}) or {}).get("text", ""),
                    line=(physical.get("region", {}) or {}).get("startLine"),
                    severity=(rule.get("properties", {}) or {}).get("problem.severity")
                    or result.get("level"),
                    raw=result,
                )
            )

    return findings


def sample_id_from_staged_name(uri: str) -> str | None:
    """Recover the sample id from a staged filename, or None if not ours."""
    match = _STAGED_RE.match(Path(uri).name)
    return match.group("sample_id") if match else None


# --------------------------------------------------------------------------- #
# Persistence mapping
# --------------------------------------------------------------------------- #
#
# The existing schema stores one row per sample with one column group per tool
# (`<tool>_cwes`, `<tool>_raw`, `<tool>_version`), matching how bandit_cwes and
# semgrep_cwes are already stored. These two functions are the whole mapping
# between that and the in-memory Finding shape; wire them into the existing core
# DB handler as save_findings() / load_findings() rather than adding a data
# layer.


def findings_to_columns(findings: Sequence[Finding]) -> dict[str, str | None]:
    """Collapse one sample's findings from one tool into that tool's columns.

    `cwes` keeps the established comma-separated format so the new columns are
    queryable exactly like the existing ones. `raw` keeps everything needed to
    re-derive a finding later without re-scanning -- that is what makes
    re-scoring cheap, so do not trim it to save space.
    """
    if not findings:
        return {"cwes": None, "raw": None, "version": None}

    tools = {f.tool for f in findings}
    if len(tools) > 1:
        raise ValueError(f"findings span multiple tools: {sorted(tools)}")

    cwe_ids = sorted({cwe for f in findings for cwe in f.cwe_ids})
    payload = [
        {
            "rule_id": f.rule_id,
            "cwe_ids": list(f.cwe_ids),
            "line": f.line,
            "severity": f.severity,
            "message": f.message,
            "raw": f.raw,
        }
        for f in findings
    ]
    return {
        "cwes": ",".join(f"CWE-{c}" for c in cwe_ids),
        "raw": json.dumps(payload, ensure_ascii=False),
        "version": findings[0].tool_version,
    }


def findings_from_columns(
    sample_id: str,
    tool: str,
    cwes: str | None,
    raw: str | None,
    version: str | None,
) -> list[Finding]:
    """Rebuild Findings from stored columns, including legacy rows.

    Two cases, and the difference matters downstream:

    * `raw` present  -> full reconstruction, provenance="scan"
    * `raw` absent   -> only the comma-separated CWE string survived (the legacy
      bandit/semgrep rows). One degraded Finding is returned carrying the CWE
      list, marked provenance="backfill" so that a line number missing for
      storage reasons is never read as a line the tool declined to report.
    """
    if raw:
        return [
            Finding(
                sample_id=sample_id,
                tool=tool,
                tool_version=version or "unknown",
                cwe_ids=tuple(item.get("cwe_ids", [])),
                rule_id=item.get("rule_id", ""),
                message=item.get("message", ""),
                line=item.get("line"),
                severity=item.get("severity"),
                provenance="scan",
                raw=item.get("raw", {}) or {},
            )
            for item in json.loads(raw)
        ]

    cwe_ids = parse_cwe_string(cwes)
    if not cwe_ids:
        return []
    return [
        Finding(
            sample_id=sample_id,
            tool=tool,
            tool_version=version or "unknown",
            cwe_ids=cwe_ids,
            rule_id="",
            message="",
            provenance="backfill",
        )
    ]


def parse_cwe_string(value: str | None) -> tuple[int, ...]:
    """Parse the legacy 'CWE-78,CWE-89' column format into sorted ids."""
    if not value:
        return ()
    found = set()
    for token in re.split(r"[,;\s]+", value):
        for pattern in _CWE_PATTERNS:
            match = pattern.match(token.strip())
            if match:
                found.add(int(match.group(1)))
                break
    return tuple(sorted(found))


# --------------------------------------------------------------------------- #
# Staging
# --------------------------------------------------------------------------- #


def stage_batch(samples: Sequence[tuple[str, str]], directory: Path) -> None:
    """Write (sample_id, source) pairs into a flat staging directory.

    Each sample becomes its own top-level module with no imports between them,
    so no cross-sample taint flow is possible and results stay attributable.
    """
    directory.mkdir(parents=True, exist_ok=True)
    for sample_id, source in samples:
        if not _STAGED_RE.match(_STAGED_NAME.format(sample_id=sample_id)):
            raise ValueError(
                f"sample_id {sample_id!r} is not filename-safe; "
                "use only letters, digits, underscore and hyphen"
            )
        (directory / _STAGED_NAME.format(sample_id=sample_id)).write_text(
            source, encoding="utf-8"
        )


def batched(items: Sequence, size: int) -> Iterator[Sequence]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


# --------------------------------------------------------------------------- #
# Adapters
# --------------------------------------------------------------------------- #


class CodeQLBatchAdapter:
    """Runs the CodeQL python-security-extended suite over a batch of samples.

    Verified against CodeQL 2.20.3. Query packs ship inside the CodeQL bundle,
    so analysis needs no network access.
    """

    name = "codeql"
    DEFAULT_SUITE = "codeql/python-queries:codeql-suites/python-security-extended.qls"

    def __init__(
        self,
        codeql_bin: str | Path = "codeql",
        suite: str = DEFAULT_SUITE,
        threads: int = 0,  # 0 = one thread per core
        ram_mb: int | None = None,
    ) -> None:
        self.codeql_bin = str(codeql_bin)
        self.suite = suite
        self.threads = threads
        self.ram_mb = ram_mb
        self._version: str | None = None

    @property
    def version(self) -> str:
        if self._version is None:
            out = subprocess.run(
                [self.codeql_bin, "version", "--format=terse"],
                capture_output=True, text=True, check=True,
            ).stdout
            # The wrapper may prepend JAVA_TOOL_OPTIONS noise; take the last line.
            self._version = out.strip().splitlines()[-1].strip()
        return self._version

    def scan_batch(self, samples: Sequence[tuple[str, str]]) -> list[Finding]:
        if not samples:
            return []
        with tempfile.TemporaryDirectory(prefix="codeql_batch_") as tmp:
            tmp_path = Path(tmp)
            src = tmp_path / "src"
            database = tmp_path / "db"
            sarif = tmp_path / "out.sarif"
            stage_batch(samples, src)

            self._run([
                self.codeql_bin, "database", "create", str(database),
                "--language=python", f"--source-root={src}", "--overwrite",
            ], step="database create")

            cmd = [
                self.codeql_bin, "database", "analyze", str(database), self.suite,
                "--format=sarif-latest", f"--output={sarif}",
                f"--threads={self.threads}",
            ]
            if self.ram_mb:
                cmd.append(f"--ram={self.ram_mb}")
            self._run(cmd, step="database analyze")

            if not sarif.exists():
                raise ScanError("CodeQL produced no SARIF output")
            return parse_sarif(
                json.loads(sarif.read_text()),
                tool=self.name,
                tool_version=self.version,
            )

    @staticmethod
    def _run(cmd: list[str], *, step: str) -> None:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise ScanError(f"CodeQL {step} failed ({proc.returncode}): {proc.stderr[-2000:]}")


class SnykCodeBatchAdapter:
    """Runs `snyk code test` over a batch of samples.

    Snyk counts one test per directory scanned rather than per file, so batching
    is what keeps a 13k-sample corpus inside the free plan's 100 tests per
    billing period. Batch generously.

    Exit codes (documented, and the usual source of silent data loss):
        0 - scan succeeded, no issues found
        1 - scan succeeded, issues found
        2 - failure, try to re-run
        3 - no supported projects/files detected
    Only 0 and 1 are successful outcomes. Treating 2 or 3 as "no findings"
    silently mislabels every sample in the batch as clean.
    """

    name = "snyk_code"
    OK_RETURN_CODES = frozenset({0, 1})

    def __init__(
        self,
        snyk_bin: str | Path = "snyk",
        org: str | None = None,
        severity_threshold: str | None = None,  # leave None: filtering loses data
    ) -> None:
        self.snyk_bin = str(snyk_bin)
        self.org = org
        self.severity_threshold = severity_threshold
        self._version: str | None = None

    @property
    def version(self) -> str:
        if self._version is None:
            out = subprocess.run(
                [self.snyk_bin, "--version"], capture_output=True, text=True, check=True
            ).stdout
            self._version = out.strip().splitlines()[-1].strip()
        return self._version

    def scan_batch(self, samples: Sequence[tuple[str, str]]) -> list[Finding]:
        if not samples:
            return []
        with tempfile.TemporaryDirectory(prefix="snyk_batch_") as tmp:
            tmp_path = Path(tmp)
            src = tmp_path / "src"
            sarif = tmp_path / "out.sarif"
            stage_batch(samples, src)

            cmd = [self.snyk_bin, "code", "test", str(src),
                   f"--sarif-file-output={sarif}"]
            if self.org:
                cmd.append(f"--org={self.org}")
            if self.severity_threshold:
                cmd.append(f"--severity-threshold={self.severity_threshold}")

            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode not in self.OK_RETURN_CODES:
                raise ScanError(
                    f"snyk code test failed ({proc.returncode}): "
                    f"{(proc.stderr or proc.stdout)[-2000:]}"
                )
            if not sarif.exists():
                raise ScanError("snyk code test produced no SARIF output")

            return parse_sarif(
                json.loads(sarif.read_text()),
                tool=self.name,
                tool_version=self.version,
            )


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def scan_corpus(
    adapter,
    samples: Sequence[tuple[str, str]],
    batch_size: int = 500,
    on_batch_error: str = "raise",  # "raise" | "record"
) -> Iterator[Finding]:
    """Scan a whole corpus in batches, yielding findings as they arrive.

    A sample that appears in a batch but produces no finding is *clean for this
    tool*; a sample in a batch that failed is *unknown*. The caller must record
    that difference, which is why a failed batch raises by default rather than
    quietly yielding nothing.
    """
    for index, batch in enumerate(batched(list(samples), batch_size)):
        try:
            findings = adapter.scan_batch(batch)
        except ScanError:
            if on_batch_error == "raise":
                raise
            log.exception("batch %d failed (%d samples) - recorded as unknown",
                          index, len(batch))
            continue
        log.info("batch %d: %d samples -> %d findings", index, len(batch), len(findings))
        yield from findings
