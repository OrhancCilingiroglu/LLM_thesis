# LLM-Based Static Code Analysis

Master's thesis project (Sabancı University, CS&E): an end-to-end pipeline that
generates single-file Python/Flask web applications with LLM APIs, runs them
in Docker, scans them with a SAST/DAST tool stack, turns tool findings into
CWE labels, and fine-tunes open-weight LLMs on those labels.

Each generated sample targets one CWE drawn from the OWASP Top 10:2025 "List
of Mapped CWEs" and is produced in matched **secure / vulnerable** pairs
sharing the same task, product, style and producer model.

## Pipeline

1. **Generation** — `project/main.py` calls three LLM API providers (OpenAI,
   Groq, Claude) to produce secure/vulnerable code pairs per CWE, generates a
   matching Dockerfile/requirements file, and stores everything in the
   SQLite DB.
2. **Docker build & run** — `project/logic/docker_pipeline.py` builds and
   runs each sample in an isolated container; only samples that come up and
   serve HTTP traffic continue past this gate.
3. **Static/dynamic scanning** — `project/scan_pipeline.py` drives the SAST
   tools (Bandit, Semgrep, SonarQube) and DAST tools (OWASP ZAP, Burp Suite
   Professional) against every Docker-successful sample. CodeQL and Snyk
   Code are run separately in batches (see `src/tools/sarif_scanners.py`)
   since both need many samples staged per invocation to be practical.
4. **CWE labeling** — `project/core/cwe_hierarchy_matching.py` classifies how
   each tool's reported CWE(s) relate to a sample's target CWE (exact /
   ancestor / descendant / sibling / unrelated), and
   `project/core/ground_truth.py` turns that into the project's actual
   strict/relaxed ground-truth label. `project/core/llm_judge.py` runs an LLM
   judge panel (Claude, GPT-4.1) as an independent labeling source.
5. **Dataset build** — `project/core/build_dataset.py` produces a balanced,
   stratified JSONL dataset from the labeled DB rows, ready for fine-tuning.
6. **Fine-tuning & evaluation** — QLoRA fine-tuning of open-weight LLMs runs
   on Google Colab (A100/T4), not locally; see `colab_outputs/`.

`phase1-` and `phase2-acceptance-artifacts.md` hold results snapshots for
each completed phase (detection rates, LLM judge panel).

## Repository layout

```
project/
  main.py            entry point for Stage 1 (code generation)
  scan_pipeline.py    entry point for Stage 2/3 (docker + SAST/DAST loop)
  db_filler.py, dast.py   ad hoc / targeted re-scan helpers
  core/               DB access, tool result columns, ground truth,
                       LLM judge panel, dataset builder, analysis scripts
  logic/               code generation, docker, SAST, DAST pipelines
  utils/               OWASP CWE lists, prompt templates, response parsing
  app_data/, app_written/   generated sample artifacts (local, gitignored)
src/tools/
  sarif_scanners.py    batch CodeQL / Snyk Code adapters (SARIF-based)
```

## Requirements

### Python

Python 3.12 (developed/tested on 3.12.3). Key packages actually installed in
this project's environment:

| Package | Version |
| --- | --- |
| openai | 2.6.1 |
| anthropic | 0.84.0 |
| groq | 0.33.0 |
| Flask | 3.1.2 |
| docker | 7.1.0 |
| bandit | 1.8.6 |
| semgrep | 1.142.0 |
| zaproxy | 0.4.0 |
| python-dotenv | 1.2.1 |
| pandas | 3.0.3 |
| numpy | 2.4.4 |
| requests | 2.32.5 |
| pytest | 9.1.1 |

(No `requirements.txt` is checked in yet; the table above reflects the
development environment as of 2026-09-26.)

### External tools

| Tool | Version used | Notes |
| --- | --- | --- |
| Docker | 29.8.1 | isolated build/run per sample |
| Bandit | 1.8.6 | SAST |
| Semgrep | 1.142.0 | SAST, 5 rulesets currently (known limitation) |
| SonarQube | Community Edition (server) | SAST; taint analysis (injection rules) is not available in Community Edition — see known issues |
| OWASP ZAP | 2.17.0 (`zaproxy` Python client 0.4.0) | DAST, API mode |
| Burp Suite Professional | — (REST API enabled, `http://127.0.0.1:1337`) | DAST |
| CodeQL CLI | 2.26.4 (earlier measurements in this doc were taken at 2.20.3) | batch SARIF scan |
| Snyk CLI | 1.1307.0 | batch SARIF scan, ~100 tests/billing-period on the free plan |

Every tool's version is also recorded per-run in the database (`<tool>_version`
columns), independent of what is in this table, so results stay attributable
even as tools get upgraded.

### Environment variables

Create a `.env` file at the repo root (never committed) with:

```
openai_key=
groq_key=
claude_key=
burp_api_key=
burpsuite_api_key=
owasp_zap_api_key=
semgrep_token=
sonar_user_token=
sonar_global_token=
hugging_token=
git_token=
DB_PATH=
```

## Running the pipeline

```bash
# 1. Generate code samples for all 10 OWASP 2025 categories
python project/main.py

# 2. Build/run each sample in Docker, then loop SAST (Bandit/Semgrep/SonarQube)
#    and DAST (ZAP/Burp) over everything that came up successfully
python project/scan_pipeline.py

# 3. Batch CodeQL + Snyk Code (staged directory scan, see the module docstring
#    for why these run separately from step 2)
python -c "from tools.sarif_scanners import CodeQLBatchAdapter, SnykCodeBatchAdapter"

# 4. Hierarchy-aware CWE matching (additive, read-only against the main table)
python project/core/cwe_hierarchy_matching.py

# 6. Project's actual ground-truth label (strict, then relaxed)
python project/core/ground_truth.py --match strict
python project/core/ground_truth.py --match relaxed

# 7. LLM judge panel (repeat per judge: claude_judge, gpt4_judge, and their
#    _blind / _guided variants)
python project/core/llm_judge.py --judge claude_judge --limit 5   # smoke test
python project/core/llm_judge.py --judge claude_judge             # full run

# 8. Build the fine-tuning dataset
python project/core/build_dataset.py
```

Every stage is resumable: each script queries the DB for already-processed
samples before doing work, so re-running after an interruption only covers
what is still missing. Fine-tuning itself is done separately on Google Colab.

## Tests

```bash
pytest project/core/test_llm_judge.py
pytest src/tools/test_sarif_scanners.py
```
