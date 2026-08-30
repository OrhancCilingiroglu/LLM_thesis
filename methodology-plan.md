# Methodology Plan — Thesis Revision (v2)

Revised against the advisor meeting notes. This document is the single source of
truth for what is being built, which research question each piece answers, and
what is explicitly out of scope.

Hard constraint carried over from the meeting: **every experiment maps to exactly
one research question, and no research question is left without an experiment.**
Section 1 is that mapping. If a task cannot be traced to a row in Section 1, it
does not get built.

---

## 0. Research questions — resolved set

The meeting notes contain two conflicting definitions of RQ4 ("compare LLMs with
SAST/DAST tools" under *To Be Determined*, and "effect of the detection prompt"
under *Finalized*). The Finalized definition wins; the comparison question is
renumbered to RQ6. Numbering must be fixed before anything is written up —
two RQ4s in a thesis is a defence-day problem.

| ID | Question | Status |
| --- | --- | --- |
| RQ1 | To what extent can a base LLM, without security-specific fine-tuning, detect vulnerabilities in Python-Flask code? | Existing, answered |
| RQ2 | To what extent does CWE-oriented fine-tuning improve that? | Existing, answered — needs re-running with seeds |
| RQ3 | How do training and data parameters affect fine-tuned performance? | Finalized |
| RQ4 | How does the *detection prompt* affect fine-tuned performance? Which prompt components matter? | Finalized |
| RQ5 | Label format: multi-label bit string (all vulnerabilities) vs. single label (target / most significant) — which is learned better? | More-or-less determined |
| RQ6 | How do fine-tuned LLMs compare against the SAST/DAST tool stack? | Reduced scope — see 0.1 |

### 0.1 RQ6 without a human gold set

**Scope decision: manual annotation is out.** There is not enough time left to
hand-label a gold set, so everything below is built to work without one. The
consequences must be stated in the thesis rather than glossed over.

The naive version of RQ6 is circular: the models are trained on labels produced
by the tool stack, so comparing them to that stack compares a student to its own
answer key. The thesis already concedes this in §5.3.2 — the A06 result (models
79–86% vs. tools 7.1%) is explicitly *not* evidence that the LLM found what the
tools missed.

But one label in this pipeline is independent of **both** parties: the
**generation-time target CWE**. Each sample was generated from a prompt
demanding a specific weakness, before any tool or model saw it. It is noisy —
the producer LLM sometimes fails to inject the weakness — but it is not
circular. That gives a defensible reduced form:

> **RQ6′.** On a held-out set drawn from *all* Docker-successful samples (not
> only the tool-confirmed ones), how well do the fine-tuned models and the
> SAST/DAST stack each recover the generation-time target CWE?

Why this is legitimate:

- The target label predates and is independent of both the tools and the models.
- Both parties are scored against the *same* noisy labels, so the comparison is
  valid in relative terms even though neither absolute number is exact. This is
  the standard noisy-label evaluation setting and is defensible when stated.
- Drawing the held-out set from all Docker-successful samples — not just the
  1,224 the tools confirmed — removes the selection bias that makes the current
  comparison circular.

What must be written into Limitations, plainly:

- The target-CWE label's noise rate is **unknown**. The producer self-check
  (3× agreement) bounds it loosely and nothing else does.
- No claim of the form "the model detected a vulnerability the tools missed"
  can be made about any individual sample. Only aggregate recovery rates
  against the target label are supportable.
- Absolute accuracy figures are accuracy *against a noisy reference*, not
  against ground truth, and must be labelled that way in every table caption.

§5 lists the one automated route that would lift this restriction if any time
appears.

### 0.2 The "specific vs. generic" question, reformulated

The meeting proposed a new RQ: does training on specific CWEs affect generic
(OWASP) detection, and vice versa?

The question is real but as literally phrased it does not survive scrutiny:

- **CWE → OWASP is a lookup, not transfer.** OWASP category is a deterministic
  function of the CWE in this pipeline (categories were derived from the OWASP
  "List of Mapped CWEs"). A CWE-predicting model's OWASP accuracy can be
  computed by table lookup from its existing output. Nothing is being measured.
- **OWASP → CWE is ill-posed.** A model trained to emit only OWASP categories
  has never been asked to produce a CWE identifier. Its CWE accuracy is zero by
  construction, not by inability.

Reformulated as a **label-granularity condition inside RQ5**, it becomes
measurable. Three training conditions, all evaluated on both granularities:

| Condition | Training target |
| --- | --- |
| G1 | CWE identifier only |
| G2 | OWASP category only |
| G3 | Hierarchical — OWASP category followed by CWE |

Evaluation: CWE-level accuracy (G2 scored as correct if the predicted category
contains the true CWE — a ceiling comparison, stated as such) and OWASP-level
accuracy for all three. G3 vs G1 is the interesting comparison: does making the
coarse label explicit help the fine one?

---

## 1. RQ ↔ experiment matrix

This table is the deliverable the advisor asked for. Keep it current; it goes in
the thesis as-is.

| Exp | Name | RQ | Phase | Output |
| --- | --- | --- | --- | --- |
| E0 | Tool-stack audit + expansion (Snyk, CodeQL, hierarchy matching) | — (dataset) | 1 | Detection-rate before/after table |
| E1 | Parallel judgment + fusion model comparison (union / majority / Dawid-Skene) | — (dataset) | 1 | Label-quality vs. dataset-size curve |
| E2 | Source characterisation without gold: target-CWE recovery, agreement matrix, evidence-check rate | RQ6′ input | 2 | Per-source reliability table |
| E3 | Stage-1: all base models, vanilla vs. fine-tuned | RQ1, RQ2 | 3 | Baseline comparison; selects 2 models |
| E4 | Label format: single vs. multi-label bit string | RQ5 | 3 | Format comparison table |
| E5 | Label granularity: G1 / G2 / G3 | RQ5 | 3 | Granularity comparison table |
| E6 | Detection-prompt component ablation | RQ4 | 3 | Prompt-component contribution table |
| E7 | Stage-2: epoch count sweep | RQ3 | 4 | Parameter curve |
| E8 | Stage-2: context length sweep (2048 / 4096 / 8192) | RQ3 | 4 | Parameter curve |
| E9 | Stage-2: model size (3B vs 7B, within and across families) | RQ3 | 4 | Parameter curve |
| E10 | Adaptation method: QLoRA vs DoRA vs rank sweep vs encoder classifier | RQ3 | 4 | Parameter/method table |
| E11 | Data content: with vs. without problematic line number in the target | RQ3 | 4 | Localisation result |
| E12 | Fine-tuned models vs. tool stack, scored on target-CWE recovery | RQ6′ | 4 | Head-to-head table |
| V1 | Validity checks: matched pairs, length-matched, comment-stripped, seeds | all | 4 | "Threats to validity" subsection |

---

## Phase 1 — Dataset: fix the stack, then judge in parallel

Addresses the meeting's *Finalized* item 1 (dataset quality and size) and the
*To Be Determined* item 3 (alternative methodology path). Also the direct answer
to "insufficient sample size".

### 1.0 Where the samples are going

Current funnel:

| Stage | Count |
| --- | --- |
| Generated | ~28,130 |
| Docker-successful | 13,434 |
| Vulnerable reaching the tool stack | 8,544 |
| Confirmed by ≥1 tool | 1,224 (14.3%) |
| Secure, unflagged | 4,944 |
| **Available for training** | **6,168** |
| **Actually used** | **~2,494** |

Note the last two rows. Roughly 3,700 already-labelled samples are not reaching
training. Before adding a single new tool, find out why — stratification,
class balancing, or a filter nobody remembers writing. This is the cheapest
sample-size gain available and it costs nothing but a query.

**Target after Phases 1–2: 8,000–12,000 usable samples.** Track this number.

### 1.1 Prerequisite — additive, not a restructure

**Scope decision: the existing schema and module layout stay.** No new tables, no
directory reorganisation. New capability arrives as new columns on the existing
results table and new functions in the existing `core` DB handler. This matches
the project's own rule — *prefer adding a new column over mutating existing
labeled data* — and keeps every current result reproducible beside the new ones.

What that means concretely:

**`Finding` is an in-memory shape, not a table.** It is what an adapter returns
and what scoring consumes. Persistence stays in the per-tool column pattern
already in use:

```
codeql_cwes      TEXT      -- "CWE-22,CWE-89", same format as bandit_cwes
codeql_raw       TEXT      -- SARIF results for this sample, JSON
codeql_version   TEXT
snyk_cwes        TEXT
snyk_raw         TEXT
snyk_version     TEXT
```

Add `<tool>_version` for the five existing tools too — it is a project ground
rule and it is one column each.

**The DB handler gains two functions, not a rewrite:**

```python
def save_findings(sample_id, tool, findings) -> None
def load_findings(sample_id, tools=None) -> list[Finding]
```

`save_findings` collapses a list of Findings into that tool's three columns;
`load_findings` reverses it. Everything above the handler works in `Finding`s;
everything below stays exactly as it is today.

**What this costs, so it is a choice and not an accident.** Per-tool columns mean
one row per sample, so a sample with three CodeQL findings stores them together
in `codeql_raw` and line numbers are only reachable by parsing that JSON. That is
fine for scoring and for the fusion matrix, which need one vote per source. It is
mildly awkward for E11 (localisation), which wants per-finding rows. Accept it;
E11 can parse `codeql_raw` when it runs, and it is on the cut list anyway.

**Scoring moves out of scanning.** This is the one non-negotiable part, and it is
a new module, not a change to existing ones: a function that takes findings plus
a target CWE and returns a detection outcome. The §1.3 hierarchy rule, the strict
and relaxed comparison, and every re-score afterwards live there.

**Regression test:** backfilling the new columns from existing data and
re-scoring must reproduce **1,224 / 8,544** exactly. Run this before adding any
new tool — once CodeQL lands, the number changes and the reference is gone.

### 1.6 What has to be re-scanned, and what does not

The migration is a data transformation, not a re-scan. What is recoverable
depends on what each tool persisted:

| Tool | Stored today | Backfill | Re-scan cost |
| --- | --- | --- | --- |
| ZAP | full alert array (JSON) | full fidelity | Docker + spider + active scan — **days** |
| Burp | per-CWE records + config, severity, path | near-full | Docker + scan — **days** |
| SonarQube | CWE string + issue/hotspot summaries | partial | local server, moderate |
| Semgrep | comma-separated CWE string only | CWE list only | local, hours, parallelisable |
| Bandit | comma-separated CWE string only | CWE list only | local, **minutes** |

The two lossy tools are the two cheapest, and both are being re-run anyway
because §1.2 changes their configuration — so the migration rides along free.
**Do not re-run ZAP or Burp for the migration.** Backfill them.

The one genuine re-scan decision is ZAP's CWE-targeted policy: it costs days and
buys an unknown amount. Defer it until after CodeQL has landed and the detection
rate is known — it may turn out to be unnecessary.

Findings recovered this way carry `provenance="backfill"` and an empty `raw`;
scoring must not read a missing field as a field the tool did not report.

### 1.2 Audit the existing five

In expected-payoff order. Details of each finding go in the thesis as
configuration notes.

**Bandit** (52.1% of all current detections — losses here are expensive)
- Use `bandit -f json`; read the structured `results[].issue_cwe.id` instead of
  regex-matching stdout. Requires Bandit ≥ 1.7.3; pin the version.
- Verify no severity/confidence filter is applied anywhere.
- Store `test_id` (B608, B201, …) per finding for the appendix mapping table.

**Semgrep**
- Read CWE ids from `results[].extra.metadata.cwe` (a list of strings like
  `"CWE-89: Improper Neutralization …"`); parse the numeric id out.
- Do not decide "findings exist" from the process return code — parse the JSON
  and count `results`. A non-empty `errors` array is a scan failure and must be
  recorded, not silently skipped.
- Add `p/default`, `p/security-audit`, `p/python`, `p/flask`, `p/secrets`.
  Record which ruleset produced each finding so marginal contribution is
  reportable.

**SonarQube** (currently zero detections — resolve before investing further)
- Check the edition. Injection detection depends on **taint analysis, which the
  Community edition does not ship**. If you are running the free image, zero is
  the expected result and says nothing about the tool.
- If a Developer-edition licence is reachable through the university, use it and
  re-scan. If not, state this explicitly in the thesis and demote SonarQube from
  the headline stack. Reporting "SonarQube found nothing" without this caveat
  misrepresents the tool and a reviewer will catch it.
- Set `sonar.python.version`; some rules do not fire without it.

**OWASP ZAP**
- Use the `cweid` field present on every alert rather than correlating via rule
  name. Cheap, and recoverable from the stored alert JSON without re-scanning.
- Select a CWE-targeted scan policy per sample, as Burp already does. Note this
  *does* require re-scanning, so decide it against §1.6 rather than assuming it.
- **Authentication is not the problem here.** The generated applications have no
  login; endpoints are reachable directly. So the low A01 detection rate is not
  a crawler-coverage artefact, and adding a ZAP auth context would buy nothing.
  See §1.2.1 — the real cause is more interesting and needs no code at all.

#### 1.2.1 Why A01 detection is low: a structural finding, not a bug

A01 (Broken Access Control) is 15% of generated samples and had the *highest*
Docker success rate (56.6%), yet the lowest-but-one detection rate. With
authentication ruled out as the cause, the explanation is in the category
itself.

A01's mapped CWEs split into two groups:

| Group | Examples | Testable in these apps? |
| --- | --- | --- |
| Needs a privilege boundary | CWE-862, CWE-863, CWE-639, CWE-285 | **No.** "Missing authorization" presupposes an authorization model to be missing from. In an app with no users and no roles, the weakness is trivially true and indistinguishable from an app that simply has no auth by design. Neither SAST nor DAST can flag it, because there is nothing to compare against. |
| Self-contained | CWE-22, CWE-23, CWE-601, CWE-352 | **Yes.** Path traversal and open redirect are ordinary taint problems. CodeQL detects `py/path-injection` → CWE-22 reliably (verified). |

This is a **generation-design consequence**, not a tool failure, and it is worth
a paragraph in the thesis: prompting a single-file, auth-less Flask app to
exhibit "missing authorization" produces a sample whose weakness has no
observable signature. The honest move is to report A01 detection split by these
two groups rather than as one number, and to state that the privilege-boundary
subset is outside what this pipeline can validate.

**Concrete prediction to check after CodeQL lands:** A01 detection should rise
noticeably, but the rise should be concentrated almost entirely in the
self-contained subset. If it rises evenly across both, something is wrong with
the CWE attribution and it needs investigating before the number is reported.

The same reasoning applies to the fine-tuned models' A01 results — including the
79–86% A06 figure's cousin. A model scoring well on privilege-boundary CWEs is
reproducing the label, not detecting a weakness, because no observable weakness
was there to detect.

**Burp Suite Professional**
- Cross-check the hand-built `type_index` → CWE table against PortSwigger's
  published issue definitions. Report how many issue types are mapped and how
  many are unmapped; an unmapped type is a silent miss.

### 1.3 Hierarchy-aware CWE matching

Detection currently requires an exact CWE match, while the cross-CWE matrix
(Fig. 5.10) shows tools routinely reporting generic ancestors (CWE-668, 693,
497).

Build the CWE relationship graph from MITRE's catalogue XML
(`Related_Weaknesses`, view CWE-1000) and classify each outcome as `exact`,
`ancestor`, `descendant`, `sibling`, `unrelated` or `none`. Report detection
rate under both strict and relaxed rules; the gap between them is itself a
result about how tools report.

Cheapest large gain in the plan.

### 1.4 New tools: CodeQL and Snyk Code

Both were verified end-to-end before this plan was written; the numbers below
are measured, not estimated. A tested reference implementation of both adapters
lives in `src/tools/` (see `sarif_scanners.py` and its test suite).

**Both must be run in batches, for different reasons that happen to have the
same solution.**

| | CodeQL | Snyk Code |
| --- | --- | --- |
| Why batch | 20 s fixed query-compilation overhead per invocation | Free plan allows ~100 tests per billing period |
| What counts as one unit | one database | one directory scanned, regardless of file count |
| Corpus at batch size 500 | ~27 batches, well under an hour | ~27 tests, inside the free allowance |

Measured on CodeQL 2.20.3 with single-file Flask apps carrying four injected
weaknesses each:

| Batch size | DB create | Analyse |
| --- | --- | --- |
| 1 | 1.4 s | 20.2 s |
| 60 | 4.2 s | 21.7 s |
| 500 | 8.6 s | 26.5 s |

The cost is almost entirely fixed overhead, so one-sample-at-a-time would take
roughly 75 hours where batching takes well under one. Per-file attribution was
verified exact at 500 samples: all 333 samples carrying an injected SQL
injection were recovered, and none of the 167 patched samples was flagged for
CWE-89.

**Mechanics.** Stage each batch as a flat directory of independent modules named
`sample_<id>.py` — no imports between them, so no cross-sample taint flow is
possible — then attribute results back through the SARIF
`artifactLocation.uri`. The staged filename is the attribution key, so sample
ids must be filename-safe.

```
codeql database create db --language=python --source-root=<batch_dir> --overwrite
codeql database analyze db \
  codeql/python-queries:codeql-suites/python-security-extended.qls \
  --format=sarif-latest --output=out.sarif --threads=0

snyk code test <batch_dir> --sarif-file-output=out.sarif
```

**CWE extraction differs between the two and both must be handled:**

- CodeQL puts them in `runs[].tool.driver.rules[].properties.tags` as
  `external/cwe/cwe-089` — note the **zero padding**, which must be stripped.
  One rule often carries several CWEs (`py/path-injection` → 22, 23, 36, 73,
  99), which composes well with the hierarchy matching in §1.3.
- Snyk puts them in `properties.cwe` as `["CWE-89"]`, sometimes also in `tags`.

**Two traps:**

- `snyk code test` exit codes are `0` = clean, `1` = issues found, `2` = failure,
  `3` = no supported files. Only 0 and 1 are successes. Treating 2 or 3 as "no
  findings" silently mislabels every sample in the batch as clean — the same
  class of bug as the Semgrep return-code issue in §1.2.
- Snyk Code uploads source to Snyk's servers for analysis. Not a problem for
  synthetic data, but it belongs in the thesis as a methodological note.

CodeQL was not in the meeting notes; it is recommended anyway. It is the
strongest Python taint-tracking engine available, free for academic research,
and the thesis already names it as a gap in its own Limitations section — adding
it converts a stated limitation into a result. It also reports **line numbers**,
which feed E11 directly.

No additional DAST scanners. Coverage is not the bottleneck there.

### 1.5 Architecture change: parallel judgment + fusion (E1)

This is the meeting's key methodological question, and the answer is that the
parallel design is strictly better — the sequential cascade should be treated as
a budget fallback, not the design.

**Current pipeline (sequential):**
producer LLM generates → same LLM self-checks 3× → SAST/DAST filters → label.

Two structural problems. The self-check is the *producer grading its own
homework*, which is the weakest possible evidence and sits at the most decisive
point in the funnel. And the tool stack acts as a gate, so a sample the tools
miss is simply lost — its 86% miss rate becomes an 86% data loss rate.

**The cascade variant** (*More or less determined* item 1b: tools first, LLMs
decide the fate of what tools miss) fixes the data loss but not the science.
The LLM panel only ever sees the hard cases, so you never learn how it behaves
on the easy ones — which means you can never estimate its reliability, and
therefore can never weight it against the tools.

**Recommended: parallel with a label model.**

Every source scores every sample independently. Each source becomes a *labelling
function* emitting `VULNERABLE` / `SECURE` / `ABSTAIN` for the sample's target
CWE:

| Source group | Members |
| --- | --- |
| SAST | Bandit, Semgrep, SonarQube, CodeQL, Snyk |
| DAST | OWASP ZAP, Burp Suite |
| LLM judges | 2–3 frontier API models (see Phase 2.2) |
| Weak prior | producer self-check (kept, but explicitly down-weighted) |

Fusion methods, compared against each other as E1:

| Method | Needs gold? | Notes |
| --- | --- | --- |
| F0: 1-of-n union | No | Current thesis behaviour; the baseline to beat |
| F1: majority vote | No | Trivial, but treats a broken tool as equal to a good one |
| F2: **Dawid–Skene / EM label model** | No (gold for validation only) | Estimates each source's sensitivity and specificity from agreement patterns alone, then emits a *probabilistic* label |
| F3: meta-classifier on the vote vector | Yes | Likely to overfit on 200–300 gold samples; report only if F2 underperforms |

F2 is the answer to "bu ikisinin yargılarını birleştirecek başka bir yöntem".
It is established, citable work (Dawid & Skene 1979; Snorkel, Ratner et al.
2017), and it does something the union rule cannot: it produces a confidence per
label. That confidence directly addresses the sample-size problem — instead of a
binary keep/discard, you get a **dataset-size vs. label-confidence curve**, and
the threshold becomes a tunable parameter feeding RQ3.

**Cost.** Running the judge panel on all 13,434 Docker-successful samples rather
than only the 7,320 unconfirmed is roughly 2× — not prohibitive. At ~4k tokens
per sample that is ~55M input tokens per judge. Start with a stratified 3,000-
sample subset, measure, then decide whether the full run pays for itself. If
budget forces a cut, run parallel on a stratified subset large enough to fit the
label model and cascade for the remainder — but say so in the thesis, because
the label model's accuracy estimates then come from a subsample.

### Phase 1 acceptance artifacts

1. Detection-rate table: strict/old config → strict/new config → hierarchy-aware,
   broken down per tool and per OWASP category, with configuration fixes and
   genuine tool additions reported separately.
2. Fusion comparison (F0–F2) with the dataset-size vs. confidence curve.
3. The updated funnel table, with the usable-sample count against the 8,000–
   12,000 target.

---

## Phase 2 — The LLM judges

### 2.1 No gold set: what replaces it

Manual annotation is cut. Two things stand in for it, and neither costs
annotation time:

**The target CWE as a weak reference.** Every judge and every tool can be scored
on how often it recovers the generation-time target CWE. Noisy, independent of
both parties, free. This is what feeds RQ6′ (§0.1) and it is also enough to
sanity-check a judge that has gone badly wrong.

**The label model's own reliability estimates.** Dawid–Skene infers each
source's sensitivity and specificity from agreement patterns alone — that is the
entire point of the method, and the reason it was chosen in Phase 1.5 over a
plain majority vote. Gold data was only ever going to *validate* those
estimates, not produce them.

What this costs, stated for the write-up: the reliability figures are
**model-estimated, not measured**. Dawid–Skene assumes sources err
independently, and that assumption is visibly shaky here — Bandit and Semgrep
share rule heritage, and two frontier LLM judges may share the same blind spots.
Correlated errors inflate the estimated reliability of a correlated group. Say
so, and report the source-agreement matrix so a reader can see the correlation
structure and judge for themselves.

### 2.2 Judge design

- **Judges must not be the students.** Judges are frontier API models
  (GPT-4.1, Claude, optionally a third); the fine-tuned models are Qwen /
  Mistral / Llama. Same-family judging adds no information.
- **Keep the producer self-check, but demote it.** It stays in the pipeline as a
  weak labelling function inside the fusion model, where its measured
  reliability determines its weight, instead of acting as a hard gate.
- **Structured output with mandatory evidence:**

```json
{
  "verdict": "VULNERABLE" | "SECURE" | "UNCERTAIN",
  "cwe": 89,
  "evidence_line": "<verbatim line copied from the code>",
  "line_number": 42,
  "sink": "cursor.execute",
  "exploit_sketch": "one sentence",
  "confidence": 0.0
}
```

- **Programmatic evidence check.** After whitespace normalisation,
  `evidence_line` must appear verbatim in the sample; otherwise the verdict is
  discarded as unsupported. A mechanical filter on hallucination, and worth
  writing up as a methodological contribution.
- `line_number` is not decoration — it feeds E11 (see Phase 4). SAST tools
  report line numbers too, so localisation labels are available for confirmed
  samples from both sides.
- Temperature 0; store the prompt version with every verdict; cache on
  `hash(code + prompt_version + model)` so re-runs are free.

### 2.3 Characterise the judges without gold (E2)

Three things are measurable with no annotation at all, and together they carry
the section:

1. **Target-CWE recovery rate** per judge and per tool, on all Docker-successful
   samples. Free, independent, directly comparable across sources.
2. **Source-agreement matrix** — pairwise agreement between every tool and every
   judge. This is what exposes the correlated-error problem in §2.1, and it is
   also the most informative single figure available without ground truth.
3. **Evidence-check pass rate** per judge: how often the quoted
   `evidence_line` actually exists in the sample. A judge that fails this often
   is hallucinating regardless of whether its verdicts happen to agree with
   anything.

Add the Dawid–Skene estimated sensitivity/specificity per source alongside these,
clearly labelled as estimates.

### Phase 2 acceptance artifacts

Per-source table (target-CWE recovery, evidence-check pass rate, estimated
sensitivity/specificity), the source-agreement matrix, and the recovered-sample
count: how many previously-discarded samples the fusion model labels above
threshold with supported evidence.

---

## Phase 3 — Stage-1 experiments: model selection and data design

Follows the meeting's two-stage structure: broad comparison first, then deep
parameter work on the two best models.

### 3.1 E3 — vanilla vs. fine-tuned across all base models (RQ1, RQ2)

All four existing base models (Qwen2.5-7B, Qwen2.5-3B, Mistral-7B,
Llama-3.2-3B), baseline and fine-tuned, on the Phase-1 dataset with the fusion
labels.

**Model selection must not touch the test set.** Pick the top two on the
*validation* split. If the two models carried into Stage 2 were chosen by test
performance, every Stage-2 number is contaminated by selection bias, and this is
exactly the kind of thing a jury catches. Freeze the test set now and do not
look at it until E12.

Three seeds per configuration — see V1.

### 3.2 E4 — label format (RQ5)

Single label (target CWE) vs. multi-label bit string (all CWEs raised for the
sample). Runs 1/2 vs. Runs 3/4 in the current thesis already gesture at this,
but they also differ in base model and dataset, so nothing is isolated. Hold
everything else fixed and vary only the target format.

Report: accuracy, weighted F1, hallucination rate, CWEs emitted per sample. The
current results suggest the multi-label target is what drives the 100%
hallucination rate — confirm or refute it under controlled conditions.

### 3.3 E5 — label granularity (RQ5)

Conditions G1 (CWE), G2 (OWASP), G3 (hierarchical: category then CWE), as
defined in §0.2. G3 vs. G1 is the comparison that carries the section.

### 3.4 E6 — detection-prompt ablation (RQ4)

Components to ablate in the prompt that asks the model to detect:

| Component | Levels |
| --- | --- |
| Role framing | "You are a SAST tool" / neutral / absent |
| Candidate CWE list | provided / absent |
| Output format constraint | strict comma-separated / free text |
| Few-shot examples | 0 / 2 / 4 |
| Reasoning | direct answer / brief reasoning before answer |

**Critical caveat.** Fine-tuning bakes in one prompt format. A fine-tuned model
evaluated under a different prompt will degrade sharply, and that degradation is
prompt sensitivity, not a property of the prompt component. Run the ablation on
*both* baseline and fine-tuned models and report them separately. Framed
correctly, "fine-tuned models are brittle to prompt changes their training never
covered" is itself a finding worth having.

---

## Phase 4 — Stage-2 experiments: parameters, on the two selected models

### 4.1 E7 — epoch count (RQ3)

**Implementation conflict to resolve first.** The current setup uses
`EarlyStoppingCallback(patience=2)` with `load_best_model_at_end=True`. Under
early stopping, epoch count is not a controlled variable — the callback picks it.
Sweeping epochs requires disabling early stopping for these runs, and the thesis
must state that the two sets of runs differ in this respect.

### 4.2 E8 — context length (RQ3)

Levels 2048 / 4096 / 8192. Scope note: the thesis already found 2048 truncates
samples mid-code, so 2048 → 4096 has a known direction. The genuinely open
question is 8192, and it matters for a specific subpopulation — **Claude-produced
samples average 586 SLOC** against OpenAI's ~250 and Groq's ~74. Report the
context-length effect broken down by producer model; a global average will hide
the only place the effect lives.

8192 with QLoRA will not fit a T4. Plan for A100 or reduce batch size further.

### 4.3 E9 — model size (RQ3)

The notes say "3-4B instead of 9B"; the existing runs used 3B and 7B. Much of
this axis is already covered — Qwen2.5-3B vs 7B within a family, Llama-3.2-3B vs
Mistral-7B across families. What is missing is not more sizes but **seeds**.
Re-run the existing comparison with three seeds rather than adding new scales;
the current single-run result ("model scale mattered less than expected") is
unsupported until it survives repetition.

### 4.4 E10 — adaptation method (RQ3, the "replace LoRA?" item)

Cheap ablations, single-flag changes in `peft`, all worth a row in one table:

- **DoRA** — `LoraConfig(use_dora=True)`; the strongest drop-in replacement.
- **rsLoRA** — `use_rslora=True`; matters more at higher ranks.
- **LoRA+** — separate learning rates for the A and B matrices (ratio ~16), as
  optimizer parameter groups.
- **Rank sweep** — r ∈ {8, 16, 32, 64} at fixed α/r. Produces a parameter-budget
  curve, which is a more useful figure than a method leaderboard.
- **IA³** — far fewer trainable parameters; the question is how much survives.

Plus one genuinely different mechanism:

- **Encoder + multi-label classification head**, fully fine-tuned. Candidates:
  `answerdotai/ModernBERT-base`, `microsoft/unixcoder-base`,
  `Salesforce/codet5p-220m`. Context length decides: samples need ~4096 tokens
  and CodeBERT/UniXcoder cap at 512, so either use ModernBERT (8192) or chunk
  with aggregation — and if you chunk, say so, because it changes what the model
  can see.

  Worth doing because the thesis reviews CodeBERT, GraphCodeBERT and UniXcoder
  in its literature chapter and then never uses any of them. "Does this task
  need a 7B generative model, or does a 125M encoder match it?" has a
  publishable answer either way.

Expect small differences between the PEFT variants. Report them as mean ± std
over three seeds and do not describe a difference smaller than the standard
deviation as a difference.

### 4.5 E11 — data content: localisation (RQ3)

The notes list "the content in the data i.e., problematic line number" as an
RQ3 parameter. This is the most interesting item on that list and it composes
with Phase 2's evidence requirement: SAST tools report line numbers, and the
judge protocol already demands `line_number`, so localisation labels exist on
both sides for confirmed samples.

Two training targets, everything else fixed:

- T1: `CWE-89`
- T2: `CWE-89 @ line 42` (or CWE plus the vulnerable line verbatim)

Evaluate CWE accuracy for both, plus line-localisation accuracy for T2. If T2
matches T1 on classification while also localising, that is a strictly stronger
model and a clear differentiator against the literature — the thesis already
cites Sovrano et al. on LLMs being "lost in the end" of long files, which is a
localisation failure.

### 4.6 E12 — LLM vs. tool stack (RQ6′)

Head-to-head on a held-out set drawn from **all** Docker-successful samples, not
only the tool-confirmed ones: the two selected fine-tuned models, their
baselines, the public API models, and each SAST/DAST tool, all scored by the
same harness on recovery of the generation-time target CWE.

Two rules that make the difference between defensible and circular:

- **The held-out set must include samples no tool confirmed.** Restricting it to
  the confirmed pool re-introduces exactly the selection bias that made the
  original comparison meaningless.
- **Every table caption says "against the generation-time target CWE", not
  "accuracy".** The reference is noisy and the reader must be told which
  reference is in use.

Report the tool stack's number on the same held-out set for context, and expect
it to be low by construction on the unconfirmed portion — that is a property of
the sampling, not a finding, and must be stated as such.

### 4.7 V1 — validity checks

Not optional, and not a footnote. These belong in their own results subsection.

- **Three seeds minimum per configuration**, mean ± std everywhere.
- **Matched-pair evaluation.** Every secure sample has a vulnerable twin sharing
  task, product, style, CWE and producer; reconstruct pair ids from those five
  fields if the DB has none. Score on pairs: can the model separate the two
  members? Secure samples are systematically longer and more complex than
  vulnerable ones (avg CC max 6.36 vs 4.23; Halstead 223.5 vs 119.6), so a model
  can learn length instead of security. The generalisation gap does not detect
  this — the shortcut is present in train and test alike. Nearly free to
  implement, and it closes the most obvious line of attack on the results.
- **Length-matched subset** evaluation.
- **Comment-stripped condition** — already promised in the thesis; run it.
- **Shuffled-label control** — train on randomised labels; anything above chance
  reveals leakage.
- Log git commit, config hash, seed and dataset hash with every run.

### 4.8 Compute planning

Colab session limits are what forced single runs last time, and three seeds
triples demand. Before starting: checkpoint to Drive so an interrupted run
resumes rather than restarts, and consider Kaggle (30 GPU-hours/week free) or a
rented A100 for the seed sweeps. Running out of compute halfway through a seed
sweep produces the same unreportable result as running one seed.

---

## 5. Explicitly out of scope

Recorded here so the decision is not relitigated, and so the thesis can state
what was deliberately not attempted.

| Item | Why not |
| --- | --- |
| **Regenerating all data with a new generation prompt** | Confirmed infeasible in the meeting. Generation is the cheap part; the ~13,400 Docker builds and five tool scans behind them are not, and all of it would be invalidated. **Scoped exception:** regenerate only the long-tail CWEs with <10 samples, and add prompt variants for a small controlled subset if generation-prompt effects need any evidence at all. |
| **Manual gold set** (200–300 hand-labelled samples) | Cut for time. §0.1 and §2.1 describe what replaces it and what can no longer be claimed. |
| **DPO / ORPO / GRPO** (changing the training objective) | Attractive for the hallucination and verbosity problem, and the task has a mechanically checkable reward. Out of scope: not requested, high VRAM, and RQ3 is about parameters, not objectives. Future Work. |
| **Full fine-tuning, GaLore, prompt/prefix tuning** | Full FT of 7B does not fit the available hardware; GaLore needs more VRAM than QLoRA, defeating the constraint being worked under; prompt/prefix tuning is too weak for structured output. Mention in the RQ3 write-up as considered-and-rejected, with these reasons. |
| **Bearer, Opengrep, additional DAST scanners** | Marginal on top of Snyk and CodeQL. Tool count is not the bottleneck; configuration quality is. |
| **RQ6 in its original form** ("which is better") | Circular without ground truth. Replaced by RQ6′ (§0.1): recovery of the generation-time target CWE, on a held-out set that includes tool-unconfirmed samples, with the reference's noisiness stated in every caption. |
| **"Specific vs. generic" as a standalone RQ, in its literal form** | One direction is a table lookup, the other is ill-posed. Absorbed into RQ5 as the granularity condition (§0.2). |
| **SonarQube as a headline tool, if the deployment is Community edition** | Zero detections is then a licensing artefact, not a result. Either license Developer edition or report it as a configuration limitation and demote it. |

### 5.1 The one automated route back to real ground truth

Recorded here because it is the only option left that produces certainty, and
unlike the gold set it is **code, not annotation** — which may make it fit the
remaining time where hand-labelling does not.

Scope it to the two largest CWE classes only: **CWE-89 (SQL injection)** and
**CWE-79 (reflected XSS)**. Together they dominate A05 Injection, the single
largest OWASP category at 21% of generated samples.

The Docker lifecycle already exists and already confirms each container serves
HTTP. Adding a probe step is a small extension of it:

- Enumerate the app's routes and their query parameters (a crawl, or parse the
  `@app.route` decorators out of the single-file source).
- For CWE-89, send a boolean-difference payload pair (`' OR '1'='1` vs
  `' AND '1'='2`) and compare responses; a reliable difference is an exploit.
- For CWE-79, send a marker payload and check whether it comes back unescaped
  in the response body.

A successful exploit is **ground truth** — not a tool's opinion, not a model's
opinion. Even on two CWEs this changes what the thesis can say: RQ6 can be
answered properly on that subset, the tool stack's true false-negative rate
becomes measurable there, and the label model's estimated reliabilities can
finally be validated against something real.

A failed probe is weak evidence and must be recorded as "not exploitable by this
probe", never as "secure".

Estimate: two to three days. If any time at all opens up, this buys more than
anything else on the cut list.

---

## 6. Open items — advisor decisions, not engineering

Tracked here because they gate the write-up rather than the code:

1. **Target conference** — to be decided with Orçun Hoca. Affects length,
   format, and how much of the pipeline chapter survives into a paper.
2. **Final thesis deadline** — Budi's current comments plus the comments that
   follow the work in this plan. Needs a date before Phase 4 scope can be fixed.
3. **Single vs. multi-label as the *primary* framing** — marked "to be
   discussed". E4 and E5 produce the evidence; the framing decision follows the
   result, not the other way round.
4. **SonarQube Developer-edition licence** — university availability.

---

## 7. Sequencing

| Phase | Contents | Effort | Blocks |
| --- | --- | --- | --- |
| 1 | Adapter refactor, tool audit, Snyk + CodeQL, hierarchy matching, parallel fusion | ~2 weeks | Everything — changes the dataset |
| 2 | Judge panel, source characterisation | ~1 week | Fusion weights, Phase 4 test set |
| 3 | E3–E6: model selection, label format, granularity, prompt | ~2 weeks | Selects the 2 models for Phase 4 |
| 4 | E7–E12 + V1 | ~3 weeks | Results chapter |

The one item everything else depends on is Phase 1.1's re-scoring harness. Build
it first; without it every configuration change costs a full re-scan.

**Cut order, if time runs short.** Take these from the bottom up, and stop as
soon as the schedule fits:

1. E11 (localisation) — self-contained, nothing depends on it.
2. E10's encoder baseline — keep the single-flag PEFT ablations, drop the
   encoder.
3. E5 (label granularity) — E4 alone still answers RQ5.
4. Snyk **or** CodeQL rather than both — keep CodeQL, it is stronger on Python
   taint and has no quota.

**Do not cut V1.** The validity checks — three seeds, matched pairs,
length-matched, comment-stripped — are what make the results defensible, and
without a gold set they are now the *only* internal check on the numbers. A
thesis with fewer experiments and honest validity checks defends; a thesis with
more experiments, a single seed and no ground truth does not.
