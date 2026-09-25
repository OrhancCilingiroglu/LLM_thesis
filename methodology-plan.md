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
| RQ5 | Label format: multi-label bit string (all vulnerabilities) vs. single label (target / most significant) — which is learned better? | **Rejected, 2026-09-06** — user decision: no multi-label work. See note below the table. |
| RQ6 | How do fine-tuned LLMs compare against the SAST/DAST tool stack? | **Dropped, 2026-09-24** — see note below the table. |

**Advisor finalized note, 2026-09-24.** The advisor's finalized scope names
only RQ1–RQ4 — no label-granularity question and no tool-stack comparison.
Confirmed with the user: this is a real scope cut, not an omission. Two
consequences:

- **§0.2's granularity reformulation (G1/G2/G3) is cancelled.** It had
  reoccupied the RQ5 slot after the original label-format question was
  rejected above; that reoccupation is now moot too. E5 is cancelled — see
  §1's matrix.
- **RQ6′ (§0.1, target-CWE recovery as a stand-in for a head-to-head
  comparison) is cancelled.** E12 is cancelled — see §1's matrix. §0.1's
  reasoning about why a gold-set-free comparison would have been circular
  is kept below for the record (and because its target-CWE-recovery
  machinery is repurposed by the ground-truth decision immediately after),
  but it no longer drives an experiment.

**Advisor finalized note, 2026-09-24 — ground truth source.** The first pass
of this note (below the table earlier the same day) framed the all-source
Dawid–Skene fusion as a kept method-comparison artifact (E1) and left
strict-vs-hierarchy matching as an open decision. This was narrowed
further the same day, confirmed explicitly with the user: **no
Dawid–Skene, no majority vote, no weighted fusion of any kind, anywhere in
this project — not even as a method comparison.** E1 is **cancelled
outright** — see §1's matrix and §1.5.

**Hierarchy-aware matching (§1.3) is NOT cancelled — this was
momentarily misread as covered by "partial match falan da
kullanmayacağız" and immediately corrected by the user: "hem strict
raporlama ve db üretimi hem hierarchy devam etmeli" (both strict
reporting/DB production and hierarchy continue).** The "no partial match"
instruction scoped out fusion (above), not hierarchy classification. Both
strict and hierarchy-aware (relaxed) detection continue exactly as §1.3
describes; ground-truth label construction (below) uses strict exact
match, and hierarchy classification runs alongside as its own reported
axis.

What survives, confirmed as the final ground-truth rule:

- **Primary label: tool-stack union, strict match.** VULNERABLE if *any*
  of the 7 SAST/DAST tools (Bandit, Semgrep, SonarQube, CodeQL, Snyk,
  ZAP, Burp) reports the sample's exact target CWE; SECURE if none does
  and at least one tool actually scanned the sample (i.e. the tool stack
  is not simply silent). This is plain OR across tools — no weighting, no
  EM, no vote-counting — and it is already what the codebase calls the F0
  union (`fusion_labels.f0_union`); it just stops being "one fusion method
  among several" and becomes *the* label. Hierarchy-aware matching (§1.3)
  is reported alongside this label as a separate strict-vs-relaxed
  detection-rate breakdown, not folded into the label itself.
- **Fallback: single best LLM-judge method, tool-stack-silent samples
  only.** For samples where every tool abstains (no tool scanned it, or no
  tool could reach a verdict), fall back to one LLM-judge method (blind or
  guided — decided per §2.3/E2's existing characterisation, not both, not
  a vote between them). This part is unchanged from the note above and is
  **not** cancelled — confirmed explicitly ("ek olarak llm as a judge
  var" — "additionally there is llm as a judge"). It stays because the
  tool-stack-silent pool would otherwise just be discarded, which is the
  ~3,700-sample loss §1.0 already flags as the cheapest sample-size gain
  available.
- **E2/Phase 2's role is unchanged by this update**: it still picks which
  single judge method serves the fallback role, using target-CWE recovery
  rate and evidence-check pass rate on the tool-silent pool (Phase 2
  acceptance artifacts already contain the numbers needed: `claude_judge_blind`
  vs `claude_judge_guided`, plus the gpt4 variants). No new scanning or
  judging required — it is a re-read of existing artifacts, restricted to
  a single winner rather than a fusion weight.
- `fusion_model.py`'s Dawid–Skene/majority code is now **dead code for this
  project's remaining scope** — do not extend it, do not call it for
  anything new. Whether to delete it outright or leave it as an unused,
  already-tested module is a housekeeping call, not a methodology one; not
  addressed here.

**Implemented and run, 2026-09-24 — `project/core/ground_truth.py`.** Builds
on `fusion_model.build_vote_matrix()`/`union_label()` (vote extraction and
plain OR only, never `majority_label()`/`fit_dawid_skene()`), persists to a
new `ground_truth_labels` table. First real numbers, current corpus:

| Pool | n | strict VULNERABLE | strict SECURE | tool-stack silent |
| --- | --- | --- | --- | --- |
| vulnerable | 9,202 | 1,139 (12.4%) | 8,063 | 0 (0.0%) |
| secure | 5,537 | 247 (4.5%, contaminated) | 5,290 | 0 (0.0%) |

**The judge-fallback tier is currently empty: every Docker-successful
sample already has at least one tool-stack scan.** The ~3,700-sample gap
§1.0 describes is real (funnel table, "available for training" 6,168 vs.
"actually used" ~2,494) but is **not** a scanning-coverage gap — it must
come from a later stage (`collect_rows()`'s per-CWE floor, dedup, or
bucket cap in `build_dataset.py`). E2/the guided-judge fallback stays
implemented for when it is needed (a newly generated or newly Docker-
successful sample the tool batches haven't reached yet), but right now it
contributes 0 labels and cannot be characterised on an empty pool — the
"pick the best judge method" analysis (§2.3) has nothing to select over
until the silent set is non-empty.

Also notable for E0's write-up: strict-match confirmed rate (12.4%) lands
close to the *original*, pre-fix thesis number (14.3%, computed with the
buggy regex/comma-string CWE extraction) even after CodeQL and Snyk were
added — worth investigating in E0 rather than assuming the tool audit
under-delivered; RELAXED_MATCH's old default number (49.8% on the same
9,202-sample pool, from `fusion_labels.f0_union`) shows most of the
apparent detection lift the tool audit produced was via ancestor/descendant
credit, not exact-match gains. Report both readings side by side, as
§1.3 already requires.

**`build_dataset.py` wired to the new label, 2026-09-24/25 — and the real
cost of strict-only ground truth, measured.** `--corr_filter GROUND_TRUTH`
added (reads `ground_truth_labels`, additive — `FUSION_F0`/`FULL`/`PARTIAL`/
`FULL_OR_PARTIAL` untouched, still reproduce their documented numbers
exactly; verified: `FUSION_F0` still gives 6,945 rows / 122 CWEs, matching
phase1-acceptance-artifacts.md). `GROUND_TRUTH` is now the CLI default.
Also added `--print_stats`, surfacing the per-stage drop funnel that was
already implemented but never wired to the CLI (this answers "why didn't a
run extract everything" directly, going forward, instead of requiring a
fresh investigation each time).

**Head-to-head, default settings (`min_per_cwe=15, max_per_bucket=60`,
single-label), current corpus:**

| corr_filter | accepted pre-floor | CWEs surviving floor | final rows | train/val/test |
| --- | --- | --- | --- | --- |
| FUSION_F0 (relaxed, old) | 9,871 | 122 | 6,945 | 4,862 / 695 / 1,388 |
| GROUND_TRUTH (strict, new) | 6,429 | **30** | **1,557** | 1,090 / 155 / 312 |

**This is not a bug and not the ~3,700-sample gap** (that one was
root-caused and fixed 2026-09-08 — legacy stale-column correlation logic,
already documented in phase1-acceptance-artifacts.md item 3, unrelated to
today's work; `FUSION_F0`'s 9,871-accepted/6,945-final numbers above
confirm that fix still holds). This is the direct, expected cost of
today's strict-only decision: dropping ancestor/descendant credit removes
enough confirmed-vulnerable rows per CWE that **92 of 122 previously
usable CWE classes now fall below the `min_per_cwe=15` floor** and are
excluded entirely, not just thinned. **Flagged for the user, not decided
here**: proceed with 30 CWEs / 1,557 rows as-is, lower `min_per_cwe` to
recover more CWE classes at the cost of noisier per-class estimates, or
revisit. Whichever is chosen, state the CWE-count drop explicitly in the
thesis — it is a direct, visible consequence of choosing strict matching
over relaxed for the training label, not an incidental detail.

**User decision, 2026-09-25: don't pick one — run E3 across every config.**
Resolves the "flagged, not decided" note just above. `ground_truth.py`
extended with `--match strict|relaxed` (§1.3's hierarchy-aware matching was
never dropped — see the correction earlier in this section — so both
readings needed to be selectable, not just strict), persisting to separate
tables (`ground_truth_labels` / `ground_truth_labels_relaxed`) so neither
overwrites the other. `build_dataset.py` gained a second filter,
`GROUND_TRUTH_RELAXED`, reading the relaxed table; both `GROUND_TRUTH*`
filters now also gate **secure** rows consistently with their own match
rule (previously secure-row rejection always used the legacy strict-only
`row_correlation`, regardless of which filter was selected for vulnerable
rows — `_accept_secure()` in `build_dataset.py` fixes this). Also added:
`--print_stats` now works end-to-end from the CLI, and every run
auto-writes `<out_dir>/cwe_bucket_counts.csv` (CWE, OWASP category,
n_secure, n_vulnerable, total) — no more one-off scripts needed to answer
"how many secure vs. vulnerable per CWE did this config produce."

**Five dataset configs generated and persisted to
`project/core/dataset_out/`** (JSONL, gitignored by design like the rest of
this project's dataset outputs — not lost, just not git-tracked; back up
the directory itself if needed). All single-label (`--multi_label False`,
per RQ5's rejection above), `max_per_bucket=60` unless noted:

| Folder | corr_filter | min_per_cwe | CWEs | final rows | train/val/test |
| --- | --- | --- | --- | --- | --- |
| `ground_truth_strict_mpc15` | GROUND_TRUTH | 15 | 30 | 1,557 | 1,090/155/312 |
| `ground_truth_relaxed_mpc15` | GROUND_TRUTH_RELAXED | 15 | 122 | 4,964 | 3,476/496/992 |
| `ground_truth_strict_mpc8` | GROUND_TRUTH | 8 | 43 | 1,962 | 1,374/196/392 |
| `ground_truth_strict_mpc5` | GROUND_TRUTH | 5 | 49 | 2,126 | 1,489/212/425 |
| `fusion_f0_mpc15_reference` | FUSION_F0 (legacy, kept as a baseline reference for E3, not a candidate ground-truth) | 15 | 122 | 6,945 | 4,862/695/1,388 |

JSONL row schema, same across all five: `id, prompt, target, code, meta` —
`prompt` already contains the SAST-tool-style instruction plus the code;
`target` is `NONE` or a comma-separated CWE list (single-label, so one CWE
in practice). This is what a fresh session (e.g. a Colab-side one) needs to
start writing training code without re-deriving anything above.

**Repo status, 2026-09-25:** all of the above code (`ground_truth.py`,
`build_dataset.py`, this file) is committed on `modular`
(`bcdb169`, "Add strict/relaxed two-tier ground truth, wire into
build_dataset.py") and pushed to `origin/modular` by the user. The five
`dataset_out/` folders are local-only (gitignored `.jsonl`s) — pushing code
does not carry them; upload them separately (Drive/Colab) when starting
Phase 3 training.

**Next step, not yet started: E3** — vanilla vs. fine-tuned, all four base
models, run once per dataset config above (5 configs × 4 models × vanilla/
fine-tuned, 3 seeds per V1) to see whether the ground-truth choice itself
changes which two models get selected for Phase 4, not just the headline
numbers.

**RQ5, rejected 2026-09-06.** Dropped entirely at the user's explicit request
("multi label işine girmeyeceğim kesinlikle") — not deferred, not
descoped-but-kept, rejected. This was not an arbitrary call: an actual check
of what a naive multi-label target ("every CWE any source reports for this
sample") would contain found a median of 5-6 distinct CWEs per sample
across just 6 sources, for samples each generated to contain **exactly one**
target weakness — collapsing hierarchy-related duplicates barely changed
this, meaning most of that noise is genuinely unrelated to the target, not
a relabelling of it. This matches the thesis's own §5.3.4 finding (Run 1's
baseline over-predicts 582 distinct CWEs, 529 never correct; the fine-tuned
model converges on generic catch-alls like CWE-605/CWE-497 that were baked
into its multi-label training target). E4 (label format ablation) is
cancelled along with it — see §3.2's note. This also resolves Open Item 3
in §6 ("single vs. multi-label as the primary framing") in favour of
single-label, permanently.

The "New RQ" (specific-vs-generic transfer, §0.2) is **not** affected by
this: its reformulation into G1/G2/G3 label-granularity conditions (E5) is
independent of RQ5 — none of G1/G2/G3 is a multi-label bit-string, all
three are single-target formats at different specificity levels.
~~E5 stays in scope unless separately cut.~~ **E5 was itself cut, 2026-09-24
— the advisor's finalized RQ list is RQ1–RQ4 only. See the note above this
table.** §0.2 below is kept for the record of why the reformulation was
correct engineering, not because it still drives an experiment.

### 0.1 RQ6 without a human gold set — cancelled 2026-09-24, kept for the record

**This section no longer drives an experiment.** The advisor's finalized
scope is RQ1–RQ4; RQ6/RQ6′ and E12 are dropped (see the note above the RQ
table in §0). The reasoning below is kept because the target-CWE-recovery
machinery it describes is exactly what E2 now uses to pick the gap-filling
judge method for ground-truth construction — read it as background for
that, not as a live research question.

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
| E0 | Tool-stack audit + expansion (Snyk, CodeQL, hierarchy matching), strict-match ground truth (tool-stack union + judge fallback on the silent pool) | — (dataset) | 1 | Detection-rate before/after table |
| ~~E1~~ | ~~Parallel judgment + fusion model comparison (union / majority / Dawid-Skene)~~ | — (dataset) | — | **Cancelled 2026-09-24** — no fusion of any kind, anywhere; ground truth is plain tool-stack union, see §0 note |
| E2 | Judge-method selection for tool-silent samples: target-CWE recovery, agreement matrix, evidence-check rate per method | ground-truth construction (§0's 2026-09-24 note) | 2 | Per-method reliability table; picks the gap-filling judge method |
| E3 | Stage-1: all base models, vanilla vs. fine-tuned | RQ1, RQ2 | 3 | Baseline comparison; selects 2 models |
| ~~E4~~ | ~~Label format: single vs. multi-label bit string~~ | ~~RQ5~~ | — | **Cancelled 2026-09-06** — RQ5 rejected, see §0 note |
| ~~E5~~ | ~~Label granularity: G1 / G2 / G3~~ | ~~RQ5~~ | — | **Cancelled 2026-09-24** — advisor finalized scope is RQ1–RQ4 only, see §0 note |
| E6 | Detection-prompt component ablation (incl. guided vs. blind wording, train- and test-time) | RQ4 | 3 | Prompt-component contribution table |
| E7 | Stage-2: epoch count sweep | RQ3 | 4 | Parameter curve |
| E8 | Stage-2: context length sweep (2048 / 4096 / 8192) | RQ3 | 4 | Parameter curve |
| E9 | Stage-2: model size (3B vs 7B, within and across families) | RQ3 | 4 | Parameter curve |
| E10 | Adaptation method: QLoRA vs DoRA vs rank sweep vs encoder classifier | RQ3 | 4 | Parameter/method table |
| ~~E11~~ | ~~Data content: with vs. without problematic line number in the target~~ | ~~RQ3~~ | — | **Cancelled 2026-09-17** — no `line_number` data exists, see §4.5 |
| ~~E12~~ | ~~Fine-tuned models vs. tool stack, scored on target-CWE recovery~~ | ~~RQ6′~~ | — | **Cancelled 2026-09-24** — advisor finalized scope drops RQ6, see §0 note |
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
fine for scoring and for the tool-stack union, which need one vote per source. It is
mildly awkward for what would have been E11 (localisation, per-finding rows) —
moot now that E11 is cancelled outright (§4.5): no `line_number` field exists
to build it from regardless of row shape.

**Scoring moves out of scanning.** This is the one non-negotiable part, and it is
a new module, not a change to existing ones: a function that takes findings plus
a target CWE and returns a detection outcome. The §1.3 hierarchy rule, the strict
and relaxed comparison, and every re-score afterwards live there. Ground-truth
label construction (§0's note) uses the strict result; the relaxed result is
reported separately, not blended into the label.

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

**Confirmed in scope, 2026-09-24 (an earlier pass of this document briefly
cancelled this section reading "partial match falan da kullanmayacağız" as
covering it; the user corrected that immediately after: "hem strict
raporlama ve db üretimi hem hierarchy devam etmeli" — both strict
reporting/DB production and hierarchy continue). What the "no partial
match" instruction actually scoped out was fusion (§1.5/E1), not this.**

Detection currently requires an exact CWE match, while the cross-CWE matrix
(Fig. 5.10) shows tools routinely reporting generic ancestors (CWE-668, 693,
497).

Build the CWE relationship graph from MITRE's catalogue XML
(`Related_Weaknesses`, view CWE-1000) and classify each outcome as `exact`,
`ancestor`, `descendant`, `sibling`, `unrelated` or `none`. Report detection
rate under both strict and relaxed rules; the gap between them is itself a
result about how tools report. **DB production and the ground-truth label
(§0's note) use strict exact match**; hierarchy classification runs
alongside as its own reported axis, not a redefinition of the label.

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
it converts a stated limitation into a result. It also reports line numbers in
its raw SARIF output — not wired into a persisted column, and not used for
anything now that E11 is cancelled (§4.5), but worth knowing it's there if
localisation is ever revisited.

No additional DAST scanners. Coverage is not the bottleneck there.

### 1.5 ~~Architecture change: parallel judgment + fusion (E1)~~ — cancelled 2026-09-24

**This section's recommendation was overridden by the advisor's own design
choice and no longer describes what gets built.** Kept in full below for
the historical record — it explains the science tradeoff the advisor's
choice accepts — but E1 (the fusion-method comparison this section
proposed) is cancelled, see §1's matrix.

Was: the meeting's key methodological question was framed as sequential
cascade vs. parallel-with-a-label-model, and this section argued parallel
was strictly better, because a pure cascade (tools first, LLM decides the
fate of what tools miss) means the LLM panel only ever sees the hard
cases — you never learn how it behaves on the easy ones, so you can never
estimate its reliability or weight it against the tools. The recommended
fix was every source scoring every sample independently (SAST + DAST +
2-3 LLM judges + the down-weighted producer self-check, each a
`VULNERABLE`/`SECURE`/`ABSTAIN` labelling function), fused via F0 (1-of-n
union) / F1 (majority) / F2 (Dawid–Skene) / F3 (meta-classifier),
compared against each other as E1, with F2 expected to win because it
estimates each source's reliability from agreement patterns and produces
a confidence per label.

**What actually got adopted, confirmed 2026-09-24: the cascade, not the
parallel design** — tool-stack union (strict match) as the primary label,
single best-performing LLM-judge method as the fallback for samples the
tool stack is silent on, no fusion of any source votes at all (§0's note).
This is exactly the "cascade variant" this section argued against on
scientific grounds. That objection **still holds as a stated limitation**
and belongs in the thesis in the same words used here: the judge's
reliability is only ever characterised on the tool-silent pool (via E2),
never validated against the easy cases the tools already resolve, so its
estimated recovery rate cannot be assumed to generalise to samples it
never sees in production use of this label. The advisor's instruction
overrides the objection as a design choice, not as a rebuttal of it.

`fusion_model.py`'s F0/F1/F2/F3 implementation (already built and tested)
is not deleted by this decision, just unused for anything new — see §0's
note.

### Phase 1 acceptance artifacts

1. Detection-rate table: strict/old config → strict/new config → hierarchy-aware,
   broken down per tool and per OWASP category, with configuration fixes and
   genuine tool additions reported separately.
2. ~~Fusion comparison (F0–F2) with the dataset-size vs. confidence curve.~~
   **Cancelled 2026-09-24 — E1 dropped, see §1.5.**
3. The updated funnel table, with the usable-sample count against the 8,000–
   12,000 target, and the tool-stack-union / judge-fallback split (§0's note)
   shown explicitly — how many usable samples come from each tier.

---

## Phase 2 — The LLM judges

### 2.1 No gold set: what replaces it

Manual annotation is cut. Two things stand in for it, and neither costs
annotation time:

**The target CWE as a weak reference.** Every judge and every tool can be scored
on how often it recovers the generation-time target CWE. Noisy, independent of
both parties, free. RQ6′ (§0.1) is cancelled, but this same recovery rate is
what E2 uses to pick which judge method fills the tool-silent gap (§0's
2026-09-24 ground-truth note) — it is also enough to sanity-check a judge
that has gone badly wrong.

**~~The label model's own reliability estimates~~ — moot, 2026-09-24: no
label model.** This subsection originally relied on Dawid–Skene inferring
each source's sensitivity/specificity from agreement patterns, as the
reason gold data was skippable. §1.5 is cancelled, so there is no label
model producing those estimates any more. What replaces it: judge
reliability for the fallback role is now **only** the raw target-CWE
recovery rate and evidence-check pass rate per method, measured directly
on the tool-silent pool (E2, §2.3 below) — a simpler, weaker, but
model-free measurement. State plainly in the write-up that this is a raw
rate against a noisy reference, not a reliability estimate in the
Dawid–Skene sense; there is no correlated-error correction of any kind
now, so if the chosen judge method and the tool stack happen to share a
blind spot, nothing here would detect it. The source-agreement matrix
(§2.3) is still worth reporting as a diagnostic, just not as an input to
any weighting.

### 2.2 Judge design

- **Judges must not be the students.** Judges are frontier API models
  (GPT-4.1, Claude, optionally a third); the fine-tuned models are Qwen /
  Mistral / Llama. Same-family judging adds no information.
- **Producer self-check's role is now unclear — flag for the advisor, don't
  guess.** It was previously kept as a down-weighted labelling function inside
  the fusion model (§1.5); with fusion cancelled outright, there is no
  mechanism left for it to feed into. It is not part of the confirmed
  two-tier rule (tool-stack union, then single judge fallback — §0's note).
  Default assumption until told otherwise: it plays no role in ground truth
  construction; confirm this explicitly rather than reviving it informally.
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
- `line_number` stays in the verdict schema (evidence quality still benefits
  from asking for it), but it feeds nothing downstream now — E11 is cancelled
  (§4.5), and `code_cwe` never gained a persisted `line_number` column, so this
  field only ever lived inside each judge's raw JSON blob, never aggregated.
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

~~Add the Dawid–Skene estimated sensitivity/specificity per source alongside
these, clearly labelled as estimates.~~ **Cancelled 2026-09-24 — no
Dawid–Skene, no estimated sensitivity/specificity of any kind.** The three
items above (recovery rate, agreement matrix, evidence-check pass rate) are
what E2 has to select the fallback judge method with; there is no fourth,
model-derived figure.

### Phase 2 acceptance artifacts

Per-method table (target-CWE recovery, evidence-check pass rate) on the
tool-stack-silent pool, the source-agreement matrix, the method picked as
the fallback judge and why, and the recovered-sample count: how many
previously tool-stack-silent samples that method labels with supported
evidence.

---

## Phase 3 — Stage-1 experiments: model selection and data design

Follows the meeting's two-stage structure: broad comparison first, then deep
parameter work on the two best models.

### 3.1 E3 — vanilla vs. fine-tuned across all base models (RQ1, RQ2)

All four existing base models (Qwen2.5-7B, Qwen2.5-3B, Mistral-7B,
Llama-3.2-3B), baseline and fine-tuned, on the Phase-1 dataset with the
**two-tier ground-truth label** (§0's 2026-09-24 note): strict tool-stack
union verdict where the tool stack has one, best-performing judge method
(per E2) where it does not. No Dawid-Skene, no fusion of any kind — E1 is
cancelled outright, not kept as a comparison artifact (§1.5).

**Model selection must not touch the test set.** Pick the top two on the
*validation* split. If the two models carried into Stage 2 were chosen by test
performance, every Stage-2 number is contaminated by selection bias, and this is
exactly the kind of thing a jury catches. Freeze the test set now and do not
look at it.

Three seeds per configuration — see V1.

### 3.2 E4 — label format (RQ5) — **cancelled, 2026-09-06**

Was: single label (target CWE) vs. multi-label bit string (all CWEs raised
for the sample), isolated from Runs 1/2 vs. Runs 3/4's base-model/dataset
confound. Dropped at the user's request before being run — no multi-label
work in this thesis. The confound-affected Run 1/2 vs Run 3/4 numbers
already in the thesis stand as-is (not re-run, not further investigated);
report them with the confound caveat already written into §5.3.1, nothing
more. See §0's rejection note for the supporting data (median 5-6 distinct,
mostly-unrelated CWEs per sample in a naive multi-label target).

### 3.3 ~~E5 — label granularity (RQ5)~~ — cancelled 2026-09-24

Was: conditions G1 (CWE), G2 (OWASP), G3 (hierarchical: category then CWE),
as defined in §0.2, with G3 vs. G1 as the carrying comparison. Dropped
because the advisor's finalized RQ list is RQ1–RQ4 only — no granularity
question. Not re-run, not descoped-but-kept: cancelled the same way E4 and
E11 were.

### 3.4 E6 — detection-prompt ablation (RQ4)

Components to ablate in the prompt that asks the model to detect:

| Component | Levels |
| --- | --- |
| Role framing | "You are a SAST tool" / neutral / absent |
| Candidate CWE list | provided / absent |
| Output format constraint | strict comma-separated / free text |
| Few-shot examples | 0 / 2 / 4 |
| Reasoning | direct answer / brief reasoning before answer |

**Guided vs. blind, crossed at train time and test time (advisor's explicit
ask, 2026-09-24).** "Candidate CWE list: provided/absent" above is the
guided/blind axis, but it must be varied **independently** at fine-tuning
time and at evaluation time, not just once: train-guided/test-guided,
train-guided/test-blind, train-blind/test-guided, train-blind/test-blind.
The two matched cells are the ordinary ablation; the two mismatched cells
are what actually answers "what happens when the wording changes between
training and test" rather than only "does guidance help." This reuses the
existing `claude_judge_blind` / `claude_judge_guided` prompt pair as the
guided/blind wording template rather than inventing a new one.

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
samples mid-code, so 2048 → 4096 has a known direction. Report the
context-length effect broken down by producer model — a global average hides
the only place the effect lives.

**8192's necessity, settled with real token counts (2026-09-17)**, not the
SLOC estimate this section used to cite. Full `cl100k_base` tokenisation of
all 14,739 docker-successful samples' `code` column:

| Producer | n | mean | median | p95 | max |
| --- | --- | --- | --- | --- | --- |
| claude | 4,174 | 4,366 | 4,344 | 6,075 | 6,601 |
| openai | 7,380 | 1,996 | 1,870 | 3,295 | 5,973 |
| groq | 3,185 | 601 | 556 | 1,017 | 2,506 |

Corpus-wide: 48.2% of samples exceed 2048 tokens, **16.8% exceed 4096**
(already a real, active truncation problem — Claude's *mean* alone clears
4096), and **0.0% exceed 8192** (max observed: 6,601, code only). 8192
covers the entire corpus with room for prompt-template overhead; 4096 does
not. This closes the "genuinely open question" framing below — 8192 is not
speculative, it measurably recovers content 4096 is currently discarding,
concentrated in the Claude-produced subpopulation as expected.

**Feasibility, 8192 arm — needs A100, not a T4.** QLoRA 4-bit, 7B model,
seq_len 8192, batch_size 1, gradient checkpointing + flash-attention-2:
~3.5GB base weights + ~0.5GB adapter/optimiser + ~12-18GB activations ≈
16-22GB total in the optimistic case (flash-attn compiled, checkpointing
on) — already above a T4's 16GB with no margin, and considerably worse
without flash-attention-2 (attention memory becomes O(n²)). Confirms this
section's original T4 verdict with an actual budget, not just an assertion.

- **Colab tier**: Free (T4-only) and base Colab Pro (no guaranteed A100
  priority) are both too risky for this arm. Needs **Colab Pro+** (priority
  A100 access, background execution).
- **Compute-hour estimate**: ~4,600 training samples × 8192 tokens × ~3
  epochs ≈ 113M tokens/run; at a rough 2,000-3,000 tok/s QLoRA-7B-on-A100
  throughput, **~10-11 hours per run**. The 8192 arm alone (2 models × 3
  seeds) is ~60-65 A100-hours — likely exceeds a single month's standard
  Pro+ compute-unit allocation.
- **If budget is tight** (see §7's cut order): drop the 8192 arm to 1 seed
  instead of 3, and/or run it only on the smaller of the two selected
  models, and/or restrict it to the Claude-produced subpopulation where the
  effect concentrates — any of these keeps the 2048/4096/8192 directional
  finding intact while cutting the A100-hour bill substantially. Do not cut
  the arm outright: it is the one condition with real, measured content loss
  behind it, unlike a hypothetical parameter sweep.

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

### 4.5 E11 — data content: localisation (RQ3) — **cancelled, 2026-09-17**

Was: "the content in the data i.e., problematic line number" as an RQ3
parameter, composing with Phase 2's evidence requirement (SAST tools report
line numbers, and the judge protocol demands `line_number`, so localisation
labels were assumed to exist on both sides for confirmed samples).

**Dropped at the user's explicit statement: "satır numarası bilgimiz yok"
(we don't have line number data).** Verified: `code_cwe` has **no
`line_number` column at all** — the assumption above was wrong. What exists
is scattered and inconsistent: some of it might be recoverable by parsing
`codeql_raw`'s SARIF per-finding locations or individual judges' stored
`raw_text` JSON, but it was never persisted as a first-class, queryable
field, isn't available across all sources, and building it now is real new
extraction work, not a config flip. Not worth it for one RQ3 sub-experiment.

Was: two training targets, everything else fixed — T1: `CWE-89`, T2:
`CWE-89 @ line 42` (or CWE plus the vulnerable line verbatim), evaluating
CWE accuracy for both plus line-localisation accuracy for T2. Already on
§7's own cut list as the first item to drop if time runs short; this makes
that cut permanent rather than conditional.

### 4.6 ~~E12 — LLM vs. tool stack (RQ6′)~~ — cancelled 2026-09-24

Was: a head-to-head on a held-out set drawn from all Docker-successful
samples (the two selected fine-tuned models, their baselines, the public
API models, and each SAST/DAST tool, all scored on recovery of the
generation-time target CWE), designed specifically to avoid the selection
bias of restricting to the tool-confirmed pool. Dropped because the
advisor's finalized RQ list is RQ1–RQ4 only — no tool-stack comparison
question. Kept here, not deleted, because the reasoning (why the held-out
set must include tool-unconfirmed samples, why every caption must name the
reference as noisy) is the same reasoning behind the E2 gap-filling design
in §0's ground-truth note, just applied there to picking a label instead
of to comparing model families.

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
| **RQ6, in every form (original and RQ6′)** | Original form circular without ground truth; RQ6′ (§0.1) was the gold-set-free fix. Both are moot: **the advisor's finalized scope, 2026-09-24, is RQ1–RQ4 only** — no tool-stack-comparison question at all. E12 cancelled with it. |
| **"Specific vs. generic" as a standalone RQ, and its G1/G2/G3 granularity reformulation (E5)** | The literal form doesn't survive scrutiny (one direction is a table lookup, the other ill-posed); the granularity reformulation (§0.2) fixed that, but is itself now out of scope — **advisor's finalized RQ list, 2026-09-24, is RQ1–RQ4 only.** |
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
opinion. RQ6 is dropped (§5's table above), so this is no longer framed as
answering it, but the value doesn't disappear: even on two CWEs, the tool
stack's true false-negative rate becomes measurable there, and — more
relevant now — **the E2 gap-filling judge-method choice (§0's 2026-09-24
ground-truth note) can finally be validated against something real** rather
than only against agreement-matrix proxies.

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
3. ~~Single vs. multi-label as the *primary* framing~~ — **resolved
   2026-09-06: single-label, permanently.** RQ5/E4 rejected outright (see §0);
   there is no multi-label result to weigh against single-label, so the
   framing decision is no longer pending.
4. **SonarQube Developer-edition licence** — university availability.

---

## 7. Sequencing

| Phase | Contents | Effort | Blocks |
| --- | --- | --- | --- |
| 1 | Adapter refactor, tool audit, Snyk + CodeQL, hierarchy matching, strict tool-stack-union ground truth | ~2 weeks | Everything — changes the dataset |
| 2 | Judge panel, source characterisation, gap-filling judge-method selection (E2) | ~1 week | Ground-truth label construction, Phase 4 test set |
| 3 | E3, E6: model selection, prompt ablation | ~2 weeks | Selects the 2 models for Phase 4 |
| 4 | E7–E10 + V1 | ~3 weeks | Results chapter |

The one item everything else depends on is Phase 1.1's re-scoring harness. Build
it first; without it every configuration change costs a full re-scan.

**Cut order, if time runs short.** Take these from the bottom up, and stop as
soon as the schedule fits. E11 and E4 are no longer entries here — both are
already permanently cancelled (§4.5, §3.2/§0), not conditional on schedule:

1. E10's encoder baseline — keep the single-flag PEFT ablations, drop the
   encoder.
2. E8's 8192-context arm down to 1 seed instead of 3 (see §4.2's feasibility
   note) before cutting it outright — it is the single most compute-expensive
   item left in Phase 4.
3. Snyk **or** CodeQL rather than both — keep CodeQL, it is stronger on Python
   taint and has no quota.

**Do not cut V1.** The validity checks — three seeds, matched pairs,
length-matched, comment-stripped — are what make the results defensible, and
without a gold set they are now the *only* internal check on the numbers. A
thesis with fewer experiments and honest validity checks defends; a thesis with
more experiments, a single seed and no ground truth does not.
