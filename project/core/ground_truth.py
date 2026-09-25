"""
ground_truth.py
================
Two-tier ground-truth label construction (methodology-plan.md Section 0's
2026-09-24 ground-truth note). This is the project's actual training/eval
label going forward -- **not** fusion_model.py's F0/F1/F2 comparison.

Confirmed explicitly with the user, 2026-09-24: no Dawid-Skene, no majority
vote, no fusion of any kind feeds this label -- not even as a comparison.
The rule is a plain two-tier cascade:

    Tier 1 (primary): tool-stack union, under either of two match rules
    (both kept, neither one deleted -- same "both are legitimate, report
    both" reasoning fusion_model.py already uses for its own strict/relaxed
    split):
      - strict (`match="strict"`, default): VULNERABLE only on an exact
        target-CWE match (STRICT_MATCH) -- no ancestor/descendant/sibling
        credit.
      - hierarchy-aware / relaxed (`match="relaxed"`): VULNERABLE also on
        an ancestor/descendant match (RELAXED_MATCH, methodology-plan.md
        Section 1.3). This is *not* a fusion method and is not the F0
        union sitting in `fusion_labels` (that table mixes relaxed
        matching with the old default `strict=False` call in
        `run_fusion()`) -- it is this same two-tier construction, just
        with the looser match rule, persisted to its own table
        (`ground_truth_labels_relaxed`) so both readings stay queryable
        side by side.
    SECURE if at least one tool actually scanned the sample and none of
    them found a match under the chosen rule.

    Tier 2 (fallback, tool-stack-silent samples only): a single LLM-judge
    method, applied only where *every* tool-stack source is ABSTAIN (never
    scanned, or scanned and produced nothing usable). "guided" is used --
    already the evidenced choice from the fusion work (see
    fusion_model.py's JUDGE_SOURCES_GUIDED comment and changes_summary.md
    2026-09-03 (3): guided recovers more of the long-tail CWEs than blind
    at comparable specificity). This is a stated limitation, not a free
    win -- see methodology-plan.md Section 1.5: a judge characterised only
    on the tool-silent pool is never validated against the easy cases the
    tools already resolve.

Hierarchy-aware / relaxed matching (methodology-plan.md Section 1.3) is
*not* used here -- it stays in scope as a separate, parallel reporting axis
(strict-vs-relaxed detection-rate tables), never blended into this label.

This module only calls fusion_model.build_vote_matrix() (vote extraction)
and fusion_model.union_label() (F0, plain OR across sources) -- never
majority_label() or fit_dawid_skene(). Those two remain unused by design.

Usage:
    python ground_truth.py                            # strict, vulnerable pool, compute + persist + print
    python ground_truth.py --match relaxed             # hierarchy-aware instead
    python ground_truth.py --pool secure --report-only # compute + print, don't persist
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(__file__))
from fusion_model import (  # noqa: E402
    ALL_SOURCES,
    ABSTAIN,
    DEFAULT_DB_PATH,
    JUDGE_SOURCE_SETS,
    SEC,
    VULN,
    build_vote_matrix,
    union_label,
)

FALLBACK_JUDGE_MODE = "guided"

MATCH_TABLE = {"strict": "ground_truth_labels", "relaxed": "ground_truth_labels_relaxed"}


def table_for(match: str) -> str:
    if match not in MATCH_TABLE:
        raise ValueError(f"match must be one of {sorted(MATCH_TABLE)}, got {match!r}")
    return MATCH_TABLE[match]


def ensure_schema(conn: sqlite3.Connection, table_name: str) -> None:
    conn.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            code_id           INTEGER PRIMARY KEY,
            tool_stack_silent INTEGER NOT NULL,
            label             INTEGER NOT NULL,
            label_source      TEXT NOT NULL,
            computed_at       TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    conn.commit()


def build_ground_truth(
    db_path: str | None = None, pool: str = "vulnerable", match: str = "strict",
) -> tuple[list[int], dict[int, int], dict[int, str], dict[int, bool]]:
    """Returns (sample_ids, label, label_source, tool_stack_silent).

    `match` is "strict" (exact CWE only, the default) or "relaxed"
    (hierarchy-aware -- ancestor/descendant also count, methodology-plan.md
    Section 1.3). Both the tool-stack tier and, for consistency, the judge
    fallback tier use the same match rule within one call.

    `label` is VULN/SEC (fusion_model's 1/0 convention -- imported from
    there so both modules stay in sync on the encoding, nothing else).
    `label_source` is "tool_stack" or "judge_fallback" per sample.
    """
    db_path = db_path or DEFAULT_DB_PATH
    if match not in MATCH_TABLE:
        raise ValueError(f"match must be one of {sorted(MATCH_TABLE)}, got {match!r}")
    is_strict = match == "strict"
    sample_ids, tool_votes = build_vote_matrix(db_path, strict=is_strict, judge_mode=None, pool=pool)
    tool_label = union_label(sample_ids, tool_votes)
    tool_stack_silent = {
        sid: all(tool_votes[s][sid] == ABSTAIN for s in ALL_SOURCES) for sid in sample_ids
    }

    silent_ids = [sid for sid in sample_ids if tool_stack_silent[sid]]
    fallback_label: dict[int, int] = {}
    if silent_ids:
        _, judge_votes = build_vote_matrix(
            db_path, strict=is_strict, judge_mode=FALLBACK_JUDGE_MODE, pool=pool,
        )
        judge_sources = JUDGE_SOURCE_SETS[FALLBACK_JUDGE_MODE]
        for sid in silent_ids:
            fallback_label[sid] = (
                VULN if any(judge_votes[j][sid] == VULN for j in judge_sources) else SEC
            )

    label: dict[int, int] = {}
    label_source: dict[int, str] = {}
    for sid in sample_ids:
        if tool_stack_silent[sid]:
            label[sid] = fallback_label.get(sid, SEC)
            label_source[sid] = "judge_fallback"
        else:
            label[sid] = tool_label[sid]
            label_source[sid] = "tool_stack"

    return sample_ids, label, label_source, tool_stack_silent


def persist(
    db_path: str,
    sample_ids: list[int],
    label: dict[int, int],
    label_source: dict[int, str],
    tool_stack_silent: dict[int, bool],
    match: str = "strict",
) -> None:
    table_name = table_for(match)
    conn = sqlite3.connect(db_path)
    ensure_schema(conn, table_name)
    for sid in sample_ids:
        conn.execute(
            f"""
            INSERT INTO {table_name} (code_id, tool_stack_silent, label, label_source)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(code_id) DO UPDATE SET
                tool_stack_silent = excluded.tool_stack_silent,
                label = excluded.label,
                label_source = excluded.label_source,
                computed_at = datetime('now')
            """,
            (sid, int(tool_stack_silent[sid]), label[sid], label_source[sid]),
        )
    conn.commit()
    conn.close()


def print_report(
    sample_ids: list[int],
    label: dict[int, int],
    label_source: dict[int, str],
    tool_stack_silent: dict[int, bool],
    match: str = "strict",
) -> None:
    n = len(sample_ids)
    n_silent = sum(tool_stack_silent.values())
    n_tool_vuln = sum(
        1 for sid in sample_ids if label_source[sid] == "tool_stack" and label[sid] == VULN
    )
    n_tool_sec = sum(
        1 for sid in sample_ids if label_source[sid] == "tool_stack" and label[sid] == SEC
    )
    n_fallback_vuln = sum(
        1 for sid in sample_ids if label_source[sid] == "judge_fallback" and label[sid] == VULN
    )
    n_fallback_sec = sum(
        1 for sid in sample_ids if label_source[sid] == "judge_fallback" and label[sid] == SEC
    )
    print(f"Match rule: {match} (table: {table_for(match)})")
    print(f"Total samples in pool: {n}")
    print(f"  Tool-stack has a verdict: {n - n_silent} ({(n - n_silent) / n:.1%})")
    print(f"    -> VULNERABLE ({match} match): {n_tool_vuln}")
    print(f"    -> SECURE (scanned, no {match} match): {n_tool_sec}")
    print(f"  Tool-stack fully silent (fallback pool): {n_silent} ({n_silent / n:.1%})")
    print(f"    -> VULNERABLE (guided judge, {match}): {n_fallback_vuln}")
    print(f"    -> SECURE (guided judge, {match}): {n_fallback_sec}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", default=DEFAULT_DB_PATH)
    ap.add_argument("--pool", default="vulnerable", choices=["vulnerable", "secure"])
    ap.add_argument("--match", default="strict", choices=list(MATCH_TABLE),
                     help="strict (default, exact CWE only) or relaxed "
                          "(hierarchy-aware -- ancestor/descendant also count). "
                          "Both are persisted to their own table, never blended.")
    ap.add_argument("--report-only", action="store_true")
    args = ap.parse_args()

    sample_ids, label, label_source, tool_stack_silent = build_ground_truth(
        args.db, pool=args.pool, match=args.match,
    )
    if not args.report_only:
        persist(args.db, sample_ids, label, label_source, tool_stack_silent, match=args.match)
    print_report(sample_ids, label, label_source, tool_stack_silent, match=args.match)


if __name__ == "__main__":
    main()
