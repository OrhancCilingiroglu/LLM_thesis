"""
Build a balanced, stratified JSONL dataset from code_cwe.db for LLM fine-tuning.

Selection rules (all configurable):
  * only rows where docker == 'tested-successful'
  * vulnerable rows must be correlation-verified (FULL or PARTIAL MATCH)
    using bandit/semgrep/sonarqube/zap/burpsuite — reuses the same logic as
    db_manipulation.py so we stay consistent with the analyser
  * secure rows must be correlation-NO MATCH (no tool flagged them → clean)
  * per-CWE cap: at most MAX_PER_CLASS per (cwe, secure) bucket
  * per-CWE floor: CWEs with < MIN_PER_CLASS vulnerable samples are dropped
  * code-level dedup via sha1 of stripped source
  * stratified split by (owasp_category, secure_flag) so every split
    preserves both distributions

Outputs:
  - dataset_train.jsonl, dataset_val.jsonl, dataset_test.jsonl
  - dataset_stats.json  (counts per CWE / OWASP / split)
"""
import os, re, json, hashlib, random, argparse
from collections import defaultdict, Counter
from core.db_handler import DBManager
from core.cwe_summary import cwe_to_owasp, parse_sast_cwes, parse_zap_cwes  # reuse

RNG = random.Random(42)
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

    # token mode
    cleaned, n = CWE_LITERAL_RE.subn("", code)
    # collapse the double spaces that result from token removal
    cleaned = re.sub(r"[ \t]{2,}", " ", cleaned)
    return cleaned, n


def row_correlation(db_cwe, sast_row, dast_row, burp_status):
    """Return 'FULL' / 'PARTIAL' / 'NONE' for a single row, consistent with analyser."""
    bandit    = parse_sast_cwes(sast_row[1] if sast_row and len(sast_row) > 1 else "")
    semgrep   = parse_sast_cwes(sast_row[2] if sast_row and len(sast_row) > 2 else "")
    sonarqube = parse_sast_cwes(sast_row[3] if sast_row and len(sast_row) > 3 else "")
    zap       = parse_zap_cwes(dast_row[1]  if dast_row and len(dast_row) > 1 else None)

    in_sast = db_cwe in (bandit | semgrep | sonarqube)
    in_zap  = db_cwe in zap
    in_burp = str(burp_status or "").strip().lower() == "found"
    in_dast = in_zap or in_burp

    if in_sast and in_dast:      return "FULL"
    if in_sast or in_dast:       return "PARTIAL"
    return "NONE"


def collect_rows(db, min_per_cwe, max_per_bucket, scrub_mode="line"):
    ids = db.get_ids_by_docker_status("tested-successful")
    # bucket[(cwe, is_secure)] = [record, ...]
    buckets = defaultdict(list)
    seen_hashes = set()

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
                continue
            # ──────────────────────────────────────────────────────

            # dedup is done AFTER scrubbing so that two rows which only
            # differed by their CWE comment collapse into one
            h = hashlib.sha1(code.encode("utf-8", errors="replace")).hexdigest()
            if h in seen_hashes:
                continue

            db_cwe_raw = db.get_CWE_by_id(cid)
            if not db_cwe_raw:
                continue
            cwe = str(db_cwe_raw).strip().upper()
            if not cwe.startswith("CWE-"):
                cwe = f"CWE-{cwe}"
            owasp = cwe_to_owasp(cwe)

            is_secure = db.is_secure_by_id(cid)
            sast_row  = db.fetch_sast_data_by_id(cid)
            dast_row  = db.fetch_dast_data_by_id(cid)   # (id, zap, burp)
            burp      = dast_row[2] if dast_row and len(dast_row) > 2 else None
            corr      = row_correlation(cwe, sast_row, dast_row, burp)

            # acceptance rules
            if is_secure:
                if corr != "NONE":       # any tool alarm → skip (not clean)
                    continue
            else:
                if corr not in ("FULL", "PARTIAL"):   # verified-vuln only
                    continue

            seen_hashes.add(h)
            buckets[(cwe, bool(is_secure))].append({
                "id": cid, "code": code, "cwe": cwe, "owasp": owasp,
                "is_secure": bool(is_secure), "correlation": corr,
            })
        except Exception as e:
            print(f"[warn] id={cid}: {e}")

    print(f"[scrub] mode={scrub_mode} | rows touched={scrubbed_rows} | "
          f"total tokens/lines removed={total_removals} | "
          f"dropped (empty after scrub)={empty_after_scrub}")

    # enforce floor on vulnerable count per CWE
    kept_cwes = {c for (c, sec), rows in buckets.items()
                 if not sec and len(rows) >= min_per_cwe}
    buckets = {k: v for k, v in buckets.items() if k[0] in kept_cwes}

    # cap per bucket with a fixed seed so the selection is reproducible
    for k in buckets:
        RNG.shuffle(buckets[k])
        buckets[k] = buckets[k][:max_per_bucket]
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


def to_jsonl_record(r):
    target = "NONE" if r["is_secure"] else r["cwe"]
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
        },
    }


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(to_jsonl_record(r), ensure_ascii=False) + "\n")


def stats(rows):
    s = {"total": len(rows),
         "by_cwe":   Counter(r["cwe"]   for r in rows),
         "by_owasp": Counter(r["owasp"] for r in rows),
         "secure":   sum(1 for r in rows if r["is_secure"]),
         "vulnerable": sum(1 for r in rows if not r["is_secure"])}
    s["by_cwe"]   = dict(s["by_cwe"])
    s["by_owasp"] = dict(s["by_owasp"])
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out_dir",        default="dataset_out")
    ap.add_argument("--min_per_cwe",    type=int, default=15,
                    help="Skip CWEs with fewer than this many verified vulnerable samples")
    ap.add_argument("--max_per_bucket", type=int, default=60,
                    help="Cap per (cwe, secure_flag) to keep the set balanced")
    ap.add_argument("--scrub_mode",     default="line", choices=["line", "token"],
                    help="How to remove CWE-xx leaks from code: "
                         "'line' drops the whole line (recommended), "
                         "'token' only removes the CWE-xx token")
    ap.add_argument("--test_frac",      type=float, default=0.2)
    ap.add_argument("--val_frac",       type=float, default=0.1)
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    db = DBManager()
    buckets = collect_rows(db, args.min_per_cwe, args.max_per_bucket,
                           scrub_mode=args.scrub_mode)
    all_rows = [r for rows in buckets.values() for r in rows]
    print(f"[info] collected {len(all_rows)} rows across {len({r['cwe'] for r in all_rows})} CWEs")

    train, val, test = stratified_split(all_rows, args.test_frac, args.val_frac)
    write_jsonl(os.path.join(args.out_dir, "dataset_train.jsonl"), train)
    write_jsonl(os.path.join(args.out_dir, "dataset_val.jsonl"),   val)
    write_jsonl(os.path.join(args.out_dir, "dataset_test.jsonl"),  test)

    report = {"train": stats(train), "val": stats(val), "test": stats(test)}
    with open(os.path.join(args.out_dir, "dataset_stats.json"), "w") as f:
        json.dump(report, f, indent=2)
    print(json.dumps({k: v["total"] for k, v in report.items()}, indent=2))


if __name__ == "__main__":
    main()