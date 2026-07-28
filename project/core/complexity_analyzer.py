"""
Computes complexity metrics for Python code stored in code_cwe.db
and writes results to the code_complexity table.
Metrics: cc_avg, cc_max, cc_grade, loc, lloc, sloc, mi, halstead_vol
Usage:
  python complexity_analyzer.py                  # all rows
  python complexity_analyzer.py --start 1 --end 500
  python complexity_analyzer.py --id_list 42 99 200
  python complexity_analyzer.py --only_missing   # skip already computed
  python complexity_analyzer.py --summary_only   # print stats, no computation
"""
import argparse
import sqlite3
import os
from radon.complexity import cc_visit, cc_rank
from radon.metrics import mi_visit, h_visit
from radon.raw import analyze

DB_PATH = os.path.join(os.path.dirname(__file__), "code_cwe.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS code_complexity (
    code_id        INTEGER PRIMARY KEY,
    cc_avg         REAL,
    cc_max         INTEGER,
    cc_grade       TEXT,
    loc            INTEGER,
    lloc           INTEGER,
    sloc           INTEGER,
    mi             REAL,
    halstead_vol   REAL,
    error          TEXT
);
"""

# Canonical set of values that represent the "secure" class
_SECURE_VALUES = ("secure", "SECURE", "1", "TRUE", "true", "YES", "yes")

# SQL fragment used to identify secure rows
_SECURE_SQL = f"d.secure IN {_SECURE_VALUES}"
_VULN_SQL   = f"(d.secure NOT IN {_SECURE_VALUES} OR d.secure IS NULL)"


def compute_metrics(code: str) -> dict:
    """Compute all radon metrics for a single code snippet."""
    result = {}

    try:
        blocks = cc_visit(code)
        if blocks:
            complexities = [b.complexity for b in blocks]
            result["cc_avg"]   = round(sum(complexities) / len(complexities), 2)
            result["cc_max"]   = max(complexities)
            result["cc_grade"] = cc_rank(result["cc_max"])
        else:
            result["cc_avg"], result["cc_max"], result["cc_grade"] = 1.0, 1, "A"
    except Exception:
        result["cc_avg"] = result["cc_max"] = result["cc_grade"] = None

    try:
        raw = analyze(code)
        result["loc"], result["lloc"], result["sloc"] = raw.loc, raw.lloc, raw.sloc
    except Exception:
        result["loc"] = result["lloc"] = result["sloc"] = None

    try:
        result["mi"] = round(mi_visit(code, multi=True), 2)
    except Exception:
        result["mi"] = None

    try:
        h = h_visit(code)
        result["halstead_vol"] = round(h[0].volume, 2) if h else None
    except Exception:
        result["halstead_vol"] = None

    result["error"] = None
    return result


def ensure_table(conn):
    conn.execute(SCHEMA)
    conn.commit()


def get_ids(conn, start=None, end=None, id_list=None, only_missing=False):
    cur = conn.cursor()
    if id_list:
        placeholders = ",".join("?" * len(id_list))
        cur.execute(f"SELECT id FROM code_cwe WHERE id IN ({placeholders})", id_list)
    elif start is not None and end is not None:
        cur.execute("SELECT id FROM code_cwe WHERE id BETWEEN ? AND ?", (start, end))
    else:
        cur.execute("SELECT id FROM code_cwe")
    ids = [r[0] for r in cur.fetchall()]

    if only_missing:
        cur.execute("SELECT code_id FROM code_complexity")
        already = {r[0] for r in cur.fetchall()}
        ids = [i for i in ids if i not in already]

    return ids


def fetch_code(conn, code_id):
    cur = conn.cursor()
    cur.execute("SELECT code FROM code_cwe WHERE id = ?", (code_id,))
    row = cur.fetchone()
    return row[0] if row else None


def upsert(conn, code_id, metrics):
    conn.execute("""
        INSERT OR REPLACE INTO code_complexity
            (code_id, cc_avg, cc_max, cc_grade, loc, lloc, sloc, mi, halstead_vol, error)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        code_id,
        metrics.get("cc_avg"), metrics.get("cc_max"), metrics.get("cc_grade"),
        metrics.get("loc"),    metrics.get("lloc"),    metrics.get("sloc"),
        metrics.get("mi"),     metrics.get("halstead_vol"), metrics.get("error"),
    ))


def run(start=None, end=None, id_list=None, only_missing=False, batch_size=100):
    conn = sqlite3.connect(DB_PATH)
    ensure_table(conn)

    ids   = get_ids(conn, start=start, end=end, id_list=id_list, only_missing=only_missing)
    total = len(ids)
    print(f"[INFO] Processing {total} records...")

    ok = err = skip = 0

    for i, code_id in enumerate(ids, 1):
        code = fetch_code(conn, code_id)

        if not code or not code.strip():
            skip += 1
            conn.execute(
                "INSERT OR REPLACE INTO code_complexity (code_id, error) VALUES (?, ?)",
                (code_id, "empty_code"),
            )
        else:
            try:
                upsert(conn, code_id, compute_metrics(code))
                ok += 1
            except Exception as e:
                conn.execute(
                    "INSERT OR REPLACE INTO code_complexity (code_id, error) VALUES (?, ?)",
                    (code_id, str(e)[:200]),
                )
                err += 1

        if i % batch_size == 0:
            conn.commit()
            print(f"  [{i}/{total}] ok={ok} err={err} skip={skip}")

    conn.commit()
    conn.close()
    print(f"\n[DONE] total={total} | ok={ok} | error={err} | skip={skip}")


# ── Summary helpers ───────────────────────────────────────────────────────────

def _print_group_summary(cur, label: str, secure_filter: str):
    """Print aggregate metrics for one security class (SECURE or VULNERABLE)."""
    print(f"\n  --- {label} ---")

    cur.execute(f"""
        SELECT
            COUNT(*)                       AS n,
            ROUND(AVG(c.cc_avg), 2)        AS avg_cc,
            ROUND(AVG(c.cc_max), 2)        AS avg_cc_max,
            MAX(c.cc_max)                  AS max_cc,
            ROUND(AVG(c.sloc), 1)          AS avg_sloc,
            ROUND(AVG(c.mi), 2)            AS avg_mi,
            ROUND(AVG(c.halstead_vol), 1)  AS avg_hvol
        FROM code_complexity c
        JOIN code_cwe d ON c.code_id = d.id
        WHERE c.error IS NULL AND {secure_filter}
    """)
    n, avg_cc, avg_cc_max, max_cc, avg_sloc, avg_mi, avg_hvol = cur.fetchone()
    for lbl, val in [
        ("Count", n), ("Avg CC", avg_cc), ("Avg CC Max", avg_cc_max),
        ("Hardest CC", max_cc), ("Avg SLOC", avg_sloc),
        ("Avg MI", avg_mi), ("Avg Halstead Vol", avg_hvol),
    ]:
        print(f"  {lbl:<22}: {val}")

    # CC grade distribution
    cur.execute(f"""
        SELECT c.cc_grade, COUNT(*) AS cnt
        FROM code_complexity c
        JOIN code_cwe d ON c.code_id = d.id
        WHERE c.cc_grade IS NOT NULL AND {secure_filter}
        GROUP BY c.cc_grade ORDER BY c.cc_grade
    """)
    grade_rows   = cur.fetchall()
    total_graded = sum(r[1] for r in grade_rows)
    print("  Grade distribution (cc_max):")
    for grade, cnt in grade_rows:
        pct = cnt / total_graded * 100 if total_graded else 0
        bar = "█" * min(cnt // max(total_graded // 40, 1) + 1, 40)
        print(f"    {grade}  {bar:<42} {cnt:>5}  ({pct:.1f}%)")

    # MI buckets
    cur.execute(f"""
        SELECT
            CASE
                WHEN c.mi >= 85 THEN 'High   (>=85)'
                WHEN c.mi >= 65 THEN 'Medium (65-84)'
                WHEN c.mi >= 25 THEN 'Low    (25-64)'
                ELSE                 'V.Low  (<25)'
            END AS bucket,
            COUNT(*) AS cnt
        FROM code_complexity c
        JOIN code_cwe d ON c.code_id = d.id
        WHERE c.mi IS NOT NULL AND {secure_filter}
        GROUP BY bucket ORDER BY MIN(c.mi) DESC
    """)
    mi_rows  = cur.fetchall()
    mi_total = sum(r[1] for r in mi_rows)
    print("  Maintainability Index buckets:")
    for bucket, cnt in mi_rows:
        pct = cnt / mi_total * 100 if mi_total else 0
        print(f"    {bucket}  {cnt:>5}  ({pct:.1f}%)")


def _print_delta(cur):
    """Print per-metric delta: SECURE minus VULNERABLE."""
    def fetch_means(filt):
        cur.execute(f"""
            SELECT
                ROUND(AVG(c.cc_avg), 2),
                ROUND(AVG(c.cc_max), 2),
                ROUND(AVG(c.sloc),   1),
                ROUND(AVG(c.mi),     2),
                ROUND(AVG(c.halstead_vol), 1)
            FROM code_complexity c
            JOIN code_cwe d ON c.code_id = d.id
            WHERE c.error IS NULL AND {filt}
        """)
        return cur.fetchone()

    s = fetch_means(_SECURE_SQL)
    v = fetch_means(_VULN_SQL)

    print("\n  --- Delta (SECURE − VULNERABLE) ---")
    for name, sv, vv in zip(
        ["Avg CC", "Avg CC Max", "Avg SLOC", "Avg MI", "Avg Halstead Vol"], s, v
    ):
        if sv is None or vv is None:
            continue
        delta = round(sv - vv, 2)
        direction = "↑" if delta > 0 else ("↓" if delta < 0 else "=")
        print(f"  {name:<22}: {direction}  {delta:+.2f}   (secure={sv}, vuln={vv})")


def print_summary():
    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()

    # Overall stats
    print("\n" + "=" * 60)
    print("COMPLEXITY SUMMARY — OVERALL")
    print("=" * 60)

    cur.execute("""
        SELECT COUNT(*), ROUND(AVG(cc_avg),2), ROUND(AVG(cc_max),2),
               MAX(cc_max), ROUND(AVG(sloc),1), ROUND(AVG(mi),2)
        FROM code_complexity WHERE error IS NULL
    """)
    for lbl, val in zip(
        ["Total rows", "Avg CC", "Avg CC Max", "Hardest CC", "Avg SLOC", "Avg MI"],
        cur.fetchone()
    ):
        print(f"  {lbl:<20}: {val}")

    print("\nGrade distribution (cc_max):")
    cur.execute("""
        SELECT cc_grade, COUNT(*) FROM code_complexity
        WHERE cc_grade IS NOT NULL GROUP BY cc_grade ORDER BY cc_grade
    """)
    for grade, cnt in cur.fetchall():
        print(f"  {grade}  {'█' * min(cnt // 10 + 1, 40)} {cnt}")

    print("\nTop 10 most complex codes:")
    cur.execute("""
        SELECT c.code_id, c.cc_max, c.cc_grade, c.sloc, c.mi, d.CWE
        FROM code_complexity c
        LEFT JOIN code_cwe d ON c.code_id = d.id
        WHERE c.cc_max IS NOT NULL ORDER BY c.cc_max DESC LIMIT 10
    """)
    print(f"  {'ID':>6}  {'CC_MAX':>6}  {'Grade':>5}  {'SLOC':>6}  {'MI':>6}  CWE")
    for row in cur.fetchall():
        print(f"  {row[0]:>6}  {row[1]:>6}  {row[2]:>5}  {row[3]:>6}  {str(row[4]):>6}  CWE-{row[5]}")

    # Secure vs Vulnerable
    print("\n" + "=" * 60)
    print("COMPLEXITY SUMMARY — SECURE vs VULNERABLE")
    print("=" * 60)
    _print_group_summary(cur, "SECURE",     _SECURE_SQL)
    _print_group_summary(cur, "VULNERABLE", _VULN_SQL)
    _print_delta(cur)

    # Per-producer breakdown
    # GROUP BY uses a normalized CASE WHEN label instead of the raw `secure` column
    # to avoid duplicate rows caused by heterogeneous values ('SECURE', '1', 1, etc.)
    print("\n" + "=" * 60)
    print("COMPLEXITY SUMMARY — BY PRODUCER")
    print("=" * 60)
    cur.execute("""
        SELECT
            d.producer,
            CASE
                WHEN d.secure IN ('secure','SECURE','1',1,'TRUE','true','YES','yes')
                THEN 'SECURE' ELSE 'VULNERABLE'
            END                       AS sec_label,
            COUNT(*)                  AS n,
            ROUND(AVG(c.cc_avg), 2)  AS avg_cc,
            ROUND(AVG(c.cc_max), 2)  AS avg_cc_max,
            ROUND(AVG(c.sloc),  1)   AS avg_sloc,
            ROUND(AVG(c.mi),    2)   AS avg_mi
        FROM code_complexity c
        JOIN code_cwe d ON c.code_id = d.id
        WHERE c.error IS NULL
        GROUP BY d.producer, sec_label
        ORDER BY d.producer, sec_label
    """)
    print(f"  {'Producer':<10}  {'Secure':<10}  {'N':>5}  {'CC Avg':>7}  {'CC Max':>7}  {'SLOC':>7}  {'MI':>7}")
    print(f"  {'-'*10}  {'-'*10}  {'-'*5}  {'-'*7}  {'-'*7}  {'-'*7}  {'-'*7}")
    for producer, label, n, avg_cc, avg_cc_max, avg_sloc, avg_mi in cur.fetchall():
        print(f"  {str(producer):<10}  {label:<10}  {n:>5}  {str(avg_cc):>7}  {str(avg_cc_max):>7}  {str(avg_sloc):>7}  {str(avg_mi):>7}")

    conn.close()


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compute complexity metrics for code_cwe.db")
    parser.add_argument("--start",        type=int, default=None)
    parser.add_argument("--end",          type=int, default=None)
    parser.add_argument("--id_list",      type=int, nargs="+", default=None)
    parser.add_argument("--only_missing", action="store_true", help="Skip already computed rows")
    parser.add_argument("--summary_only", action="store_true", help="Print stats without computing")
    parser.add_argument("--batch_size",   type=int, default=100)
    args = parser.parse_args()

    if args.summary_only:
        print_summary()
    else:
        run(
            start=args.start, end=args.end,
            id_list=args.id_list, only_missing=args.only_missing,
            batch_size=args.batch_size,
        )
        print_summary()