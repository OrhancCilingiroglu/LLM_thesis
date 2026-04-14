"""
complexity_analyzer.py
======================
DB'deki Python kodlarının kompleksitesini hesaplar ve code_cwe.db'ye yazar.

Metrikler:
  - cc_avg        : Cyclomatic Complexity ortalama (fonksiyon başına)
  - cc_max        : En yüksek CC değeri (en karmaşık fonksiyon)
  - cc_grade      : Radon harf notu (A-F)
  - loc           : Satır sayısı (boş/yorum dahil)
  - lloc           : Logical lines of code
  - sloc          : Source lines of code
  - mi            : Maintainability Index (0-100, yüksek=iyi)
  - halstead_vol  : Halstead Volume

Kullanım:
  python complexity_analyzer.py                   # tüm DB
  python complexity_analyzer.py --start 1 --end 500
  python complexity_analyzer.py --id_list 42 99 200
  python complexity_analyzer.py --only_missing     # sadece boş olanları doldur
"""

import argparse
import sqlite3
import os
import sys
import json
from radon.complexity import cc_visit, cc_rank
from radon.metrics import mi_visit, h_visit
from radon.raw import analyze

DB_PATH = os.path.join(os.path.dirname(__file__), "code_cwe.db")

# ── Tablo oluştur / güncelle ──────────────────────────────────────────────────

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

# ── Hesaplama ─────────────────────────────────────────────────────────────────

def compute_metrics(code: str) -> dict:
    """Verilen Python kodu için tüm metrikleri hesapla."""
    result = {}
    try:
        # Cyclomatic Complexity
        blocks = cc_visit(code)
        if blocks:
            complexities = [b.complexity for b in blocks]
            result["cc_avg"]   = round(sum(complexities) / len(complexities), 2)
            result["cc_max"]   = max(complexities)
            result["cc_grade"] = cc_rank(result["cc_max"])
        else:
            result["cc_avg"]   = 1.0
            result["cc_max"]   = 1
            result["cc_grade"] = "A"
    except Exception as e:
        result["cc_avg"]   = None
        result["cc_max"]   = None
        result["cc_grade"] = None

    try:
        # Raw metrics (LOC, LLOC, SLOC)
        raw = analyze(code)
        result["loc"]  = raw.loc
        result["lloc"] = raw.lloc
        result["sloc"] = raw.sloc
    except Exception:
        result["loc"]  = None
        result["lloc"] = None
        result["sloc"] = None

    try:
        # Maintainability Index
        mi = mi_visit(code, multi=True)
        result["mi"] = round(mi, 2)
    except Exception:
        result["mi"] = None

    try:
        # Halstead Volume
        h = h_visit(code)
        if h:
            result["halstead_vol"] = round(h[0].volume, 2)
        else:
            result["halstead_vol"] = None
    except Exception:
        result["halstead_vol"] = None

    result["error"] = None
    return result


# ── DB işlemleri ──────────────────────────────────────────────────────────────

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
        metrics.get("cc_avg"),
        metrics.get("cc_max"),
        metrics.get("cc_grade"),
        metrics.get("loc"),
        metrics.get("lloc"),
        metrics.get("sloc"),
        metrics.get("mi"),
        metrics.get("halstead_vol"),
        metrics.get("error"),
    ))


# ── Ana fonksiyon ─────────────────────────────────────────────────────────────

def run(start=None, end=None, id_list=None, only_missing=False, batch_size=100):
    conn = sqlite3.connect(DB_PATH)
    ensure_table(conn)

    ids = get_ids(conn, start=start, end=end, id_list=id_list, only_missing=only_missing)
    total = len(ids)
    print(f"[INFO] {total} ID işlenecek...")

    ok = err = skip = 0

    for i, code_id in enumerate(ids, 1):
        code = fetch_code(conn, code_id)

        if not code or not code.strip():
            skip += 1
            conn.execute(
                "INSERT OR REPLACE INTO code_complexity (code_id, error) VALUES (?, ?)",
                (code_id, "empty_code")
            )
            if i % batch_size == 0:
                conn.commit()
            continue

        try:
            metrics = compute_metrics(code)
            upsert(conn, code_id, metrics)
            ok += 1
        except Exception as e:
            conn.execute(
                "INSERT OR REPLACE INTO code_complexity (code_id, error) VALUES (?, ?)",
                (code_id, str(e)[:200])
            )
            err += 1

        if i % batch_size == 0:
            conn.commit()
            print(f"  [{i}/{total}] ok={ok} err={err} skip={skip}")

    conn.commit()
    conn.close()

    print(f"\n[DONE] total={total} | ok={ok} | error={err} | skip={skip}")
    print(f"Sonuçlar: code_complexity tablosuna yazıldı → {DB_PATH}")


# ── Özet istatistik ───────────────────────────────────────────────────────────

def _secure_label(raw) -> str:
    """Normalize the secure column value to 'SECURE' or 'VULNERABLE'."""
    if raw is None:
        return "VULNERABLE"
    if isinstance(raw, int):
        return "SECURE" if raw == 1 else "VULNERABLE"
    s = str(raw).strip().upper()
    if s in {"SECURE", "TRUE", "1", "YES"}:
        return "SECURE"
    return "VULNERABLE"


def _print_group_summary(cur, label: str, secure_filter: str):
    """
    Print complexity statistics for a single group (SECURE or VULNERABLE).

    Parameters
    ----------
    cur          : sqlite3 cursor
    label        : display label e.g. "SECURE"
    secure_filter: SQL fragment applied to d.secure, e.g. "IN ('secure','SECURE','1',1,'TRUE')"
    """
    print(f"\n  --- {label} ---")

    cur.execute(f"""
        SELECT
            COUNT(*)                  AS n,
            ROUND(AVG(c.cc_avg), 2)  AS avg_cc,
            ROUND(AVG(c.cc_max), 2)  AS avg_cc_max,
            MAX(c.cc_max)             AS max_cc,
            ROUND(AVG(c.sloc),  1)   AS avg_sloc,
            ROUND(AVG(c.mi),    2)   AS avg_mi,
            ROUND(AVG(c.halstead_vol), 1) AS avg_hvol
        FROM code_complexity c
        JOIN code_cwe d ON c.code_id = d.id
        WHERE c.error IS NULL
          AND {secure_filter}
    """)
    row = cur.fetchone()
    n, avg_cc, avg_cc_max, max_cc, avg_sloc, avg_mi, avg_hvol = row
    print(f"  {'Count':<22}: {n}")
    print(f"  {'Avg CC (mean)':<22}: {avg_cc}")
    print(f"  {'Avg CC Max':<22}: {avg_cc_max}")
    print(f"  {'Hardest CC':<22}: {max_cc}")
    print(f"  {'Avg SLOC':<22}: {avg_sloc}")
    print(f"  {'Avg MI':<22}: {avg_mi}")
    print(f"  {'Avg Halstead Vol':<22}: {avg_hvol}")

    # Grade distribution
    cur.execute(f"""
        SELECT c.cc_grade, COUNT(*) AS cnt
        FROM code_complexity c
        JOIN code_cwe d ON c.code_id = d.id
        WHERE c.cc_grade IS NOT NULL
          AND {secure_filter}
        GROUP BY c.cc_grade
        ORDER BY c.cc_grade
    """)
    grade_rows = cur.fetchall()
    total_graded = sum(r[1] for r in grade_rows)
    print(f"  Grade distribution (cc_max):")
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
        WHERE c.mi IS NOT NULL
          AND {secure_filter}
        GROUP BY bucket
        ORDER BY MIN(c.mi) DESC
    """)
    mi_rows = cur.fetchall()
    mi_total = sum(r[1] for r in mi_rows)
    print(f"  Maintainability Index buckets:")
    for bucket, cnt in mi_rows:
        pct = cnt / mi_total * 100 if mi_total else 0
        print(f"    {bucket}  {cnt:>5}  ({pct:.1f}%)")


def _print_delta(cur):
    """Print the per-metric delta between SECURE and VULNERABLE groups."""
    secure_filter  = "d.secure IN ('secure','SECURE','1',1,'TRUE','true')"
    vuln_filter    = "d.secure NOT IN ('secure','SECURE','1',1,'TRUE','true') OR d.secure IS NULL"

    def fetch_means(filt):
        cur.execute(f"""
            SELECT
                ROUND(AVG(c.cc_avg),  2),
                ROUND(AVG(c.cc_max),  2),
                ROUND(AVG(c.sloc),    1),
                ROUND(AVG(c.mi),      2),
                ROUND(AVG(c.halstead_vol), 1)
            FROM code_complexity c
            JOIN code_cwe d ON c.code_id = d.id
            WHERE c.error IS NULL AND {filt}
        """)
        return cur.fetchone()  # (cc_avg, cc_max, sloc, mi, hvol)

    s = fetch_means(secure_filter)
    v = fetch_means(vuln_filter)

    print("\n  --- Delta (SECURE − VULNERABLE) ---")
    metrics = ["Avg CC", "Avg CC Max", "Avg SLOC", "Avg MI", "Avg Halstead Vol"]
    for name, sv, vv in zip(metrics, s, v):
        if sv is None or vv is None:
            continue
        delta = round(sv - vv, 2)
        direction = "↑" if delta > 0 else ("↓" if delta < 0 else "=")
        print(f"  {name:<22}: {direction}  {delta:+.2f}   (secure={sv}, vuln={vv})")


def print_summary():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # ── Overall ──────────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("COMPLEXITY SUMMARY — OVERALL")
    print("=" * 60)

    cur.execute("""
        SELECT
            COUNT(*) as total,
            ROUND(AVG(cc_avg), 2) as avg_cc,
            ROUND(AVG(cc_max), 2) as avg_cc_max,
            MAX(cc_max) as hardest_cc,
            ROUND(AVG(sloc), 1) as avg_sloc,
            ROUND(AVG(mi), 2) as avg_mi
        FROM code_complexity
        WHERE error IS NULL
    """)
    row = cur.fetchone()
    labels = ["Total rows", "Avg CC", "Avg CC Max", "Hardest CC", "Avg SLOC", "Avg MI"]
    for label, val in zip(labels, row):
        print(f"  {label:<20}: {val}")

    print("\nGrade distribution (cc_max):")
    cur.execute("""
        SELECT cc_grade, COUNT(*) as cnt
        FROM code_complexity
        WHERE cc_grade IS NOT NULL
        GROUP BY cc_grade
        ORDER BY cc_grade
    """)
    for grade, cnt in cur.fetchall():
        bar = "█" * min(cnt // 10 + 1, 40)
        print(f"  {grade}  {bar} {cnt}")

    print("\nTop 10 most complex codes:")
    cur.execute("""
        SELECT c.code_id, c.cc_max, c.cc_grade, c.sloc, c.mi, d.CWE
        FROM code_complexity c
        LEFT JOIN code_cwe d ON c.code_id = d.id
        WHERE c.cc_max IS NOT NULL
        ORDER BY c.cc_max DESC
        LIMIT 10
    """)
    print(f"  {'ID':>6}  {'CC_MAX':>6}  {'Grade':>5}  {'SLOC':>6}  {'MI':>6}  CWE")
    for row in cur.fetchall():
        print(f"  {row[0]:>6}  {row[1]:>6}  {row[2]:>5}  {row[3]:>6}  {str(row[4]):>6}  CWE-{row[5]}")

    # ── Secure vs Vulnerable ─────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("COMPLEXITY SUMMARY — SECURE vs VULNERABLE")
    print("=" * 60)

    secure_filter = "d.secure IN ('secure','SECURE','1',1,'TRUE','true')"
    vuln_filter   = "d.secure NOT IN ('secure','SECURE','1',1,'TRUE','true') OR d.secure IS NULL"

    _print_group_summary(cur, "SECURE",     secure_filter)
    _print_group_summary(cur, "VULNERABLE", vuln_filter)
    _print_delta(cur)

    # ── Producer breakdown ───────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("COMPLEXITY SUMMARY — BY PRODUCER")
    print("=" * 60)
    cur.execute("""
        SELECT
            d.producer,
            d.secure,
            COUNT(*)                  AS n,
            ROUND(AVG(c.cc_avg), 2)  AS avg_cc,
            ROUND(AVG(c.cc_max), 2)  AS avg_cc_max,
            ROUND(AVG(c.sloc),  1)   AS avg_sloc,
            ROUND(AVG(c.mi),    2)   AS avg_mi
        FROM code_complexity c
        JOIN code_cwe d ON c.code_id = d.id
        WHERE c.error IS NULL
        GROUP BY d.producer, d.secure
        ORDER BY d.producer, d.secure
    """)
    print(f"  {'Producer':<10}  {'Secure':<10}  {'N':>5}  {'CC Avg':>7}  {'CC Max':>7}  {'SLOC':>7}  {'MI':>7}")
    print(f"  {'-'*10}  {'-'*10}  {'-'*5}  {'-'*7}  {'-'*7}  {'-'*7}  {'-'*7}")
    for row in cur.fetchall():
        producer, secure_raw, n, avg_cc, avg_cc_max, avg_sloc, avg_mi = row
        label = _secure_label(secure_raw)
        print(f"  {str(producer):<10}  {label:<10}  {n:>5}  {str(avg_cc):>7}  {str(avg_cc_max):>7}  {str(avg_sloc):>7}  {str(avg_mi):>7}")

    conn.close()


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DB'deki Python kodlarının kompleksitesini hesapla")
    parser.add_argument("--start",        type=int,   default=None)
    parser.add_argument("--end",          type=int,   default=None)
    parser.add_argument("--id_list",      type=int,   nargs="+", default=None)
    parser.add_argument("--only_missing", action="store_true",
                        help="Sadece henüz hesaplanmamış ID'leri işle")
    parser.add_argument("--summary_only", action="store_true",
                        help="Hesaplama yapma, sadece özet göster")
    parser.add_argument("--batch_size",   type=int,   default=100)
    args = parser.parse_args()

    if args.summary_only:
        print_summary()
    else:
        run(
            start=args.start,
            end=args.end,
            id_list=args.id_list,
            only_missing=args.only_missing,
            batch_size=args.batch_size,
        )
        print_summary()