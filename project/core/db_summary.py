import argparse
import csv
import os
import sqlite3
from collections import defaultdict

from core.db_handler import DBManager
from utils import OWASP

DOCKER_SUCCESS_STATUS = "tested-successful"

DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "code_cwe.db")
DEFAULT_OUT_DIR = os.path.join(os.path.dirname(__file__), "thesis_stats")

UNMAPPED_CATEGORY = "UNMAPPED"

SECURE_TRUE = {"SECURE", "TRUE", "1", "YES", "Y"}
SECURE_FALSE = {"VULNERABLE", "INSECURE", "FALSE", "0", "NO", "N"}


def build_owasp_map() -> dict:
    return {
        "A01_2025_Broken_Access_Control":                  set(OWASP.A01_2025_Broken_Access_Control_list),
        "A02_2025_Security_Misconfiguration":              set(OWASP.A02_2025_Security_Misconfiguration_list),
        "A03_2025_Sofware_Supply_Chain":                   set(OWASP.A03_2025_Sofware_Supply_Chain_list),
        "A04_2025_Cryptographic_Failures":                 set(OWASP.A04_2025_Cryptographic_Failures_list),
        "A05_2025_Injection":                              set(OWASP.A05_2025_Injection_list),
        "A06_2025_Insecure_Design":                        set(OWASP.A06_2025_Insecure_Design_list),
        "A07_2025_Authentication_Failures":                set(OWASP.A07_2025_Authentication_Failures_list),
        "A08_2025_Software_or_Data_Integrity_Failures":    set(OWASP.A08_2025_Software_or_Data_Integrity_Failures_list),
        "A09_2025_Security_Logging_and_Alerting_Failures": set(OWASP.A09_2025_Security_Logging_and_Alerting_Failures_list),
        "A10_2025_Mishandling_of_Exceptional_Conditions":  set(OWASP.A10_2025_Mishandling_of_Exceptional_Conditions_list),
    }


def normalize_cwe(raw) -> str | None:
    if raw is None:
        return None
    s = str(raw).strip().upper()
    if not s or s in {"NONE", "NULL", "NAN", "N/A", "-"}:
        return None
    if not s.startswith("CWE-"):
        s = f"CWE-{s}"
    return s


def cwe_number(cwe_str: str) -> int | None:
    try:
        return int(cwe_str.replace("CWE-", "").strip())
    except (ValueError, AttributeError):
        return None


def cwe_to_owasp(cwe_str: str, owasp_map: dict) -> str:
    num = cwe_number(cwe_str)
    if num is None:
        return UNMAPPED_CATEGORY
    for category, numbers in owasp_map.items():
        if num in numbers:
            return category
    return UNMAPPED_CATEGORY


def normalize_secure(raw) -> bool:
    if raw is None:
        return False
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, int):
        return raw == 1
    s = str(raw).strip().upper()
    if s in SECURE_TRUE:
        return True
    if s in SECURE_FALSE:
        return False
    return False


def normalize_producer(raw) -> str:
    if raw is None:
        return "UNKNOWN"
    s = str(raw).strip().lower()
    return s if s else "UNKNOWN"


def fetch_all_rows(db_path: str) -> list[tuple]:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT id, CWE, secure, docker, producer FROM code_cwe")
    rows = cur.fetchall()
    conn.close()
    return rows


def aggregate(rows: list[tuple], owasp_map: dict) -> dict:
    total_samples = 0
    unmapped_skipped = 0

    cwe_total = defaultdict(int)
    cwe_docker_ok = defaultdict(int)
    cwe_secure = defaultdict(int)
    cwe_vulnerable = defaultdict(int)

    owasp_total = defaultdict(int)
    owasp_docker_ok = defaultdict(int)
    owasp_secure = defaultdict(int)
    owasp_vulnerable = defaultdict(int)

    producer_total = defaultdict(int)
    producer_docker_ok = defaultdict(int)

    overall_docker_ok = 0
    secure_total = 0
    secure_docker_ok = 0
    vulnerable_total = 0
    vulnerable_docker_ok = 0

    for _id, raw_cwe, raw_secure, raw_docker, raw_producer in rows:
        cwe = normalize_cwe(raw_cwe)
        if cwe is None:
            continue

        owasp_cat = cwe_to_owasp(cwe, owasp_map)
        if owasp_cat == UNMAPPED_CATEGORY:
            unmapped_skipped += 1
            continue

        is_secure = normalize_secure(raw_secure)
        is_docker_ok = (str(raw_docker).strip() == DOCKER_SUCCESS_STATUS)
        producer = normalize_producer(raw_producer)

        total_samples += 1
        cwe_total[cwe] += 1
        owasp_total[owasp_cat] += 1
        producer_total[producer] += 1

        if is_docker_ok:
            overall_docker_ok += 1
            cwe_docker_ok[cwe] += 1
            owasp_docker_ok[owasp_cat] += 1
            producer_docker_ok[producer] += 1

        if is_secure:
            secure_total += 1
            cwe_secure[cwe] += 1
            owasp_secure[owasp_cat] += 1
            if is_docker_ok:
                secure_docker_ok += 1
        else:
            vulnerable_total += 1
            cwe_vulnerable[cwe] += 1
            owasp_vulnerable[owasp_cat] += 1
            if is_docker_ok:
                vulnerable_docker_ok += 1

    return {
        "total_samples": total_samples,
        "unmapped_skipped": unmapped_skipped,
        "overall_docker_ok": overall_docker_ok,
        "secure_total": secure_total,
        "secure_docker_ok": secure_docker_ok,
        "vulnerable_total": vulnerable_total,
        "vulnerable_docker_ok": vulnerable_docker_ok,
        "cwe_total": cwe_total,
        "cwe_docker_ok": cwe_docker_ok,
        "cwe_secure": cwe_secure,
        "cwe_vulnerable": cwe_vulnerable,
        "owasp_total": owasp_total,
        "owasp_docker_ok": owasp_docker_ok,
        "owasp_secure": owasp_secure,
        "owasp_vulnerable": owasp_vulnerable,
        "producer_total": producer_total,
        "producer_docker_ok": producer_docker_ok,
    }


def pct(part: int, whole: int) -> float:
    return round((part / whole) * 100, 2) if whole else 0.0


def table_cwe_distribution(agg: dict) -> list[dict]:
    total = agg["total_samples"]
    rows = [
        {"cwe": cwe, "count": n, "percentage": pct(n, total)}
        for cwe, n in agg["cwe_total"].items()
    ]
    rows.sort(key=lambda r: r["count"], reverse=True)
    return rows


def table_owasp_distribution(agg: dict) -> list[dict]:
    total = agg["total_samples"]
    rows = [
        {"owasp_category": cat, "count": n, "percentage": pct(n, total)}
        for cat, n in agg["owasp_total"].items()
        if cat != UNMAPPED_CATEGORY
    ]
    rows.sort(key=lambda r: r["count"], reverse=True)
    return rows


def table_docker_success_per_cwe(agg: dict) -> list[dict]:
    rows = []
    for cwe, total in agg["cwe_total"].items():
        ok = agg["cwe_docker_ok"].get(cwe, 0)
        rows.append({
            "cwe": cwe,
            "total_samples": total,
            "docker_ok": ok,
            "docker_success_rate_pct": pct(ok, total),
        })
    rows.sort(key=lambda r: r["docker_success_rate_pct"], reverse=True)
    return rows


def table_docker_success_per_owasp(agg: dict) -> list[dict]:
    rows = []
    for cat, total in agg["owasp_total"].items():
        if cat == UNMAPPED_CATEGORY:
            continue
        ok = agg["owasp_docker_ok"].get(cat, 0)
        rows.append({
            "owasp_category": cat,
            "total_samples": total,
            "docker_ok": ok,
            "docker_success_rate_pct": pct(ok, total),
        })
    rows.sort(key=lambda r: r["docker_success_rate_pct"], reverse=True)
    return rows


def table_secure_vulnerable_per_cwe(agg: dict) -> list[dict]:
    rows = []
    for cwe, total in agg["cwe_total"].items():
        secure_n = agg["cwe_secure"].get(cwe, 0)
        vuln_n = agg["cwe_vulnerable"].get(cwe, 0)
        rows.append({
            "cwe": cwe,
            "total_samples": total,
            "secure_count": secure_n,
            "vulnerable_count": vuln_n,
            "secure_pct": pct(secure_n, total),
            "vulnerable_pct": pct(vuln_n, total),
        })
    rows.sort(key=lambda r: r["total_samples"], reverse=True)
    return rows


def table_secure_vulnerable_per_owasp(agg: dict) -> list[dict]:
    rows = []
    for cat, total in agg["owasp_total"].items():
        if cat == UNMAPPED_CATEGORY:
            continue
        secure_n = agg["owasp_secure"].get(cat, 0)
        vuln_n = agg["owasp_vulnerable"].get(cat, 0)
        rows.append({
            "owasp_category": cat,
            "total_samples": total,
            "secure_count": secure_n,
            "vulnerable_count": vuln_n,
            "secure_pct": pct(secure_n, total),
            "vulnerable_pct": pct(vuln_n, total),
        })
    rows.sort(key=lambda r: r["total_samples"], reverse=True)
    return rows


def table_docker_success_per_producer(agg: dict) -> list[dict]:
    overall_docker_ok = agg["overall_docker_ok"]
    rows = []
    for producer, total in agg["producer_total"].items():
        ok = agg["producer_docker_ok"].get(producer, 0)
        rows.append({
            "producer": producer,
            "total_samples": total,
            "docker_ok": ok,
            "docker_success_rate_pct": pct(ok, total),
            "share_of_all_docker_ok_pct": pct(ok, overall_docker_ok),
        })
    rows.sort(key=lambda r: r["docker_success_rate_pct"], reverse=True)
    return rows


def write_csv(path: str, rows: list[dict]) -> None:
    if not rows:
        return
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_summary_md(path: str, agg: dict) -> None:
    overall_rate = pct(agg["overall_docker_ok"], agg["total_samples"])
    secure_rate = pct(agg["secure_docker_ok"], agg["secure_total"])
    vulnerable_rate = pct(agg["vulnerable_docker_ok"], agg["vulnerable_total"])

    lines = [
        "# Code Pipeline Efficiency - Genel Özet\n",
        f"- Toplam örnek sayısı (OWASP Top 10 2025 kapsamında, CWE atanmış): **{agg['total_samples']}**",
        f"- OWASP Top 10 (2025) kapsamı dışında kaldığı için analiz dışı bırakılan örnek sayısı: "
        f"**{agg['unmapped_skipped']}**",
        f"- Genel Docker çalıştırılabilirlik oranı: **{agg['overall_docker_ok']} / {agg['total_samples']} (%{overall_rate})**",
        f"- Secure (güvenli) kod örnekleri: **{agg['secure_total']}**, "
        f"Docker başarı oranı: **{agg['secure_docker_ok']} / {agg['secure_total']} (%{secure_rate})**",
        f"- Vulnerable (güvensiz) kod örnekleri: **{agg['vulnerable_total']}**, "
        f"Docker başarı oranı: **{agg['vulnerable_docker_ok']} / {agg['vulnerable_total']} (%{vulnerable_rate})**",
        "",
        "Detaylı tablolar için aynı klasördeki CSV dosyalarına bakınız:",
        "cwe_distribution.csv, owasp_distribution.csv, docker_success_per_cwe.csv, "
        "docker_success_per_owasp.csv, secure_vulnerable_per_cwe.csv, secure_vulnerable_per_owasp.csv, "
        "docker_success_per_producer.csv",
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def print_console_summary(agg: dict) -> None:
    overall_rate = pct(agg["overall_docker_ok"], agg["total_samples"])
    secure_rate = pct(agg["secure_docker_ok"], agg["secure_total"])
    vulnerable_rate = pct(agg["vulnerable_docker_ok"], agg["vulnerable_total"])

    print("=" * 60)
    print("CODE PIPELINE EFFICIENCY - SUMMARY")
    print("=" * 60)
    print(f"Total samples (OWASP-mapped)  : {agg['total_samples']}")
    print(f"Excluded (UNMAPPED CWE)       : {agg['unmapped_skipped']}")
    print(f"Overall docker success rate  : {agg['overall_docker_ok']} / {agg['total_samples']} ({overall_rate}%)")
    print(f"Secure samples                : {agg['secure_total']}")
    print(f"  -> docker success rate      : {agg['secure_docker_ok']} / {agg['secure_total']} ({secure_rate}%)")
    print(f"Vulnerable samples            : {agg['vulnerable_total']}")
    print(f"  -> docker success rate      : {agg['vulnerable_docker_ok']} / {agg['vulnerable_total']} ({vulnerable_rate}%)")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Generate thesis-ready code pipeline efficiency statistics.")
    parser.add_argument("--db", default=DEFAULT_DB_PATH, help="Path to code_cwe.db")
    parser.add_argument("--out", default=DEFAULT_OUT_DIR, help="Output directory for CSV/summary files")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)

    rows = fetch_all_rows(args.db)
    owasp_map = build_owasp_map()
    agg = aggregate(rows, owasp_map)

    write_csv(os.path.join(args.out, "cwe_distribution.csv"), table_cwe_distribution(agg))
    write_csv(os.path.join(args.out, "owasp_distribution.csv"), table_owasp_distribution(agg))
    write_csv(os.path.join(args.out, "docker_success_per_cwe.csv"), table_docker_success_per_cwe(agg))
    write_csv(os.path.join(args.out, "docker_success_per_owasp.csv"), table_docker_success_per_owasp(agg))
    write_csv(os.path.join(args.out, "secure_vulnerable_per_cwe.csv"), table_secure_vulnerable_per_cwe(agg))
    write_csv(os.path.join(args.out, "secure_vulnerable_per_owasp.csv"), table_secure_vulnerable_per_owasp(agg))
    write_csv(os.path.join(args.out, "docker_success_per_producer.csv"), table_docker_success_per_producer(agg))
    write_summary_md(os.path.join(args.out, "summary.md"), agg)

    print_console_summary(agg)
    print(f"\nCSV/markdown files written to: {args.out}")


if __name__ == "__main__":
    main()