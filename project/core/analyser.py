from core.db_handler import DBManager
import json
from collections import Counter, defaultdict
from utils import OWASP


OWASP_2025_MAP = {
    "A01_2025_Broken_Access_Control": set(OWASP.A01_2025_Broken_Access_Control_list),
    "A02_2025_Security_Misconfiguration": set(OWASP.A02_2025_Security_Misconfiguration_list),
    "A03_2025_Sofware_Supply_Chain": set(OWASP.A03_2025_Sofware_Supply_Chain_list),
    "A04_2025_Cryptographic_Failures": set(OWASP.A04_2025_Cryptographic_Failures_list),
    "A05_2025_Injection": set(OWASP.A05_2025_Injection_list),
    "A06_2025_Insecure_Design": set(OWASP.A06_2025_Insecure_Design_list),
    "A07_2025_Authentication_Failures": set(OWASP.A07_2025_Authentication_Failures_list),
    "A08_2025_Software_or_Data_Integrity_Failures": set(OWASP.A08_2025_Software_or_Data_Integrity_Failures_list),
    "A09_2025_Security_Logging_and_Alerting_Failures": set(OWASP.A09_2025_Security_Logging_and_Alerting_Failures_list),
    "A10_2025_Mishandling_of_Exceptional_Conditions": set(OWASP.A10_2025_Mishandling_of_Exceptional_Conditions_list),
}

def cwe_to_owasp_2025(db_cwe: str) -> str:
    if not db_cwe:
        return "UNMAPPED"
    s = str(db_cwe).strip().upper()
    if not s.startswith("CWE-"):
        s = f"CWE-{s}"
    try:
        cwe_num = int(s.replace("CWE-", "").strip())
    except ValueError:
        return "UNMAPPED"
    for cat, cwe_set in OWASP_2025_MAP.items():
        if cwe_num in cwe_set:
            return cat
    return "UNMAPPED"

PLACEHOLDERS = {"not-tested", "not_tested", "not tested", "na", "n/a", "none", "null", "nan", "-"}

def safe_json_loads(raw):
    if raw is None:
        return None, "empty_zap_json"
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="replace")
    s = str(raw).strip()
    if not s:
        return None, "empty_zap_json"
    if s.lower() in PLACEHOLDERS:
        return None, f"zap_unavailable:{s.lower()}"
    if s[0] not in "{[":
        return None, f"zap_json_not_json_prefix:{s[:30]}"
    try:
        return json.loads(s), None
    except json.JSONDecodeError as e:
        return None, f"invalid_zap_json:{e}"

def normalize_secure(secure_raw) -> bool:
    if isinstance(secure_raw, bool):
        return secure_raw
    if isinstance(secure_raw, int):
        return bool(secure_raw)
    if isinstance(secure_raw, str):
        return secure_raw.strip().lower() == "secure"
    return False

def normalize_burpsuite(burpsuite_raw) -> bool:
    """
    code_cwe tablosundaki burpsuite kolonu "found" ise True döner.
    Bu durumda ZAP çıktısı bulamamış olsa bile DAST tarafı bulmuş sayılır.
    """
    if not burpsuite_raw:
        return False
    return str(burpsuite_raw).strip().lower() == "found"

def analyze_cwe_correlation(db_cwe, bandit_out, semgrep_out, sonarqube_out, dast_output_json, burpsuite_raw=None):
    """
    Extended version — tracks which tool detected the CWE individually
    so we can calculate per-tool contribution later.

    burpsuite_raw : code_cwe.burpsuite kolonu değeri ("found" / "not-found" / None).
                    "found" ise ZAP bulamasaydı bile DAST tarafı bulmuş kabul edilir.
    """
    if not db_cwe:
        return {"error": "missing_db_cwe"}

    db_cwe = str(db_cwe).strip().upper()
    if not db_cwe.startswith("CWE-"):
        db_cwe = f"CWE-{db_cwe}"

    def parse_sast_cwes(raw):
        found = set()
        if not raw:
            return found
        for item in raw.split(","):
            item = item.strip().upper()
            if item.startswith("CWE-"):
                found.add(item)
        return found

    bandit_cwes    = parse_sast_cwes(bandit_out)
    semgrep_cwes   = parse_sast_cwes(semgrep_out)
    sonarqube_cwes = parse_sast_cwes(sonarqube_out)
    sast_cwes      = bandit_cwes | semgrep_cwes | sonarqube_cwes

    burpsuite_found = normalize_burpsuite(burpsuite_raw)

    # ZAP JSON parse
    # ZAP "not-tested" veya parse hatası → zap_cwes boş kalır, satır düşürülmez
    # Sadece ZAP geçerli JSON döndürürse parse edilir
    zap_alerts, err = safe_json_loads(dast_output_json)
    if err:
        zap_alerts = []   # ZAP yoksa/hatalıysa boş say, satırı düşürme

    if isinstance(zap_alerts, dict):
        if "alerts" in zap_alerts and isinstance(zap_alerts["alerts"], list):
            zap_alerts = zap_alerts["alerts"]
        elif "site" in zap_alerts and isinstance(zap_alerts["site"], list):
            merged = []
            for s in zap_alerts["site"]:
                if isinstance(s, dict) and isinstance(s.get("alerts"), list):
                    merged.extend(s["alerts"])
            zap_alerts = merged
        else:
            zap_alerts = []

    if not isinstance(zap_alerts, list):
        zap_alerts = []

    zap_cwes = set()
    for alert in zap_alerts:
        if not isinstance(alert, dict):
            continue

        # cweid part
        cweid = str(alert.get("cweid", "")).strip()
        if cweid and cweid not in ("0", "-1", ""):
            zap_cwes.add(f"CWE-{cweid}")

        # tags part
        tags = alert.get("tags", {})
        if isinstance(tags, dict):
            for tag_key in tags:
                tag_upper = tag_key.strip().upper()
                if tag_upper.startswith("CWE-"):
                    try:
                        # Filters anything that looks like CWE but isn't a valid number (e.g., "CWE-ABC") to avoid false positives
                        int(tag_upper.replace("CWE-", ""))
                        zap_cwes.add(tag_upper)
                    except ValueError:
                        pass

    db_in_bandit    = db_cwe in bandit_cwes
    db_in_semgrep   = db_cwe in semgrep_cwes
    db_in_sonarqube = db_cwe in sonarqube_cwes
    db_in_sast      = db_cwe in sast_cwes
    db_in_zap       = db_cwe in zap_cwes

    # BurpSuite "found" → satır bazında DAST detection tetiklenir
    db_in_burpsuite = burpsuite_found

    # DAST tarafı: ZAP veya BurpSuite'den biri bulduysa yeterli
    db_in_dast = db_in_zap or db_in_burpsuite

    sast_zap_overlap = bool(sast_cwes & zap_cwes)

    result = {
        "db_cwe":           db_cwe,
        "sast_cwes":        list(sast_cwes),
        "zap_cwes":         list(zap_cwes),
        "db_in_sast":       db_in_sast,
        "db_in_zap":        db_in_zap,
        "db_in_burpsuite":  db_in_burpsuite,
        "db_in_dast":       db_in_dast,
        "sast_zap_overlap": sast_zap_overlap,
        # per-tool detection flags
        "db_in_bandit":     db_in_bandit,
        "db_in_semgrep":    db_in_semgrep,
        "db_in_sonarqube":  db_in_sonarqube,
    }

    # Correlation: ZAP yerine db_in_dast (ZAP + BurpSuite birleşimi) kullanılıyor
    if db_in_sast and db_in_dast:
        result["correlation"] = "FULL MATCH"
        result["partial_type"] = None
    elif db_in_sast or db_in_dast:
        result["correlation"] = "PARTIAL MATCH"
        result["partial_type"] = "SAST_ONLY" if db_in_sast else "DAST_ONLY"
    elif sast_zap_overlap:
        result["correlation"] = "TOOL MATCH BUT NOT DB"
        result["partial_type"] = None
    else:
        result["correlation"] = "NO MATCH"
        result["partial_type"] = None

    return result


def run_modular_correlation_analysis(output_file="cwe_correlation_results.txt"):
    db = DBManager()

    # ---------------------------------------------------------------
    # Tüm DB'deki satır sayıları — "Total Rows" için (docker durumuna
    # bakılmaksızın, sadece CWE → OWASP mapping'e göre gruplandırılır)
    # ---------------------------------------------------------------
    all_ids         = db.get_all_ids()
    # per_owasp_all_total   : tüm DB'deki satır sayısı (sol kolon)
    # per_owasp_all_vuln    : tüm DB'deki vulnerable satır sayısı (sol kolon)
    # per_owasp_all_secure  : tüm DB'deki secure satır sayısı (sol kolon)
    per_owasp_all_total  = Counter()
    per_owasp_all_vuln   = Counter()
    per_owasp_all_secure = Counter()

    for aid in all_ids:
        try:
            cwe_val    = db.get_CWE_by_id(aid)
            cwe_str    = str(cwe_val).strip().upper() if cwe_val else ""
            owasp_cat  = cwe_to_owasp_2025(cwe_str)
            is_sec     = db.is_secure_by_id(aid)
            per_owasp_all_total[owasp_cat] += 1
            if is_sec:
                per_owasp_all_secure[owasp_cat] += 1
            else:
                per_owasp_all_vuln[owasp_cat] += 1
        except Exception:
            pass

    # ---------------------------------------------------------------
    # docker = 'tested-successful' satırları — analiz için
    # ---------------------------------------------------------------
    successful_ids = db.get_ids_by_docker_status("tested-successful")

    all_valid_results = []
    error_counts      = Counter()
    corr_counts       = Counter()
    partial_counts    = Counter()

    tool_detection_counts = Counter()

    per_cwe_corr    = defaultdict(Counter)
    per_cwe_partial = defaultdict(Counter)

    # docker-success satır sayıları (sağ kolon için)
    per_owasp_docker_vuln   = Counter()   # docker success & vulnerable
    per_owasp_docker_secure = Counter()   # docker success & secure

    # valid (hatasız parse edilen) satır sayıları
    per_owasp_vuln_valid    = Counter()
    per_owasp_secure_valid  = Counter()

    per_owasp_corr    = defaultdict(Counter)
    per_owasp_partial = defaultdict(Counter)

    # Correlation detay sayaçları: owasp → {"vuln": Counter, "secure": Counter}
    per_owasp_vuln_corr   = defaultdict(Counter)   # vulnerable satırların correlation dağılımı
    per_owasp_secure_corr = defaultdict(Counter)   # secure satırların correlation dağılımı

    per_owasp_detected_cwes = defaultdict(set)
    per_owasp_cwe_corr      = defaultdict(lambda: defaultdict(lambda: defaultdict(Counter)))

    secure_corr_counts     = Counter()
    vulnerable_corr_counts = Counter()

    # ---------------------------------------------------------------
    # Producer bazlı sayaçlar
    # ---------------------------------------------------------------
    # Tüm DB'deki satır sayısı (docker durumuna bakılmaksızın)
    per_producer_total        = Counter()
    # docker tested-successful olan satır sayısı
    per_producer_docker_ok    = Counter()
    # valid analyze edilen satırlar içinde correlation dağılımı
    per_producer_corr         = defaultdict(Counter)

    # Önce tüm DB'deki producer dağılımını say
    import sqlite3 as _sqlite3
    _conn = _sqlite3.connect(db.db_path)
    _cur  = _conn.cursor()
    _cur.execute("SELECT producer, COUNT(*) FROM code_cwe GROUP BY producer")
    for _prod, _cnt in _cur.fetchall():
        per_producer_total[_prod or "unknown"] = _cnt
    _conn.close()

    with open(output_file, "w", encoding="utf-8") as f:

        for code_id in successful_ids:
            try:
                dast_row   = db.fetch_dast_data_by_id(code_id)   # (id, owasp_zap, burpsuite)
                sast_row   = db.fetch_sast_data_by_id(code_id)   # (id, bandit, semgrep, sonarqube)
                db_cwe     = db.get_CWE_by_id(code_id)

                secure_row   = db.is_secure_by_id(code_id)
                secure_raw   = secure_row[0] if isinstance(secure_row, tuple) else secure_row
                is_secure    = normalize_secure(secure_raw)
                secure_label = "Secure" if is_secure else "Vulnerable"

                zap_json      = dast_row[1] if dast_row and len(dast_row) > 1 else None
                burpsuite_raw = dast_row[2] if dast_row and len(dast_row) > 2 else None

                bandit    = sast_row[1] if sast_row and len(sast_row) > 1 else None
                semgrep   = sast_row[2] if sast_row and len(sast_row) > 2 else None
                sonarqube = sast_row[3] if sast_row and len(sast_row) > 3 else None

                db_cwe    = str(db_cwe).strip().upper() if db_cwe else ""
                owasp_cat = cwe_to_owasp_2025(db_cwe)

                # docker-success satır sayaçları (hata olsa da sayılır)
                if is_secure:
                    per_owasp_docker_secure[owasp_cat] += 1
                else:
                    per_owasp_docker_vuln[owasp_cat] += 1

                result = analyze_cwe_correlation(
                    db_cwe, bandit, semgrep, sonarqube, zap_json,
                    burpsuite_raw=burpsuite_raw
                )

                if "error" in result:
                    error_counts[result["error"]] += 1
                    continue

                # valid satır sayaçları
                if is_secure:
                    per_owasp_secure_valid[owasp_cat] += 1
                else:
                    per_owasp_vuln_valid[owasp_cat] += 1

                all_valid_results.append(result)

                corr = result.get("correlation", "UNKNOWN")
                corr_counts[corr] += 1

                if is_secure:
                    secure_corr_counts[corr] += 1
                    per_owasp_secure_corr[owasp_cat][corr] += 1
                else:
                    vulnerable_corr_counts[corr] += 1
                    per_owasp_vuln_corr[owasp_cat][corr] += 1

                if corr == "PARTIAL MATCH":
                    partial_counts[result.get("partial_type") or "UNKNOWN_PARTIAL"] += 1

                cwe = result.get("db_cwe", "CWE-UNKNOWN")
                per_cwe_corr[cwe][corr] += 1
                if corr == "PARTIAL MATCH":
                    per_cwe_partial[cwe][result.get("partial_type") or "UNKNOWN_PARTIAL"] += 1

                per_owasp_corr[owasp_cat][corr] += 1
                per_owasp_cwe_corr[owasp_cat][cwe][secure_label][corr] += 1
                if corr == "PARTIAL MATCH":
                    per_owasp_partial[owasp_cat][result.get("partial_type") or "UNKNOWN_PARTIAL"] += 1

                if corr in ("FULL MATCH", "PARTIAL MATCH"):
                    per_owasp_detected_cwes[owasp_cat].add(cwe)

                # per-tool contribution — only vulnerable rows
                if not is_secure:
                    if result.get("db_in_bandit"):
                        tool_detection_counts["bandit"] += 1
                    if result.get("db_in_semgrep"):
                        tool_detection_counts["semgrep"] += 1
                    if result.get("db_in_sonarqube"):
                        tool_detection_counts["sonarqube"] += 1
                    if result.get("db_in_zap"):
                        tool_detection_counts["owasp_zap"] += 1
                    if result.get("db_in_burpsuite"):
                        tool_detection_counts["burpsuite"] += 1

            except Exception as e:
                error_counts[f"exception:{e}"] += 1

        # =========================
        # SUMMARY
        # =========================
        f.write("\n" + "=" * 80 + "\n")
        f.write("SUMMARY\n")
        f.write("=" * 80 + "\n")

        total_valid = len(all_valid_results)
        f.write(f"Total docker tested-successful IDs  : {len(successful_ids)}\n")
        f.write(f"Total valid analyzed results        : {total_valid}\n")

        if error_counts:
            f.write("\nErrors:\n")
            for k, v in error_counts.most_common():
                f.write(f"  - {k}: {v}\n")

        f.write(f"\nSecure codes docker success rate : {db.get_secure_docker_success_rate():.2f}\n")
        f.write(f"Secure code rate                 : {db.get_secure_rate():.2f}\n")

        if total_valid == 0:
            f.write("\nNo valid results to summarize.\n")
            print(f"Correlation analysis completed → {output_file}")
            return

        f.write("\nOverall correlation distribution (valid only):\n")
        for k, v in corr_counts.most_common():
            f.write(f"  - {k}: {v} ({v/total_valid*100:.2f}%)\n")

        total_secure_valid = sum(secure_corr_counts.values())
        total_vuln_valid   = sum(vulnerable_corr_counts.values())
        f.write(f"\nValid results — Secure: {total_secure_valid} | Vulnerable: {total_vuln_valid}\n")

        if total_secure_valid > 0:
            f.write("  Secure correlation distribution:\n")
            for k, v in secure_corr_counts.most_common():
                f.write(f"    - {k}: {v} ({v/total_secure_valid*100:.2f}%)\n")

        if total_vuln_valid > 0:
            f.write("  Vulnerable correlation distribution:\n")
            for k, v in vulnerable_corr_counts.most_common():
                f.write(f"    - {k}: {v} ({v/total_vuln_valid*100:.2f}%)\n")

        if corr_counts.get("PARTIAL MATCH", 0) > 0:
            partial_total = corr_counts["PARTIAL MATCH"]
            f.write("\nPARTIAL MATCH breakdown:\n")
            for k, v in partial_counts.most_common():
                f.write(f"  - {k}: {v} ({v/partial_total*100:.2f}% of partial)\n")

        # =========================
        # TOOL CONTRIBUTION
        # =========================
        f.write("\n" + "=" * 80 + "\n")
        f.write("TOOL DETECTION CONTRIBUTION (vulnerable rows only)\n")
        f.write("=" * 80 + "\n")
        f.write("Counts how many times each tool independently detected the expected CWE.\n")
        f.write("One row can be counted by multiple tools if they all found it.\n")
        f.write("BurpSuite: 'found' in code_cwe.burpsuite column counts as DAST detection.\n\n")

        total_tool_hits = sum(tool_detection_counts.values())
        if total_tool_hits == 0:
            f.write("  No tool detections found.\n")
        else:
            for tool, count in tool_detection_counts.most_common():
                pct = count / total_tool_hits * 100
                f.write(f"  - {tool:<15}: {count:>5} detections  ({pct:.2f}% of all tool hits)\n")
            f.write(f"\n  Total tool hits (sum across tools) : {total_tool_hits}\n")
            f.write(f"  Unique vulnerable rows analyzed    : {total_vuln_valid}\n")

        # =========================
        # OWASP CATEGORY SUMMARY
        # =========================
        f.write("\n" + "=" * 80 + "\n")
        f.write("OWASP CATEGORY SUMMARY\n")
        f.write("=" * 80 + "\n")

        def cwe_sort_key(cwe_str):
            try:
                return int(cwe_str.replace("CWE-", "").strip())
            except ValueError:
                return float("inf")

        # Kategorileri tüm DB toplamına göre sırala
        for cat in sorted(per_owasp_all_total, key=lambda c: per_owasp_all_total[c], reverse=True):
            all_total    = per_owasp_all_total[cat]
            all_vuln     = per_owasp_all_vuln[cat]
            all_secure   = per_owasp_all_secure[cat]
            dock_vuln    = per_owasp_docker_vuln[cat]
            dock_secure  = per_owasp_docker_secure[cat]
            valid_vuln   = per_owasp_vuln_valid[cat]
            valid_secure = per_owasp_secure_valid[cat]

            f.write(f"\n[{cat}]\n")
            # Sol: tüm DB'deki satır sayısı  |  Sağ: docker tested-successful satır sayısı
            f.write(f"  Total Rows                                 : {all_total}\n")
            f.write(f"  Vulnerable Rows | Docker runnable rows     : {all_vuln} | {dock_vuln}\n")
            f.write(f"  Secure Rows     | Docker runnable rows     : {all_secure} | {dock_secure}\n")

            cat_corr     = per_owasp_corr[cat]
            valid_in_cat = sum(cat_corr.values())

            # ---- Correlation distribution — overall ----
            f.write("  Correlation distribution:\n")
            if valid_in_cat == 0:
                f.write("    - (no valid results)\n")
            else:
                for k, v in cat_corr.most_common():
                    f.write(f"    - {k}: {v} ({v/valid_in_cat*100:.2f}%)\n")

            # ---- Vulnerable codes breakdown ----
            vuln_corr = per_owasp_vuln_corr[cat]
            vuln_total_valid = sum(vuln_corr.values())
            f.write("  Vulnerable Codes:\n")
            if vuln_total_valid == 0:
                f.write("    - (no valid vulnerable results)\n")
            else:
                CORR_ORDER = ["FULL MATCH", "PARTIAL MATCH", "TOOL MATCH BUT NOT DB", "NO MATCH"]
                for k in CORR_ORDER:
                    v = vuln_corr.get(k, 0)
                    f.write(f"    * {k}: {v} ({v/vuln_total_valid*100:.2f}%)\n")
                # partial sub-breakdown for vulnerable
                if vuln_corr.get("PARTIAL MATCH", 0) > 0:
                    f.write("      Partial breakdown:\n")
                    for pk, pv in per_owasp_partial[cat].most_common():
                        f.write(f"        - {pk}: {pv}\n")

            # ---- Secure codes breakdown ----
            sec_corr = per_owasp_secure_corr[cat]
            sec_total_valid = sum(sec_corr.values())
            f.write("  Secure Codes:\n")
            if sec_total_valid == 0:
                f.write("    - (no valid secure results)\n")
            else:
                # For secure codes: NO MATCH = correctly identified as secure
                #                   anything else = falsely flagged as vulnerable
                no_match   = sec_corr.get("NO MATCH", 0)
                flagged    = sec_total_valid - no_match
                f.write(f"    * Secure-tested (no tool alarm) : {no_match} ({no_match/sec_total_valid*100:.2f}%)\n")
                f.write(f"    * Flagged as vulnerable         : {flagged} ({flagged/sec_total_valid*100:.2f}%)\n")
                if flagged > 0:
                    f.write("      Flagged breakdown:\n")
                    for k in ["FULL MATCH", "PARTIAL MATCH", "TOOL MATCH BUT NOT DB"]:
                        v = sec_corr.get(k, 0)
                        if v > 0:
                            f.write(f"        - {k}: {v}\n")

            if cat_corr.get("PARTIAL MATCH", 0) > 0:
                ptotal = cat_corr["PARTIAL MATCH"]
                f.write("  Partial breakdown (overall):\n")
                for pk, pv in per_owasp_partial[cat].most_common():
                    f.write(f"    - {pk}: {pv} ({pv/ptotal*100:.2f}% of partial)\n")

            # detected CWEs — at least one partial or full match
            detected = sorted(per_owasp_detected_cwes.get(cat, set()), key=cwe_sort_key)
            f.write(f"  CWEs with at least one detection (partial or full): {len(detected)}\n")
            if detected:
                f.write("    " + ", ".join(detected) + "\n")
            else:
                f.write("    - (none detected)\n")

            # full CWE breakdown — numerik sıralama
            f.write("  CWE breakdown:\n")
            cwe_map = per_owasp_cwe_corr[cat]
            if not cwe_map:
                f.write("    - (empty)\n")
            else:
                for cwe, label_dict in sorted(cwe_map.items(), key=lambda x: cwe_sort_key(x[0])):
                    for secure_label in ["Secure", "Vulnerable"]:
                        ccounter = label_dict.get(secure_label)
                        if not ccounter:
                            continue
                        cwe_total = sum(ccounter.values())
                        if secure_label == "Secure":
                            no_match_count = ccounter.get("NO MATCH", 0)
                            flagged_count  = cwe_total - no_match_count
                            f.write(
                                f"    - {cwe} | {secure_label:<10} | total={cwe_total} | "
                                f"tested-secure={no_match_count}, flagged={flagged_count}\n"
                            )
                        else:
                            f.write(
                                f"    - {cwe} | {secure_label:<10} | total={cwe_total} | "
                                f"FULL={ccounter.get('FULL MATCH', 0)} "
                                f"PARTIAL={ccounter.get('PARTIAL MATCH', 0)} "
                                f"TOOL_NOT_DB={ccounter.get('TOOL MATCH BUT NOT DB', 0)} "
                                f"NO={ccounter.get('NO MATCH', 0)}\n"
                            )

    print(f"Correlation analysis completed → {output_file}")


run_modular_correlation_analysis()