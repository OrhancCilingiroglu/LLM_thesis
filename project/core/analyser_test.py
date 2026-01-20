from core.db_handler import DBManager
import json
from collections import Counter, defaultdict


def analyze_cwe_correlation(
    *,
    db_cwe: str,
    sast_output: str,
    dast_output_json: str,
    is_secure: bool,
                                        ):
    if not db_cwe:
        return {"error": "missing_db_cwe"}

    # normalize
    db_cwe = str(db_cwe).strip().upper()
    if not db_cwe.startswith("CWE-"):
        db_cwe = f"CWE-{db_cwe}"

    # -------- SAST ----------
    sast_cwes = set()
    if sast_output:
        for item in sast_output.split(","):
            item = item.strip().upper()
            if item.startswith("CWE-"):
                sast_cwes.add(item)

    # -------- DAST ----------
    zap_cwes = set()
    if dast_output_json:
        try:
            zap_alerts = json.loads(dast_output_json)

            if isinstance(zap_alerts, dict):
                if "alerts" in zap_alerts:
                    zap_alerts = zap_alerts["alerts"]
                elif "site" in zap_alerts:
                    merged = []
                    for s in zap_alerts["site"]:
                        merged.extend(s.get("alerts", []))
                    zap_alerts = merged
                else:
                    zap_alerts = []

            for alert in zap_alerts:
                if isinstance(alert, dict):
                    cweid = str(alert.get("cweid", "")).strip()
                    if cweid and cweid != "0":
                        zap_cwes.add(f"CWE-{cweid}")
        except Exception as e:
            return {"error": f"invalid_zap_json: {e}"}

    # -------- CORE FLAGS ----------
    db_in_sast = db_cwe in sast_cwes
    db_in_zap = db_cwe in zap_cwes
    any_tool_hit = db_in_sast or db_in_zap

    result = {
        "db_cwe": db_cwe,
        "is_secure": is_secure,
        "sast_cwes": list(sast_cwes),
        "zap_cwes": list(zap_cwes),
        "db_in_sast": db_in_sast,
        "db_in_zap": db_in_zap,
    }

    # =====================================================
    # SECURE-AWARE CORRELATION LOGIC
    # =====================================================

    if is_secure:
        if not any_tool_hit:
            result["correlation"] = "SECURE_CORRECT"
        else:
            result["correlation"] = "SECURE_FALSE_POSITIVE"
    else:
        if db_in_sast and db_in_zap:
            result["correlation"] = "FULL MATCH"
        elif db_in_sast or db_in_zap:
            result["correlation"] = "PARTIAL MATCH"
            result["partial_type"] = "SAST_ONLY" if db_in_sast else "ZAP_ONLY"
        else:
            result["correlation"] = "NO MATCH"

    return result



def run_modular_correlation_analysis(output_file="cwe_correlation_results.txt"):
    db = DBManager()
    successful_ids = db.get_ids_by_docker_status("tested-successful")

    # --- İstatistik toplayıcılar ---
    all_valid_results = []
    error_counts = Counter()
    corr_counts = Counter()
    partial_counts = Counter()  # SAST_ONLY / ZAP_ONLY

    # CWE bazlı (db_cwe üzerinden)
    per_cwe_corr = defaultdict(Counter)      # cwe -> Counter({"FULL MATCH": x, ...})
    per_cwe_partial = defaultdict(Counter)   # cwe -> Counter({"SAST_ONLY": x, "ZAP_ONLY": x})

    with open(output_file, "w") as f:
        for code_id in successful_ids:
            try:
                dast_row = db.fetch_dast_data_by_id(code_id)
                sast_row = db.fetch_sast_data_by_id(code_id)
                db_cwe = db.get_CWE_by_id(code_id)

                # Tuple unpack
                zap_json = dast_row[1] if dast_row and len(dast_row) > 1 else None
                bandit = sast_row[1] if sast_row and len(sast_row) > 1 else None
                semgrep = sast_row[2] if sast_row and len(sast_row) > 2 else None
                sonarqube = sast_row[3] if sast_row and len(sast_row) > 3 else None

                sast_combined = ",".join(filter(None, [bandit, semgrep, sonarqube]))
                db_cwe = str(db_cwe[0] if isinstance(db_cwe, tuple) else db_cwe).strip().upper() if db_cwe else ""
                is_secure = db.is_secure_by_id(code_id)
                result = analyze_cwe_correlation(
                db_cwe=db_cwe,
                sast_output=sast_combined,
                dast_output_json=zap_json,
                is_secure=is_secure,
)
                result["code_id"] = code_id

                if "error" in result:
                    err = result["error"]
                    error_counts[err] += 1
                    f.write(
                    f"ID: {code_id} | SECURE: {is_secure} | "
                    f"DB_CWE: {result['db_cwe']} | "
                    f"SAST: {result['sast_cwes']} | "
                    f"ZAP: {result['zap_cwes']} | "
                    f"Correlation: {result['correlation']}\n"
)
                    continue

                # normal sonuç
                all_valid_results.append(result)

                corr = result.get("correlation", "UNKNOWN")
                corr_counts[corr] += 1

                # partial breakdown
                if corr == "PARTIAL MATCH":
                    ptype = result.get("partial_type") or "UNKNOWN_PARTIAL"
                    partial_counts[ptype] += 1

                # CWE bazlı
                cwe = result.get("db_cwe", "CWE-UNKNOWN")
                per_cwe_corr[cwe][corr] += 1
                if corr == "PARTIAL MATCH":
                    ptype = result.get("partial_type") or "UNKNOWN_PARTIAL"
                    per_cwe_partial[cwe][ptype] += 1

                f.write(
                    f"ID: {result['code_id']} | DB_CWE: {result['db_cwe']} | "
                    f"SAST: {result['sast_cwes']} | ZAP: {result['zap_cwes']} | "
                    f"Correlation: {result['correlation']}"
                )
                if result.get("partial_type"):
                    f.write(f" | PartialType: {result['partial_type']}")
                f.write("\n")

            except Exception as e:
                error_counts["exception"] += 1
                f.write(f"[!] ID: {code_id} | Exception: {str(e)}\n")

        # =========================
        #        SUMMARY
        # =========================
        f.write("\n" + "=" * 80 + "\n")
        f.write("SUMMARY\n")
        f.write("=" * 80 + "\n")

        total = len(all_valid_results)
        f.write(f"Total successful IDs: {len(successful_ids)}\n")
        f.write(f"Total valid analyzed results: {total}\n")

        if error_counts:
            f.write("\nErrors:\n")
            for k, v in error_counts.most_common():
                f.write(f"  - {k}: {v}\n")

        secure_docker_ratio = db.get_secure_docker_success_rate()
        f.write(f"\nSecure codes that Docker 'tested-successful' rate: {secure_docker_ratio:.2f}\n")

        secure_ratio = db.get_secure_rate()
        f.write(f"\nSecure code rate: {secure_ratio:.2f}\n")

        if total == 0:
            f.write("\nNo valid results to summarize.\n")
            print(f"✅ Correlation analysis completed. Output saved to → {output_file}")
            return

        # Genel oranlar
        f.write("\nOverall correlation distribution:\n")
        for k, v in corr_counts.most_common():
            pct = (v / total) * 100
            f.write(f"  - {k}: {v} ({pct:.2f}%)\n")

        # Partial kırılımı
        if corr_counts.get("PARTIAL MATCH", 0) > 0:
            partial_total = corr_counts["PARTIAL MATCH"]
            f.write("\nPARTIAL MATCH breakdown:\n")
            for k, v in partial_counts.most_common():
                pct = (v / partial_total) * 100
                f.write(f"  - {k}: {v} ({pct:.2f}% of partial)\n")

        # CWE bazlı dominant sonuçlar
        f.write("\nPer-CWE dominant outcomes (by DB_CWE):\n")
        dominant_map = {}
        for cwe, counter in sorted(per_cwe_corr.items(), key=lambda x: sum(x[1].values()), reverse=True):
            total_cwe = sum(counter.values())
            dominant, dom_count = counter.most_common(1)[0]
            dominant_map[cwe] = dominant
            f.write(
                f"  - {cwe} | total={total_cwe} | dominant={dominant} ({dom_count}/{total_cwe}) | "
                f"FULL={counter.get('FULL MATCH', 0)} PARTIAL={counter.get('PARTIAL MATCH', 0)} "
                f"TOOL_NOT_DB={counter.get('TOOL MATCH BUT NOT DB', 0)} NO={counter.get('NO MATCH', 0)}\n"
            )

        # Örnek verebileceğin FULL MATCH CWE'ler
        full_match_cwes = sorted(
            [cwe for cwe, cnt in per_cwe_corr.items() if cnt.get("FULL MATCH", 0) > 0],
            key=lambda c: per_cwe_corr[c].get("FULL MATCH", 0),
            reverse=True
        )
        f.write("\nCWEs with at least one FULL MATCH (good examples to cite):\n")
        if full_match_cwes:
            for cwe in full_match_cwes:
                f.write(f"  - {cwe} (FULL={per_cwe_corr[cwe].get('FULL MATCH', 0)})\n")
        else:
            f.write("  (none)\n")

        # Partial match CWE'ler
        partial_match_cwes = sorted(
            [cwe for cwe, cnt in per_cwe_corr.items() if cnt.get("PARTIAL MATCH", 0) > 0],
            key=lambda c: per_cwe_corr[c].get("PARTIAL MATCH", 0),
            reverse=True
        )
        f.write("\nCWEs with PARTIAL MATCH occurrences:\n")
        if partial_match_cwes:
            for cwe in partial_match_cwes:
                pt = per_cwe_partial[cwe]
                f.write(
                    f"  - {cwe} (PARTIAL={per_cwe_corr[cwe].get('PARTIAL MATCH', 0)} | "
                    f"SAST_ONLY={pt.get('SAST_ONLY', 0)} ZAP_ONLY={pt.get('ZAP_ONLY', 0)})\n"
                )
        else:
            f.write("  (none)\n")

        # Tamamen NO MATCH olan CWE'ler (hepsi NO MATCH)
        trash_cwes = []
        for cwe, cnt in per_cwe_corr.items():
            total_cwe = sum(cnt.values())
            if total_cwe > 0 and cnt.get("NO MATCH", 0) == total_cwe:
                trash_cwes.append(cwe)

        trash_cwes = sorted(trash_cwes)
        f.write("\nCWEs with ONLY NO MATCH results (candidates to discard as 'completely useless'):\n")
        if trash_cwes:
            for cwe in trash_cwes:
                f.write(f"  - {cwe} (total={sum(per_cwe_corr[cwe].values())})\n")
        else:
            f.write("  (none)\n")

    print(f"✅ Correlation analysis completed. Output saved to → {output_file}")


run_modular_correlation_analysis()
