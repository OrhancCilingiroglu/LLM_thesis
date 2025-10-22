from core.db_handler import DBManager
import json

def analyze_cwe_correlation(db_cwe, sast_output, dast_output_json):
    """
    db_cwe: string, örn: 'CWE-79'
    sast_output: string, örn: 'CWE-79, CWE-89'
    dast_output_json: string (JSON), OWASP ZAP alert JSON
    """
    if not db_cwe:
        return {"error": "missing_db_cwe"}

    # 1. Normalize CWE
    db_cwe = str(db_cwe).strip().upper()
    if not db_cwe.startswith("CWE-"):
        db_cwe = f"CWE-{db_cwe}"

    # 2. Parse SAST Output
    sast_cwes = set()
    if sast_output:
        for item in sast_output.split(","):
            item = item.strip().upper()
            if item.startswith("CWE-"):
                sast_cwes.add(item)

    # 3. Parse DAST (ZAP) Output
    zap_cwes = set()
    if not dast_output_json:
        return {"error": "empty_zap_json"}

    try:
        zap_alerts = json.loads(dast_output_json)
        for alert in zap_alerts:
            cweid = str(alert.get("cweid", "")).strip()
            if cweid and cweid != "0":
                zap_cwes.add(f"CWE-{cweid.upper()}")
    except json.JSONDecodeError as e:
        return {"error": f"invalid_zap_json: {e}"}

    # 4. Correlation logic
    db_in_sast = db_cwe in sast_cwes
    db_in_zap = db_cwe in zap_cwes
    sast_zap_overlap = bool(sast_cwes & zap_cwes)

    result = {
        "db_cwe": db_cwe,
        "sast_cwes": list(sast_cwes),
        "zap_cwes": list(zap_cwes),
        "db_in_sast": db_in_sast,
        "db_in_zap": db_in_zap,
        "sast_zap_overlap": sast_zap_overlap
    }

    if db_in_sast and db_in_zap:
        result["correlation"] = "FULL MATCH"
    elif db_in_sast or db_in_zap:
        result["correlation"] = "PARTIAL MATCH"
    elif sast_zap_overlap:
        result["correlation"] = "TOOL MATCH BUT NOT DB"
    else:
        result["correlation"] = "NO MATCH"

    return result


def run_modular_correlation_analysis(output_file="cwe_correlation_results.txt"):
    db = DBManager()
    successful_ids = db.get_ids_by_docker_status("tested-successful")
    results = []

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
                
                result = analyze_cwe_correlation(db_cwe, sast_combined, zap_json)
                result["code_id"] = code_id

                if "error" in result:
                    f.write(f"[!] ID: {code_id} | Error: {result['error']}\n")
                else:
                    f.write(f"ID: {result['code_id']} | DB_CWE: {result['db_cwe']} | "
                            f"SAST: {result['sast_cwes']} | ZAP: {result['zap_cwes']} | "
                            f"Correlation: {result['correlation']}\n")

            except Exception as e:
                f.write(f"[!] ID: {code_id} | Exception: {str(e)}\n")

    print(f"✅ Correlation analysis completed. Output saved to → {output_file}")

run_modular_correlation_analysis()