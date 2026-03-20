import os
import json
import argparse
import re
from datetime import datetime
from utils import OWASP
from core.db_handler import DBManager

OWASP_2025_MAP = {
    "A01": set(OWASP.A01_2025_Broken_Access_Control_list),
    "A02": set(OWASP.A02_2025_Security_Misconfiguration_list),
    "A03": set(OWASP.A03_2025_Sofware_Supply_Chain_list),
    "A04": set(OWASP.A04_2025_Cryptographic_Failures_list),
    "A05": set(OWASP.A05_2025_Injection_list),
    "A06": set(OWASP.A06_2025_Insecure_Design_list),
    "A07": set(OWASP.A07_2025_Authentication_Failures_list),
    "A08": set(OWASP.A08_2025_Software_or_Data_Integrity_Failures_list),
    "A09": set(OWASP.A09_2025_Security_Logging_and_Alerting_Failures_list),
    "A10": set(OWASP.A10_2025_Mishandling_of_Exceptional_Conditions_list),
}
# ==============================
# Prompt — code only, target is DB CWE
# ==============================
EVAL_PROMPT = """You are a Static Application Security Testing (SAST) tool.
List the CWE IDs present in the following code.
Output ONLY a comma-separated list like: CWE-xx, CWE-yy.
If none, output: NONE.

### code
<CODE>
{code}
</CODE>
"""

PARTIAL_EVAL_PROMPT = """Analyze the following code for security vulnerabilities.

For each vulnerability found:
1. Describe the vulnerability clearly and explain how it manifests in this code
2. Provide the exact CWE number (e.g., CWE-xx)
3. Provide the exact CWE title (e.g., Improper Neutralization of Special Elements used in an SQL Command)

If the code is secure, respond with: "No vulnerabilities found."

<CODE>
{code}
</CODE>
"""
# ==============================
# Helpers
# ==============================

PLACEHOLDERS = {"not-tested", "not_tested", "not tested", "na", "n/a", "none", "null", "nan", "-"}

def parse_cwe_tokens(text):
    if text is None:
        return []
    s = str(text)
    tokens = re.findall(r"CWE-\d+|\b\d{1,5}\b", s, flags=re.IGNORECASE)
    out = []
    for t in tokens:
        t = t.strip().upper()
        out.append(t if t.startswith("CWE-") else "CWE-" + t)
    seen = set()
    final = []
    for x in out:
        if x not in seen:
            seen.add(x)
            final.append(x)
    return final


def normalize_secure(secure_raw) -> bool:
    if isinstance(secure_raw, bool):
        return secure_raw
    if isinstance(secure_raw, int):
        return bool(secure_raw)
    if isinstance(secure_raw, str):
        return secure_raw.strip().lower() == "secure"
    return False


def safe_json_loads(raw):
    if raw is None:
        return None, "empty_zap_json"
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="replace")
    s = str(raw).strip()
    if not s or s.lower() in PLACEHOLDERS:
        return None, "zap_unavailable"
    if s[0] not in "{[":
        return None, "zap_not_json"
    try:
        return json.loads(s), None
    except json.JSONDecodeError as e:
        return None, f"invalid_zap_json:{e}"


def get_correlation(db_cwe: str, sast_combined: str, zap_json_raw) -> str:
    """
    Returns one of:
        FULL MATCH | PARTIAL MATCH | TOOL MATCH BUT NOT DB | NO MATCH | ERROR
    """
    if not db_cwe:
        return "ERROR"

    db_cwe = str(db_cwe).strip().upper()
    if not db_cwe.startswith("CWE-"):
        db_cwe = f"CWE-{db_cwe}"

    # SAST CWEs
    sast_cwes = set()
    if sast_combined:
        for item in sast_combined.split(","):
            item = item.strip().upper()
            if item.startswith("CWE-"):
                sast_cwes.add(item)

    # ZAP CWEs
    zap_alerts, err = safe_json_loads(zap_json_raw)
    if err:
        return "ERROR"

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
        cweid = str(alert.get("cweid", "")).strip()
        if cweid and cweid != "0":
            zap_cwes.add(f"CWE-{cweid.upper()}")

    db_in_sast = db_cwe in sast_cwes
    db_in_zap  = db_cwe in zap_cwes

    if db_in_sast and db_in_zap:
        return "FULL MATCH"
    if db_in_sast or db_in_zap:
        return "PARTIAL MATCH"
    if sast_cwes & zap_cwes:
        return "TOOL MATCH BUT NOT DB"
    return "NO MATCH"


def cwe_in_owasp(db_cwe: str, owasp_short: str) -> bool:
    """Check whether db_cwe belongs to the requested OWASP category (e.g. 'A05')."""
    key = owasp_short.strip().upper()[:3]
    cwe_set = OWASP_2025_MAP.get(key)
    if cwe_set is None:
        raise ValueError(f"Unknown OWASP key: {owasp_short}. Use A01–A10.")
    try:
        cwe_num = int(str(db_cwe).strip().upper().replace("CWE-", ""))
    except ValueError:
        return False
    return cwe_num in cwe_set


def should_include(is_secure: bool, correlation: str, skip_correlation: bool = False) -> bool:
    if skip_correlation:
        return True          # hiçbir correlation filtresi uygulanmaz
    if not is_secure and correlation in ("FULL MATCH", "PARTIAL MATCH"):
        return True
    if is_secure and correlation == "NO MATCH":
        return True
    return False


def build_target(is_secure: bool, db_cwe: str) -> str:
    """
    Target label for fine-tuning:
      - Secure code   → "NONE"  (model should output no vulnerabilities)
      - Vulnerable    → DB CWE  (e.g. "CWE-89")
    """
    if is_secure:
        return "NONE"
    return db_cwe if db_cwe else "NONE"


# ==============================
# Main exporter
# ==============================

def export_local_llm_jsonl(out_dir, file_name, docker_status, limit, owasp_short, prompt_template="partial", skip_correlation=False):

    # Template seçimi
    TEMPLATE_MAP = {
        "simple":  EVAL_PROMPT,
        "partial": PARTIAL_EVAL_PROMPT,
    }
    selected_template = TEMPLATE_MAP.get(prompt_template, PARTIAL_EVAL_PROMPT)

    if file_name:
        if file_name.endswith(".py"):
            file_name = file_name[:-3]
    else:
        file_name = datetime.now().strftime("%Y%m%d_%H%M%S")

    owasp_tag = owasp_short.upper() if owasp_short else "ALL"
    out_path = os.path.join(out_dir, f"local_llm_{file_name}_{owasp_tag}.jsonl")

    db = DBManager()

    if docker_status:
        ids = db.get_ids_by_docker_status(docker_status)
    else:
        ids = db.get_all_ids()

    if limit:
        ids = ids[:limit]

    written        = 0
    skipped_owasp  = 0
    skipped_filter = 0
    skipped_error  = 0
    # Dağılımı takip etmek için sayaçlar
    target_vulnerable = 0
    target_secure     = 0
    created_at        = datetime.now().isoformat(timespec="seconds")

    with open(out_path, "w", encoding="utf-8") as f:
        for code_id in ids:
            code_row = db.get_code(code_id)
            if not code_row:
                continue
            code = (code_row[0] or "").strip()
            if not code:
                continue

            # DB fields
            db_cwe_raw = db.get_CWE_by_id(code_id)
            db_cwe     = str(db_cwe_raw[0] if isinstance(db_cwe_raw, tuple) else db_cwe_raw).strip().upper() if db_cwe_raw else ""
            if not db_cwe.startswith("CWE-"):
                db_cwe = f"CWE-{db_cwe}" if db_cwe else ""

            secure_raw = db.is_secure_by_id(code_id)
            raw_val    = secure_raw[0] if isinstance(secure_raw, tuple) else secure_raw
            is_secure  = normalize_secure(raw_val)

            # OWASP category filter
            if owasp_short:
                try:
                    if not db_cwe or not cwe_in_owasp(db_cwe, owasp_short):
                        skipped_owasp += 1
                        continue
                except ValueError as e:
                    raise e

            # Tool outputs (for correlation only, NOT in prompt)
            sast_row  = db.fetch_sast_data_by_id(code_id, ["bandit", "semgrep", "sonarqube"])
            bandit    = str(sast_row[1] or "") if sast_row else ""
            semgrep   = str(sast_row[2] or "") if sast_row else ""
            sonarqube = str(sast_row[3] or "") if sast_row else ""
            sast_combined = ",".join(filter(None, [bandit, semgrep, sonarqube]))

            dast_row  = db.fetch_dast_data_by_id(code_id)
            zap_json  = dast_row[1] if dast_row and len(dast_row) > 1 else None

            # Correlation check
            correlation = get_correlation(db_cwe, sast_combined, zap_json)
            if correlation == "ERROR":
                skipped_error += 1
                continue

            # Apply inclusion filter
            if not should_include(is_secure, correlation, skip_correlation=skip_correlation):
                skipped_filter += 1
                continue

            # ── FIX: target depends on whether the code is secure or vulnerable ──
            # Vulnerable → DB CWE (e.g. "CWE-89")
            # Secure     → "NONE" (model should find nothing)
            target = build_target(is_secure, db_cwe)

            if is_secure:
                target_secure += 1
            else:
                target_vulnerable += 1

            # Prompt: code only
            formatted_prompt = selected_template.format(code=code)

            record = {
                "id":                 code_id,
                "prompt":             formatted_prompt,
                "target":             target,
                "local_llm_response": "",
                "local_llm_model":    "",
                "meta": {
                    "created_at":      created_at,
                    "docker_status":   docker_status,
                    "db_secure":       is_secure,
                    "db_cwe":          db_cwe,        # always stored for reference
                    "correlation":     correlation,   # FULL MATCH / PARTIAL MATCH / NO MATCH
                    "owasp_filter":    owasp_short,
                    "prompt_template": prompt_template,
                }
            }

            json.dump(record, f, ensure_ascii=False)
            f.write("\n")
            written += 1

    print(f"\nJSONL written       : {out_path}")
    print(f"Total written       : {written}")
    print(f"  → Vulnerable (CWE target) : {target_vulnerable}")
    print(f"  → Secure     (NONE target): {target_secure}")
    print(f"Skipped (OWASP filter)      : {skipped_owasp}")
    print(f"Skipped (inclusion filter)  : {skipped_filter}")
    print(f"Skipped (correlation error) : {skipped_error}")
    return out_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--docker_status",   default=None)
    parser.add_argument("--limit",           type=int, default=None)
    parser.add_argument("--file_name",       default=None)
    parser.add_argument("--owasp",           default=None,
                        help="OWASP category to filter by, e.g. A05, A01, A10")
    parser.add_argument("--prompt_template", default="partial",
                        choices=["simple", "partial"],
                        help="Prompt template: 'simple' (CWE list only) or 'partial' (detailed analysis)")
    parser.add_argument(
    "--no_correlation_filter",
    action="store_true",
    default=False,
    help="Correlation filtresi olmadan tüm kayıtları dahil et"
    )
    args = parser.parse_args()

    BASE_DIR = os.path.dirname(__file__)
    OUT_DIR  = os.path.join(BASE_DIR, "exports")

    export_local_llm_jsonl(
        out_dir=OUT_DIR,
        file_name=args.file_name,
        docker_status=args.docker_status,
        limit=args.limit,
        owasp_short=args.owasp,
        prompt_template=args.prompt_template,
        skip_correlation=args.no_correlation_filter
    )