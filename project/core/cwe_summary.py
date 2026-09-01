from core.db_handler import DBManager
from core.cwe_correlations import parse_sonarqube_cwes
import json
import sqlite3
from collections import defaultdict, Counter
from utils import OWASP

# ── same OWASP map from your analyser ────────────────────────────────────────
OWASP_2025_MAP = {
    "A01_2025_Broken_Access_Control":               set(OWASP.A01_2025_Broken_Access_Control_list),
    "A02_2025_Security_Misconfiguration":           set(OWASP.A02_2025_Security_Misconfiguration_list),
    "A03_2025_Sofware_Supply_Chain":                set(OWASP.A03_2025_Sofware_Supply_Chain_list),
    "A04_2025_Cryptographic_Failures":              set(OWASP.A04_2025_Cryptographic_Failures_list),
    "A05_2025_Injection":                           set(OWASP.A05_2025_Injection_list),
    "A06_2025_Insecure_Design":                     set(OWASP.A06_2025_Insecure_Design_list),
    "A07_2025_Authentication_Failures":             set(OWASP.A07_2025_Authentication_Failures_list),
    "A08_2025_Software_or_Data_Integrity_Failures": set(OWASP.A08_2025_Software_or_Data_Integrity_Failures_list),
    "A09_2025_Security_Logging_and_Alerting_Failures": set(OWASP.A09_2025_Security_Logging_and_Alerting_Failures_list),
    "A10_2025_Mishandling_of_Exceptional_Conditions": set(OWASP.A10_2025_Mishandling_of_Exceptional_Conditions_list),
}

PLACEHOLDERS = {"not-tested", "not_tested", "not tested", "na", "n/a", "none", "null", "nan", "-"}

def cwe_to_owasp(db_cwe: str) -> str:
    s = str(db_cwe).strip().upper()
    if not s.startswith("CWE-"):
        s = f"CWE-{s}"
    try:
        num = int(s.replace("CWE-", "").strip())
    except ValueError:
        return "UNMAPPED"
    for cat, cwe_set in OWASP_2025_MAP.items():
        if num in cwe_set:
            return cat
    return "UNMAPPED"

def safe_json(raw):
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="replace")
    s = str(raw).strip()
    if not s or s.lower() in PLACEHOLDERS or s[0] not in "{[":
        return None
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        return None

def parse_sast_cwes(raw: str) -> set:
    found = set()
    if not raw:
        return found
    for item in raw.split(","):
        item = item.strip().upper()
        if item.startswith("CWE-"):
            found.add(item)
    return found

def parse_zap_cwes(zap_raw) -> set:
    found = set()
    alerts = safe_json(zap_raw)
    if alerts is None:
        return found

    if isinstance(alerts, dict):
        if "alerts" in alerts:
            alerts = alerts["alerts"]
        elif "site" in alerts:
            merged = []
            for s in alerts["site"]:
                if isinstance(s, dict) and isinstance(s.get("alerts"), list):
                    merged.extend(s["alerts"])
            alerts = merged
        else:
            alerts = []

    if not isinstance(alerts, list):
        return found

    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        cweid = str(alert.get("cweid", "")).strip()
        if cweid and cweid not in ("0", "-1", ""):
            found.add(f"CWE-{cweid}")
        tags = alert.get("tags", {})
        if isinstance(tags, dict):
            for tag_key in tags:
                tag_upper = tag_key.strip().upper()
                if tag_upper.startswith("CWE-"):
                    try:
                        int(tag_upper.replace("CWE-", ""))
                        found.add(tag_upper)
                    except ValueError:
                        pass
    return found


def build_detection_db(source_db=None):
    """`source_db=None` uses the real project/core/code_cwe.db; pass a
    DBManager pointed at a scratch DB to test safely first."""
    if source_db is None:
        source_db = DBManager()
    successful_ids = source_db.get_ids_by_docker_status("tested-successful")

    cwe_data = defaultdict(lambda: {
        "owasp":            "",
        "full_ids":         [],
        "partial_ids":      [],
        "bandit":           0,
        "semgrep":          0,
        "sonarqube":        0,
        "zap":              0,
        "burpsuite":        0,
        "total_docker_ok":  0,
        "secure_docker_ok": 0,
        "vuln_docker_ok":   0,
    })

    sample_rows = []

    # ── Pass 1: population counts for ALL docker-ok rows (secure + vulnerable) ─
    # This must run before the detection loop which skips secure rows early.
    for code_id in successful_ids:
        try:
            db_cwe_raw = source_db.get_CWE_by_id(code_id)
            is_secure  = source_db.is_secure_by_id(code_id)
        except Exception:
            continue
        if not db_cwe_raw:
            continue
        db_cwe = str(db_cwe_raw).strip().upper()
        if not db_cwe.startswith("CWE-"):
            db_cwe = f"CWE-{db_cwe}"
        owasp_cat = cwe_to_owasp(db_cwe)
        cwe_data[db_cwe]["owasp"]            = owasp_cat
        cwe_data[db_cwe]["total_docker_ok"] += 1
        if is_secure:
            cwe_data[db_cwe]["secure_docker_ok"] += 1
        else:
            cwe_data[db_cwe]["vuln_docker_ok"]   += 1

    # ── Pass 2: detection analysis (vulnerable rows only) ────────────────────
    for code_id in successful_ids:
        try:
            sast_row   = source_db.fetch_sast_data_by_id(code_id)
            dast_row   = source_db.fetch_dast_data_by_id(code_id)
            db_cwe_raw = source_db.get_CWE_by_id(code_id)
            is_secure  = source_db.is_secure_by_id(code_id)
        except Exception:
            continue

        if is_secure:
            continue
        if not db_cwe_raw:
            continue

        db_cwe = str(db_cwe_raw).strip().upper()
        if not db_cwe.startswith("CWE-"):
            db_cwe = f"CWE-{db_cwe}"

        owasp_cat = cwe_to_owasp(db_cwe)

        bandit_raw    = sast_row[1] if sast_row and len(sast_row) > 1 else None
        semgrep_raw   = sast_row[2] if sast_row and len(sast_row) > 2 else None
        sonarqube_raw = sast_row[3] if sast_row and len(sast_row) > 3 else None
        zap_raw       = dast_row[1] if dast_row and len(dast_row) > 1 else None
        burp_raw      = source_db.fetch_burp_data_by_id(code_id) if hasattr(source_db, "fetch_burp_data_by_id") else None
        burp_val      = str(burp_raw).strip().lower() if burp_raw else ""
        hit_burpsuite = burp_val == "found"

        bandit_cwes    = parse_sast_cwes(bandit_raw)
        semgrep_cwes   = parse_sast_cwes(semgrep_raw)
        sonarqube_cwes = parse_sonarqube_cwes(sonarqube_raw)
        zap_cwes       = parse_zap_cwes(zap_raw)

        hit_bandit    = db_cwe in bandit_cwes
        hit_semgrep   = db_cwe in semgrep_cwes
        hit_sonarqube = db_cwe in sonarqube_cwes
        hit_zap       = db_cwe in zap_cwes
        hit_sast      = hit_bandit or hit_semgrep or hit_sonarqube
        hit_dast      = hit_zap or hit_burpsuite
        hit_any       = hit_sast or hit_dast

        # FULL  = en az 1 SAST + en az 1 DAST hedef CWE'yi buldu
        # PARTIAL = sadece SAST ya da sadece DAST buldu (FULL degil)
        # NO MATCH = hicbiri bulamadi -> satirı atla
        if hit_sast and hit_dast:
            match_type = "FULL"
        elif hit_any:
            match_type = "PARTIAL"
        else:
            continue

        sample_rows.append((
            code_id, db_cwe, owasp_cat, match_type,
            int(hit_bandit), int(hit_semgrep),
            int(hit_sonarqube), int(hit_zap), int(hit_burpsuite),
        ))

        entry = cwe_data[db_cwe]
        entry["owasp"] = owasp_cat

        if match_type == "FULL":
            entry["full_ids"].append(code_id)
        else:
            entry["partial_ids"].append(code_id)

        if hit_bandit:    entry["bandit"]    += 1
        if hit_semgrep:   entry["semgrep"]   += 1
        if hit_sonarqube: entry["sonarqube"] += 1
        if hit_zap:       entry["zap"]       += 1
        if hit_burpsuite: entry["burpsuite"] += 1

    # ── write into the same code_cwe.db — never touch existing tables ────────
    conn = sqlite3.connect(source_db.db_path)
    cur  = conn.cursor()

    # Add population columns if running against an existing database
    existing_cols = {row[1] for row in cur.execute("PRAGMA table_info(cwe_summary)").fetchall()}
    for col, coltype in [
        ("total_docker_ok",  "INTEGER"),
        ("secure_docker_ok", "INTEGER"),
        ("vuln_docker_ok",   "INTEGER"),
    ]:
        if col not in existing_cols:
            cur.execute(f"ALTER TABLE cwe_summary ADD COLUMN {col} {coltype} DEFAULT 0")
    conn.commit()

    # CREATE TABLE IF NOT EXISTS — only creates if it doesn't exist yet
    # no DROP, no DELETE, existing data is never touched
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS sample_detections (
            id                    INTEGER PRIMARY KEY,
            cwe                   TEXT,
            owasp_category        TEXT,
            match_type            TEXT,
            detected_by_bandit    INTEGER,
            detected_by_semgrep   INTEGER,
            detected_by_sonarqube INTEGER,
            detected_by_zap       INTEGER,
            detected_by_burpsuite INTEGER
        );

        CREATE TABLE IF NOT EXISTS cwe_summary (
            cwe                   TEXT PRIMARY KEY,
            owasp_category        TEXT,
            full_match_count      INTEGER,
            partial_match_count   INTEGER,
            full_match_ids        TEXT,
            partial_match_ids     TEXT,
            bandit_detections     INTEGER,
            semgrep_detections    INTEGER,
            sonarqube_detections  INTEGER,
            zap_detections        INTEGER,
            burpsuite_detections  INTEGER,
            total_detections      INTEGER,
            total_docker_ok       INTEGER,
            secure_docker_ok      INTEGER,
            vuln_docker_ok        INTEGER
        );
    """)

    # INSERT OR REPLACE — updates the row if it already exists, no duplicates
    cur.executemany("""
        INSERT OR REPLACE INTO sample_detections
            (id, cwe, owasp_category, match_type,
             detected_by_bandit, detected_by_semgrep,
             detected_by_sonarqube, detected_by_zap, detected_by_burpsuite)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, sample_rows)

    for cwe, entry in sorted(cwe_data.items()):
        full_ids    = ",".join(str(i) for i in sorted(entry["full_ids"]))
        partial_ids = ",".join(str(i) for i in sorted(entry["partial_ids"]))
        total = (entry["bandit"] + entry["semgrep"] + entry["sonarqube"]
                 + entry["zap"] + entry["burpsuite"])
        cur.execute("""
            INSERT OR REPLACE INTO cwe_summary
                (cwe, owasp_category,
                 full_match_count, partial_match_count,
                 full_match_ids, partial_match_ids,
                 bandit_detections, semgrep_detections,
                 sonarqube_detections, zap_detections,
                 burpsuite_detections, total_detections,
                 total_docker_ok, secure_docker_ok, vuln_docker_ok)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cwe, entry["owasp"],
            len(entry["full_ids"]), len(entry["partial_ids"]),
            full_ids, partial_ids,
            entry["bandit"], entry["semgrep"], entry["sonarqube"],
            entry["zap"], entry["burpsuite"], total,
            entry["total_docker_ok"], entry["secure_docker_ok"], entry["vuln_docker_ok"],
        ))

    conn.commit()
    conn.close()

    print(f"Done. Tables written into {source_db.db_path}")
    print(f"  sample_detections : {len(sample_rows)} rows")
    print(f"  cwe_summary       : {len(cwe_data)} CWEs")


if __name__ == "__main__":
    build_detection_db()