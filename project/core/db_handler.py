from json import tool
import sqlite3
import os
import json
import sys
from pathlib import Path

DB_PATH = os.path.join(os.path.dirname(__file__), "code_cwe.db")

# sarif_scanners.py lives in the new src/tools/ tree (batch CodeQL/Snyk adapters);
# the live pipeline and DB accessor still live under project/core. Reach across
# rather than duplicating the column-mapping logic here.
_SRC_TOOLS = Path(__file__).resolve().parents[2] / "src" / "tools"
if str(_SRC_TOOLS) not in sys.path:
    sys.path.insert(0, str(_SRC_TOOLS))

from sarif_scanners import findings_from_columns, findings_to_columns  # noqa: E402

# Tools persisted via the <tool>_cwes/_raw/_version column triplet (findings_to_columns
# shape), as opposed to the legacy tools that store one raw-text column (see
# save_scan_results). Add a new tool here when it starts emitting SARIF-style Findings.
#
# "bandit" and "semgrep" here are the NEW structured re-scan (bandit_cwes/_raw/_version,
# semgrep_cwes/_raw/_version columns) -- distinct from the legacy `bandit`/`semgrep` TEXT
# columns save_scan_results() still writes. Both are kept: the legacy columns are never
# touched again (old numbers stay reproducible), the new columns hold the fixed
# extraction (bandit's structured issue_cwe.id, semgrep's ruleset-tagged findings).
STRUCTURED_FINDING_TOOLS = frozenset({"codeql", "snyk_code", "bandit", "semgrep"})

class DBManager:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path

    def get_files_by_id(self, code_id: int):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT code, dockerfile, sql_script, port, requirements, docker FROM code_cwe WHERE id = ?",
            (code_id,)
        )
        result = cursor.fetchone()
        conn.close()
        if result:
            code, dockerfile, sql, port, reqs, docker = result
            return code, dockerfile, sql, port, reqs, docker
        else:
            raise ValueError(f"No entry found for ID: {code_id}")
        
    def fill_row_to_database(self ,cwe, producer, codetask, webproduct, webstyle,  secure, code, dockerfile, sql_script, requirements, port):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO code_cwe (
                    CWE, producer, codetask, webproduct, webstyle,
                    secure, code, dockerfile, sql_script, requirements,
                    port
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cwe, producer, codetask, webproduct, webstyle,
                secure, code, dockerfile, sql_script, requirements,
                port
            ))
            conn.commit()
            print("Row save done!")
        except sqlite3.Error as e:
            conn.rollback()  # To prevent half filled rows
            print(f"DB commit error: {e}")
        finally:
            conn.close()

    def get_id_range(self) -> tuple[int, int]:
        """Returns the ID range of DB"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT MIN(id), MAX(id) FROM code_cwe")
        row = cursor.fetchone()
        conn.close()
        return (row[0] or 0, row[1] or 0)

    def update_docker_flag(self, code_id: int, status: str):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE code_cwe SET docker = ? WHERE id = ?", (status, code_id)
        )
        conn.commit()
        conn.close()
        print(f"SUCCESS: Updated docker status: {status} (ID: {code_id})")

    def get_code(self, code_id =int):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT code FROM code_cwe WHERE id = ?",
            (code_id,)
        )
        result = cursor.fetchone()
        conn.close()
        return result

    def get_docker_status(self, code_id =int):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT docker FROM code_cwe WHERE id = ?",
            (code_id,)
        )
        result = cursor.fetchone()
        conn.close()
    
    def get_not_tested_tools(self, status="not-tested"):
        """
        For the orchestration of all tools, get ids per tool which are the not-tested
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            # discover available columns
            cursor.execute("PRAGMA table_info(code_cwe)")
            cols = [row[1] for row in cursor.fetchall()]

            # canonical list of tool columns (note: 'nicto' is misspelled in db. It is nikto in fact)
            possible_tools = ["bandit", "semgrep", "sonarqube", "owasp_zap", "nicto", "burpsuite", "docker"]
            tools = [t for t in possible_tools if t in cols]

            result = {}
            for t in tools:
                cursor.execute(f"SELECT id FROM code_cwe WHERE {t} = ?", (status,))
                result[t] = [r[0] for r in cursor.fetchall()]

            return result
        finally:
            conn.close()
    
    def get_ids_by_docker_status(self, status):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM code_cwe WHERE docker = ?", (status,))
        rows = [row[0] for row in cursor.fetchall()]
        conn.close()
        return rows


    def save_scan_results(self, id, tool, results):
        if tool not in {"bandit", "owasp_zap", "nikto", "burpsuite", "semgrep", "sonarqube"}:
            raise ValueError("ERROR : invalid tool name for db column")
    
        if tool == "burpsuite":
            self.save_burp_scan_results(code_id=id, burp_json=results)
            parsed = json.loads(results) if results else []
            if parsed:
                # We have to check if burp really found the targeted CWE
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT CWE FROM code_cwe WHERE id = ?", (id,))
                row = cursor.fetchone()
                conn.close()
                row_cwe = f"CWE-{row[0]}" if row else None
                mapped_cwes = {r.get("mapped_cwe") for r in parsed}
                status = "found" if row_cwe in mapped_cwes else "not-found"
            else:
                status = "not-found"
            results = status

        query = f"UPDATE code_cwe SET {tool} = ? WHERE id = ?"
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(query, (results, id))
        conn.commit()
        conn.close()

    def _ensure_finding_columns(self, tool: str, conn: sqlite3.Connection) -> None:
        """Add <tool>_cwes/_raw/_version to code_cwe the first time `tool` is saved.

        Additive only -- never touches or drops an existing column, so old data
        stays intact while a new tool's storage comes online.
        """
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(code_cwe)")
        existing = {row[1] for row in cursor.fetchall()}
        for suffix in ("cwes", "raw", "version"):
            column = f"{tool}_{suffix}"
            if column not in existing:
                cursor.execute(f"ALTER TABLE code_cwe ADD COLUMN {column} TEXT")

    def save_findings(self, code_id: int, tool: str, findings, tool_version: str) -> None:
        """Persist one sample's Findings for a structured-output tool (CodeQL, Snyk).

        Findings are collapsed into the <tool>_cwes/_raw/_version columns via
        findings_to_columns (src/tools/sarif_scanners.py) and written to code_cwe --
        raw tool output stays in the DB, never in a separate file, matching how
        bandit/semgrep/etc. are already stored.

        `tool_version` is always written, even when `findings` is empty --
        findings_to_columns() has no version to infer from a clean scan, but a
        clean scan is still a completed one. Without this, has_scanned() could
        not tell "scanned, found nothing" apart from "never scanned", and a
        resumable pipeline would rescan every clean sample forever.
        """
        if tool not in STRUCTURED_FINDING_TOOLS:
            raise ValueError(
                f"{tool!r} is not a structured-finding tool; "
                f"expected one of {sorted(STRUCTURED_FINDING_TOOLS)}"
            )
        columns = findings_to_columns(findings)
        columns["version"] = tool_version
        conn = sqlite3.connect(self.db_path)
        try:
            self._ensure_finding_columns(tool, conn)
            conn.execute(
                f"UPDATE code_cwe SET {tool}_cwes = ?, {tool}_raw = ?, {tool}_version = ? "
                "WHERE id = ?",
                (columns["cwes"], columns["raw"], columns["version"], code_id),
            )
            conn.commit()
        finally:
            conn.close()

    def has_scanned(self, code_id: int, tool: str) -> bool:
        """True if `tool` has already recorded a result (clean or not) for this sample.

        Use this for resumability, not `load_findings(...) == []` -- an empty
        finding list means either "clean scan" or "never scanned", and only the
        version column (always written by save_findings) tells them apart.
        """
        if tool not in STRUCTURED_FINDING_TOOLS:
            raise ValueError(
                f"{tool!r} is not a structured-finding tool; "
                f"expected one of {sorted(STRUCTURED_FINDING_TOOLS)}"
            )
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(code_cwe)")
            existing = {row[1] for row in cursor.fetchall()}
            if f"{tool}_version" not in existing:
                return False
            cursor.execute(f"SELECT {tool}_version FROM code_cwe WHERE id = ?", (code_id,))
            row = cursor.fetchone()
        finally:
            conn.close()
        return row is not None and row[0] is not None

    def load_findings(self, code_id: int, tool: str) -> list:
        """Rebuild Findings for one sample/tool from stored columns.

        Returns [] for both "clean scan" and "never scanned" -- use has_scanned()
        to tell those apart for resumability; this method is for reading results
        you already know exist.
        """
        if tool not in STRUCTURED_FINDING_TOOLS:
            raise ValueError(
                f"{tool!r} is not a structured-finding tool; "
                f"expected one of {sorted(STRUCTURED_FINDING_TOOLS)}"
            )
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(code_cwe)")
            existing = {row[1] for row in cursor.fetchall()}
            if f"{tool}_raw" not in existing:
                return []
            cursor.execute(
                f"SELECT {tool}_cwes, {tool}_raw, {tool}_version FROM code_cwe WHERE id = ?",
                (code_id,),
            )
            row = cursor.fetchone()
        finally:
            conn.close()
        if row is None:
            return []
        cwes, raw, version = row
        return findings_from_columns(str(code_id), tool, cwes, raw, version)

    def save_burp_scan_results(self, code_id: int, burp_json: str):
        if not burp_json:
            return
        results = json.loads(burp_json)
        if not results:          # boş liste → detay kaydı yok
            return

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        for r in results:
            cursor.execute("""
                INSERT INTO burp_scan_result
                    (code_id, scan_id, scan_type, issue_name, type_index,
                    mapped_cwe, severity, confidence, path, origin)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
            code_id,
            r.get("scan_id"),
            r.get("scan_type"),
            r.get("issue_name"),
            r.get("type_index"),
            r.get("mapped_cwe"),
            r.get("severity"),
            r.get("confidence"),
            r.get("path"),
            r.get("origin"),
        ))
        conn.commit()
        conn.close()
    
    def get_docker_success_rate(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM code_cwe")
        total = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM code_cwe WHERE docker = 'tested-successful'")
        successful = cursor.fetchone()[0]
        conn.close()

        if total == 0:
            return 0.0
        return successful / total
    
    def get_secure_rate(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM code_cwe")
        total = cursor.fetchone()[0]
        cursor.execute("""
            SELECT COUNT(*) 
            FROM code_cwe 
            WHERE secure = 'SECURE' 
                OR secure = 1
                OR UPPER(secure) = 'TRUE'
            """)
        secure_count = cursor.fetchone()[0]
        conn.close()
        if total == 0:
            return 0.0
        return secure_count / total
    
    def get_secure_docker_success_rate(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM code_cwe")
        total = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM code_cwe WHERE docker = 'tested-successful' AND (secure = 1 OR UPPER(secure) = 'SECURE')")
        successful = cursor.fetchone()[0]
        conn.close()

        if total == 0:
            return 0.0
        return successful / total
    
    def count_rows_by_cwe(self, cwe: int) -> int:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM code_cwe WHERE CWE = ?", (cwe,))
        successful = cursor.fetchone()[0]
        conn.close()
        return successful

    def fetch_dast_data_by_id(self, code_id):
        """
        Returns (id, owasp_zap, burpsuite) for the given code_id.
        burpsuite kolonu "found" / "not-found" / None değerlerini taşır.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        # burpsuite kolonu yoksa hata vermemesi için PRAGMA ile kontrol et
        cursor.execute("PRAGMA table_info(code_cwe)")
        cols = [row[1] for row in cursor.fetchall()]
        if "burpsuite" in cols:
            query = "SELECT id, owasp_zap, burpsuite FROM code_cwe WHERE id = ?"
        else:
            query = "SELECT id, owasp_zap, NULL FROM code_cwe WHERE id = ?"
        cursor.execute(query, (code_id,))
        result = cursor.fetchone()
        conn.close()
        return result   # (id, owasp_zap, burpsuite)


    def fetch_sast_data_by_id(self, code_id, sast_tool_columns=None):

        if sast_tool_columns is None:
            sast_tool_columns = ["bandit", "semgrep", "sonarqube"]

        if not sast_tool_columns: # Because is None =! []
            raise ValueError("sast_tool_columns listesi boş. En az bir sütun belirtmelisin.")

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        query = f"""
        SELECT id, {', '.join(sast_tool_columns)}
        FROM code_cwe
        WHERE id = ?
        """
        cursor.execute(query, (code_id,))
        result = cursor.fetchone()
        conn.close()
        return result

    # Mid project i changed how i save secure/vulnerable info.
    # So this function will normalize the old and new values to boolean
    def is_secure_by_id(self, code_id: int) -> bool:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT secure FROM code_cwe WHERE id = ?", (code_id,))
        row = cur.fetchone()
        conn.close()
        if not row or row[0] is None:
            return False  # default: vulnerable
        val = row[0]
        # numeric / boolean
        if isinstance(val, bool):
            return val
        if isinstance(val, int):
            return val == 1
        # string normalization
        s = str(val).strip().upper()
        SECURE_TRUE = {"SECURE", "TRUE", "1", "YES", "Y"}
        SECURE_FALSE = {"VULNERABLE", "INSECURE", "FALSE", "0", "NO", "N"}
        if s in SECURE_TRUE:
            return True
        if s in SECURE_FALSE:
            return False
        # fallback: conservative
        return False
    
    def get_CWE_by_id(self, code_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        query = f"""
        SELECT CWE
        FROM code_cwe
        WHERE id = ?
        """
        cursor.execute(query, (code_id,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None  # to get strip tuple error
    
    def fetch_burp_data_by_id(self, code_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, burpsuite FROM code_cwe WHERE id = ?", (code_id,))
        result = cursor.fetchone()
        conn.close()
        return result[1] if result else None

    def get_docker_info_by_cwe(self, cwe_id):
        #* it will work for burpsuite so no reason to make docker status dynamic
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        query = """
        SELECT id, port 
        FROM code_cwe 
        WHERE CWE = ? AND docker = 'tested-successful'"""
        cursor.execute(query, (cwe_id,)
        )
        return cursor.fetchall()

    def get_all(self, code_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        query = f"""
        SELECT *
        FROM code_cwe
        WHERE id = ?
        """
        cursor.execute(query, (code_id,))
        result = cursor.fetchone()
        conn.close()
        return result  

    def get_all_ids(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM code_cwe")
        rows = [row[0] for row in cursor.fetchall()]
        conn.close()
        return rows

    def mark_docker_tested_successful(self, code_id: int):
        self.update_docker_flag(code_id, "tested-successful")

    def mark_docker_tested_failed(self, code_id: int):
        self.update_docker_flag(code_id, "tested-failed")

    def mark_sql_failed(self, code_id: int):
        self.update_docker_flag(code_id, "sql-failed")

    #!! FOR DATA TRANSFORMATION BEFORE LLM TRAINING

    def export_llm_jsonl(
        self,
        out_path: str,
        only_docker_status: str | None = None,
        limit: int | None = None,
    ):
        """
        Output JSONL per line:
          {
            "input": "<prompt string>",
            "target": "secure" | "vulnerable",
            "code": "<raw code>",
            "cwe": "<CWE id>",
            "tools": { ... }              # for training
          }
        - only_docker_status: "tested-successfull" (as in db).
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Take column names
        cursor.execute("PRAGMA table_info(code_cwe)")
        cols_info = cursor.fetchall()
        if not cols_info:
            conn.close()
            raise ValueError("ERROR: Cant take column names")
        columns = [c[1] for c in cols_info]

        # Create query
        query = "SELECT * FROM code_cwe"
        params = []

        if only_docker_status is not None and "docker" in columns:
            query += " WHERE docker = ?"
            params.append(only_docker_status)

        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)

        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()
        conn.close()

        possible_tool_cols = [
            "bandit",
            "semgrep",
            "sonarqube",
            "owasp_zap",
            "nikto",
            "burpsuite",
        ]
        tool_cols = [c for c in possible_tool_cols if c in columns]

        def norm_label(x) -> str:
            """
            normalize secure column
            """
            s = str(x).strip().lower()
            if s in ["secure", "safe", "1", "true"]:
                return "secure"
            # insecure/vulnerable/vuln/0/false vs.
            return "vulnerable"

        written = 0
        with open(out_path, "w", encoding="utf-8") as f:
            for row in rows:
                row_dict = dict(zip(columns, row))

                code = row_dict.get("code", "") or ""
                cwe = row_dict.get("CWE", "") or ""
                secure_val = row_dict.get("secure", "")

                # ---- tools dict + readable block ----
                tools_dict = {}
                if tool_cols:
                    for col in tool_cols:
                        val = row_dict.get(col)
                        if val not in (None, ""):
                            tools_dict[col] = val

                tools_block = "\n".join([f"- {k}: {v}" for k, v in tools_dict.items()]) if tools_dict else "NONE"

                # ---- prompt (tools included) ----
                prompt = (
                    "You are a senior application security engineer.\n\n"
                    "Your task:\n"
                    "Analyze the given Python/Flask code and list the vulnerabilities as CWE IDs.\n"
                    "### Code (Python/Flask):\n"
                    "```python\n"
                    f"{code}\n"
                    "```\n\n"
                )
##! Buradaki prompt kısmı değiştirebiliriz, promptu değiştirmeden önce bir tekrar et. sonra değiştirip karşılaştır
#! Lama 3.x, Llama 4, QWEN latest, Deepseek models,
                target_str = norm_label(secure_val)

                json_line = {
                    "input": prompt,        # trainer için
                    "target": target_str,   # SADECE "secure" / "vulnerable"
                    # aşağıdakiler opsiyonel ama çok faydalı:
                    "code": code,
                    "cwe": cwe,
                    "tools": tools_dict
                }

                json.dump(json_line, f, ensure_ascii=False)
                f.write("\n")
                written += 1

        print(f"[export_llm_jsonl] {written} row {out_path} written to file.")