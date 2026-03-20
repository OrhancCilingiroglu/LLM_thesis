import sqlite3
import os
import json

DB_PATH = os.path.join(os.path.dirname(__file__), "code_cwe.db")

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
        query = f"UPDATE code_cwe SET {tool} = ? WHERE id = ?"
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(query, (results, id))
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

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        query = """
        SELECT id, owasp_zap
        FROM code_cwe
        WHERE id = ?
        """
        cursor.execute(query, (code_id,))
        result = cursor.fetchone()
        conn.close()
        return result


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