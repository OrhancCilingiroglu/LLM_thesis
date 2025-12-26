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
        cursor.execute("SELECT COUNT(*) FROM code_cwe WHERE docker = 'tested-succesful'")
        successful = cursor.fetchone()[0]
        conn.close()

        if total == 0:
            return 0.0
        return successful / total
    
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

    def mark_docker_tested_successful(self, code_id: int):
        self.update_docker_flag(code_id, "tested-successful")

    def mark_docker_tested_failed(self, code_id: int):
        self.update_docker_flag(code_id, "tested-failed")

    def mark_sql_failed(self, code_id: int):
        self.update_docker_flag(code_id, "sql-failed")

    #!! FOR DATA TRANSFORMATION BEFORE LLM TRAINING

    def export_llm_jsonl(self, out_path: str, only_docker_status: str | None = None, limit: int | None = None,):
        """
        Write lines of db to json
        {
            "input": "<prompt>",
            "target": "<json string olarak secure/CWE + tool sonuçları>"
        }

        - only_docker_status: If you want to only take the docker-run successfull examples type "tested-successfull" as in db.
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

        # 3) Write JSONL
        written = 0
        with open(out_path, "w", encoding="utf-8") as f:
            for row in rows:
                row_dict = dict(zip(columns, row))

                code = row_dict.get("code", "") or ""
                cwe = row_dict.get("CWE", "")
                secure = row_dict.get("secure", "")
                meta_parts = []
                for key in ["id", "CWE", "secure", "producer", "codetask", "webproduct", "webstyle", "port", "docker"]:
                    if key in row_dict:
                        meta_parts.append(f"{key}: {row_dict.get(key)}")
                meta_block = "\n".join(meta_parts) if meta_parts else "YOK"

                if tool_cols:
                    tools_block = "\n".join(
                        f"{col}: {row_dict.get(col)}" for col in tool_cols if row_dict.get(col) not in (None, "")
                    )
                else:
                    tools_block = "YOK"

                # LLM için input prompt
                prompt = (
                "Below is a Python/Flask web application code snippet along with some metadata "
                "and the outputs of various static and dynamic analysis tools.\n\n"
                "Your task:\n"
                "- Determine whether the code is secure or contains any vulnerabilities (insecure).\n"
                "- If insecure, identify the relevant CWE identifiers, explain the vulnerability, and describe how to fix it.\n"
                "- Provide an example patch or a secure code recommendation.\n\n"
                "### Metadata:\n"
                f"{meta_block}\n\n"
                "### Code (Python/Flask):\n"
                f"{code}\n\n"
                "### Tool Outputs:\n"
                f"{tools_block}\n\n"
                "### Answer:\n"
)

                # Target: secure + CWE + tool sonuçlarını JSON string yapalım (distillation için)
                target_obj = {
                    "secure": secure,
                    "CWE": cwe,
                    "tools": {col: row_dict.get(col) for col in tool_cols},
                }
                target_str = json.dumps(target_obj, ensure_ascii=False)

                json_line = {
                    "input": prompt,
                    "target": target_str,
                }

                json.dump(json_line, f, ensure_ascii=False)
                f.write("\n")
                written += 1

        print(f"[export_llm_jsonl] {written} satır {out_path} dosyasına yazıldı.")