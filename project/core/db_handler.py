import sqlite3
import os

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

    def mark_docker_tested_successful(self, code_id: int):
        self.update_docker_flag(code_id, "tested-successful")

    def mark_docker_tested_failed(self, code_id: int):
        self.update_docker_flag(code_id, "tested-failed")

    def mark_sql_failed(self, code_id: int):
        self.update_docker_flag(code_id, "sql-failed")